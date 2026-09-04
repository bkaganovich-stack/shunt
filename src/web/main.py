#!/usr/bin/env python3
"""Xray Proxy Gateway — Web Management Interface v1.6.0"""

import asyncio, base64, fcntl, hashlib, hmac, io, ipaddress, json, os, pty
import re, shutil, signal, socket, struct, subprocess, tarfile, termios, time
import urllib.parse, urllib.request
import uuid as _uuid_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = "1.7.0"

# ── Bootstrap db + features (import before app creation) ─────────────────────
import db as _db
import features as _ft

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, Response, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import (HTMLResponse, JSONResponse, StreamingResponse,
                               FileResponse)
import mimetypes
from pydantic import BaseModel

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE      = Path("/opt/xray-proxy")
CFG_DIR   = BASE / "config"
SNAP_DIR  = CFG_DIR / "snapshots"
SCRIPT    = BASE / "scripts"
LOGS      = BASE / "logs"
STATIC    = BASE / "web" / "static"
SETTINGS  = CFG_DIR / "settings.json"
XCFG      = CFG_DIR / "xray.json"
SINGBOX_CFG = Path("/etc/sing-box/config.json")   # managed for the SOCKS proxy toggle
SINGBOX_BIN = "/usr/bin/sing-box"
PROXY_TAG   = "socks-tg"                            # SOCKS inbound tag owned by the Proxy UI
DNS_CONF  = Path("/etc/dnsmasq.d/gateway.conf")

MAX_SNAPSHOTS   = 15
ALERT_LOG_SIZE  = 100   # keep last N alert events in memory

# Wire features module paths after BASE is defined
def _wire_features() -> None:
    _db.set_db_path(CFG_DIR / "gateway.db")
    _ft.BASE    = BASE
    _ft.CFG_DIR = CFG_DIR

# ── Default settings (v1.6) ────────────────────────────────────────────────────
DEFAULT_SETTINGS: dict = {
    "version":      "1.6.0",
    "auth":         {"username": "admin",
                     "password_hash": hashlib.sha256(b"admin").hexdigest()},
    # VPN: single key kept for migration compatibility; canonical list in vpn_servers
    "vpn_key":      None,       # DEPRECATED — use vpn_servers
    "vpn_servers":  [],         # list of VPNServer dicts
    "active_vpn_id": None,      # id of active server
    "profile":      "all_except_ru",
    "geo_updated":  None,
    "force_aaplimg_vpn": True,
    "custom_rules": {"always_direct": [], "always_vpn": []},
    # Devices: keyed by MAC (or "ip:A.B.C.D" when MAC unavailable)
    # {"aa:bb:cc:dd:ee:ff": {"name":"...", "policy":"inherit", "ips":[]}}
    "devices":      {},
    "device_names": {},         # DEPRECATED — migrated into devices on load
    # DNS config (drives dnsmasq)
    "dns": {
        "upstream":     ["192.168.50.1"],
        "upstream_ru":  [],          # split-DNS: upstream for .ru / local
        "cache_size":   1000,
        "local_records": [],         # [{"hostname":"x.local","ip":"1.2.3.4"}]
    },
    # Alerts
    "alerts": {
        "enabled":      False,
        "webhook_url":  "",
        "events":       ["vpn_down", "config_rollback", "geo_update_failed",
                         "disk_high", "all_vpn_unavailable", "login_failed"],
        "cooldown_min": 30,
    },
    # v1.6 additions ─────────────────────────────────────────────────────────
    # Device groups: [{id, name, description, routing_policy, devices:[keys]}]
    "groups":        [],
    # Subscriptions: [{id, name, url, type, enabled, schedule, last_update,
    #                  last_error, rule_count}]
    "subscriptions": [],
    # Adblock DNS
    "adblock": {
        "enabled":         False,
        "use_starter_list": True,
        "custom_rules":    [],
        "allowlist":       [],
    },
    # Scheduler tasks: [{id, name, type, enabled, schedule, last_run_ts,
    #                    last_result, last_error}]
    "scheduler_tasks": [],
    # Terminal mode
    "terminal": {
        "mode":             "full",  # disabled|diagnostic|allowlist|full
        "allowlist_extra":  [],
    },
    # Analytics
    "analytics": {
        "enabled":         True,
        "retention_days":  30,
    },
    # SOCKS proxy (a sing-box inbound; lets a device route selected apps
    # through the gateway/VPN, e.g. Telegram on the phone). Live state is read
    # from the sing-box config; this mirror is kept for export/record.
    "proxy": {
        "enabled":          False,
        "port":             1080,
        "restrict_to_home": False,   # bind to the Home-LAN ip instead of 0.0.0.0
        "auth": {"enabled": False, "username": "", "password": ""},
    },
    # AdGuard VPN egress: when enabled, the xray proxy outbound becomes a SOCKS
    # outbound to the local adguardvpn-cli (127.0.0.1:1081) instead of the VPN-server
    # shadowsocks/vless key. Keeps this regen-safe across build_xray_config().
    "adguard": {"enabled": False, "socks_host": "127.0.0.1", "socks_port": 1081,
                "post_quantum": False},
    # Update history stored in SQLite; this just holds last-check cache
    "update_cache": {},
}

# ── In-memory alert state ──────────────────────────────────────────────────────
_alert_last_sent: dict[str, float] = {}   # event_type → timestamp
_alert_log:       list[dict]        = []  # recent alert events
_login_fail_count: dict[str, int]   = {}  # ip → consecutive failures
_failover_last:    float            = 0.0 # timestamp of last failover

# ── Settings helpers ───────────────────────────────────────────────────────────
def _migrate_settings(s: dict) -> dict:
    """Upgrade settings from any previous version to current schema."""
    # v1.4 → v1.5: vpn_key → vpn_servers
    if s.get("vpn_key") and not s.get("vpn_servers"):
        srv_id = str(_uuid_mod.uuid4())
        s["vpn_servers"] = [{
            "id": srv_id, "name": "Server 1",
            "key": s["vpn_key"], "enabled": True, "priority": 1,
            "last_status": "unknown", "latency_ms": None, "last_checked": None,
        }]
        s["active_vpn_id"] = srv_id

    # v1.4 → v1.5: device_names → devices
    if s.get("device_names") and not s.get("devices"):
        s["devices"] = {}
        for ip, name in s["device_names"].items():
            key = f"ip:{ip}"
            s["devices"][key] = {"name": name, "policy": "inherit", "ips": [ip]}

    # Fill missing keys from defaults
    for k, v in DEFAULT_SETTINGS.items():
        s.setdefault(k, v)
    # Deep-merge nested dicts
    for nested_key in ("dns", "alerts", "adblock", "terminal", "analytics", "proxy", "adguard"):
        if nested_key not in s:
            s[nested_key] = dict(DEFAULT_SETTINGS[nested_key])
        else:
            for k, v in DEFAULT_SETTINGS[nested_key].items():
                s[nested_key].setdefault(k, v)
    s.setdefault("version", VERSION)
    s["custom_rules"].setdefault("always_direct", [])
    s["custom_rules"].setdefault("always_vpn", [])
    return s

def load_settings() -> dict:
    if SETTINGS.exists():
        try:
            s = json.loads(SETTINGS.read_text())
        except Exception:
            s = {}
        return _migrate_settings(s)
    return _migrate_settings(dict(DEFAULT_SETTINGS))

def save_settings(s: dict) -> None:
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS.write_text(json.dumps(s, indent=2))

SECRET = (BASE / ".secret").read_text().strip() if (BASE / ".secret").exists() \
         else "xray-proxy-default-secret"

# ── Auth ───────────────────────────────────────────────────────────────────────
def make_token(user: str) -> str:
    exp = int(time.time()) + 86400
    payload = f"{user}:{exp}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()

def verify_token(tok: str) -> Optional[str]:
    try:
        decoded = base64.urlsafe_b64decode(tok + "==").decode()
        user, exp, sig = decoded.rsplit(":", 2)
        if int(exp) < int(time.time()):
            return None
        expected = hmac.new(SECRET.encode(), f"{user}:{exp}".encode(), hashlib.sha256).hexdigest()
        return user if hmac.compare_digest(sig, expected) else None
    except Exception:
        return None

def auth_dep(req: Request) -> str:
    tok = req.cookies.get("token") or req.headers.get("X-Token", "")
    user = verify_token(tok)
    if not user:
        raise HTTPException(401, "Unauthorized")
    return user

# ── VPN Key Parsing ────────────────────────────────────────────────────────────
def _b64d(s: str) -> str:
    pad = (4 - len(s) % 4) % 4
    return base64.b64decode(s + "=" * pad).decode()

def parse_key(key: str):
    k = key.strip()
    if k.startswith("ss://"):     return _parse_ss(k)
    if k.startswith("vless://"):  return _parse_vless(k)
    if k.startswith("vmess://"):  return _parse_vmess(k)
    if k.startswith("trojan://"): return _parse_trojan(k)
    raise ValueError(f"Unknown protocol in: {k[:30]}")

def _sockopt():       return {"mark": 255}
def _proxy_sockopt(): return {"mark": 255, "tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15}

def mask_key(key: str) -> str:
    """Return a masked version of a VPN key safe for display."""
    if not key:
        return ""
    try:
        if "@" in key:
            # Show protocol and server only
            at = key.rfind("@")
            host_part = key[at+1:]
            proto = key.split("://")[0] if "://" in key else "??"
            return f"{proto}://***@{host_part}"
        return key[:8] + "***"
    except Exception:
        return "***"

def _parse_ss(uri: str):
    uri = uri[5:]; name = ""
    if "#" in uri:
        uri, name = uri.rsplit("#", 1); name = urllib.parse.unquote(name)
    if "@" not in uri:
        uri = _b64d(uri)
    user, hostport = uri.rsplit("@", 1)
    try:
        user = _b64d(user)
    except Exception:
        pass
    method, password = user.split(":", 1)
    host, port = hostport.rsplit(":", 1)
    ob = {"protocol": "shadowsocks", "tag": "proxy",
          "settings": {"servers": [{"address": host, "port": int(port),
                                    "method": method, "password": password}]},
          "streamSettings": {"network": "tcp", "sockopt": _proxy_sockopt()}}
    return ob, {"name": name or f"{host}:{port}", "server": host,
                "port": int(port), "protocol": "Shadowsocks"}

def _parse_vless(uri: str):
    uri = uri[8:]; name = ""
    if "#" in uri:
        uri, name = uri.rsplit("#", 1); name = urllib.parse.unquote(name)
    uuid, rest = uri.split("@", 1)
    hostport, qs = (rest.split("?", 1) + [""])[:2]
    host, port = hostport.rsplit(":", 1)
    p = dict(urllib.parse.parse_qsl(qs))
    net = p.get("type", "tcp"); sec = p.get("security", "none")
    ss = {"network": net, "sockopt": _proxy_sockopt()}
    if sec == "tls":
        ss["security"] = "tls"
        ss["tlsSettings"] = {"serverName": p.get("sni", host),
                             "allowInsecure": p.get("allowInsecure", "0") == "1"}
    elif sec == "reality":
        ss["security"] = "reality"
        ss["realitySettings"] = {"serverName": p.get("sni", host),
                                  "publicKey": p.get("pbk", ""),
                                  "shortId": p.get("sid", ""),
                                  "fingerprint": p.get("fp", "chrome")}
    if net == "ws":
        ss["wsSettings"] = {"path": p.get("path", "/"), "headers": {"Host": p.get("host", host)}}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": p.get("serviceName", "")}
    ob = {"protocol": "vless", "tag": "proxy",
          "settings": {"vnext": [{"address": host, "port": int(port),
                                   "users": [{"id": uuid, "encryption": "none",
                                              "flow": p.get("flow", "")}]}]},
          "streamSettings": ss}
    return ob, {"name": name or f"{host}:{port}", "server": host,
                "port": int(port), "protocol": "VLESS"}

def _parse_vmess(uri: str):
    d = json.loads(_b64d(uri[8:]))
    host = d.get("add", ""); port = int(d.get("port", 443))
    net = d.get("net", "tcp"); tls_val = d.get("tls", "")
    ss = {"network": net, "sockopt": _proxy_sockopt()}
    if tls_val == "tls":
        ss["security"] = "tls"; ss["tlsSettings"] = {"serverName": d.get("sni", host)}
    if net == "ws":
        ss["wsSettings"] = {"path": d.get("path", "/"), "headers": {"Host": d.get("host", host)}}
    ob = {"protocol": "vmess", "tag": "proxy",
          "settings": {"vnext": [{"address": host, "port": port,
                                   "users": [{"id": d.get("id", ""),
                                              "alterId": int(d.get("aid", 0)),
                                              "security": d.get("scy", "auto")}]}]},
          "streamSettings": ss}
    return ob, {"name": d.get("ps", f"{host}:{port}"), "server": host,
                "port": port, "protocol": "VMess"}

def _parse_trojan(uri: str):
    uri = uri[9:]; name = ""
    if "#" in uri:
        uri, name = uri.rsplit("#", 1); name = urllib.parse.unquote(name)
    password, rest = uri.split("@", 1)
    hostport, qs = (rest.split("?", 1) + [""])[:2]
    host, port = hostport.rsplit(":", 1)
    p = dict(urllib.parse.parse_qsl(qs))
    ob = {"protocol": "trojan", "tag": "proxy",
          "settings": {"servers": [{"address": host, "port": int(port), "password": password}]},
          "streamSettings": {"network": "tcp", "security": "tls",
                             "tlsSettings": {"serverName": p.get("sni", host)},
                             "sockopt": _proxy_sockopt()}}
    return ob, {"name": name or f"{host}:{port}", "server": host,
                "port": int(port), "protocol": "Trojan"}

# ── ARP helpers ────────────────────────────────────────────────────────────────
def get_arp_table() -> list[dict]:
    """Read ARP table; merge IPv4+IPv6 by MAC. Return [{ip, mac, state}...]."""
    try:
        r = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5)
        devices: dict[str, dict] = {}  # mac → {ips:set, mac, state}
        ip_only: dict[str, dict] = {}  # ip → entry (for MAC-less entries)
        seen_ips: set[str] = set()
        for line in r.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) < 2: continue
            ip_str = parts[0]
            try:
                ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if ip_str in seen_ips:
                continue
            seen_ips.add(ip_str)
            mac = state = ""
            for i, p in enumerate(parts):
                if p == "lladdr" and i + 1 < len(parts):
                    mac = parts[i + 1].lower()
                if p in ("REACHABLE", "STALE", "DELAY", "FAILED", "NOARP", "PERMANENT"):
                    state = p
            if state == "FAILED":
                continue
            if mac:
                if mac not in devices:
                    devices[mac] = {"mac": mac, "ips": set(), "state": state}
                devices[mac]["ips"].add(ip_str)
                # prefer REACHABLE state
                if state == "REACHABLE":
                    devices[mac]["state"] = state
            else:
                ip_only[ip_str] = {"mac": "", "ips": {ip_str}, "state": state}
        result = []
        for mac, d in devices.items():
            result.append({"mac": mac, "ips": sorted(d["ips"]), "state": d["state"]})
        for ip, d in ip_only.items():
            result.append({"mac": "", "ips": [ip], "state": d["state"]})
        return result
    except Exception:
        return []

def arp_ip_to_mac() -> dict[str, str]:
    """Return {ip: mac} mapping from current ARP table."""
    m: dict[str, str] = {}
    for entry in get_arp_table():
        if entry["mac"]:
            for ip in entry["ips"]:
                m[ip] = entry["mac"]
    return m

def get_devices_merged(settings: dict) -> list[dict]:
    """Return merged device list: ARP + stored names/policies."""
    stored = settings.get("devices", {})
    arp = get_arp_table()
    result = []
    # Build set of MACs from ARP
    seen_keys: set[str] = set()
    for entry in arp:
        key = entry["mac"] if entry["mac"] else f"ip:{entry['ips'][0]}"
        seen_keys.add(key)
        d = stored.get(key, {})
        result.append({
            "key":    key,
            "mac":    entry["mac"],
            "ips":    entry["ips"],
            "state":  entry["state"],
            "name":   d.get("name", ""),
            "policy": d.get("policy", "inherit"),
        })
    # Add stored devices not in current ARP (offline devices)
    for key, d in stored.items():
        if key not in seen_keys:
            result.append({
                "key":    key,
                "mac":    "" if key.startswith("ip:") else key,
                "ips":    d.get("ips", []),
                "state":  "OFFLINE",
                "name":   d.get("name", ""),
                "policy": d.get("policy", "inherit"),
            })
    return result

# ── Custom Rules Validation ────────────────────────────────────────────────────
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)

def validate_custom_rule(rule: str) -> tuple[bool, str]:
    rule = rule.strip()
    if not rule:    return False, "Empty rule"
    if len(rule) > 512: return False, "Rule too long"
    for prefix in ("domain:", "full:", "keyword:", "regexp:"):
        if rule.startswith(prefix):
            value = rule[len(prefix):]
            if not value: return False, f"Empty value after {prefix}"
            if prefix == "regexp:":
                try:   re.compile(value)
                except re.error as e: return False, f"Invalid regexp: {e}"
            return True, ""
    try:
        ipaddress.ip_network(rule, strict=False); return True, ""
    except ValueError:
        pass
    if _DOMAIN_RE.match(rule): return True, ""
    return False, f"Invalid rule '{rule}'"

def _custom_rule_to_xray(rule: str) -> tuple[str, str]:
    rule = rule.strip()
    for prefix in ("domain:", "full:", "keyword:", "regexp:"):
        if rule.startswith(prefix): return "domain", rule
    try:
        net = ipaddress.ip_network(rule, strict=False); return "ip", str(net)
    except ValueError:
        pass
    return "domain", f"domain:{rule}"

def _rules_to_xray_entry(rules: list[str], outbound: str) -> list[dict]:
    if not rules: return []
    domain_vals, ip_vals = [], []
    for r in rules:
        kind, val = _custom_rule_to_xray(r)
        if kind == "domain": domain_vals.append(val)
        else:                ip_vals.append(val)
    result = []
    if domain_vals: result.append({"type": "field", "domain": domain_vals, "outboundTag": outbound})
    if ip_vals:     result.append({"type": "field", "ip":     ip_vals,     "outboundTag": outbound})
    return result

# ── Device Policy → Xray Rules ─────────────────────────────────────────────────
DEVICE_POLICIES = ("inherit", "blocked_only", "all_except_ru", "all", "always_direct", "always_vpn")

def _device_policy_rules(ips: list[str], policy: str, final: str) -> list[dict]:
    """Generate xray routing rules for a device with a given policy."""
    if policy == "inherit" or not ips: return []
    src = sorted(set(ips))
    if policy == "always_direct":
        return [{"type": "field", "source": src, "network": "tcp,udp", "outboundTag": "direct"}]
    if policy in ("always_vpn", "all"):
        return [{"type": "field", "source": src, "network": "tcp,udp", "outboundTag": final}]
    if policy == "all_except_ru":
        return [
            {"type": "field", "source": src, "ip":     ["geoip:ru"],            "outboundTag": "direct"},
            {"type": "field", "source": src, "domain": ["geosite:category-ru"], "outboundTag": "direct"},
            {"type": "field", "source": src, "network": "tcp,udp",              "outboundTag": final},
        ]
    if policy == "blocked_only":
        return [
            {"type": "field", "source": src, "domain": ["geosite:category-ru-blocked"], "outboundTag": final},
            {"type": "field", "source": src, "ip":     ["geoip:ru"],                    "outboundTag": "direct"},
            {"type": "field", "source": src, "domain": ["geosite:category-ru"],         "outboundTag": "direct"},
            {"type": "field", "source": src, "network": "tcp,udp",                      "outboundTag": "direct"},
        ]
    return []

def _build_device_rules(settings: dict, final: str) -> list[dict]:
    """Build all per-device xray routing rules from stored device policies."""
    rules: list[dict] = []
    stored = settings.get("devices", {})
    # Build MAC→IPs from current ARP for REACHABLE/STALE devices
    arp = get_arp_table()
    arp_by_key: dict[str, list[str]] = {}
    for entry in arp:
        key = entry["mac"] if entry["mac"] else f"ip:{entry['ips'][0]}"
        arp_by_key[key] = entry["ips"]

    for key, d in stored.items():
        policy = d.get("policy", "inherit")
        if policy == "inherit": continue
        # Prefer live ARP IPs; fall back to stored IPs
        ips = arp_by_key.get(key, d.get("ips", []))
        if not ips: continue
        rules.extend(_device_policy_rules(ips, policy, final))
    return rules

def _build_subscription_rules(settings: dict, final: str) -> list[dict]:
    """Inject subscription rules into xray config."""
    sub_rules = _db.get_all_subscription_rules_by_type(settings)
    result: list[dict] = []
    # direct subscriptions
    for r in sub_rules.get("direct", []):
        pass  # will batch below
    # Batch by type
    for sub in settings.get("subscriptions", []):
        if not sub.get("enabled"):
            continue
        t = sub.get("type", "direct")
        if t not in ("direct", "vpn", "block"):
            continue
        outbound = "direct" if t == "direct" else ("block" if t == "block" else final)
        result.extend(_ft.subscription_rules_to_xray(sub["id"], t, outbound))
    return result

# ── Xray Config Builder ────────────────────────────────────────────────────────
def _get_active_vpn_outbound(settings: dict) -> tuple[list, bool, Optional[str]]:
    """Return (outbounds, has_proxy, proxy_server_ip) for active VPN server."""
    # AdGuard VPN egress takes precedence: route the proxy outbound through the local
    # adguardvpn-cli SOCKS. No proxy_server_ip bypass rule — the adguardvpn-cli's own
    # traffic to AdGuard servers is bypassed at L3 (agvpn uid owner rule in iptables.sh).
    fp = settings.get("fptn", {})
    if settings.get("egress_active") == "fptn" and fp.get("enabled"):
        # Second egress: the FPTN client lives in a netns and exposes a SOCKS
        # bridge that can only reach the internet through its tunnel, so a dead
        # tunnel means failed connections rather than a silent direct leak.
        ob = {"protocol": "socks", "tag": "proxy",
              "settings": {"servers": [{"address": fp.get("socks_host", "192.168.244.2"),
                                        "port": int(fp.get("socks_port", 1082))}]}}
        return [ob], True, None
    ag = settings.get("adguard", {})
    if ag.get("enabled"):
        host = ag.get("socks_host", "127.0.0.1")
        port = int(ag.get("socks_port", 1081))
        ob = {"protocol": "socks", "tag": "proxy",
              "settings": {"servers": [{"address": host, "port": port}]}}
        return [ob], True, None
    servers = settings.get("vpn_servers", [])
    active_id = settings.get("active_vpn_id")
    active = None
    if active_id:
        active = next((s for s in servers if s.get("id") == active_id and s.get("enabled")), None)
    if not active and servers:
        active = next((s for s in sorted(servers, key=lambda x: x.get("priority", 99))
                       if s.get("enabled")), None)
    if active:
        try:
            ob, info = parse_key(active["key"])
            return [ob], True, info.get("server")
        except Exception:
            pass
    # Fallback: legacy vpn_key
    vpn_key = settings.get("vpn_key")
    if vpn_key:
        try:
            ob, info = parse_key(vpn_key)
            return [ob], True, info.get("server")
        except Exception:
            pass
    return [], False, None

def build_xray_config(settings: dict) -> dict:
    profile        = settings.get("profile", "all_except_ru")
    custom         = settings.get("custom_rules", {"always_direct": [], "always_vpn": []})
    force_aaplimg  = settings.get("force_aaplimg_vpn", True)

    vpn_obs, has_proxy, proxy_server_ip = _get_active_vpn_outbound(settings)
    outbounds = vpn_obs + [
        {"protocol": "freedom", "tag": "direct",
         "settings": {"domainStrategy": "UseIP"}, "streamSettings": {"sockopt": _sockopt()}},
        {"protocol": "blackhole", "tag": "block"},
    ]
    final = "proxy" if has_proxy else "direct"
    if profile == "direct":
        # Emergency profile: nothing goes through the tunnel. Overriding `final`
        # here (before the rules are built) makes every rule that would have
        # pointed at the proxy resolve to direct as well.
        final = "direct"

    rules: list[dict] = [
        *([{"type": "field", "ip": [proxy_server_ip], "outboundTag": "direct"}]
          if proxy_server_ip else []),
        {"type": "field", "ip":     ["geoip:private"],   "outboundTag": "direct"},
        {"type": "field", "domain": ["geosite:private"],  "outboundTag": "direct"},
        *_rules_to_xray_entry(custom.get("always_direct", []), "direct"),
        *_rules_to_xray_entry(custom.get("always_vpn", []),    final),
        # Per-device policies (override global profile)
        *_build_device_rules(settings, final),
        # Per-group policies (devices with inherit policy that belong to a group)
        *_ft.build_group_policy_rules(settings, final),
        # Subscription rules (direct/vpn/block)
        *_build_subscription_rules(settings, final),
    ]

    if profile == "blocked_only":
        rules += [
            *([{"type": "field",
                "domain": ["domain:cdn-apple.com", "domain:itunes.apple.com", "domain:aaplimg.com"],
                "outboundTag": final}] if force_aaplimg else []),
            {"type": "field", "ip":     ["geoip:ru"],                   "outboundTag": "direct"},
            {"type": "field", "domain": ["geosite:category-ru"],         "outboundTag": "direct"},
            {"type": "field", "domain": ["geosite:category-ru-blocked"], "outboundTag": final},
        ]
        default = "direct"
    elif profile == "direct":
        default = "direct"
    elif profile == "all_except_ru":
        rules += [
            *([{"type": "field",
                "domain": ["domain:cdn-apple.com", "domain:itunes.apple.com", "domain:aaplimg.com"],
                "outboundTag": final}] if force_aaplimg else []),
            {"type": "field", "ip":     ["geoip:ru"],            "outboundTag": "direct"},
            {"type": "field", "domain": ["geosite:category-ru"], "outboundTag": "direct"},
        ]
        default = final
    else:
        default = final

    rules += [
        {"type": "field", "network": "tcp",     "port": "5228", "outboundTag": "direct"},
        {"type": "field", "network": "tcp,udp",                  "outboundTag": default},
    ]

    return {
        "log": {"loglevel": "warning",
                "access": str(LOGS / "access.log"),
                "error":  str(LOGS / "xray.log")},
        "inbounds": [{
            "tag": "tproxy-in", "port": 12345,
            "protocol": "dokodemo-door",
            "settings": {"network": "tcp,udp", "followRedirect": True},
            "sniffing": {"enabled": True,
                         "destOverride": ["http", "tls", "quic"],
                         "routeOnly": True},
            "streamSettings": {"sockopt": {"tproxy": "tproxy", "mark": 255}},
        }],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
        # stats/policy removed: per-connection goroutine counters leaked file descriptors,
        # causing "accept4: too many open files" after 3 days of operation (65535 FD exhaustion).
    }

# ── DNS Config ─────────────────────────────────────────────────────────────────
def _validate_dns_ip(ip: str) -> bool:
    try: ipaddress.ip_address(ip); return True
    except ValueError: return False

def _validate_hostname(h: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9.\-]+$', h) and len(h) <= 253)

def validate_dns_settings(dns: dict) -> list[str]:
    errors = []
    for ip in dns.get("upstream", []):
        if not _validate_dns_ip(ip):
            errors.append(f"Invalid upstream IP: {ip}")
    for ip in dns.get("upstream_ru", []):
        if not _validate_dns_ip(ip):
            errors.append(f"Invalid upstream_ru IP: {ip}")
    cs = dns.get("cache_size", 1000)
    if not isinstance(cs, int) or cs < 0 or cs > 100000:
        errors.append("cache_size must be 0–100000")
    for rec in dns.get("local_records", []):
        if not _validate_hostname(rec.get("hostname", "")):
            errors.append(f"Invalid hostname: {rec.get('hostname')}")
        if not _validate_dns_ip(rec.get("ip", "")):
            errors.append(f"Invalid IP for record: {rec.get('ip')}")
    return errors

def build_dnsmasq_conf(dns: dict) -> str:
    lan_ip = _get_lan_ip() or "127.0.0.1"
    lines = [
        "# Generated by xray-gateway — do not edit manually",
        f"listen-address={lan_ip}",
        "bind-interfaces",
        "port=5335",
        "no-resolv",
        f"cache-size={dns.get('cache_size', 1000)}",
        "",
    ]
    for ip in dns.get("upstream", ["192.168.50.1"]):
        lines.append(f"server={ip}")
    for ip in dns.get("upstream_ru", []):
        lines.append(f"server=/ru/{ip}")
        lines.append(f"server=/local/{ip}")
    for rec in dns.get("local_records", []):
        lines.append(f"address=/{rec['hostname']}/{rec['ip']}")
    return "\n".join(lines) + "\n"

def build_dnsmasq_conf_full(settings: dict) -> str:
    """Build full dnsmasq config including adblock rules."""
    base = build_dnsmasq_conf(settings.get("dns", DEFAULT_SETTINGS["dns"]))
    adblock_lines = _ft.build_adblock_dnsmasq_lines(settings)
    if adblock_lines:
        base += "\n# Adblock rules\n" + "\n".join(adblock_lines) + "\n"
    return base

def apply_dns_config(dns: dict, settings: Optional[dict] = None) -> tuple[bool, str]:
    """Write dnsmasq config (with optional adblock) and restart. Returns (ok, error)."""
    try:
        if settings is not None:
            conf = build_dnsmasq_conf_full(settings)
        else:
            conf = build_dnsmasq_conf(dns)
        DNS_CONF.write_text(conf)
        r = subprocess.run(["systemctl", "restart", "dnsmasq"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False, r.stderr[:200]
        return True, ""
    except Exception as e:
        return False, str(e)

def get_dns_status() -> dict:
    """Return current DNS status: active upstream, dnsmasq state."""
    try:
        dns_active = subprocess.run(["systemctl", "is-active", "dnsmasq"],
                                    capture_output=True, text=True).stdout.strip()
        # Test each upstream with a quick ping-level check
        s = load_settings()
        upstreams = s.get("dns", {}).get("upstream", [])
        upstream_status = []
        for ip in upstreams:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                start = time.time()
                sock.connect((ip, 53)); sock.close()
                lat = int((time.time() - start) * 1000)
                upstream_status.append({"ip": ip, "reachable": True, "latency_ms": lat})
            except Exception:
                upstream_status.append({"ip": ip, "reachable": False, "latency_ms": None})
        return {"dnsmasq": dns_active, "upstreams": upstream_status}
    except Exception as e:
        return {"dnsmasq": "unknown", "upstreams": [], "error": str(e)}

# ── Snapshot Management ────────────────────────────────────────────────────────
def _snap_path(snap_id: str) -> Path:
    return SNAP_DIR / f"snap_{snap_id}.json"

def create_snapshot(reason: str, settings: Optional[dict] = None) -> str:
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    snap_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    s = settings or load_settings()
    xray_cfg = {}
    if XCFG.exists():
        try:  xray_cfg = json.loads(XCFG.read_text())
        except Exception: pass
    snap = {"id": snap_id, "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": reason, "settings": s, "xray_config": xray_cfg}
    _snap_path(snap_id).write_text(json.dumps(snap, indent=2))
    _rotate_snapshots(); return snap_id

def _rotate_snapshots() -> None:
    snaps = sorted(SNAP_DIR.glob("snap_*.json"), key=lambda p: p.name)
    for old in snaps[:-MAX_SNAPSHOTS]:
        try: old.unlink()
        except Exception: pass

def list_snapshots() -> list[dict]:
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    result = []
    for p in sorted(SNAP_DIR.glob("snap_*.json"), key=lambda x: x.name, reverse=True):
        try:
            snap = json.loads(p.read_text())
            result.append({"id": snap["id"], "timestamp": snap["timestamp"],
                           "reason": snap.get("reason", ""),
                           "profile": snap.get("settings", {}).get("profile", "?"),
                           "has_vpn": bool(snap.get("settings", {}).get("vpn_key") or
                                          snap.get("settings", {}).get("vpn_servers"))})
        except Exception:
            pass
    return result

def restore_snapshot(snap_id: str) -> tuple[bool, str]:
    p = _snap_path(snap_id)
    if not p.exists(): return False, f"Snapshot {snap_id} not found"
    try:
        snap = json.loads(p.read_text())
    except Exception as e:
        return False, f"Failed to read snapshot: {e}"
    settings = snap.get("settings", {})
    xray_cfg = snap.get("xray_config", {})
    save_settings(settings)
    if xray_cfg: XCFG.write_text(json.dumps(xray_cfg, indent=2))
    r = subprocess.run(["systemctl", "restart", "xray-proxy"], capture_output=True, text=True)
    if r.returncode != 0: return False, f"xray restart failed: {r.stderr[:200]}"
    fire_alert("config_rollback", f"Restored snapshot {snap_id}")
    return True, f"Restored snapshot {snap_id}"

# ── Apply Config (safe, with auto-rollback) ────────────────────────────────────
def apply_config(settings: dict, reason: str = "config_change",
                 _pre_settings: Optional[dict] = None) -> tuple[bool, str]:
    snap_id = create_snapshot(f"pre_{reason}", settings=_pre_settings)
    cfg = build_xray_config(settings)
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    XCFG.write_text(json.dumps(cfg, indent=2))
    subprocess.run(["systemctl", "restart", "xray-proxy"], capture_output=True)
    for _ in range(10):
        time.sleep(0.5)
        r = subprocess.run(["systemctl", "is-active", "xray-proxy"],
                            capture_output=True, text=True)
        if r.stdout.strip() == "active":
            return True, ""
    # Auto-rollback
    ok, msg = restore_snapshot(snap_id)
    rolled = (f"xray failed to start; auto-rollback to {snap_id} "
              f"{'ok' if ok else 'FAILED: '+msg}")
    fire_alert("config_rollback", rolled)
    return False, rolled

# ── SOCKS proxy (sing-box inbound) ─────────────────────────────────────────────
def _read_singbox() -> dict:
    return json.loads(SINGBOX_CFG.read_text())

def _proxy_state() -> dict:
    """Live SOCKS inbound state, read from the sing-box config (the source of truth)."""
    st = {"enabled": False, "port": 1080, "listen": "0.0.0.0",
          "auth_enabled": False, "username": "", "restrict_to_home": False}
    try:
        cfg = _read_singbox()
    except Exception:
        return st
    for inb in cfg.get("inbounds", []):
        if inb.get("tag") == PROXY_TAG or inb.get("type") == "socks":
            users  = inb.get("users") or []
            listen = inb.get("listen", "0.0.0.0")
            st.update({"enabled": True, "port": inb.get("listen_port", 1080),
                       "listen": listen, "auth_enabled": bool(users),
                       "username": (users[0].get("username", "") if users else ""),
                       "restrict_to_home": listen not in ("0.0.0.0", "::", "")})
            break
    return st

def apply_proxy(enabled: bool, port: int, restrict_to_home: bool,
                auth_enabled: bool, username: str, password: str) -> tuple[bool, str]:
    """Add/remove/modify the managed SOCKS inbound and restart sing-box.
    Validates with `sing-box check` first; rolls back if the service fails to come up."""
    try:
        cfg = _read_singbox()
    except Exception as e:
        return False, f"конфиг sing-box не читается: {e}"
    port = int(port)
    if not (1 <= port <= 65535):
        return False, "порт вне диапазона 1-65535"
    cfg["inbounds"] = [i for i in cfg.get("inbounds", [])
                       if i.get("tag") != PROXY_TAG and i.get("type") != "socks"]
    if enabled:
        listen = (_get_mgmt_ip() or "0.0.0.0") if restrict_to_home else "0.0.0.0"
        inb = {"type": "socks", "tag": PROXY_TAG, "listen": listen, "listen_port": port}
        if auth_enabled and username and password:
            inb["users"] = [{"username": username, "password": password}]
        cfg["inbounds"].append(inb)
    new_json = json.dumps(cfg, ensure_ascii=False, indent=2)
    Path("/tmp/singbox_check.json").write_text(new_json)
    chk = subprocess.run([SINGBOX_BIN, "check", "-c", "/tmp/singbox_check.json"],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        return False, "конфиг невалиден: " + (chk.stderr or chk.stdout)[:200]
    backup = SINGBOX_CFG.read_text()
    SINGBOX_CFG.write_text(new_json)
    subprocess.run(["systemctl", "restart", "sing-box"], capture_output=True)
    for _ in range(16):
        time.sleep(0.5)
        r = subprocess.run(["systemctl", "is-active", "sing-box"], capture_output=True, text=True)
        if r.stdout.strip() == "active":
            return True, ""
    SINGBOX_CFG.write_text(backup)
    subprocess.run(["systemctl", "restart", "sing-box"], capture_output=True)
    return False, "sing-box не поднялся; выполнен откат к прежнему конфигу"

# ── Alerts ─────────────────────────────────────────────────────────────────────
def fire_alert(event: str, detail: str = "") -> None:
    """Non-blocking: record event, send webhook if configured and not on cooldown."""
    s = load_settings()
    cfg = s.get("alerts", {})
    now = time.time()
    # Log the event regardless of alert config
    entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, "detail": detail}
    _alert_log.append(entry)
    if len(_alert_log) > ALERT_LOG_SIZE: _alert_log.pop(0)

    if not cfg.get("enabled"): return
    if event not in cfg.get("events", []): return
    cooldown = cfg.get("cooldown_min", 30) * 60
    last = _alert_last_sent.get(event, 0)
    if now - last < cooldown: return
    url = cfg.get("webhook_url", "").strip()
    if not url: return
    _alert_last_sent[event] = now
    # Fire-and-forget in background thread to not block caller
    import threading
    def _send():
        try:
            payload = json.dumps({
                "event": event, "detail": detail,
                "timestamp": entry["ts"],
                "gateway": "xray-gateway",
            }).encode()
            req = urllib.request.Request(
                url, data=payload, method="POST",
                headers={"Content-Type": "application/json",
                         "User-Agent": "xray-gateway-alert/1.5.0"})
            with urllib.request.urlopen(req, timeout=10): pass
        except Exception as exc:
            _alert_log.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": "_alert_send_error",
                "detail": f"{event}: {exc}",
            })
    threading.Thread(target=_send, daemon=True).start()

# ── VPN Health Check ───────────────────────────────────────────────────────────
def _vpn_server_health(srv: dict) -> tuple[bool, Optional[int]]:
    """TCP connect to VPN server:port. Returns (reachable, latency_ms)."""
    try:
        _, info = parse_key(srv["key"])
        host = info["server"]; port = info["port"]
        start = time.time()
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        return True, int((time.time() - start) * 1000)
    except Exception:
        return False, None

async def _failover_loop() -> None:
    """Background task: check active VPN, failover if down."""
    global _failover_last
    await _idle(30)  # initial delay
    while True:
        try:
            s = load_settings()
            servers = s.get("vpn_servers", [])
            if not servers:
                await _idle(60); continue
            active_id = s.get("active_vpn_id")
            active = next((x for x in servers if x.get("id") == active_id), None)
            if not active:
                await _idle(60); continue

            ok, lat = await asyncio.get_event_loop().run_in_executor(
                None, _vpn_server_health, active)

            # Update health status
            s2 = load_settings()
            for srv in s2.get("vpn_servers", []):
                if srv.get("id") == active_id:
                    srv["last_status"] = "ok" if ok else "error"
                    srv["latency_ms"]  = lat
                    srv["last_checked"] = datetime.now(timezone.utc).isoformat()
            save_settings(s2)

            if not ok:
                fire_alert("vpn_down", f"Server {active.get('name','?')} unreachable")
                now = time.time()
                if now - _failover_last > 300:   # max one failover per 5 min
                    # Find next available enabled server
                    candidates = [x for x in sorted(servers, key=lambda x: x.get("priority", 99))
                                  if x.get("enabled") and x.get("id") != active_id]
                    for cand in candidates:
                        cok, _ = await asyncio.get_event_loop().run_in_executor(
                            None, _vpn_server_health, cand)
                        if cok:
                            _failover_last = now
                            s3 = load_settings()
                            s3["active_vpn_id"] = cand["id"]
                            save_settings(s3)
                            apply_config(s3, "failover")
                            fire_alert("failover_executed",
                                       f"Switched to {cand.get('name','?')}")
                            break
                    else:
                        fire_alert("all_vpn_unavailable", "No reachable VPN server found")
        except Exception:
            pass
        await _idle(120)  # check every 2 minutes

# ── Disk Health Check ──────────────────────────────────────────────────────────
async def _disk_monitor_loop() -> None:
    """Alert when root disk > 90% full."""
    await _idle(60)
    while True:
        try:
            du = shutil.disk_usage("/")
            pct = du.used / max(du.total, 1) * 100
            if pct > 90:
                fire_alert("disk_high", f"Root partition {pct:.1f}% full")
        except Exception:
            pass
        await _idle(3600)  # check every hour

async def _xray_fd_watchdog() -> None:
    """Monitor xray-proxy file descriptor usage and restart before exhaustion.

    Root cause of Jun-04 outage: xray exhausted its 65535 FD limit after 3 days
    of operation (high-traffic home gateway with long-lived TLS/QUIC sessions),
    causing accept4: too many open files. Systemd did NOT restart because the
    process was still 'active' — it just couldn't accept new connections.

    This watchdog restarts xray when FD usage exceeds 80% of limit.
    Also checks xray.log for the error signature as a fallback.
    """
    await _idle(120)  # let everything start first
    while True:
        try:
            # Method 1: count open FDs via /proc/<pid>/fd
            r = subprocess.run(
                ["systemctl", "show", "-p", "MainPID", "xray-proxy"],
                capture_output=True, text=True)
            pid_str = r.stdout.strip().split("=")[-1].strip()
            if pid_str and pid_str != "0":
                fd_dir = Path(f"/proc/{pid_str}/fd")
                if fd_dir.exists():
                    fd_count = len(list(fd_dir.iterdir()))
                    # Limit is 1048576 (after fix); warn at 80% = ~838K
                    # For safety also alert if we somehow hit old 65535 threshold
                    fd_warn = 800_000
                    if fd_count > fd_warn:
                        _restart_xray_watchdog(f"FD count {fd_count} > {fd_warn}")
                    elif fd_count > 50_000:
                        # Approaching old limit — log but don't restart yet
                        _log_watchdog(f"xray FD count elevated: {fd_count}")

            # Method 2: check xray.log for recent FD errors (fallback)
            xray_log = LOGS / "xray.log"
            if xray_log.exists():
                r2 = subprocess.run(
                    ["tail", "-20", str(xray_log)],
                    capture_output=True, text=True)
                recent = r2.stdout
                if "too many open files" in recent:
                    _restart_xray_watchdog("xray.log: too many open files detected")

        except Exception:
            pass
        await _idle(300)  # check every 5 minutes

def _restart_xray_watchdog(reason: str) -> None:
    """Restart xray-proxy due to watchdog detection."""
    fire_alert("vpn_down", f"Watchdog restart: {reason}")
    try:
        subprocess.run(["systemctl", "restart", "xray-proxy"], capture_output=True)
    except Exception:
        pass

def _log_watchdog(msg: str) -> None:
    _alert_log.append({"ts": datetime.now(timezone.utc).isoformat(),
                        "event": "watchdog_info", "detail": msg})
    if len(_alert_log) > ALERT_LOG_SIZE:
        _alert_log.pop(0)

# ── GeoIP / GeoSite Parsers ────────────────────────────────────────────────────
def _varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80): return result, pos
        shift += 7
    return result, pos

def _parse_len_field(data: bytes, pos: int) -> tuple[bytes, int]:
    length, pos = _varint(data, pos)
    return data[pos:pos + length], pos + length

_geoip_ru_nets:    Optional[list] = None
_geoip_ru_mtime:   float          = 0.0
_geosite_ru_data:  Optional[dict] = None
_geosite_ru_mtime: float          = 0.0

def _load_geoip_ru() -> list:
    global _geoip_ru_nets, _geoip_ru_mtime
    geoip_path = CFG_DIR / "geoip.dat"
    try:   mtime = geoip_path.stat().st_mtime
    except Exception: return []
    if _geoip_ru_nets is not None and mtime == _geoip_ru_mtime:
        return _geoip_ru_nets
    networks: list = []
    try:
        data = geoip_path.read_bytes(); pos = 0; n = len(data)
        while pos < n:
            try:
                tag, pos = _varint(data, pos)
                wire = tag & 7; field = tag >> 3
                if wire == 2:
                    entry, pos = _parse_len_field(data, pos)
                    if field != 1: continue
                    cc = None; cidrs_raw = []
                    p = 0; m = len(entry)
                    while p < m:
                        t, p = _varint(entry, p); f, w = t >> 3, t & 7
                        if w == 2:
                            v, p = _parse_len_field(entry, p)
                            if f == 1: cc = v.decode("ascii", errors="replace").strip("\x00 ")
                            elif f == 2:
                                ip_b = plen = None; cp = 0; cm = len(v)
                                while cp < cm:
                                    ct, cp = _varint(v, cp); cf, cw = ct >> 3, ct & 7
                                    if cw == 2:
                                        iv, cp = _parse_len_field(v, cp)
                                        if cf == 1: ip_b = iv
                                    elif cw == 0:
                                        pval, cp = _varint(v, cp)
                                        if cf == 2: plen = pval
                                    else: break
                                if ip_b and plen is not None: cidrs_raw.append((ip_b, plen))
                        elif w == 0: _, p = _varint(entry, p)
                        elif w == 1: p += 8
                        elif w == 5: p += 4
                        else: break
                    if cc and cc.upper() == "RU":
                        for ip_b, plen in cidrs_raw:
                            try:
                                if len(ip_b) == 4:
                                    networks.append(ipaddress.IPv4Network((ip_b, plen), strict=False))
                                elif len(ip_b) == 16:
                                    networks.append(ipaddress.IPv6Network((ip_b, plen), strict=False))
                            except Exception: pass
                elif wire == 0: _, pos = _varint(data, pos)
                elif wire == 1: pos += 8
                elif wire == 5: pos += 4
                else: break
            except Exception: break
    except Exception: pass
    _geoip_ru_nets = networks; _geoip_ru_mtime = mtime
    return networks

def _ip_in_geoip_ru(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _load_geoip_ru())
    except ValueError: return False

def _load_geosite_ru() -> dict:
    global _geosite_ru_data, _geosite_ru_mtime
    geosite_path = CFG_DIR / "geosite.dat"
    try:   mtime = geosite_path.stat().st_mtime
    except Exception: return {"full": set(), "domain": set(), "plain": [], "regex": []}
    if _geosite_ru_data is not None and mtime == _geosite_ru_mtime:
        return _geosite_ru_data
    result: dict = {"full": set(), "domain": set(), "plain": [], "regex": []}
    try:
        data = geosite_path.read_bytes(); pos = 0; n = len(data)
        while pos < n:
            try:
                tag, pos = _varint(data, pos); wire = tag & 7; field = tag >> 3
                if wire == 2:
                    entry, pos = _parse_len_field(data, pos)
                    if field != 1: continue
                    cc = None; domains_raw = []
                    p = 0; m = len(entry)
                    while p < m:
                        t, p = _varint(entry, p); f, w = t >> 3, t & 7
                        if w == 2:
                            v, p = _parse_len_field(entry, p)
                            if f == 1: cc = v.decode("ascii", errors="replace").strip("\x00 ")
                            elif f == 2:
                                dtype = 0; dval = ""; dp = 0; dm = len(v)
                                while dp < dm:
                                    dt, dp = _varint(v, dp); df, dw = dt >> 3, dt & 7
                                    if dw == 0:
                                        dnum, dp = _varint(v, dp)
                                        if df == 1: dtype = dnum
                                    elif dw == 2:
                                        dv, dp = _parse_len_field(v, dp)
                                        if df == 2: dval = dv.decode("utf-8", errors="replace")
                                    else: break
                                if dval: domains_raw.append((dtype, dval.lower()))
                        elif w == 0: _, p = _varint(entry, p)
                        elif w == 1: p += 8
                        elif w == 5: p += 4
                        else: break
                    if cc and cc.upper() == "CATEGORY-RU":
                        for dtype, dval in domains_raw:
                            if dtype == 3:   result["full"].add(dval)
                            elif dtype == 2: result["domain"].add(dval)
                            elif dtype == 0: result["plain"].append(dval)
                            elif dtype == 1:
                                try:   result["regex"].append(re.compile(dval))
                                except Exception: pass
                elif wire == 0: _, pos = _varint(data, pos)
                elif wire == 1: pos += 8
                elif wire == 5: pos += 4
                else: break
            except Exception: break
    except Exception: pass
    _geosite_ru_data = result; _geosite_ru_mtime = mtime
    return result

def _domain_in_geosite_ru(query: str) -> bool:
    q = query.lower().rstrip(".")
    gs = _load_geosite_ru()
    if q in gs["full"]: return True
    for d in gs["domain"]:
        if q == d or q.endswith("." + d): return True
    for k in gs["plain"]:
        if k in q: return True
    for r in gs["regex"]:
        if r.search(q): return True
    return False

# ── Route Tester ──────────────────────────────────────────────────────────────
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]
_PRIVATE_DOMAINS   = {"localhost", "local"}
_APPLE_CDN_DOMAINS = {"cdn-apple.com", "itunes.apple.com", "aaplimg.com"}

def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError: return False

def _is_private_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return d in _PRIVATE_DOMAINS or d.endswith(".local") or d.endswith(".localhost")

def _domain_matches_apple_cdn(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == cdn or d.endswith("." + cdn) for cdn in _APPLE_CDN_DOMAINS)

def _custom_matches(rule: str, target_domain: Optional[str], target_ip: Optional[str]) -> bool:
    rule = rule.strip()
    if rule.startswith("domain:"):
        if not target_domain: return False
        d = rule[7:].lower(); q = target_domain.lower()
        return q == d or q.endswith("." + d)
    if rule.startswith("full:"):
        return bool(target_domain) and target_domain.lower() == rule[5:].lower()
    if rule.startswith("keyword:"):
        return bool(target_domain) and rule[8:].lower() in target_domain.lower()
    if rule.startswith("regexp:"):
        target = target_domain or target_ip or ""
        try: return bool(re.search(rule[7:], target))
        except Exception: return False
    if target_ip:
        try:
            net = ipaddress.ip_network(rule, strict=False)
            return ipaddress.ip_address(target_ip) in net
        except ValueError: pass
    if target_domain:
        d = rule.lower(); q = target_domain.lower()
        return q == d or q.endswith("." + d)
    return False

def route_test(target: str, settings: dict) -> dict:
    target = target.strip()
    profile       = settings.get("profile", "all_except_ru")
    custom        = settings.get("custom_rules", {"always_direct": [], "always_vpn": []})
    _, has_vpn, _ = _get_active_vpn_outbound(settings)
    force_aaplimg = settings.get("force_aaplimg_vpn", True)
    final = "proxy" if has_vpn else "direct"

    domain: Optional[str] = None
    ips:    list[str]      = []
    target_type = "unknown"

    try:
        ipaddress.ip_network(target, strict=False)
        target_type = "cidr" if "/" in target else "ip"
        test_ip = str(ipaddress.ip_network(target, strict=False).network_address)
        ips = [test_ip]
    except ValueError:
        target_type = "domain"
        domain = target.lower().rstrip(".")
        if not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
            return {"error": f"Invalid domain or IP: '{target}'", "outbound": None, "matched_rule": None}
        try:
            info = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list({r[4][0] for r in info})[:5]
        except socket.gaierror:
            ips = []

    def result(outbound: str, rule: str, note: str = "", rule_source: str = "") -> dict:
        return {"target": target, "target_type": target_type, "domain": domain,
                "resolved_ips": ips, "outbound": outbound,
                "matched_rule": rule, "note": note or rule,
                "rule_source": rule_source, "error": None}

    vpn_server = None
    _, _, vpn_server = _get_active_vpn_outbound(settings)

    if vpn_server and ips and vpn_server in ips:
        return result("direct", "vpn-server-ip", f"VPN server {vpn_server} always direct", "system")
    for ip in ips:
        if _is_private_ip(ip):
            return result("direct", "geoip:private", f"{ip} is private range", "system")
    if domain and _is_private_domain(domain):
        return result("direct", "geosite:private", f"{domain} is private domain", "system")

    for rule in custom.get("always_direct", []):
        if _custom_matches(rule, domain, ips[0] if ips else None):
            return result("direct", f"custom:always_direct ({rule})", rule_source="custom_rule")
    for rule in custom.get("always_vpn", []):
        if _custom_matches(rule, domain, ips[0] if ips else None):
            return result(final, f"custom:always_vpn ({rule})", rule_source="custom_rule")

    # Check device policies for current source (route test is source-agnostic, skip)

    if force_aaplimg and profile in ("blocked_only", "all_except_ru"):
        if domain and _domain_matches_apple_cdn(domain):
            return result(final, "apple-cdn-override", rule_source="system_override")

    if profile == "all":
        return result(final, "catch-all", f"Profile: all traffic via {final}", "global_profile")

    for ip in ips:
        if _ip_in_geoip_ru(ip):
            return result("direct", "geoip:ru", f"{ip} is in geoip:ru", "geoip_database")
    if domain and _domain_in_geosite_ru(domain):
        return result("direct", "geosite:category-ru",
                      f"{domain} is in geosite:category-ru", "geosite_database")

    if profile == "blocked_only":
        return result("direct", "catch-all", "Profile: blocked_only default=direct", "global_profile")

    return result(final, "catch-all",
                  f"not matched by any rule → {final}", "global_profile_fallback")

# ── Connection Explain ─────────────────────────────────────────────────────────
_explain_cache: dict[str, dict] = {}  # key → result

def explain_connection(src_ip: str, dst: str, dst_port: int,
                       proto: str, outbound: str, settings: dict) -> dict:
    cache_key = f"{src_ip}|{dst}|{dst_port}|{proto}"
    if cache_key in _explain_cache:
        return _explain_cache[cache_key]

    # Identify source device
    s_devices = settings.get("devices", {})
    src_mac = arp_ip_to_mac().get(src_ip, "")
    src_key = src_mac if src_mac else f"ip:{src_ip}"
    src_device = s_devices.get(src_key, {})
    src_name = src_device.get("name", "")
    device_policy = src_device.get("policy", "inherit")

    # Determine rule source
    rule_source = "global_profile_fallback"
    matched_rule = outbound
    note = ""

    if device_policy != "inherit":
        rule_source = "device_policy"
        matched_rule = f"device:{device_policy}"
        note = f"Device policy '{device_policy}' overrides global profile"
    elif outbound in ("proxy", "direct"):
        result = route_test(dst, settings)
        rule_source = result.get("rule_source", "")
        matched_rule = result.get("matched_rule", outbound)
        note = result.get("note", "")

    # ASN / country (lightweight: just geoip:ru check)
    country = ""
    try:
        ipaddress.ip_address(dst)
        if _ip_in_geoip_ru(dst): country = "RU"
    except ValueError: pass

    out = {
        "src_ip":       src_ip,
        "src_mac":      src_mac,
        "src_name":     src_name,
        "device_policy": device_policy,
        "dst":          dst,
        "dst_port":     dst_port,
        "proto":        proto,
        "outbound":     outbound,
        "matched_rule": matched_rule,
        "rule_source":  rule_source,
        "note":         note,
        "country":      country,
    }
    _explain_cache[cache_key] = out
    if len(_explain_cache) > 500: # trim oldest
        oldest = next(iter(_explain_cache))
        del _explain_cache[oldest]
    return out

# ── Network helpers ────────────────────────────────────────────────────────────
def _get_lan_if() -> str:
    try:
        conf = (CFG_DIR / "network.conf").read_text()
        for line in conf.splitlines():
            if line.startswith("LAN_IF="):
                iface = line.split("=", 1)[1].strip()
                if iface: return iface
    except Exception: pass
    return "enp1s0"

def _usb_product_max_speed(device_link: Path) -> Optional[int]:
    """Walk up from a netdev's device symlink to the USB device node and parse
    its product string for the top speed, e.g. 'USB 10/100/1G/2.5G/5G LAN' → 5000.
    Returns Mbps, or None if no USB product string with a Gbit token is found."""
    try:
        node = device_link.resolve()
    except OSError:
        return None
    for _ in range(6):
        prod = node / "product"
        if prod.exists():
            try:
                text = prod.read_text()
            except OSError:
                return None
            # Gbit tokens like 1G / 2.5G / 5G / 10G are the meaningful ceiling;
            # the leading 10/100 are Mbit fallback modes we ignore.
            gtok = re.findall(r"(\d+(?:\.\d+)?)\s*G\b", text)
            if gtok:
                return int(max(float(t) for t in gtok) * 1000)
            return None
        node = node.parent
    return None

def list_net_interfaces() -> list[dict]:
    """Physical ethernet interfaces with link state, for the UI selector."""
    active = _get_lan_if()
    out: list[dict] = []
    for p in sorted(Path("/sys/class/net").iterdir()):
        name = p.name
        if name == "lo" or not (p / "device").exists():
            continue  # skip loopback, tun/bridges/virtual
        if (p / "wireless").exists():
            continue  # ethernet only — Wi-Fi can't serve as a TProxy LAN port
        try:
            if (p / "type").read_text().strip() != "1":  # ARPHRD_ETHER
                continue
            mac = (p / "address").read_text().strip()
            carrier = False
            try: carrier = (p / "carrier").read_text().strip() == "1"
            except OSError: pass
            speed = None
            try:
                sp = int((p / "speed").read_text().strip())
                if sp > 0: speed = sp
            except (OSError, ValueError): pass
            dev = (p / "device").resolve()
            bus = "usb" if "usb" in str(dev) else "pci"
            # Adapter capability (NOT the negotiated link). Two sources, because
            # neither is universal:
            #  1) ethtool "Supported link modes" — works for NICs on a dedicated
            #     driver (r8169 built-in, r8152 2.5G), but generic USB drivers
            #     like cdc_ncm report "Not reported" and yield nothing.
            #  2) USB product string, e.g. "USB 10/100/1G/2.5G/5G LAN" — the
            #     manufacturer's stated capability; reliable for the multigig
            #     USB adapters where ethtool comes up empty.
            max_speed = None
            try:
                et = subprocess.run(["ethtool", name], capture_output=True,
                                    text=True, timeout=5)
                modes = re.findall(r"(\d+)base", et.stdout.split("Advertised", 1)[0])
                if modes: max_speed = max(int(m) for m in modes)
            except Exception: pass
            if max_speed is None and bus == "usb":
                max_speed = _usb_product_max_speed(p / "device")
            driver = ""
            try: driver = (dev / "driver").resolve().name
            except OSError: pass
            ip = None
            r = subprocess.run(["ip", "-4", "addr", "show", name],
                               capture_output=True, text=True)
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout)
            if m: ip = m.group(1)
            out.append({"name": name, "mac": mac, "link": carrier,
                        "speed_mbps": speed, "max_speed_mbps": max_speed,
                        "bus": bus, "driver": driver,
                        "ip": ip, "active": name == active})
        except OSError:
            continue
    return out

NETSWITCH_STATUS = CFG_DIR / "netswitch-status.json"
TOPOLOGY_STATUS  = CFG_DIR / "topology-status.json"
TOPOLOGY_TARGET  = CFG_DIR / "topology-target.json"

def _netswitch_running() -> bool:
    r = subprocess.run(["systemctl", "is-active", "xray-netswitch.service"],
                       capture_output=True, text=True)
    return r.stdout.strip() == "active"

def _topo_running() -> bool:
    r = subprocess.run(["systemctl", "is-active", "xray-topology.service"],
                       capture_output=True, text=True)
    return r.stdout.strip() == "active"

def _net_conf() -> dict:
    out = {}
    try:
        for line in (CFG_DIR / "network.conf").read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1); out[k.strip()] = v.strip()
    except Exception: pass
    return out

def _get_topology() -> str:
    return _net_conf().get("TOPOLOGY", "loop")

def _wan_status(wan_if: str) -> dict:
    """Link/IP/internet state of the WAN interface (inline monitoring)."""
    def _carrier(i):
        try: return (Path(f"/sys/class/net/{i}/carrier").read_text().strip() == "1")
        except OSError: return False
    ip = None
    r = subprocess.run(["ip", "-4", "addr", "show", wan_if], capture_output=True, text=True)
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout)
    if m: ip = m.group(1)
    gw = None
    r = subprocess.run(["ip", "route", "show", "dev", wan_if], capture_output=True, text=True)
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", r.stdout)
    if m: gw = m.group(1)
    return {"iface": wan_if, "link": _carrier(wan_if), "ip": ip, "gateway": gw}

def _get_lan_ip() -> Optional[str]:
    try:
        r = subprocess.run(["ip", "-4", "addr", "show", _get_lan_if()],
                           capture_output=True, text=True)
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout)
        return m.group(1) if m else None
    except Exception: return None

def _get_mgmt_ip():
    """Gateway's Home-LAN (192.168.50.0/24) address — how the UI is reached in inline (Wi-Fi mgmt)."""
    try:
        r = subprocess.run(["ip","-4","-o","addr","show"], capture_output=True, text=True)
        m = re.search(r"inet (192\.168\.50\.\d+)", r.stdout)
        return m.group(1) if m else None
    except Exception:
        return None

def _nav_flags(s: dict) -> dict:
    """Which side-menu sections are worth showing. Hides what is empty/disabled or
    meaningless in the current topology; each flag flips back on by itself once the
    section gains data, and the UI keeps a "показать все разделы" switch, so nothing
    is ever actually lost."""
    topo = _net_conf().get("TOPOLOGY", "loop")
    devs = s.get("devices", {}) or {}
    return {
        "subscriptions": len(s.get("subscriptions", [])) > 0,
        "groups":        len(s.get("groups", [])) > 0,
        "adblock":       bool(s.get("adblock", {}).get("enabled")),
        "alerts":        bool(s.get("alerts", {}).get("enabled")),
        # inline hides every client behind the router's single IP (double NAT), so
        # per-device policies cannot work and the page only lists ARP neighbours
        "devices":       topo != "inline" or any(d.get("policy") not in (None, "inherit")
                                                 for d in devs.values()),
        # the router-setup guide is a loop concept; in inline nothing is configured there
        "router":        topo != "inline",
    }

_prev: dict = {}
def get_speeds() -> dict:
    global _prev
    iface = _get_lan_if(); now = time.time()
    try:
        rx = int(Path(f"/sys/class/net/{iface}/statistics/rx_bytes").read_text())
        tx = int(Path(f"/sys/class/net/{iface}/statistics/tx_bytes").read_text())
    except Exception: return {"rx_bps": 0, "tx_bps": 0}
    p = _prev.get(iface, (now, rx, tx)); dt = max(now - p[0], 0.1)
    _prev[iface] = (now, rx, tx)
    return {"rx_bps": max(0, (rx - p[1]) / dt), "tx_bps": max(0, (tx - p[2]) / dt)}

_prev_cpu_stats: list = []
def _read_cpu_stats() -> list:
    cores = []
    try:
        for line in Path("/proc/stat").read_text().split("\n"):
            if re.match(r"^cpu\d", line):
                parts = line.split(); vals = [int(x) for x in parts[1:8]]
                total = sum(vals); idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
                cores.append((total, idle))
    except Exception: pass
    return cores

def get_system_info() -> dict:
    global _prev_cpu_stats
    curr = _read_cpu_stats(); cpu_pcts = []
    if _prev_cpu_stats and len(_prev_cpu_stats) == len(curr):
        for (ct, ci), (pt, pi) in zip(curr, _prev_cpu_stats):
            dt = ct - pt
            pct = max(0.0, min(100.0, (1 - (ci - pi) / dt) * 100)) if dt > 0 else 0.0
            cpu_pcts.append(round(pct, 1))
    else: cpu_pcts = [0.0] * len(curr)
    _prev_cpu_stats = curr
    mem_total = mem_used = 0
    try:
        m: dict = {}
        for line in Path("/proc/meminfo").read_text().split("\n"):
            if ":" in line:
                k, v = line.split(":", 1); m[k.strip()] = int(v.strip().split()[0]) * 1024
        mem_total = m.get("MemTotal", 0); mem_used = mem_total - m.get("MemAvailable", 0)
    except Exception: pass
    disk_total = disk_used = disk_free = 0
    try:
        du = shutil.disk_usage("/")
        disk_total, disk_used, disk_free = du.total, du.used, du.free
    except Exception: pass
    disk = {"total": disk_total, "used": disk_used, "free": disk_free}
    disk.update(_disk_device_info())
    return {"cpu": cpu_pcts, "mem": {"total": mem_total, "used": mem_used},
            "disk": disk}

def _disk_device_info() -> dict:
    """Physical size of the disk backing "/" and the part of it not handed to LVM.

    The Ubuntu installer gives the root LV only a fraction of the volume group by
    default, so "/" can be far smaller than the disk actually installed. Without
    this the resources page looks like it is under-reporting the hardware.
    Reads sysfs only, so it needs no root. Returns {} on non-LVM/odd layouts.
    """
    try:
        st = os.stat("/")
        base = "/sys/dev/block/%d:%d" % (os.major(st.st_dev), os.minor(st.st_dev))
        rd = lambda path: int(Path(path).read_text()) * 512
        lv = rd(base + "/size")
        slaves = os.listdir(base + "/slaves")
        if not slaves:
            return {}
        part = slaves[0]
        part_bytes = rd("/sys/class/block/%s/size" % part)
        disk = os.path.realpath("/sys/class/block/" + part).split("/")[-2]
        return {"device": disk,
                "device_total": rd("/sys/class/block/%s/size" % disk),
                "unallocated": max(0, part_bytes - lv)}
    except Exception:
        return {}

def get_xray_core_version() -> str:
    if not hasattr(get_xray_core_version, "_cache"):
        try:
            r = subprocess.run([str(BASE / "bin" / "xray"), "version"],
                               capture_output=True, text=True, timeout=5)
            first = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
            m = re.search(r"Xray\s+([\d.]+)", first)
            get_xray_core_version._cache = m.group(1) if m else first[:40] or "?"
        except Exception: get_xray_core_version._cache = "?"
    return get_xray_core_version._cache

def get_xray_state() -> str:
    r = subprocess.run(["systemctl", "is-active", "xray-proxy"], capture_output=True, text=True)
    if r.stdout.strip() != "active":
        fire_alert("vpn_down", "xray-proxy service not active")
        return "stopped"
    s = load_settings()
    if s.get("active_vpn_id") or s.get("vpn_key"):
        return "connected"
    # AdGuard VPN can be the egress instead of a key-based server. Without this
    # branch the dashboard reports "no key" while every packet is in fact being
    # tunnelled, which reads as if the gateway were wide open.
    if (s.get("adguard") or {}).get("enabled"):
        return "connected" if _adguard_status().get("connected") else "error"
    return "no_key"

def parse_access_log_line(line: str) -> Optional[dict]:
    ts_m = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
    ts = ts_m.group(1) if ts_m else ""
    acc_m = re.search(
        r"(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)\s+accepted\s+"
        r"(\w+):(.+):(\d+)\s+\[([^\]]+)\]", line)
    if not acc_m: return None
    src, proto, dst, dport, route_info = acc_m.groups()
    parts = route_info.split(" -> ")
    outbound = parts[-1].strip() if len(parts) > 1 else route_info.strip()
    return {"ts": ts, "src": src, "proto": proto.upper(),
            "dst": dst, "dport": int(dport), "outbound": outbound}

# ── Export / Import helpers ────────────────────────────────────────────────────
def _export_file_list() -> list[tuple[Path, str]]:
    entries: list[tuple[Path, str]] = []
    for rel in ["web/main.py", "web/static/index.html",
                "scripts/iptables.sh", "scripts/update-geo.sh",
                "scripts/first-boot.sh", "install.sh", "SETUP.md",
                "config/settings.json", "config/network.conf"]:
        p = BASE / rel
        if p.exists(): entries.append((p, rel))
    for svc in ("xray-proxy.service", "xray-web.service", "xray-first-boot.service"):
        p = Path("/etc/systemd/system") / svc
        if p.exists(): entries.append((p, f"systemd/{svc}"))
    return entries

def _import_dest(arcname: str) -> Optional[Path]:
    name = arcname.lstrip("./")
    if name.startswith("systemd/") and name.endswith(".service"):
        svc = Path(name).name
        if svc in ("xray-proxy.service", "xray-web.service", "xray-first-boot.service"):
            return Path("/etc/systemd/system") / svc
    allowed = {"web/main.py", "web/static/index.html",
                "scripts/iptables.sh", "scripts/update-geo.sh",
                "scripts/first-boot.sh", "install.sh", "SETUP.md",
                "config/settings.json", "config/network.conf"}
    if name in allowed: return BASE / name
    return None

# ─────────────────────────────────────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(docs_url=None, redoc_url=None)

async def _scheduler_loop() -> None:
    """Run enabled scheduled tasks."""
    await _idle(60)
    while True:
        try:
            s = load_settings()
            for task in s.get("scheduler_tasks", []):
                if not _ft.should_run_now(task):
                    continue
                start = time.time()
                result, detail = await _ft.run_scheduled_task(task, s)
                duration = time.time() - start
                _db.log_scheduler_run(task["id"], task.get("name","?"),
                                      duration, result, detail)
                # Update last_run in settings
                s2 = load_settings()
                for t in s2.get("scheduler_tasks", []):
                    if t["id"] == task["id"]:
                        t["last_run_ts"]  = int(time.time())
                        t["last_result"]  = result
                        t["last_error"]   = detail if result == "error" else ""
                save_settings(s2)
                if result == "error":
                    fire_alert("scheduler_error",
                               f"Task {task.get('name','?')}: {detail}")
        except Exception:
            pass
        await _idle(60)

async def _analytics_loop() -> None:
    """Periodically ingest access.log into SQLite analytics."""
    await _idle(30)
    while True:
        try:
            s = load_settings()
            if s.get("analytics", {}).get("enabled", True):
                ret = s.get("analytics", {}).get("retention_days", 30)
                log_path = LOGS / "access.log"
                await asyncio.get_event_loop().run_in_executor(
                    None, _ft.ingest_access_log, log_path, ret)
        except Exception:
            pass
        await _idle(60)

@app.on_event("startup")
async def startup_event():
    _install_stop_hook()
    _wire_features()
    _db.init_db()
    asyncio.create_task(_failover_loop())
    asyncio.create_task(_disk_monitor_loop())
    asyncio.create_task(_xray_fd_watchdog())
    asyncio.create_task(_scheduler_loop())
    asyncio.create_task(_analytics_loop())
    asyncio.create_task(_metrics_loop())
    asyncio.create_task(_egress_fallback_loop())

# ── Pydantic Models ────────────────────────────────────────────────────────────
class LoginReq(BaseModel):        username: str; password: str
class KeyReq(BaseModel):          key: str
class ProfileReq(BaseModel):      profile: str
class PwReq(BaseModel):           current: str; new_pw: str
class AaplimgReq(BaseModel):      enabled: bool
class RouteTestReq(BaseModel):    target: str
class IfaceSwitchReq(BaseModel):  name: str
class TopologyReq(BaseModel):
    topology: str                 # loop | inline
    wan_if: str = ""              # required for inline
    lan_if: str = ""              # required
    lan_subnet: str = "192.168.100"  # inline: /24 base for the gateway↔router link
    wan_mac: str = ""             # inline: clone this MAC on WAN (ISP MAC-binding)
class CustomRulesReq(BaseModel):
    always_direct: list[str]
    always_vpn:    list[str]
class DeviceNameReq(BaseModel):   name: str
class DevicePolicyReq(BaseModel): policy: str
class VPNServerAddReq(BaseModel): key: str; name: str = ""; priority: int = 99
class VPNServerUpdateReq(BaseModel):
    name:     Optional[str]  = None
    enabled:  Optional[bool] = None
    priority: Optional[int]  = None
class VPNActivateReq(BaseModel):  server_id: str
class DNSSettingsReq(BaseModel):
    upstream:      list[str]
    upstream_ru:   list[str]    = []
    cache_size:    int          = 1000
    local_records: list[dict]   = []
class AlertsConfigReq(BaseModel):
    enabled:      bool
    webhook_url:  str           = ""
    events:       list[str]
    cooldown_min: int           = 30
class ExplainReq(BaseModel):
    src_ip:   str
    dst:      str
    dst_port: int
    proto:    str
    outbound: str

# ── Captive Portal ────────────────────────────────────────────────────────────
@app.get("/generate_204")
@app.head("/generate_204")
async def gen204(): return Response(status_code=204)

@app.get("/hotspot-detect.html")
async def hotspot():
    return HTMLResponse("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")

@app.get("/ncsi.txt")
async def ncsi(): return Response("Microsoft NCSI")

# ── Auth ───────────────────────────────────────────────────────────────────────
@app.post("/api/login")
async def login(req: LoginReq, resp: Response, request: Request):
    s = load_settings()
    src_ip = request.client.host if request.client else "unknown"
    if (req.username != s["auth"]["username"] or
            hashlib.sha256(req.password.encode()).hexdigest() != s["auth"]["password_hash"]):
        _login_fail_count[src_ip] = _login_fail_count.get(src_ip, 0) + 1
        if _login_fail_count[src_ip] >= 5:
            fire_alert("login_failed", f"5+ failed logins from {src_ip}")
        raise HTTPException(401, "Invalid credentials")
    _login_fail_count[src_ip] = 0
    tok = make_token(req.username)
    resp.set_cookie("token", tok, max_age=86400, httponly=True, samesite="lax")
    return {"ok": True, "token": tok}

@app.post("/api/logout")
async def logout(resp: Response):
    resp.delete_cookie("token"); return {"ok": True}

@app.get("/api/auth-check")
async def auth_check(u: str = Depends(auth_dep)):
    return {"ok": True, "user": u}

@app.get("/api/version")
async def get_version(u: str = Depends(auth_dep)):
    return {"version": VERSION, "xray_core": get_xray_core_version()}

# ── Status ─────────────────────────────────────────────────────────────────────
@app.get("/api/status")
async def get_status(u: str = Depends(auth_dep)):
    s = load_settings(); speeds = get_speeds(); state = get_xray_state()
    gw = _get_lan_ip() or "?"
    vpn_meta = None
    # Build VPN meta from active server
    active_id = s.get("active_vpn_id")
    servers   = s.get("vpn_servers", [])
    active    = next((x for x in servers if x.get("id") == active_id), None)
    if active:
        try:
            _, vpn_meta = parse_key(active["key"])
            vpn_meta["masked_key"] = mask_key(active["key"])
            vpn_meta["server_id"]  = active["id"]
            vpn_meta["last_status"] = active.get("last_status", "unknown")
            vpn_meta["latency_ms"]  = active.get("latency_ms")
        except Exception:
            vpn_meta = {"name": active.get("name","?"), "protocol":"?", "server":"?",
                        "port": 0, "last_status": "error"}
    elif s.get("vpn_key"):   # legacy
        try:
            _, vpn_meta = parse_key(s["vpn_key"])
            vpn_meta["masked_key"] = mask_key(s["vpn_key"])
        except Exception:
            vpn_meta = {"name": "Invalid key", "protocol":"?","server":"?","port":0}
    egress = None
    if not (s.get("active_vpn_id") or s.get("vpn_key")):
        ag = s.get("adguard") or {}
        if ag.get("enabled"):
            egress = {"kind": "adguard", "location": ag.get("location")}
    return {"state": state, "egress": egress,
            "auto_fallback": bool(s.get("auto_fallback")),
            "egress_active": s.get("egress_active", "adguard"),
            "fptn_enabled": bool((s.get("fptn") or {}).get("enabled")),
            "in_fallback": bool(s.get("fallback_saved_profile")),
            "fallback_saved_profile": s.get("fallback_saved_profile"),
            "gateway_ip": gw, "profile": s.get("profile", "all_except_ru"),
            "topology": _net_conf().get("TOPOLOGY", "loop"), "mgmt_ip": _get_mgmt_ip(),
            "nav": _nav_flags(s),
            "vpn": vpn_meta, "geo_updated": s.get("geo_updated"), "speeds": speeds,
            "force_aaplimg_vpn": s.get("force_aaplimg_vpn", True),
            "vpn_server_count": len(servers)}

# ── Automatic fallback to direct routing ──────────────────────────────────────
def _socks_probe(host: str, port) -> bool:
    """True while a SOCKS egress still carries traffic. Same two targets the
    watchdog uses, so every component agrees on what 'egress alive' means."""
    sock = "%s:%s" % (host, port)
    for url, want in (("http://cp.cloudflare.com/generate_204", "204"),
                      ("https://api.ipify.org", "200")):
        try:
            r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-m", "8",
                                "-w", "%{http_code}", "--socks5", sock, url],
                               capture_output=True, text=True, timeout=12)
            if r.stdout.strip() == want:
                return True
        except Exception:
            pass
    return False


def _egress_probe() -> bool:
    """Is the AdGuard egress — the primary one — alive?"""
    ag = (load_settings().get("adguard") or {})
    return _socks_probe(ag.get("socks_host", "127.0.0.1"), ag.get("socks_port", 1081))


def _fptn_probe() -> bool:
    """Is the FPTN egress — the secondary one — alive?"""
    fp = (load_settings().get("fptn") or {})
    return _socks_probe(fp.get("socks_host", "192.168.244.2"), fp.get("socks_port", 1082))


async def _egress_fallback_loop() -> None:
    """Keep traffic flowing by walking down a ladder of egresses.

    AdGuard is the primary and always wins when it is alive. FPTN is the
    secondary: a different provider, protocol and network, so a block that takes
    out one is unlikely to take out the other. Direct routing is the last rung —
    unencrypted, so it is only reached when both tunnels are gone.

    Motivated by the 2026-09-03 outage: the AdGuard tunnel was dead for 6h34m
    while the ISP link stayed healthy the whole time (391 probe failures, each
    recording `ISP-gw loss=0%`), and every foreign destination was unreachable
    all night although working paths existed.
    """
    await _idle(90)
    ag_fails = 0
    loop = asyncio.get_event_loop()
    while True:
        try:
            s = load_settings()
            if s.get("auto_fallback"):
                ag_alive = await loop.run_in_executor(None, _egress_probe)
                active = s.get("egress_active", "adguard")
                saved = s.get("fallback_saved_profile")

                if ag_alive:
                    ag_fails = 0
                    # Primary is back: undo whatever we did, in reverse order.
                    if active != "adguard" or saved:
                        old_s = dict(s)
                        s["egress_active"] = "adguard"
                        if saved:
                            s["profile"] = saved
                            s["fallback_saved_profile"] = None
                        save_settings(s)
                        await loop.run_in_executor(
                            None, lambda: apply_config(s, "egress_restore_adguard",
                                                       _pre_settings=old_s))
                        fire_alert("failover_executed", "AdGuard egress restored")
                else:
                    ag_fails += 1
                    # three misses (~3 min) before acting, so a brief hiccup or a
                    # single watchdog restart does not move the household's traffic
                    if ag_fails >= 3:
                        fp = s.get("fptn") or {}
                        fptn_alive = (await loop.run_in_executor(None, _fptn_probe)
                                      if fp.get("enabled") else False)
                        if fptn_alive and active != "fptn":
                            old_s = dict(s)
                            s["egress_active"] = "fptn"
                            save_settings(s)
                            await loop.run_in_executor(
                                None, lambda: apply_config(s, "egress_switch_fptn",
                                                           _pre_settings=old_s))
                            fire_alert("failover_executed",
                                       "AdGuard dead — switched to the FPTN egress")
                        elif not fptn_alive and not saved and s.get("profile") != "direct":
                            # Both tunnels gone: routing direct beats no internet,
                            # but it is unencrypted, so it is the last resort only.
                            old_s = dict(s)
                            s["fallback_saved_profile"] = s.get("profile", "all_except_ru")
                            s["profile"] = "direct"
                            s["egress_active"] = "adguard"
                            save_settings(s)
                            await loop.run_in_executor(
                                None, lambda: apply_config(s, "egress_fallback_direct",
                                                           _pre_settings=old_s))
                            fire_alert("failover_executed",
                                       "Both egresses dead — routing direct")
        except Exception:
            pass
        await _idle(60)



# Server names as the FPTN client reports them. It matches --preferred-server
# exactly and falls back to auto-selection in silence when a name is unknown, so
# guessing region words like "usa" quietly lands you in Poland. The list is
# transcribed from the vendor's own client; USA-1 has never once connected in
# testing, which is why USA-2 is the default.
FPTN_SERVERS = {
    "premium": ["Norway-Premium", "Finland-Premium", "Czechia-Premium",
                "Austria-Premium", "Poland-Premium", "France-Premium",
                "Netherlands-Premium", "Germany-Premium", "Sweden-Premium",
                "Russia-Premium-17(Finland)", "Russia-Premium-20(Finland)",
                "Russia-Premium-21(Finland)", "Russia-Premium-22(Finland)",
                "Russia-Premium-23(France)", "Russia-Premium-24(France)"],
    "regular": ["USA-1", "USA-2", "Denmark-1", "Turkey-1",
                "Netherlands-1", "Netherlands-2", "Netherlands-3",
                "Germany-1", "Germany-2",
                "France-1", "France-2", "France-3", "France-4", "France-5",
                "Finland-1", "Finland-2", "Finland-3",
                "Poland-1", "Poland-2", "Poland-3",
                "Czechia-1", "Czechia-2", "Czechia-3", "Vietnam-1"],
    "restricted": ["Russia-Moscow"],
}
FPTN_SERVER_FILE = CFG_DIR / "fptn-server"


class SystemActionReq(BaseModel):
    confirm: bool = False


@app.post("/api/system/restart-services")
async def restart_services(req: SystemActionReq, u: str = Depends(auth_dep)):
    """Restart the traffic stack. Detached via systemd-run so the answer reaches
    the browser before the restart drops the caller's own connection — the web
    UI is reached through this very gateway."""
    if not req.confirm:
        raise HTTPException(400, "confirm required")
    subprocess.run(
        ["systemd-run", "--unit=gw-restart-services", "--collect", "/bin/sh", "-c",
         "sleep 1; systemctl restart xray-proxy sing-box dnsmasq xray-dohproxy adguardvpn"],
        capture_output=True)
    return {"ok": True, "action": "restart-services"}


@app.post("/api/system/reboot")
async def reboot_gateway(req: SystemActionReq, u: str = Depends(auth_dep)):
    """Full reboot. Deliberately the second-class action: in every incident so
    far a reboot either did not help or, on Sep 4, came back with a routing rule
    missing and took Russian sites down until it was found."""
    if not req.confirm:
        raise HTTPException(400, "confirm required")
    subprocess.run(
        ["systemd-run", "--unit=gw-reboot", "--collect", "/bin/sh", "-c",
         "sleep 3; systemctl reboot"], capture_output=True)
    return {"ok": True, "action": "reboot"}


class AdguardProtoReq(BaseModel):
    protocol: str


@app.post("/api/adguard/protocol")
async def set_adguard_protocol(req: AdguardProtoReq, u: str = Depends(auth_dep)):
    """auto | http2 | quic. QUIC is the faster default but reaches the backend
    over HTTP/3; with no IPv6 route on this box that path dead-ends and the
    client can never fetch its server list, which is what kept it disconnected
    for 6.5 hours on Sep 3."""
    if req.protocol not in ("auto", "http2", "quic"):
        raise HTTPException(400, "protocol must be auto, http2 or quic")
    r = subprocess.run(_AGVPN + ["config", "set-protocol", req.protocol],
                       capture_output=True, text=True, timeout=25)
    if r.returncode != 0:
        raise HTTPException(500, (r.stderr or r.stdout or "failed")[:200])
    subprocess.run(["systemctl", "restart", "adguardvpn"], capture_output=True)
    return {"ok": True, "protocol": req.protocol}


class FptnReq(BaseModel):
    enabled: Optional[bool] = None
    server: Optional[str] = None


@app.get("/api/fptn")
async def get_fptn(u: str = Depends(auth_dep)):
    s = load_settings()
    fp = s.get("fptn") or {}
    try:
        current = FPTN_SERVER_FILE.read_text().strip()
    except Exception:
        current = "USA-2"
    r = subprocess.run(["systemctl", "is-active", "fptn-egress"],
                       capture_output=True, text=True)
    return {"enabled": bool(fp.get("enabled")), "server": current,
            "service": r.stdout.strip(), "servers": FPTN_SERVERS,
            "active": s.get("egress_active", "adguard") == "fptn"}


@app.post("/api/fptn")
async def set_fptn(req: FptnReq, u: str = Depends(auth_dep)):
    s = load_settings()
    fp = dict(s.get("fptn") or {})
    if req.server is not None:
        known = sum(FPTN_SERVERS.values(), [])
        if req.server not in known:
            raise HTTPException(400, "Unknown server name")
        FPTN_SERVER_FILE.write_text(req.server + "\n")
    if req.enabled is not None:
        fp["enabled"] = req.enabled
    fp.setdefault("socks_host", "192.168.244.2")
    fp.setdefault("socks_port", 1082)
    s["fptn"] = fp
    save_settings(s)
    # enable/disable and (re)start so a new server name takes effect
    if fp.get("enabled"):
        subprocess.run(["systemctl", "enable", "--now", "fptn-egress"],
                       capture_output=True)
        if req.server is not None:
            subprocess.run(["systemctl", "restart", "fptn-egress"], capture_output=True)
    else:
        subprocess.run(["systemctl", "disable", "--now", "fptn-egress"],
                       capture_output=True)
    return {"ok": True, "enabled": fp.get("enabled"), "server": req.server}


class AutoFallbackReq(BaseModel):
    enabled: bool


@app.post("/api/auto-fallback")
async def set_auto_fallback(req: AutoFallbackReq, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    s["auto_fallback"] = req.enabled
    restored = None
    if not req.enabled and s.get("fallback_saved_profile"):
        restored = s["fallback_saved_profile"]
        s["profile"] = restored
        s["fallback_saved_profile"] = None
    save_settings(s)
    if restored:
        apply_config(s, "auto_fallback_off", _pre_settings=old_s)
    return {"ok": True, "enabled": req.enabled, "restored_profile": restored}


# ── Metrics sampler ───────────────────────────────────────────────────────────
_ACCT_RE = re.compile(r"^\s*\d+\s+(\d+)\s+.*?/\* (vpn_up|vpn_down) \*/", re.M)


def _read_acct() -> dict:
    """Byte counters from the XRAY_ACCT chain.

    This is how the VPN/direct split is measured. Interface counters cannot do
    it: proxied and direct traffic both leave via the WAN, and tun0 carries only
    sing-box's own SOCKS inbound (measured at ~23 KB against 1.7 MB on the WAN
    over the same 10s). xray's stats API is off limits after the Jun-04 FD leak.
    """
    try:
        r = subprocess.run(["iptables", "-t", "mangle", "-nvxL", "XRAY_ACCT"],
                           capture_output=True, text=True, timeout=5)
        return {m.group(2): int(m.group(1)) for m in _ACCT_RE.finditer(r.stdout)}
    except Exception:
        return {}


def _cpu_totals() -> tuple:
    """Aggregate (busy, total) jiffies from /proc/stat.

    The sampler needs its own CPU reading: get_system_info() reports the delta
    since its previous call, and the once-a-second SSE stream keeps resetting
    that, leaving the minute sampler a few milliseconds of data and a reading
    of 0%.
    """
    try:
        parts = Path("/proc/stat").read_text().split("\n")[0].split()[1:]
        v = [int(x) for x in parts]
        total = sum(v)
        return total - (v[3] + (v[4] if len(v) > 4 else 0)), total
    except Exception:
        return 0, 0


def _iface_bytes(iface: str) -> int:
    total = 0
    for d in ("rx_bytes", "tx_bytes"):
        try:
            total += int(Path(f"/sys/class/net/{iface}/statistics/{d}").read_text())
        except Exception:
            pass
    return total


async def _metrics_loop() -> None:
    """Sample CPU, memory and the traffic split once a minute.

    Keeps its own counter state instead of calling get_speeds(), whose deltas
    belong to the once-a-second SSE stream and would be corrupted by a second
    reader.
    """
    await _idle(45)
    prev = None
    while True:
        try:
            now = time.time()
            acct = _read_acct()
            vpn = acct.get("vpn_up", 0) + acct.get("vpn_down", 0)
            lan = _iface_bytes(_get_lan_if())
            busy, ctot = _cpu_totals()
            if prev and now > prev[0] and vpn >= prev[1] and lan >= prev[2]:
                dt = now - prev[0]
                dtot = ctot - prev[4]
                cpu = max(0.0, min(100.0, (busy - prev[3]) / dtot * 100)) if dtot > 0 else 0.0
                m = (get_system_info().get("mem") or {})
                mem = (m.get("used", 0) / m["total"] * 100) if m.get("total") else 0.0
                await asyncio.get_event_loop().run_in_executor(
                    None, _db.record_metric, int(now), cpu, mem,
                    (vpn - prev[1]) / dt, (lan - prev[2]) / dt)
            prev = (now, vpn, lan, busy, ctot)
        except Exception:
            pass
        await _idle(60)


@app.get("/api/metrics")
async def api_metrics(res: str = "m1", u: str = Depends(auth_dep)):
    """History for the resource charts. `direct` is derived, never stored:
    it is whatever crossed the LAN side but did not enter the tunnel."""
    out = []
    for r in _db.get_metrics(res):
        tot, vpn = r.get("tot_bps") or 0.0, r.get("vpn_bps") or 0.0
        out.append({"ts": r["ts"], "cpu": r.get("cpu") or 0.0,
                    "mem": r.get("mem") or 0.0, "vpn": vpn,
                    "direct": max(0.0, tot - vpn)})
    return {"res": res, "samples": out}


# ── SSE Streams ────────────────────────────────────────────────────────────────
_shutting_down = asyncio.Event()


@app.on_event("shutdown")
async def _signal_shutdown() -> None:
    # Fallback only. uvicorn runs lifespan shutdown *after* it has already
    # waited for open connections, so by the time this fires the graceful
    # timeout is spent. _install_stop_hook() is what actually unblocks things.
    _shutting_down.set()


def _install_stop_hook() -> None:
    """Set the shutdown flag the moment SIGTERM/SIGINT arrives.

    uvicorn waits for in-flight responses before running lifespan shutdown, and
    the dashboard's SSE streams never end on their own, so every restart burned
    the full timeout and ended in SIGKILL. Chain onto uvicorn's own handler
    rather than replacing it, so its shutdown sequence still runs.
    """
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        prev = signal.getsignal(sig)

        def handler(signum, frame, _prev=prev):
            loop.call_soon_threadsafe(_shutting_down.set)
            if callable(_prev):
                _prev(signum, frame)

        signal.signal(sig, handler)


_STOP = object()   # shutdown began
_IDLE = object()   # no output within the timeout


async def _read_or_stop(proc, seconds: float):
    """Read one line from `proc`, racing it against shutdown.

    A bare wait_for() on readline() cannot be interrupted, which would keep a
    log stream (and the shutdown) alive for the full timeout. Returns _STOP if
    shutdown began, _IDLE on timeout, otherwise the line.
    """
    line_f = asyncio.ensure_future(proc.stdout.readline())
    stop_f = asyncio.ensure_future(_shutting_down.wait())
    try:
        done, pending = await asyncio.wait(
            {line_f, stop_f}, timeout=seconds,
            return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (line_f, stop_f):
            if not t.done():
                t.cancel()
    if stop_f in done:
        return _STOP
    if line_f in done:
        return line_f.result()
    return _IDLE


async def _idle(seconds: float) -> None:
    """Sleep inside a background loop, ending the task once shutdown starts.

    A plain asyncio.sleep() leaves the task alive for its full duration (one of
    these waits an hour), which uvicorn reports as "Cancel N running task(s)"
    and which held every restart open until the shutdown timeout expired.
    """
    if await _sse_wait(seconds):
        raise asyncio.CancelledError


async def _sse_wait(seconds: float) -> bool:
    """Pause between SSE frames, waking immediately once shutdown begins.

    Returns True when the stream should stop. The dashboard keeps these streams
    open indefinitely, so without a way out uvicorn's graceful shutdown waits
    out its whole timeout and systemd SIGKILLs the service on every restart.
    """
    try:
        await asyncio.wait_for(_shutting_down.wait(), timeout=seconds)
        return True
    except asyncio.TimeoutError:
        return False


@app.get("/api/speed-stream")
async def speed_stream(u: str = Depends(auth_dep)):
    async def gen():
        while not _shutting_down.is_set():
            yield f"data: {json.dumps(get_speeds())}\n\n"
            if await _sse_wait(1):
                break
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.get("/api/sysinfo")
async def sysinfo_snapshot(u: str = Depends(auth_dep)):
    info = get_system_info(); info["net"] = get_speeds(); return info

@app.get("/api/sysinfo-stream")
async def sysinfo_stream(u: str = Depends(auth_dep)):
    async def gen():
        while not _shutting_down.is_set():
            info = get_system_info(); info["net"] = get_speeds()
            yield f"data: {json.dumps(info)}\n\n"
            if await _sse_wait(1):
                break
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── VPN Servers ────────────────────────────────────────────────────────────────
@app.get("/api/vpn-servers")
async def get_vpn_servers(u: str = Depends(auth_dep)):
    s = load_settings()
    servers = s.get("vpn_servers", [])
    # Return masked list
    masked = []
    for srv in servers:
        try:
            _, info = parse_key(srv["key"])
            masked.append({
                "id":           srv["id"],
                "name":         srv.get("name", info.get("name","?")),
                "protocol":     info["protocol"],
                "server":       info["server"],
                "port":         info["port"],
                "enabled":      srv.get("enabled", True),
                "priority":     srv.get("priority", 99),
                "last_status":  srv.get("last_status", "unknown"),
                "latency_ms":   srv.get("latency_ms"),
                "last_checked": srv.get("last_checked"),
                "is_active":    srv["id"] == s.get("active_vpn_id"),
            })
        except Exception:
            masked.append({
                "id": srv.get("id","?"), "name": srv.get("name","?"),
                "protocol":"?", "server":"?", "port":0,
                "enabled": srv.get("enabled", True),
                "priority": srv.get("priority", 99),
                "last_status": "parse_error",
                "latency_ms": None, "last_checked": None,
                "is_active": srv.get("id") == s.get("active_vpn_id"),
            })
    return {"servers": masked, "active_id": s.get("active_vpn_id")}

@app.post("/api/vpn-servers")
async def add_vpn_server(req: VPNServerAddReq, u: str = Depends(auth_dep)):
    try:
        _, info = parse_key(req.key)
    except ValueError as e:
        raise HTTPException(400, str(e))
    s = load_settings(); old_s = dict(s)
    srv_id = str(_uuid_mod.uuid4())
    name = req.name.strip() or info.get("name", f"Server {len(s['vpn_servers'])+1}")
    new_srv = {"id": srv_id, "name": name, "key": req.key.strip(),
               "enabled": True, "priority": req.priority,
               "last_status": "unknown", "latency_ms": None, "last_checked": None}
    s["vpn_servers"].append(new_srv)
    if not s.get("active_vpn_id"):
        s["active_vpn_id"] = srv_id
    save_settings(s)
    ok, err = apply_config(s, "vpn_server_add", _pre_settings=old_s)
    return {"ok": ok, "error": err or None, "server_id": srv_id}

@app.patch("/api/vpn-servers/{server_id}")
async def update_vpn_server(server_id: str, req: VPNServerUpdateReq, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    srv = next((x for x in s.get("vpn_servers", []) if x.get("id") == server_id), None)
    if not srv: raise HTTPException(404, "Server not found")
    if req.name     is not None: srv["name"]     = req.name.strip()[:64]
    if req.enabled  is not None: srv["enabled"]  = req.enabled
    if req.priority is not None: srv["priority"] = max(1, min(99, req.priority))
    save_settings(s)
    ok, err = apply_config(s, "vpn_server_update", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.delete("/api/vpn-servers/{server_id}")
async def delete_vpn_server(server_id: str, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    before = len(s.get("vpn_servers", []))
    removed = next((x for x in s.get("vpn_servers", []) if x.get("id") == server_id), None)
    s["vpn_servers"] = [x for x in s.get("vpn_servers", []) if x.get("id") != server_id]
    if len(s["vpn_servers"]) == before:
        raise HTTPException(404, "Server not found")
    # The deprecated vpn_key is re-materialised into vpn_servers by _migrate_settings on
    # the next load, which resurrected just-deleted servers under a fresh id. Drop it too.
    if (removed and s.get("vpn_key") == removed.get("key")) or not s["vpn_servers"]:
        s["vpn_key"] = None
    if s.get("active_vpn_id") == server_id:
        remaining = [x for x in s["vpn_servers"] if x.get("enabled")]
        s["active_vpn_id"] = remaining[0]["id"] if remaining else None
    save_settings(s)
    ok, err = apply_config(s, "vpn_server_delete", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.post("/api/vpn-servers/{server_id}/activate")
async def activate_vpn_server(server_id: str, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    if not any(x.get("id") == server_id for x in s.get("vpn_servers", [])):
        raise HTTPException(404, "Server not found")
    s["active_vpn_id"] = server_id
    save_settings(s)
    ok, err = apply_config(s, "vpn_server_activate", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.post("/api/vpn-servers/{server_id}/check")
async def check_vpn_server(server_id: str, u: str = Depends(auth_dep)):
    s = load_settings()
    srv = next((x for x in s.get("vpn_servers", []) if x.get("id") == server_id), None)
    if not srv: raise HTTPException(404, "Server not found")
    loop = asyncio.get_event_loop()
    ok, lat = await loop.run_in_executor(None, _vpn_server_health, srv)
    # Update status
    s2 = load_settings()
    for x in s2.get("vpn_servers", []):
        if x.get("id") == server_id:
            x["last_status"] = "ok" if ok else "error"
            x["latency_ms"]  = lat
            x["last_checked"] = datetime.now(timezone.utc).isoformat()
    save_settings(s2)
    return {"ok": True, "reachable": ok, "latency_ms": lat}

# Legacy single-key endpoints (kept for backward compat)
@app.post("/api/vpn-key")
async def set_key(req: KeyReq, u: str = Depends(auth_dep)):
    try: _, meta = parse_key(req.key)
    except ValueError as e: raise HTTPException(400, str(e))
    s = load_settings(); old_s = dict(s)
    # Add as new server or update first server
    servers = s.get("vpn_servers", [])
    if servers:
        servers[0]["key"] = req.key.strip()
        if not s.get("active_vpn_id"): s["active_vpn_id"] = servers[0]["id"]
    else:
        srv_id = str(_uuid_mod.uuid4())
        s["vpn_servers"] = [{"id": srv_id, "name": meta.get("name","Server 1"),
                              "key": req.key.strip(), "enabled": True, "priority": 1,
                              "last_status":"unknown","latency_ms":None,"last_checked":None}]
        s["active_vpn_id"] = srv_id
    s["vpn_key"] = req.key.strip()  # keep for compat
    save_settings(s)
    ok, err = apply_config(s, "vpn_key_change", _pre_settings=old_s)
    return {"ok": ok, "error": err or None, "vpn": meta}

@app.delete("/api/vpn-key")
async def del_key(u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    s["vpn_key"] = None; s["vpn_servers"] = []; s["active_vpn_id"] = None
    save_settings(s); apply_config(s, "vpn_key_delete", _pre_settings=old_s)
    return {"ok": True}

# ── Profile ────────────────────────────────────────────────────────────────────
@app.post("/api/profile")
async def set_profile(req: ProfileReq, u: str = Depends(auth_dep)):
    if req.profile not in ("blocked_only", "all_except_ru", "all", "direct"):
        raise HTTPException(400, "Invalid profile")
    s = load_settings(); old_s = dict(s); s["profile"] = req.profile; save_settings(s)
    ok, err = apply_config(s, "profile_change", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.post("/api/aaplimg-vpn")
async def set_aaplimg_vpn(req: AaplimgReq, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s); s["force_aaplimg_vpn"] = req.enabled; save_settings(s)
    ok, err = apply_config(s, "aaplimg_toggle", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

# ── Custom Rules ───────────────────────────────────────────────────────────────
@app.get("/api/custom-rules")
async def get_custom_rules(u: str = Depends(auth_dep)):
    return load_settings().get("custom_rules", {"always_direct":[],"always_vpn":[]})

@app.put("/api/custom-rules")
async def set_custom_rules(req: CustomRulesReq, u: str = Depends(auth_dep)):
    errors = []
    for lst, rule in [("always_direct", r) for r in req.always_direct] + \
                     [("always_vpn",    r) for r in req.always_vpn]:
        ok, msg = validate_custom_rule(rule)
        if not ok: errors.append(f"[{lst}] {msg}")
    if errors: raise HTTPException(400, "; ".join(errors))
    s = load_settings(); old_s = dict(s)
    s["custom_rules"] = {"always_direct": req.always_direct, "always_vpn": req.always_vpn}
    save_settings(s)
    ok, err = apply_config(s, "custom_rules_change", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

# ── Route Test ─────────────────────────────────────────────────────────────────
@app.post("/api/route-test")
async def api_route_test(req: RouteTestReq, u: str = Depends(auth_dep)):
    target = req.target.strip()
    if not target or len(target) > 253: raise HTTPException(400, "invalid target")
    s = load_settings()
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, route_test, target, s)

# ── Devices ────────────────────────────────────────────────────────────────────
@app.get("/api/devices")
async def get_devices(u: str = Depends(auth_dep)):
    s = load_settings()
    return {"devices": get_devices_merged(s)}

@app.post("/api/devices/{key:path}/name")
async def set_device_name(key: str, req: DeviceNameReq, u: str = Depends(auth_dep)):
    s = load_settings()
    s.setdefault("devices", {})
    name = req.name.strip()[:64]
    s["devices"].setdefault(key, {"policy": "inherit", "ips": []})
    if name: s["devices"][key]["name"] = name
    else:    s["devices"][key].pop("name", None)
    save_settings(s)
    return {"ok": True}

@app.post("/api/devices/{key:path}/policy")
async def set_device_policy(key: str, req: DevicePolicyReq, u: str = Depends(auth_dep)):
    if req.policy not in DEVICE_POLICIES:
        raise HTTPException(400, f"Invalid policy. Must be one of: {DEVICE_POLICIES}")
    s = load_settings(); old_s = dict(s)
    s.setdefault("devices", {})
    s["devices"].setdefault(key, {"name": "", "ips": []})
    s["devices"][key]["policy"] = req.policy
    # Update cached IPs from current ARP
    arp = get_arp_table()
    for entry in arp:
        arp_key = entry["mac"] if entry["mac"] else f"ip:{entry['ips'][0]}"
        if arp_key == key:
            s["devices"][key]["ips"] = entry["ips"]
            break
    save_settings(s)
    ok, err = apply_config(s, "device_policy_change", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.delete("/api/devices/{key:path}")
async def delete_device(key: str, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    s.get("devices", {}).pop(key, None)
    save_settings(s)
    ok, err = apply_config(s, "device_delete", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

# ── DNS ────────────────────────────────────────────────────────────────────────
@app.get("/api/dns")
async def get_dns(u: str = Depends(auth_dep)):
    s = load_settings()
    return s.get("dns", DEFAULT_SETTINGS["dns"])

@app.put("/api/dns")
async def set_dns(req: DNSSettingsReq, u: str = Depends(auth_dep)):
    dns = {"upstream": req.upstream, "upstream_ru": req.upstream_ru,
           "cache_size": req.cache_size, "local_records": req.local_records}
    errors = validate_dns_settings(dns)
    if errors: raise HTTPException(400, "; ".join(errors))
    s = load_settings()
    s["dns"] = dns; save_settings(s)
    ok, err = apply_dns_config(dns)
    return {"ok": ok, "error": err or None}

@app.get("/api/dns/status")
async def dns_status(u: str = Depends(auth_dep)):
    return get_dns_status()

@app.post("/api/dns/test")
async def dns_test(req: RouteTestReq, u: str = Depends(auth_dep)):
    domain = req.target.strip()
    if not domain or not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
        raise HTTPException(400, "Invalid domain")
    start = time.time()
    try:
        results = socket.getaddrinfo(domain, None)
        ips = list({r[4][0] for r in results})[:10]
        elapsed_ms = int((time.time() - start) * 1000)
        s = load_settings()
        rt = route_test(ips[0] if ips else domain, s)
        return {"domain": domain, "ips": ips, "elapsed_ms": elapsed_ms,
                "route": rt.get("outbound"), "matched_rule": rt.get("matched_rule"),
                "error": None}
    except socket.gaierror as e:
        return {"domain": domain, "ips": [], "elapsed_ms": int((time.time()-start)*1000),
                "route": None, "matched_rule": None, "error": str(e)}

# ── Explain Connection ─────────────────────────────────────────────────────────
@app.post("/api/explain-connection")
async def api_explain(req: ExplainReq, u: str = Depends(auth_dep)):
    s = load_settings()
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, explain_connection,
        req.src_ip, req.dst, req.dst_port, req.proto, req.outbound, s)

# ── Snapshots ──────────────────────────────────────────────────────────────────
@app.get("/api/snapshots")
async def get_snapshots(u: str = Depends(auth_dep)):
    return {"snapshots": list_snapshots()}

@app.post("/api/snapshots/restore/{snap_id}")
async def api_restore_snapshot(snap_id: str, u: str = Depends(auth_dep)):
    if not re.match(r'^\d{8}_\d{6}$', snap_id):
        raise HTTPException(400, "Invalid snapshot id")
    ok, msg = restore_snapshot(snap_id)
    return {"ok": ok, "message": msg}

@app.delete("/api/snapshots/{snap_id}")
async def delete_snapshot(snap_id: str, u: str = Depends(auth_dep)):
    if not re.match(r'^\d{8}_\d{6}$', snap_id):
        raise HTTPException(400, "Invalid snapshot id")
    p = _snap_path(snap_id)
    if not p.exists(): raise HTTPException(404, "Snapshot not found")
    p.unlink(); return {"ok": True}

# ── Alerts ─────────────────────────────────────────────────────────────────────
@app.get("/api/alerts/config")
async def get_alerts_config(u: str = Depends(auth_dep)):
    s = load_settings()
    cfg = dict(s.get("alerts", DEFAULT_SETTINGS["alerts"]))
    # Mask webhook URL
    url = cfg.get("webhook_url","")
    if url:
        cfg["webhook_url_masked"] = url[:20] + "***" if len(url) > 20 else "***"
        cfg["webhook_url"] = ""  # never return full URL
    return cfg

@app.put("/api/alerts/config")
async def set_alerts_config(req: AlertsConfigReq, u: str = Depends(auth_dep)):
    if req.cooldown_min < 1 or req.cooldown_min > 1440:
        raise HTTPException(400, "cooldown_min must be 1–1440")
    valid_events = {"vpn_down","config_rollback","geo_update_failed","disk_high",
                    "all_vpn_unavailable","login_failed","failover_executed","dns_upstream_unhealthy"}
    bad = [e for e in req.events if e not in valid_events]
    if bad: raise HTTPException(400, f"Unknown events: {bad}")
    s = load_settings()
    # Only update webhook_url if non-empty (empty = keep existing)
    existing_url = s.get("alerts", {}).get("webhook_url", "")
    s["alerts"] = {
        "enabled":      req.enabled,
        "webhook_url":  req.webhook_url if req.webhook_url else existing_url,
        "events":       req.events,
        "cooldown_min": req.cooldown_min,
    }
    save_settings(s); return {"ok": True}

@app.post("/api/alerts/test")
async def test_alert(u: str = Depends(auth_dep)):
    s = load_settings()
    url = s.get("alerts", {}).get("webhook_url","")
    if not url: raise HTTPException(400, "No webhook URL configured")
    # Force-send test regardless of cooldown
    old_last = _alert_last_sent.get("_test", 0)
    _alert_last_sent["_test"] = 0
    original_enabled = s["alerts"].get("enabled", False)
    s["alerts"]["enabled"] = True
    s["alerts"]["events"].append("_test") if "_test" not in s["alerts"]["events"] else None
    fire_alert("_test", "Test alert from xray-gateway")
    # Restore
    s["alerts"]["enabled"] = original_enabled
    return {"ok": True, "message": "Test alert sent"}

@app.get("/api/alerts/log")
async def get_alert_log(u: str = Depends(auth_dep)):
    return {"events": list(reversed(_alert_log[-50:]))}

# ── Geo Update ─────────────────────────────────────────────────────────────────
@app.post("/api/geo-update")
async def geo_update(u: str = Depends(auth_dep)):
    global _geoip_ru_nets, _geosite_ru_data
    try:
        r = subprocess.run([str(SCRIPT / "update-geo.sh")],
                           capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            s = load_settings(); s["geo_updated"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            save_settings(s)
            _geoip_ru_nets = None; _geosite_ru_data = None
            subprocess.run(["systemctl", "restart", "xray-proxy"])
            return {"ok": True, "output": r.stdout[-500:]}
        fire_alert("geo_update_failed", r.stderr[-200:])
        return {"ok": False, "error": r.stderr[-500:]}
    except subprocess.TimeoutExpired:
        fire_alert("geo_update_failed", "Timeout")
        return {"ok": False, "error": "Timeout"}

@app.get("/api/geo-info")
async def geo_info(u: str = Depends(auth_dep)):
    s = load_settings()
    def fsize(p: Path) -> str:
        try:
            b = p.stat().st_size
            return f"{b/1024/1024:.1f} MB" if b > 1024*1024 else f"{b//1024} KB"
        except Exception: return "—"
    return {"geo_updated": s.get("geo_updated"),
            "geoip_size": fsize(CFG_DIR/"geoip.dat"),
            "geosite_size": fsize(CFG_DIR/"geosite.dat")}

# ── Logs ───────────────────────────────────────────────────────────────────────
@app.get("/api/logs")
async def logs_snapshot(n: int = 300, u: str = Depends(auth_dep)):
    r = subprocess.run(["journalctl", "-u", "xray-proxy", "-n", str(min(n,1000)),
                        "--no-pager", "--output=short-iso"], capture_output=True, text=True)
    return {"logs": r.stdout}

@app.get("/api/logs/stream")
async def logs_stream(u: str = Depends(auth_dep)):
    async def gen():
        proc = await asyncio.create_subprocess_exec(
            "journalctl", "-u", "xray-proxy", "-f", "-n", "50",
            "--no-pager", "--output=short-iso",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            while True:
                line = await _read_or_stop(proc, 25)
                if line is _STOP: break
                if line is _IDLE:
                    yield 'data: "--- heartbeat ---"\n\n'; break
                if not line: break
                yield f"data: {json.dumps(line.decode().rstrip())}\n\n"
        finally: proc.kill()
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.get("/api/connections")
async def get_connections(n: int = 500, u: str = Depends(auth_dep)):
    log_file = LOGS / "access.log"
    if not log_file.exists(): return {"connections":[],"note":"access.log not found"}
    r = subprocess.run(["tail","-n",str(min(n,2000)),str(log_file)],capture_output=True,text=True)
    conns = [c for line in r.stdout.strip().split("\n")
             if (c := parse_access_log_line(line))]
    return {"connections": list(reversed(conns))}

@app.get("/api/connections/stream")
async def connections_stream(u: str = Depends(auth_dep)):
    log_file = LOGS / "access.log"
    async def gen():
        proc = await asyncio.create_subprocess_exec(
            "tail","-f","-n","0",str(log_file),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            while True:
                line = await _read_or_stop(proc, 25)
                if line is _STOP: break
                if line is _IDLE:
                    yield "data: null\n\n"; break
                if not line: break
                c = parse_access_log_line(line.decode().rstrip())
                if c: yield f"data: {json.dumps(c)}\n\n"
        finally: proc.kill()
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── Config Export / Import ─────────────────────────────────────────────────────
@app.get("/api/settings/export")
async def export_settings(u: str = Depends(auth_dep)):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for fspath, arcname in _export_file_list():
            tar.add(str(fspath), arcname=arcname)
    buf.seek(0)
    ts = datetime.utcnow().strftime("%Y-%m-%d")
    return Response(buf.read(), media_type="application/gzip",
                    headers={"Content-Disposition":f"attachment; filename=xray-proxy-backup-{ts}.tar.gz"})

@app.post("/api/settings/import")
async def import_settings(file: UploadFile = File(...), u: str = Depends(auth_dep)):
    data = await file.read()
    try:
        buf = io.BytesIO(data)
        with tarfile.open(fileobj=buf, mode="r:gz") as _t: pass
    except Exception: raise HTTPException(400, "Invalid tar.gz archive")
    buf.seek(0); restored: list[str] = []
    try:
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            for member in tar.getmembers():
                dest = _import_dest(member.name)
                if dest is None: continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                fobj = tar.extractfile(member)
                if fobj: dest.write_bytes(fobj.read()); restored.append(member.name.lstrip("./"))
    except Exception as e: raise HTTPException(500, f"Extraction failed: {e}")
    old_s = load_settings()
    s = load_settings()
    ok, err = apply_config(s, "settings_import", _pre_settings=old_s)
    if any(r.startswith("systemd/") for r in restored):
        subprocess.run(["systemctl","daemon-reload"],capture_output=True)
    if any(r.startswith("web/") for r in restored):
        subprocess.Popen(["systemctl","restart","xray-web"])
    return {"ok": ok, "restored": restored, "error": err or None}

# ── Network interface switch ───────────────────────────────────────────────────
@app.get("/api/network/interfaces")
async def get_network_interfaces(u: str = Depends(auth_dep)):
    return {"interfaces": list_net_interfaces(), "active": _get_lan_if(),
            "switching": _netswitch_running()}

@app.post("/api/network/interface")
async def switch_network_interface(req: IfaceSwitchReq, u: str = Depends(auth_dep)):
    if _netswitch_running():
        raise HTTPException(409, "Переключение уже выполняется")
    ifaces = {i["name"]: i for i in list_net_interfaces()}
    tgt = ifaces.get(req.name)
    if not tgt:
        raise HTTPException(404, f"Интерфейс {req.name} не найден")
    if tgt["active"]:
        raise HTTPException(400, "Этот интерфейс уже активен")
    # No-link target is allowed: single-cable workflow — the switch script
    # waits up to 90s for carrier after the config is applied.
    NETSWITCH_STATUS.unlink(missing_ok=True)
    script = BASE / "scripts" / "switch_interface.py"
    r = subprocess.run(
        ["systemd-run", "--unit", "xray-netswitch", "--collect",
         "/usr/bin/python3", str(script), req.name],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise HTTPException(500, f"Не удалось запустить переключение: {r.stderr.strip()}")
    fire_alert("iface_switch", f"LAN interface switch started: {_get_lan_if()} → {req.name}")
    return {"ok": True}

@app.get("/api/network/switch-status")
async def get_switch_status(u: str = Depends(auth_dep)):
    if not NETSWITCH_STATUS.exists():
        return {"stage": "idle"}
    try:
        return json.loads(NETSWITCH_STATUS.read_text())
    except Exception:
        return {"stage": "unknown"}

# ── Network topology (loop ↔ inline) ────────────────────────────────────────────
@app.get("/api/network/topology")
async def get_topology(u: str = Depends(auth_dep)):
    conf = _net_conf()
    topo = conf.get("TOPOLOGY", "loop")
    out = {"topology": topo, "lan_if": conf.get("LAN_IF", ""),
           "wan_if": conf.get("WAN_IF", ""), "switching": _topo_running(),
           "interfaces": list_net_interfaces()}
    if topo == "inline" and conf.get("WAN_IF"):
        out["wan"] = _wan_status(conf["WAN_IF"])
    # Suggest the downstream router's MAC for the inline WAN clone (ISP often
    # binds the lease to it). Resolve from the gateway's neighbour table.
    router_ip = conf.get("ROUTER_IP", "192.168.50.1")
    if topo == "inline":  # in inline ROUTER_IP is the gateway's own LAN ip
        router_ip = "192.168.50.1"
    try:
        r = subprocess.run(["ip", "neigh", "show", router_ip],
                           capture_output=True, text=True)
        m = re.search(r"lladdr ([0-9a-f:]{17})", r.stdout)
        out["router_mac"] = m.group(1) if m else ""
    except Exception:
        out["router_mac"] = ""
    return out

@app.post("/api/network/topology")
async def set_topology(req: TopologyReq, u: str = Depends(auth_dep)):
    if _topo_running() or _netswitch_running():
        raise HTTPException(409, "Сетевое переключение уже выполняется")
    if req.topology not in ("loop", "inline"):
        raise HTTPException(400, "topology должно быть loop или inline")
    # Inline switching via the web button is DISABLED by design. Loop and inline
    # need different physical cabling, and auto-revert to loop is impossible
    # after an inline cable-swap (no cable in a router LAN port to reach
    # 192.168.50.1) — every inline failure stranded the gateway. Inline can only
    # be done as a deliberate console reconfiguration, not a one-click action.
    if req.topology == "inline":
        raise HTTPException(409, "Inline через кнопку отключён: режимы требуют разной "
                                 "коммутации, а автооткат в loop после inline невозможен "
                                 "(шлюз оставался без сети). Inline — только консольной "
                                 "перенастройкой. Подробности — у ассистента.")
    ifaces = {i["name"]: i for i in list_net_interfaces()}
    if not req.lan_if or req.lan_if not in ifaces:
        raise HTTPException(400, f"LAN-интерфейс {req.lan_if} не найден")

    conf = _net_conf()
    ns = ["9.9.9.9"]
    if req.topology == "inline":
        if not req.wan_if or req.wan_if not in ifaces:
            raise HTTPException(400, f"WAN-интерфейс {req.wan_if} не найден")
        if req.wan_if == req.lan_if:
            raise HTTPException(400, "WAN и LAN не могут быть одним интерфейсом")
        base = req.lan_subnet.rstrip(".")
        wan_mac = req.wan_mac.strip()
        if wan_mac and not re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", wan_mac):
            raise HTTPException(400, f"Некорректный MAC: {wan_mac}")
        target = {"topology": "inline", "wan_if": req.wan_if, "wan_mode": "dhcp",
                  "lan_if": req.lan_if, "lan_ip": f"{base}.1", "lan_cidr": 24,
                  "dhcp_start": f"{base}.10", "dhcp_end": f"{base}.50",
                  "nameservers": ns}
        if wan_mac:
            target["wan_mac"] = wan_mac.lower()
    else:  # loop — restore to the router's LAN with the current/standard address
        lan_ip = _get_lan_ip() or "192.168.50.2"
        router = conf.get("ROUTER_IP", "192.168.50.1")
        target = {"topology": "loop", "lan_if": req.lan_if, "lan_ip": lan_ip,
                  "lan_cidr": 24, "router_ip": router, "nameservers": ns}

    TOPOLOGY_TARGET.write_text(json.dumps(target))
    TOPOLOGY_STATUS.unlink(missing_ok=True)
    script = BASE / "scripts" / "apply_topology.py"
    r = subprocess.run(
        ["systemd-run", "--unit", "xray-topology", "--collect",
         "/usr/bin/python3", str(script)],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise HTTPException(500, f"Не удалось запустить переключение: {r.stderr.strip()}")
    fire_alert("topology_switch",
               f"Topology switch started: {_get_topology()} → {req.topology}")
    return {"ok": True, "target": target}

@app.get("/api/network/topology-status")
async def get_topology_status(u: str = Depends(auth_dep)):
    if not TOPOLOGY_STATUS.exists():
        return {"stage": "idle"}
    try:
        return json.loads(TOPOLOGY_STATUS.read_text())
    except Exception:
        return {"stage": "unknown"}

@app.get("/api/network/wan-status")
async def get_wan_status(u: str = Depends(auth_dep)):
    conf = _net_conf()
    if conf.get("TOPOLOGY") != "inline" or not conf.get("WAN_IF"):
        return {"topology": conf.get("TOPOLOGY", "loop"), "wan": None}
    return {"topology": "inline", "wan": _wan_status(conf["WAN_IF"])}

# ── Password / Factory Reset ───────────────────────────────────────────────────
@app.post("/api/change-password")
async def change_pw(req: PwReq, u: str = Depends(auth_dep)):
    s = load_settings()
    if hashlib.sha256(req.current.encode()).hexdigest() != s["auth"]["password_hash"]:
        raise HTTPException(403, "Wrong current password")
    s["auth"]["password_hash"] = hashlib.sha256(req.new_pw.encode()).hexdigest()
    save_settings(s); return {"ok": True}

@app.post("/api/factory-reset")
async def factory_reset(u: str = Depends(auth_dep)):
    save_settings(dict(DEFAULT_SETTINGS))
    apply_config(DEFAULT_SETTINGS, "factory_reset"); return {"ok": True}

# ── Terminal WebSocket ─────────────────────────────────────────────────────────
@app.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    token = websocket.query_params.get("token","") or websocket.cookies.get("token","")
    user  = verify_token(token)
    if not user: await websocket.close(code=4401); return

    s    = load_settings()
    mode = s.get("terminal", {}).get("mode", "full")
    extra_allow = s.get("terminal", {}).get("allowlist_extra", [])

    if mode == "disabled":
        await websocket.accept()
        await websocket.send_text("\r\n\033[31mТерминал отключён в настройках.\033[0m\r\n")
        await websocket.close(); return

    session_id = str(_uuid_mod.uuid4())
    _db.start_terminal_session(session_id, user, mode)

    await websocket.accept()
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe("bash",["bash","-i"],{**os.environ,"TERM":"xterm-256color",
                                         "HOME":os.environ.get("HOME","/root")})
        os._exit(1)
    loop = asyncio.get_event_loop()
    async def pty_to_ws():
        try:
            while True:
                try:
                    data = await loop.run_in_executor(None, os.read, fd, 4096)
                    if data: await websocket.send_bytes(data)
                    else: break
                except OSError: break
        except Exception: pass
    _pending_cmd: list[str] = [""]  # accumulate typed chars for audit

    async def ws_to_pty():
        try:
            while True:
                msg = await websocket.receive()
                if msg["type"] == "websocket.disconnect": break
                raw = msg.get("bytes") or (msg["text"].encode() if msg.get("text") else None)
                if not raw: continue
                try:
                    j = json.loads(raw)
                    if j.get("type") == "resize":
                        cols = max(1, int(j.get("cols",80))); rows = max(1,int(j.get("rows",24)))
                        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH",rows,cols,0,0))
                        continue
                except Exception: pass

                # Accumulate command for allowlist check (on Enter key)
                char = raw.decode("utf-8", errors="replace")
                if char in ("\r", "\n"):
                    cmd = _pending_cmd[0].strip()
                    _pending_cmd[0] = ""
                    if cmd and mode in ("allowlist", "diagnostic"):
                        allowed, reason = _ft.terminal_command_allowed(cmd, mode, extra_allow)
                        if not allowed:
                            msg_bytes = f"\r\n\033[31m[BLOCKED] {reason}\033[0m\r\n".encode()
                            try: await websocket.send_bytes(msg_bytes)
                            except Exception: pass
                            # Don't write to PTY
                            continue
                    # Audit log
                    if cmd:
                        _db.log_terminal_command(session_id, cmd)
                else:
                    if char == "\x7f":  # backspace
                        _pending_cmd[0] = _pending_cmd[0][:-1]
                    elif char.isprintable():
                        _pending_cmd[0] += char

                try: os.write(fd, raw)
                except OSError: break
        except Exception: pass
    r_task = asyncio.create_task(pty_to_ws())
    w_task = asyncio.create_task(ws_to_pty())
    try:
        await asyncio.wait([r_task, w_task], return_when=asyncio.FIRST_COMPLETED)
    finally:
        _db.end_terminal_session(session_id)
        for t in [r_task, w_task]: t.cancel()
        # `bash -i` in a pty survives SIGTERM, so the old cleanup leaked BOTH the child
        # and the executor thread parked in os.read(fd): cancelling the asyncio task does
        # not interrupt a blocking read, and that read only EOFs once the child dies.
        # After ~13 leaked sessions the default asyncio thread pool was exhausted and every
        # NEW terminal upgraded to 101 but stayed blank (seen 2026-08-22, 14 stale bashes
        # up to 6 days old). Kill the whole process group with SIGKILL and reap it.
        for fn in [lambda: os.killpg(os.getpgid(pid), signal.SIGKILL),
                   lambda: os.kill(pid, signal.SIGKILL),
                   lambda: os.waitpid(pid, 0),
                   lambda: os.close(fd)]:
            try: fn()
            except Exception: pass
        try: await websocket.close()
        except Exception: pass

# ── P3 Pydantic models ────────────────────────────────────────────────────────
class GroupCreateReq(BaseModel):
    name: str; description: str = ""; routing_policy: str = "inherit"
class GroupUpdateReq(BaseModel):
    name: Optional[str] = None; description: Optional[str] = None
    routing_policy: Optional[str] = None
class GroupDevicesReq(BaseModel):
    devices: list[str]
class SubscriptionAddReq(BaseModel):
    name: str; url: str; type: str = "direct"
    enabled: bool = True; schedule: str = "@weekly"
class SubscriptionUpdateReq(BaseModel):
    name: Optional[str] = None; url: Optional[str] = None
    enabled: Optional[bool] = None; schedule: Optional[str] = None
class AdblockConfigReq(BaseModel):
    enabled: bool; use_starter_list: bool = True
    custom_rules: list[str] = []; allowlist: list[str] = []
class ProxyConfigReq(BaseModel):
    enabled: bool; port: int = 1080; restrict_to_home: bool = False
    auth_enabled: bool = False; username: str = ""; password: str = ""
class AdguardReq(BaseModel):
    enabled: bool
    location: Optional[str] = None       # e.g. "United States"; None = leave current location
    post_quantum: Optional[bool] = None  # None = leave as-is; changing it reconnects the tunnel
class SchedulerTaskCreateReq(BaseModel):
    name: str; type: str; enabled: bool = True; schedule: str = "@daily"
class SchedulerTaskUpdateReq(BaseModel):
    name: Optional[str] = None; enabled: Optional[bool] = None
    schedule: Optional[str] = None
class TerminalSettingsReq(BaseModel):
    mode: str; allowlist_extra: list[str] = []
class AnalyticsSettingsReq(BaseModel):
    enabled: bool; retention_days: int = 30

# ── Device Groups endpoints ───────────────────────────────────────────────────
@app.get("/api/groups")
async def get_groups(u: str = Depends(auth_dep)):
    s = load_settings()
    # Enrich with device count
    groups = []
    for g in s.get("groups", []):
        groups.append({**g, "device_count": len(g.get("devices", []))})
    return {"groups": groups}

@app.post("/api/groups")
async def create_group(req: GroupCreateReq, u: str = Depends(auth_dep)):
    errs = _ft.validate_group({"name": req.name, "routing_policy": req.routing_policy})
    if errs: raise HTTPException(400, "; ".join(errs))
    s = load_settings(); old_s = dict(s)
    gid = str(_uuid_mod.uuid4())
    s.setdefault("groups", []).append({
        "id": gid, "name": req.name.strip(), "description": req.description.strip(),
        "routing_policy": req.routing_policy, "devices": []})
    save_settings(s)
    ok, err = apply_config(s, "group_create", _pre_settings=old_s)
    return {"ok": ok, "error": err or None, "id": gid}

@app.patch("/api/groups/{gid}")
async def update_group(gid: str, req: GroupUpdateReq, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    grp = next((g for g in s.get("groups", []) if g["id"] == gid), None)
    if not grp: raise HTTPException(404, "Group not found")
    if req.name is not None: grp["name"] = req.name.strip()[:64]
    if req.description is not None: grp["description"] = req.description.strip()[:256]
    if req.routing_policy is not None:
        if req.routing_policy not in _ft.GROUP_POLICIES:
            raise HTTPException(400, f"Invalid policy")
        grp["routing_policy"] = req.routing_policy
    save_settings(s)
    ok, err = apply_config(s, "group_update", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.delete("/api/groups/{gid}")
async def delete_group(gid: str, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    before = len(s.get("groups", []))
    s["groups"] = [g for g in s.get("groups", []) if g["id"] != gid]
    if len(s["groups"]) == before: raise HTTPException(404, "Group not found")
    save_settings(s)
    ok, err = apply_config(s, "group_delete", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.put("/api/groups/{gid}/devices")
async def set_group_devices(gid: str, req: GroupDevicesReq, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    grp = next((g for g in s.get("groups", []) if g["id"] == gid), None)
    if not grp: raise HTTPException(404, "Group not found")
    grp["devices"] = req.devices[:200]  # cap at 200 devices per group
    save_settings(s)
    ok, err = apply_config(s, "group_devices_change", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

# ── Subscriptions endpoints ───────────────────────────────────────────────────
@app.get("/api/subscriptions")
async def get_subscriptions(u: str = Depends(auth_dep)):
    s = load_settings()
    subs = []
    for sub in s.get("subscriptions", []):
        subs.append({**sub, "rule_count": _db.count_subscription_rules(sub["id"])})
    return {"subscriptions": subs}

@app.post("/api/subscriptions")
async def add_subscription(req: SubscriptionAddReq, u: str = Depends(auth_dep)):
    if req.type not in _ft.SUBSCRIPTION_TYPES:
        raise HTTPException(400, f"type must be one of {_ft.SUBSCRIPTION_TYPES}")
    # Validate URL
    try:
        p = urllib.parse.urlparse(req.url)
        if p.scheme not in ("http", "https"):
            raise ValueError
    except Exception:
        raise HTTPException(400, "Invalid URL")
    s = load_settings()
    sid = str(_uuid_mod.uuid4())
    s.setdefault("subscriptions", []).append({
        "id": sid, "name": req.name.strip()[:64], "url": req.url.strip(),
        "type": req.type, "enabled": req.enabled, "schedule": req.schedule,
        "last_update": None, "last_error": None})
    save_settings(s)
    return {"ok": True, "id": sid}

@app.patch("/api/subscriptions/{sid}")
async def update_subscription(sid: str, req: SubscriptionUpdateReq, u: str = Depends(auth_dep)):
    s = load_settings()
    sub = next((x for x in s.get("subscriptions", []) if x["id"] == sid), None)
    if not sub: raise HTTPException(404, "Subscription not found")
    if req.name     is not None: sub["name"]     = req.name.strip()[:64]
    if req.url      is not None: sub["url"]      = req.url.strip()
    if req.enabled  is not None: sub["enabled"]  = req.enabled
    if req.schedule is not None: sub["schedule"] = req.schedule
    save_settings(s)
    return {"ok": True}

@app.delete("/api/subscriptions/{sid}")
async def delete_subscription(sid: str, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    before = len(s.get("subscriptions", []))
    s["subscriptions"] = [x for x in s.get("subscriptions", []) if x["id"] != sid]
    if len(s["subscriptions"]) == before: raise HTTPException(404, "Not found")
    _db.delete_subscription_rules(sid)
    save_settings(s)
    ok, err = apply_config(s, "subscription_delete", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.post("/api/subscriptions/{sid}/update")
async def refresh_subscription(sid: str, u: str = Depends(auth_dep)):
    s = load_settings()
    sub = next((x for x in s.get("subscriptions", []) if x["id"] == sid), None)
    if not sub: raise HTTPException(404, "Not found")
    loop = asyncio.get_event_loop()
    try:
        text = await loop.run_in_executor(None, _ft.fetch_subscription, sub["url"])
        rules, errs = _ft.parse_subscription_content(text, sub.get("type","direct"))
        dry_run = {"add": len(rules), "remove": _db.count_subscription_rules(sid),
                   "parse_errors": errs}
    except Exception as e:
        # Update error state
        s2 = load_settings()
        for x in s2.get("subscriptions", []):
            if x["id"] == sid:
                x["last_error"] = str(e)[:200]
        save_settings(s2)
        return {"ok": False, "error": str(e)[:200]}

    # Apply
    _db.replace_subscription_rules(sid, rules)
    s2 = load_settings(); old_s = dict(s2)
    for x in s2.get("subscriptions", []):
        if x["id"] == sid:
            x["last_update"] = datetime.now(timezone.utc).isoformat()
            x["last_error"]  = None
    save_settings(s2)
    ok, err = apply_config(s2, "subscription_update", _pre_settings=old_s)
    return {"ok": ok, "error": err or None, "rule_count": len(rules),
            "dry_run": dry_run, "parse_errors": errs}

# ── Adblock endpoints ─────────────────────────────────────────────────────────
@app.get("/api/adblock")
async def get_adblock(u: str = Depends(auth_dep)):
    s = load_settings()
    cfg = s.get("adblock", DEFAULT_SETTINGS["adblock"])
    lines = _ft.build_adblock_dnsmasq_lines(s)
    return {**cfg, "total_blocked_domains": len(lines)}

@app.put("/api/adblock")
async def set_adblock(req: AdblockConfigReq, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    s["adblock"] = {"enabled": req.enabled, "use_starter_list": req.use_starter_list,
                    "custom_rules": req.custom_rules[:500],
                    "allowlist": req.allowlist[:200]}
    save_settings(s)
    ok, err = apply_dns_config(s.get("dns", {}), settings=s)
    if ok: ok2, err2 = apply_config(s, "adblock_change", _pre_settings=old_s)
    else:  ok2, err2 = ok, err
    return {"ok": ok and ok2, "error": (err or err2) or None}

@app.post("/api/adblock/test")
async def test_adblock_domain(req: RouteTestReq, u: str = Depends(auth_dep)):
    domain = req.target.strip()
    if not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
        raise HTTPException(400, "Invalid domain")
    s = load_settings()
    blocked, reason = _ft.is_domain_blocked(domain, s)
    return {"domain": domain, "blocked": blocked, "reason": reason}

# ── SOCKS proxy endpoints ─────────────────────────────────────────────────────
@app.get("/api/proxy")
async def get_proxy(u: str = Depends(auth_dep)):
    st = _proxy_state()
    st["mgmt_ip"] = _get_mgmt_ip()
    st["listening"] = False
    if st["enabled"]:
        try:
            r = subprocess.run(["ss", "-tlnH", "sport", "=", f":{st['port']}"],
                               capture_output=True, text=True)
            st["listening"] = bool(r.stdout.strip())
        except Exception:
            pass
    return st

@app.put("/api/proxy")
async def set_proxy(req: ProxyConfigReq, u: str = Depends(auth_dep)):
    ok, err = apply_proxy(req.enabled, req.port, req.restrict_to_home,
                          req.auth_enabled, req.username, req.password)
    if ok:
        s = load_settings()
        # mirror for export/record; password is NOT persisted here (lives in sing-box config)
        s["proxy"] = {"enabled": req.enabled, "port": int(req.port),
                      "restrict_to_home": req.restrict_to_home,
                      "auth": {"enabled": req.auth_enabled,
                               "username": req.username if req.auth_enabled else "",
                               "password": ""}}
        save_settings(s)
    return {"ok": ok, "error": err or None}

# ── AdGuard VPN egress endpoints ──────────────────────────────────────────────
_AGVPN = ["runuser", "-u", "agvpn", "--", "env", "HOME=/var/lib/agvpn", "adguardvpn-cli"]

def _adguard_status() -> dict:
    # The systemd-managed daemon isn't visible to a fresh `adguardvpn-cli status`
    # (separate session), so derive connectivity from the service + SOCKS listener.
    st = {"connected": False, "location": None}
    try:
        svc = subprocess.run(["systemctl", "is-active", "adguardvpn"],
                             capture_output=True, text=True).stdout.strip()
        lst = subprocess.run(["ss", "-tlnH", "sport", "=", ":1081"],
                             capture_output=True, text=True).stdout
        st["connected"] = (svc == "active" and bool(lst.strip()))
    except Exception:
        pass
    return st

def _set_adguard_location(loc: str) -> bool:
    """Persist the location in the systemd unit's ExecStart. Caller restarts the service."""
    loc = re.sub(r'[^A-Za-z ,.\-]', '', loc)[:64].strip()
    if not loc:
        return False
    unit = Path("/etc/systemd/system/adguardvpn.service")
    try:
        txt = unit.read_text()
        txt = re.sub(r'connect --(?:location "[^"]*"|fastest)', f'connect --location "{loc}"', txt)
        unit.write_text(txt)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        return True
    except Exception:
        return False

def _set_adguard_pq(on: bool) -> bool:
    """Set post-quantum crypto in the AdGuard CLI config. Takes effect on the next
    handshake, so the caller restarts the service to apply it."""
    try:
        r = subprocess.run(_AGVPN + ["config", "set-post-quantum", "on" if on else "off"],
                           capture_output=True, text=True, timeout=25)
        return r.returncode == 0
    except Exception:
        return False

@app.get("/api/adguard")
async def get_adguard(u: str = Depends(auth_dep)):
    s = load_settings()
    ag = s.get("adguard", DEFAULT_SETTINGS["adguard"])
    svc = subprocess.run(["systemctl", "is-active", "adguardvpn"],
                         capture_output=True, text=True).stdout.strip()
    st = _adguard_status()
    return {"enabled": ag.get("enabled", False), "socks_port": ag.get("socks_port", 1081),
            "location": ag.get("location"), "post_quantum": ag.get("post_quantum", False),
            "service": svc, "connected": st["connected"], "exit_location": st["location"]}

@app.get("/api/adguard/locations")
async def get_adguard_locations(u: str = Depends(auth_dep)):
    """Live ping estimates from the AdGuard CLI. Must run as the agvpn user: the session
    lives in its HOME, root has none (that is why adguardvpn-cli in the web terminal
    asks to log in)."""
    try:
        r = subprocess.run(_AGVPN + ["list-locations"], capture_output=True,
                           text=True, timeout=45)
    except Exception as e:
        return {"ok": False, "error": str(e), "locations": []}
    out = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout or "")
    locs = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("ISO"):
            continue
        parts = re.split(r"\s{2,}", line)
        if len(parts) < 4:
            continue
        try:
            ping = int(parts[3])
        except ValueError:
            continue
        locs.append({"iso": parts[0], "country": parts[1], "city": parts[2], "ping": ping})
    locs.sort(key=lambda x: x["ping"])
    ag = load_settings().get("adguard", {})
    return {"ok": True, "current": ag.get("location"), "count": len(locs), "locations": locs}

@app.put("/api/adguard")
async def set_adguard(req: AdguardReq, u: str = Depends(auth_dep)):
    s = load_settings(); old = dict(s)
    ag = s.setdefault("adguard", dict(DEFAULT_SETTINGS["adguard"]))
    pq_changed = (req.post_quantum is not None
                  and bool(req.post_quantum) != bool(ag.get("post_quantum", False)))
    ag["enabled"] = req.enabled
    if req.location:
        ag["location"] = req.location
    if req.post_quantum is not None:
        ag["post_quantum"] = bool(req.post_quantum)
    save_settings(s)
    restart = False
    if pq_changed:
        restart = _set_adguard_pq(bool(req.post_quantum)) or restart
    if req.location:
        restart = _set_adguard_location(req.location) or restart
    if restart:          # single reconnect applies both the new location and the PQ handshake
        subprocess.run(["systemctl", "restart", "adguardvpn"], capture_output=True)
    # regenerate xray.json: proxy outbound = socks->AdGuard when enabled, else the VPN key
    ok, err = apply_config(s, "adguard_egress", _pre_settings=old)
    return {"ok": ok, "error": err or None}

# ── Scheduler endpoints ───────────────────────────────────────────────────────
@app.get("/api/scheduler")
async def get_scheduler(u: str = Depends(auth_dep)):
    s = load_settings()
    tasks = []
    for t in s.get("scheduler_tasks", []):
        nxt = _ft.next_run_ts(t)
        history = _db.list_scheduler_history(t["id"], limit=1)
        tasks.append({**t, "next_run_ts": nxt, "recent": history[0] if history else None})
    return {"tasks": tasks}

@app.post("/api/scheduler")
async def create_task(req: SchedulerTaskCreateReq, u: str = Depends(auth_dep)):
    if req.type not in _ft.SCHEDULER_TASK_TYPES:
        raise HTTPException(400, f"type must be one of {_ft.SCHEDULER_TASK_TYPES}")
    s = load_settings()
    tid = str(_uuid_mod.uuid4())
    s.setdefault("scheduler_tasks", []).append({
        "id": tid, "name": req.name.strip()[:64],
        "type": req.type, "enabled": req.enabled,
        "schedule": req.schedule, "last_run_ts": 0,
        "last_result": "", "last_error": ""})
    save_settings(s)
    return {"ok": True, "id": tid}

@app.patch("/api/scheduler/{tid}")
async def update_task(tid: str, req: SchedulerTaskUpdateReq, u: str = Depends(auth_dep)):
    s = load_settings()
    task = next((t for t in s.get("scheduler_tasks", []) if t["id"] == tid), None)
    if not task: raise HTTPException(404, "Task not found")
    if req.name    is not None: task["name"]    = req.name.strip()[:64]
    if req.enabled is not None: task["enabled"] = req.enabled
    if req.schedule is not None: task["schedule"] = req.schedule
    save_settings(s); return {"ok": True}

@app.delete("/api/scheduler/{tid}")
async def delete_task(tid: str, u: str = Depends(auth_dep)):
    s = load_settings()
    before = len(s.get("scheduler_tasks", []))
    s["scheduler_tasks"] = [t for t in s.get("scheduler_tasks", []) if t["id"] != tid]
    if len(s["scheduler_tasks"]) == before: raise HTTPException(404, "Task not found")
    save_settings(s); return {"ok": True}

@app.post("/api/scheduler/{tid}/run")
async def run_task_now(tid: str, u: str = Depends(auth_dep)):
    s = load_settings()
    task = next((t for t in s.get("scheduler_tasks", []) if t["id"] == tid), None)
    if not task: raise HTTPException(404, "Task not found")
    start = time.time()
    result, detail = await _ft.run_scheduled_task(task, s)
    duration = time.time() - start
    _db.log_scheduler_run(tid, task.get("name","?"), duration, result, detail)
    return {"ok": result == "ok", "result": result, "detail": detail}

@app.get("/api/scheduler/{tid}/history")
async def get_task_history(tid: str, u: str = Depends(auth_dep)):
    return {"history": _db.list_scheduler_history(tid, limit=20)}

# ── Terminal settings endpoints ───────────────────────────────────────────────
@app.get("/api/terminal/settings")
async def get_terminal_settings(u: str = Depends(auth_dep)):
    s = load_settings()
    cfg = s.get("terminal", {"mode": "full", "allowlist_extra": []})
    return {**cfg, "builtin_allowlist": _ft.TERMINAL_BUILTIN_ALLOWLIST}

@app.put("/api/terminal/settings")
async def set_terminal_settings(req: TerminalSettingsReq, u: str = Depends(auth_dep)):
    if req.mode not in _ft.TERMINAL_MODES:
        raise HTTPException(400, f"mode must be one of {_ft.TERMINAL_MODES}")
    s = load_settings()
    s["terminal"] = {"mode": req.mode, "allowlist_extra": req.allowlist_extra[:100]}
    save_settings(s); return {"ok": True}

@app.get("/api/terminal/audit")
async def get_terminal_audit(u: str = Depends(auth_dep)):
    return {"sessions": _db.list_terminal_sessions(limit=50)}

# ── Analytics endpoints ───────────────────────────────────────────────────────
@app.get("/api/analytics/summary")
async def analytics_summary(hours: int = 24, u: str = Depends(auth_dep)):
    hours = max(1, min(hours, 168))  # 1h – 1 week
    loop  = asyncio.get_event_loop()
    data  = await loop.run_in_executor(None, _db.get_traffic_summary, hours)
    return data

@app.get("/api/analytics/series")
async def analytics_series(hours: int = 24, u: str = Depends(auth_dep)):
    hours = max(1, min(hours, 168))
    loop  = asyncio.get_event_loop()
    data  = await loop.run_in_executor(None, _db.get_hourly_series, hours)
    return {"series": data}

@app.get("/api/analytics/settings")
async def get_analytics_settings(u: str = Depends(auth_dep)):
    s = load_settings()
    return s.get("analytics", DEFAULT_SETTINGS["analytics"])

@app.put("/api/analytics/settings")
async def set_analytics_settings(req: AnalyticsSettingsReq, u: str = Depends(auth_dep)):
    if req.retention_days < 1 or req.retention_days > 365:
        raise HTTPException(400, "retention_days must be 1–365")
    s = load_settings()
    s["analytics"] = {"enabled": req.enabled, "retention_days": req.retention_days}
    save_settings(s); return {"ok": True}

# ── Update Center endpoints ───────────────────────────────────────────────────
@app.get("/api/updates/check")
async def check_updates(u: str = Depends(auth_dep)):
    loop = asyncio.get_event_loop()
    xray_ver = get_xray_core_version()
    xray_info, gw_info = await asyncio.gather(
        loop.run_in_executor(None, _ft.check_xray_update, xray_ver),
        loop.run_in_executor(None, _ft.check_gateway_update, VERSION),
    )
    # Cache result
    s = load_settings()
    s["update_cache"] = {"ts": int(time.time()), "xray": xray_info, "gateway": gw_info}
    save_settings(s)
    return {"xray": xray_info, "gateway": gw_info,
            "checked_at": datetime.now(timezone.utc).isoformat()}

@app.get("/api/updates/cached")
async def get_cached_updates(u: str = Depends(auth_dep)):
    s = load_settings()
    return s.get("update_cache", {})

@app.post("/api/updates/xray-core")
async def update_xray_core(u: str = Depends(auth_dep)):
    """Update xray-core binary. Requires explicit confirmation via ?confirm=1."""
    # This endpoint only performs the update — caller must confirm in UI
    s = load_settings()
    cached = s.get("update_cache", {}).get("xray", {})
    tag = cached.get("latest")
    if not tag:
        raise HTTPException(400, "Run /api/updates/check first")
    if not cached.get("update_available", False):
        return {"ok": True, "message": "Already up to date"}
    current_ver = get_xray_core_version()
    # Snapshot before update
    snap_id = create_snapshot("pre_xray_update")
    loop = asyncio.get_event_loop()
    ok, msg = await loop.run_in_executor(
        None, _ft.download_and_install_xray, f"v{tag}")
    if ok:
        subprocess.run(["systemctl", "restart", "xray-proxy"], capture_output=True)
        get_xray_core_version._cache = tag  # type: ignore[attr-defined]
        _db.log_update("xray-core", current_ver, tag, "ok", msg)
        return {"ok": True, "message": msg, "snapshot_id": snap_id}
    else:
        _db.log_update("xray-core", current_ver, tag, "error", msg)
        return {"ok": False, "error": msg, "snapshot_id": snap_id}

@app.get("/api/updates/history")
async def get_update_history(u: str = Depends(auth_dep)):
    return {"history": _db.list_update_history(limit=20)}

# ── Favicon ───────────────────────────────────────────────────────────────────
# Shield (blue) + two routing arrows (white → VPN, green ← Direct)
# Matches UI accent colors: --accent #6c8ef5, --green #34d399, --bg #0f1117
_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200">'
    '<rect width="200" height="200" rx="40" fill="#0f1117"/>'
    '<path d="M100 18L172 46L172 110C172 150 142 175 100 188C58 175 28 150 28 110L28 46Z"'
    ' fill="#6c8ef5"/>'
    '<path d="M100 18L172 46L172 76L28 76L28 46Z" fill="#ffffff" opacity="0.1"/>'
    '<line x1="54" y1="90" x2="130" y2="90" stroke="#ffffff" stroke-width="14"'
    ' stroke-linecap="round"/>'
    '<polyline points="116,76 132,90 116,104" stroke="#ffffff" stroke-width="14"'
    ' fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
    '<line x1="146" y1="128" x2="70" y2="128" stroke="#34d399" stroke-width="14"'
    ' stroke-linecap="round"/>'
    '<polyline points="84,114 68,128 84,142" stroke="#34d399" stroke-width="14"'
    ' fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
    '</svg>'
)

@app.get("/favicon.svg")
async def favicon_svg():
    return Response(_FAVICON_SVG, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})

@app.get("/favicon.ico")
async def favicon_ico():
    # Modern browsers accept SVG for .ico; serves the same asset
    return Response(_FAVICON_SVG, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})

# ── Static assets ──────────────────────────────────────────────────────────────
@app.get("/static/{path:path}")
async def serve_static(path: str):
    """Serve files from the static directory with a correct content type.

    Must stay ahead of the SPA catch-all below, which otherwise answers every
    /static/* request with index.html. That went unnoticed while index.html was
    the only asset; once the xterm bundles were vendored locally they came back
    as text/html, Terminal was never defined and the connect button did nothing.
    """
    root = STATIC.resolve()
    target = (root / path).resolve()
    if not str(target).startswith(str(root) + os.sep) or not target.is_file():
        raise HTTPException(404, "not found")
    media, _ = mimetypes.guess_type(target.name)
    return FileResponse(target, media_type=media or "application/octet-stream")


# ── SPA ────────────────────────────────────────────────────────────────────────
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    html_path = STATIC / "index.html"
    if html_path.exists(): return HTMLResponse(html_path.read_text())
    return HTMLResponse("<h1>UI not installed</h1>", 500)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=80, log_level="warning")
