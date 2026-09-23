"""
Shunt — P3 feature implementations.
Imported by main.py at startup. Keeps main.py manageable.
"""
import asyncio, hashlib, json, os, re, shutil, socket, subprocess, tempfile
import time, urllib.parse, urllib.request, uuid as _uuid_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Injected by main.py after import
BASE: Path = Path("/opt/shunt")
CFG_DIR: Path = BASE / "config"

import db as _db

VERSION = "1.6.0"

# ── TERMINAL ALLOWLIST ────────────────────────────────────────────────────────
TERMINAL_BUILTIN_ALLOWLIST: list[str] = [
    "systemctl status", "systemctl is-active", "systemctl is-failed",
    "journalctl", "journalctl -u", "journalctl --since",
    "ip route", "ip route show", "ip rule", "ip rule show",
    "ip neigh", "ip neigh show", "ip addr", "ip addr show",
    "iptables -L", "iptables -t", "iptables-save",
    "nft list",
    "dig", "nslookup", "host",
    "ping", "ping -c",
    "traceroute", "tracepath",
    "curl -s https://ipinfo.io", "curl -s http://ip.me",
    "df -h", "free -h", "uptime", "uname -a",
    "cat /proc/loadavg", "cat /proc/meminfo",
    "ls /opt/shunt",
    "cat /etc/dnsmasq.d/shunt.conf",
    "cat /opt/shunt/config/network.conf",
]

TERMINAL_MODES = ("disabled", "diagnostic", "allowlist", "full")


def terminal_command_allowed(cmd: str, mode: str, extra_allowlist: list[str]) -> tuple[bool, str]:
    """Check whether a command is allowed in the given terminal mode.
    Returns (allowed, reason)."""
    cmd = cmd.strip()
    if not cmd:
        return True, ""
    if mode == "disabled":
        return False, "Терминал отключён в настройках"
    if mode == "full":
        return True, ""
    if mode == "diagnostic":
        # Read-only system commands only: no writes, no pipes to sh
        dangerous = ("|", ">", ">>", "&&", ";", "$(", "`", "rm ", "mv ", "cp ",
                     "chmod", "chown", "systemctl start", "systemctl stop",
                     "systemctl restart", "systemctl enable", "systemctl disable",
                     "apt", "dpkg", "pip", "python", "bash", "sh ", "curl -X",
                     "wget", "nc ", "ncat", "socat")
        for d in dangerous:
            if d in cmd:
                return False, f"Режим диагностики: запрещён паттерн «{d}»"
        return True, ""
    # allowlist mode
    combined = TERMINAL_BUILTIN_ALLOWLIST + (extra_allowlist or [])
    for allowed in combined:
        if cmd == allowed or cmd.startswith(allowed + " "):
            return True, ""
    return False, f"Команда не в allowlist. Режим: {mode}"


# ── DEVICE GROUPS ─────────────────────────────────────────────────────────────
GROUP_POLICIES = ("inherit", "always_direct", "always_vpn",
                  "all_except_ru", "blocked_only")


def validate_group(g: dict, settings=None) -> list[str]:
    errors = []
    if not g.get("name", "").strip():
        errors.append("name is required")
    if len(g.get("name", "")) > 64:
        errors.append("name too long")
    if g.get("routing_policy", "inherit") not in (*GROUP_POLICIES, *__import__("profiles").ids(settings or {})):
        errors.append(f"routing_policy must be one of {GROUP_POLICIES}")
    return errors


def get_device_group(settings: dict, device_key: str) -> Optional[dict]:
    """Return the first group this device belongs to, or None."""
    for grp in settings.get("groups", []):
        if device_key in grp.get("devices", []):
            return grp
    return None


def build_group_policy_rules(settings: dict, final: str) -> list[dict]:
    """Generate xray source rules for groups (devices that have no explicit device policy)."""
    from main import _device_policy_rules, get_arp_table  # deferred import
    rules: list[dict] = []
    stored_devices = settings.get("devices", {})
    groups = settings.get("groups", [])
    if not groups:
        return []

    # Build MAC→IPs from ARP
    arp = get_arp_table()
    arp_by_key: dict[str, list[str]] = {}
    for entry in arp:
        key = entry["mac"] if entry["mac"] else f"ip:{entry['ips'][0]}"
        arp_by_key[key] = entry["ips"]

    for grp in groups:
        policy = grp.get("routing_policy", "inherit")
        if policy == "inherit":
            continue
        for dev_key in grp.get("devices", []):
            # Only apply group policy if device has no explicit override
            dev = stored_devices.get(dev_key, {})
            if dev.get("policy", "inherit") != "inherit":
                continue  # device has its own policy, skip
            ips = arp_by_key.get(dev_key, dev.get("ips", []))
            if not ips:
                continue
            rules.extend(_device_policy_rules(ips, policy, final, settings))
    return rules


# ── SUBSCRIPTIONS ─────────────────────────────────────────────────────────────
SUBSCRIPTION_TYPES = ("direct", "vpn", "block", "adblock", "malware")
MAX_SUB_RULES = 50_000

_SUB_LINE_RE = re.compile(
    r'^(?:(?:0\.0\.0\.0|127\.0\.0\.1)\s+)?'          # optional hosts-file prefix
    r'(?:\|\||@@\|\|)?'                                # optional adblock prefix/exception
    r'([a-zA-Z0-9*_.\-/:]+)'                           # domain, IP or network
    r'(?:\^|\|)?'                                      # optional adblock suffix
    r'(?:\s.*)?$'                                      # optional comment/rest
)


# Cloud providers publish the address space they own as JSON, not as a list, and
# the address space is the thing worth subscribing to. A throttle applied to a
# provider's networks catches every site that provider hosts -- on 2026-09-23 32
# of the 54 destinations measured broken on the direct path were Amazon's,
# none of them in any blocklist -- and no list of names keeps up with that. The
# two shapes recognised are the two in use:
#   AWS     {"prefixes": [{"ip_prefix": ..}], "ipv6_prefixes": [{"ipv6_prefix": ..}]}
#   Google  {"prefixes": [{"ipv4Prefix": ..} or {"ipv6Prefix": ..}]}
_RANGE_LISTS = ("prefixes", "ipv6_prefixes")
_RANGE_KEYS = ("ip_prefix", "ipv6_prefix", "ipv4Prefix", "ipv6Prefix")


def parse_ip_ranges_document(text: str) -> Optional[tuple[list[str], list[str]]]:
    """
    Networks from a published IP-range document, or None when `text` is not JSON.

    Any JSON object is answered here rather than handed to the line parser,
    which would report every line of it as an unparseable domain. The networks
    are collapsed: AWS lists ten thousand prefixes, many of them nested inside
    one another, which fold into under two thousand without changing a single
    routing decision.
    """
    import ipaddress as _ip
    body = text.lstrip()
    if not body.startswith("{"):
        return None
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    if not isinstance(doc, dict) or not any(k in doc for k in _RANGE_LISTS):
        return [], ["JSON document is not a published IP-range list"]
    nets, errors = [], []
    for list_key in _RANGE_LISTS:
        for entry in doc.get(list_key) or []:
            if not isinstance(entry, dict):
                continue
            for key in _RANGE_KEYS:
                raw = entry.get(key)
                if not isinstance(raw, str):
                    continue
                try:
                    nets.append(_ip.ip_network(raw, strict=False))
                except ValueError:
                    if len(errors) < 5:
                        errors.append(f"invalid prefix «{raw[:60]}»")
    if not nets:
        return [], errors or ["no network prefixes in the document"]
    rules = [str(n) for version in (4, 6)
             for n in _ip.collapse_addresses(n for n in nets if n.version == version)]
    if len(rules) > MAX_SUB_RULES:
        errors.append(f"Truncated at {MAX_SUB_RULES} rules")
        rules = rules[:MAX_SUB_RULES]
    return rules, errors


def parse_subscription_content(text: str, sub_type: str) -> tuple[list[str], list[str]]:
    """Parse a subscription file. Returns (valid_rules, errors)."""
    ranges = parse_ip_ranges_document(text)
    if ranges is not None:
        return ranges
    rules: list[str] = []
    errors: list[str] = []
    for i, raw in enumerate(text.splitlines()):
        line = raw.strip()
        if not line or line.startswith(("#", "!", "[")):
            continue
        m = _SUB_LINE_RE.match(line)
        if not m:
            if len(errors) < 5:
                errors.append(f"line {i+1}: cannot parse «{line[:60]}»")
            continue
        val = m.group(1).strip("*").strip(".")
        if not val or len(val) > 253:
            continue
        # Validate: domain or IP
        try:
            import ipaddress as _ip
            _ip.ip_network(val, strict=False)
            rules.append(val)
            continue
        except ValueError:
            pass
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$', val):
            rules.append(val)
        elif len(errors) < 5:
            errors.append(f"line {i+1}: invalid value «{val}»")
        if len(rules) >= MAX_SUB_RULES:
            errors.append(f"Truncated at {MAX_SUB_RULES} rules")
            break
    return rules, errors


def fetch_subscription(url: str, timeout: int = 30) -> str:
    """Fetch subscription URL. Returns raw text content."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "shunt/1.6.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(8 * 1024 * 1024)  # 8 MB max
    # detect encoding
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


def subscription_rules_to_xray(sub_id: str, sub_type: str, outbound: str) -> list[dict]:
    """Convert stored subscription rules to xray routing rule entries."""
    rules = _db.get_subscription_rules(sub_id)
    if not rules:
        return []
    domain_vals: list[str] = []
    ip_vals: list[str] = []
    for r in rules:
        try:
            import ipaddress as _ip
            _ip.ip_network(r, strict=False)
            ip_vals.append(r)
        except ValueError:
            domain_vals.append(f"domain:{r}")
    result = []
    if domain_vals:
        # Split into chunks of 500 to avoid huge single rule
        chunk = 500
        for i in range(0, len(domain_vals), chunk):
            result.append({"type": "field",
                            "domain": domain_vals[i:i+chunk],
                            "outboundTag": outbound})
    if ip_vals:
        chunk = 500
        for i in range(0, len(ip_vals), chunk):
            result.append({"type": "field",
                            "ip": ip_vals[i:i+chunk],
                            "outboundTag": outbound})
    return result


# ── ADBLOCK DNS ───────────────────────────────────────────────────────────────
# Starter blocklist (minimal, safe)
STARTER_BLOCKLIST: list[str] = [
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    "ads.google.com", "adservice.google.com",
    "pagead2.googlesyndication.com", "tpc.googlesyndication.com",
    "yt3.ggpht.com",
    "amazon-adsystem.com", "advertising.amazon.com",
    "pixel.facebook.com", "an.facebook.com",
    "adsystem.servebom.com",
    "metric.gstatic.com",
]

# Domains that must never be blocked (gateway updates, etc.)
CRITICAL_DOMAINS: set[str] = {
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "api.github.com",
    "runetfreedom", "github.io",
    "xtls.github.io",
}


def build_adblock_dnsmasq_lines(settings: dict) -> list[str]:
    """Return dnsmasq address=// lines for all blocked domains."""
    adblock_cfg = settings.get("adblock", {})
    if not adblock_cfg.get("enabled", False):
        return []
    allowlist: set[str] = set(adblock_cfg.get("allowlist", []))
    blocked: set[str] = set()

    # Starter list
    if adblock_cfg.get("use_starter_list", True):
        blocked.update(STARTER_BLOCKLIST)

    # Custom user rules
    blocked.update(adblock_cfg.get("custom_rules", []))

    # Subscription adblock/malware rules
    for sub in settings.get("subscriptions", []):
        if sub.get("enabled") and sub.get("type") in ("adblock", "malware"):
            blocked.update(_db.get_subscription_rules(sub["id"]))

    # Remove allowlisted and critical
    blocked -= allowlist
    blocked = {d for d in blocked if not any(c in d for c in CRITICAL_DOMAINS)}

    return [f"address=/{d}/#" for d in sorted(blocked)]


def is_domain_blocked(domain: str, settings: dict) -> tuple[bool, str]:
    """Check if a domain would be blocked. Returns (blocked, reason)."""
    adblock_cfg = settings.get("adblock", {})
    if not adblock_cfg.get("enabled", False):
        return False, "adblock disabled"
    domain = domain.lower().rstrip(".")
    allowlist = set(adblock_cfg.get("allowlist", []))
    # Check allowlist first
    for a in allowlist:
        if domain == a or domain.endswith("." + a):
            return False, f"in allowlist: {a}"
    # Check critical
    for c in CRITICAL_DOMAINS:
        if c in domain:
            return False, f"critical domain: {c}"
    # Check starter list
    if adblock_cfg.get("use_starter_list", True):
        for b in STARTER_BLOCKLIST:
            if domain == b or domain.endswith("." + b):
                return True, f"starter-list: {b}"
    # Check custom rules
    for r in adblock_cfg.get("custom_rules", []):
        if domain == r or domain.endswith("." + r):
            return True, f"custom-rule: {r}"
    # Check subscription rules
    for sub in settings.get("subscriptions", []):
        if sub.get("enabled") and sub.get("type") in ("adblock", "malware"):
            rules = _db.get_subscription_rules(sub["id"])
            for r in rules:
                if domain == r or domain.endswith("." + r):
                    return True, f"subscription:{sub.get('name','?')}: {r}"
    return False, "not blocked"


# ── SCHEDULER ─────────────────────────────────────────────────────────────────
_HAS_CRONITER = False
try:
    import croniter as _cron_lib  # type: ignore
    _HAS_CRONITER = True
except ImportError:
    pass


def _simple_next(schedule: str) -> Optional[float]:
    """Return next run timestamp from cron expression or simple interval."""
    now = time.time()
    # Simple patterns: @hourly @daily @weekly
    simple = {"@hourly": 3600, "@daily": 86400, "@weekly": 604800,
               "@monthly": 2592000}
    if schedule in simple:
        return now + simple[schedule]
    if _HAS_CRONITER:
        try:
            c = _cron_lib.croniter(schedule, now)
            return c.get_next(float)
        except Exception:
            pass
    return None


def next_run_ts(task: dict) -> Optional[float]:
    return _simple_next(task.get("schedule", "@daily"))


def should_run_now(task: dict) -> bool:
    if not task.get("enabled", True):
        return False
    last = task.get("last_run_ts", 0)
    nxt = _simple_next(task.get("schedule", "@daily"))
    if nxt is None:
        return False
    interval = nxt - time.time()
    # Run if we haven't run in (interval) seconds since last run
    if last == 0:
        return True  # never ran → run now
    # Calculate interval from schedule
    s = task.get("schedule", "@daily")
    simple = {"@hourly": 3600, "@daily": 86400, "@weekly": 604800,
               "@monthly": 2592000}
    period = simple.get(s, 86400)
    return (time.time() - last) >= period


SCHEDULER_TASK_TYPES = (
    "geo_update", "backup", "subscription_update",
    "health_check", "log_rotate", "block_probe",
)


async def run_scheduled_task(task: dict, settings: dict) -> tuple[str, str]:
    """Execute a scheduler task. Returns (result, detail)."""
    t = task.get("type", "")
    loop = asyncio.get_event_loop()
    try:
        if t == "geo_update":
            r = await loop.run_in_executor(None, _task_geo_update)
            return r
        if t == "backup":
            r = await loop.run_in_executor(None, _task_backup)
            return r
        if t == "subscription_update":
            r = await loop.run_in_executor(None, _task_sub_update, settings)
            return r
        if t == "health_check":
            r = await loop.run_in_executor(None, _task_health_check)
            return r
        if t == "log_rotate":
            r = await loop.run_in_executor(None, _task_log_rotate)
            return r
        if t == "block_probe":
            r = await loop.run_in_executor(None, _task_block_probe)
            return r
        return "error", f"unknown task type: {t}"
    except Exception as e:
        return "error", str(e)[:200]


def _probe_paths(settings: dict) -> tuple[str, str]:
    """
    The two paths a probe compares: (wan interface, socks endpoint).

    The direct one is bound to the WAN port rather than left to routing,
    because routing is the thing under test -- asking the gateway to reach a
    host "normally" would send the probe through whatever rule already exists
    and answer a question nobody asked.
    """
    wan = ""
    try:
        for line in (BASE / "config" / "network.conf").read_text().splitlines():
            if line.startswith("WAN_IF="):
                wan = line.split("=", 1)[1].strip()
    except OSError:
        pass
    import main as _main
    outbounds, _, _ = _main._get_active_vpn_outbound(settings)
    proxy = next((ob for ob in outbounds if ob.get("tag") == "proxy"), {})
    socks = ""
    if proxy.get("protocol") == "socks":
        servers = proxy.get("settings", {}).get("servers", [])
        if servers:
            server = servers[0]
            host = server["address"]
            socks = "%s:%s" % ("[" + host + "]" if ":" in host else host, server["port"])
    return wan, socks


def _task_block_probe() -> tuple[str, str]:
    """
    Compare both paths for the domains the household uses, and route what only
    works through the tunnel.

    The lists this gateway routes by will always lag -- claude.ai was on them
    and anthropic.com was not, so the API answered 403 while the web interface
    worked. This closes that gap by measuring rather than by waiting for
    somebody upstream to notice.
    """
    import main as _main       # deferred, as everywhere else in this file
    import blockprobe as _bp
    import db as _db

    settings = _main.load_settings()
    cfg = settings.get("probe", {}) or {}
    if not cfg.get("enabled", True):
        return "ok", "проверка выключена"

    wan, socks = _probe_paths(settings)
    if not wan:
        return "error", "не определён WAN-порт: некуда направить прямую пробу"

    if not socks:
        return "error", "выбранный выход не предоставляет SOCKS-путь для проверки"

    known = settings.get("discovered", [])
    before = set(_bp.routed_domains(known) + _bp.routed_addresses(known))
    # A pool, not a shortlist: `blockprobe.candidates` ranks it further and takes
    # forty. 470 of the 500 busiest destinations on this gateway are bare
    # addresses, so a cut at 500 left only thirty names to choose from -- enough
    # today, and one bad week of address traffic away from leaving none.
    hosts = _db.top_hosts(hours=int(cfg.get("window_hours", 168)),
                          limit=int(cfg.get("pool", 2000)))

    record, counts = _bp.run_once(
        hosts, known,
        _bp.curl_runner(interface=wan),
        _bp.curl_runner(via_socks=socks),
        limit=int(cfg.get("limit", 40)),
        min_streak=int(cfg.get("min_streak", 2)),
        timeout=int(cfg.get("timeout", 12)))

    fresh = _main.load_settings()
    fresh["discovered"] = record
    _main.save_settings(fresh)

    after = set(_bp.routed_domains(record) + _bp.routed_addresses(record))
    detail = ("проверено %d: заблокировано %d, доступно %d, нет ответа на обоих путях %d"
              % (sum(counts.values()), counts.get("blocked", 0),
                 counts.get("open", 0), counts.get("down", 0)))
    if after != before:
        # Only when the routing actually changes. A run that confirms what was
        # already true must not restart the datapath a household is using.
        ok, err = _main.apply_config(fresh, "block_probe")
        added = sorted(after - before); gone = sorted(before - after)
        detail += "; в туннель: %s; обратно напрямую: %s" % (
            ", ".join(added) or "—", ", ".join(gone) or "—")
        if not ok:
            return "error", detail + "; применение не удалось: " + err
    return "ok", detail


def _task_geo_update() -> tuple[str, str]:
    script = BASE / "scripts" / "update-geo.sh"
    r = subprocess.run([str(script)], capture_output=True, text=True, timeout=1800)
    if r.returncode == 0:
        if "UNCHANGED:" not in r.stdout:
            subprocess.run(["systemctl", "restart", "shunt"], capture_output=True)
        return "ok", "geo databases unchanged" if "UNCHANGED:" in r.stdout else "geo databases updated"
    return "error", r.stderr[:200]


def _task_backup() -> tuple[str, str]:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = BASE / "config" / "backups" / f"auto_backup_{ts}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    import main as _main  # deferred
    settings = _main.load_settings()
    # Mask secrets in backup metadata (but keep in file for restore)
    out.write_text(json.dumps(settings, indent=2))
    # Keep last 10 auto backups
    backups = sorted(out.parent.glob("auto_backup_*.json"))
    for old in backups[:-10]:
        try:
            old.unlink()
        except Exception:
            pass
    return "ok", f"backup saved: {out.name}"


def _task_sub_update(settings: dict) -> tuple[str, str]:
    """
    Refresh every enabled subscription and put the result in front of xray.

    This used to stop at the database. The new rules were stored and nothing
    rebuilt the config, so a scheduled refresh reached the datapath only when
    some unrelated change next applied one -- a subscription could run a week
    behind its own schedule without saying so. It also stored whatever arrived,
    and for a fetch that got an error page or an empty body that meant routing
    silently lost the whole list.

    Now an empty result is refused and the previous rules are kept, stored
    rules are replaced only when they differ, and the config is rebuilt once,
    at the end, only if something changed: rebuilding restarts xray and drops
    every connection in the house, which a refresh that changed nothing has no
    business doing.
    """
    import main as _main  # deferred

    changed, unchanged, errors = [], 0, []
    outcome: dict[str, tuple[Optional[str], Optional[str]]] = {}
    for sub in settings.get("subscriptions", []):
        if not sub.get("enabled"):
            continue
        name = sub.get("name", "?")
        try:
            text = fetch_subscription(sub["url"])
            rules, errs = parse_subscription_content(text, sub.get("type", "direct"))
        except Exception as e:
            errors.append(f"{name}: {e}")
            outcome[sub["id"]] = (None, str(e)[:200])
            continue
        if not rules:
            why = "empty result, previous rules kept" + (f": {errs[0]}" if errs else "")
            errors.append(f"{name}: {why}")
            outcome[sub["id"]] = (None, why[:200])
            continue
        if set(rules) != set(_db.get_subscription_rules(sub["id"])):
            _db.replace_subscription_rules(sub["id"], rules)
            changed.append(name)
        else:
            unchanged += 1
        outcome[sub["id"]] = (datetime.now(timezone.utc).isoformat(), None)

    fresh = _main.load_settings()
    for sub in fresh.get("subscriptions", []):
        if sub.get("id") in outcome:
            done, err = outcome[sub["id"]]
            if done:
                sub["last_update"] = done
            sub["last_error"] = err
    _main.save_settings(fresh)

    detail = "changed: %s; unchanged: %d" % (", ".join(changed) or "—", unchanged)
    if changed:
        ok, err = _main.apply_config(fresh, "subscription_update")
        if not ok:
            errors.append("apply failed: " + (err or "?"))
    if errors:
        return "error", detail + "; errors: " + "; ".join(errors[:3])
    return "ok", detail


def _task_health_check() -> tuple[str, str]:
    results = []
    # shunt
    r = subprocess.run(["systemctl", "is-active", "shunt"],
                       capture_output=True, text=True)
    results.append(f"shunt={r.stdout.strip()}")
    # dnsmasq
    r = subprocess.run(["systemctl", "is-active", "dnsmasq"],
                       capture_output=True, text=True)
    results.append(f"dnsmasq={r.stdout.strip()}")
    return "ok", ", ".join(results)


def _task_log_rotate() -> tuple[str, str]:
    log = BASE / "logs" / "access.log"
    if not log.exists():
        return "ok", "no log file"
    size = log.stat().st_size
    if size > 50 * 1024 * 1024:  # 50 MB
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        rotated = log.parent / f"access.{ts}.log"
        log.rename(rotated)
        # Keep last 3 rotated logs
        old_logs = sorted(log.parent.glob("access.*.log"))
        for o in old_logs[:-3]:
            try:
                o.unlink()
            except Exception:
                pass
        return "ok", f"rotated {size // 1024} KB → {rotated.name}"
    return "skip", f"log size {size // 1024} KB < 50 MB threshold"


# ── UPDATE CENTER ─────────────────────────────────────────────────────────────
XRAY_RELEASES_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
GW_RELEASES_API   = "https://api.github.com/repos/bkaganovich-stack/shunt/releases/latest"


def _github_latest(api_url: str, timeout: int = 10) -> dict:
    req = urllib.request.Request(
        api_url,
        headers={"User-Agent": "shunt/1.6.0",
                 "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def check_xray_update(current_ver: str) -> dict:
    try:
        data = _github_latest(XRAY_RELEASES_API)
        latest = data.get("tag_name", "?").lstrip("v")
        body   = data.get("body", "")[:800]
        url    = data.get("html_url", "")
        assets = data.get("assets", [])
        return {"current": current_ver, "latest": latest,
                "update_available": latest != current_ver,
                "release_notes": body, "release_url": url,
                "assets": [{"name": a["name"], "url": a["browser_download_url"]}
                           for a in assets]}
    except Exception as e:
        return {"current": current_ver, "latest": None,
                "update_available": False, "error": str(e)}


def check_gateway_update(current_ver: str) -> dict:
    try:
        data = _github_latest(GW_RELEASES_API)
        latest = data.get("tag_name", "?").lstrip("v")
        body   = data.get("body", "")[:800]
        url    = data.get("html_url", "")
        return {"current": current_ver, "latest": latest,
                "update_available": latest != current_ver,
                "release_notes": body, "release_url": url}
    except Exception as e:
        return {"current": current_ver, "latest": None,
                "update_available": False, "error": str(e)}


def _arch_to_xray() -> str:
    import platform
    m = platform.machine()
    return {"x86_64": "64", "aarch64": "arm64-v8a", "armv7l": "arm32-v7a"}.get(m, "64")


def download_and_install_xray(tag: str) -> tuple[bool, str]:
    """Download xray binary for tag, verify, replace. Returns (ok, msg)."""
    arch  = _arch_to_xray()
    url   = (f"https://github.com/XTLS/Xray-core/releases/download/"
             f"{tag}/Xray-linux-{arch}.zip")
    xray_bin = BASE / "bin" / "xray"
    with tempfile.TemporaryDirectory() as td:
        tdp  = Path(td)
        zf   = tdp / "xray.zip"
        try:
            urllib.request.urlretrieve(url, str(zf))
        except Exception as e:
            return False, f"download failed: {e}"
        # unzip
        r = subprocess.run(["unzip", "-q", str(zf), "-d", str(tdp)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return False, f"unzip failed: {r.stderr[:100]}"
        new_bin = tdp / "xray"
        if not new_bin.exists():
            return False, "xray binary not found in zip"
        # smoke test
        rv = subprocess.run([str(new_bin), "version"],
                            capture_output=True, text=True, timeout=5)
        if rv.returncode != 0:
            return False, "new binary failed version check"
        # backup old
        if xray_bin.exists():
            shutil.copy2(str(xray_bin), str(xray_bin) + ".prev")
        shutil.copy2(str(new_bin), str(xray_bin))
        os.chmod(str(xray_bin), 0o755)
        return True, f"installed {tag}"


# ── ANALYTICS BACKGROUND TASK ─────────────────────────────────────────────────
_ACCESS_LOG_RE = re.compile(
    r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}):\d{2}"   # ts up to hour+min
    r".*?"
    r"(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\s+accepted\s+"
    r"(\w+):(.+):(\d+)\s+\[([^\]]+)\]"
)


_INITIAL_LOOKBACK = 10 * 1024 * 1024   # 10 MB — enough for ~24h of typical traffic
_READ_CHUNK       =  4 * 1024 * 1024   # 4 MB per iteration

def ingest_access_log(log_path: Path, retention_days: int = 30) -> int:
    """Parse new lines from access.log since last checkpoint. Returns lines ingested.

    On first run (offset=0) we skip to the last _INITIAL_LOOKBACK bytes so
    recent data appears in analytics immediately, without replaying the entire
    multi-hundred-MB history.
    """
    if not log_path.exists():
        return 0
    current_size = log_path.stat().st_size
    saved_offset, saved_size = _db.get_log_checkpoint()

    # File rotated (current size < last known size) → reset to beginning
    if current_size < saved_size:
        saved_offset = 0

    # First run (offset==0): jump near the end so recent data is available fast.
    # We skip to max(0, current_size - INITIAL_LOOKBACK).
    if saved_offset == 0 and current_size > _INITIAL_LOOKBACK:
        saved_offset = current_size - _INITIAL_LOOKBACK
        # Align to next newline to avoid splitting a log entry
        with open(str(log_path), "rb") as f:
            f.seek(saved_offset)
            nl = f.read(512).find(b"\n")
            if nl >= 0:
                saved_offset += nl + 1

    if saved_offset >= current_size:
        return 0

    # The names the resolver saw, for the addresses the log recorded. Loaded
    # once per run rather than per line: this reads a file on tmpfs that the
    # DoH proxy rewrites every thirty seconds, and a miss simply leaves the
    # address in place. See dnsnames.py for why the log has no names of its own.
    try:
        import dnsnames as _dn
        names = _dn.NameMap.load()
    except Exception:
        _dn, names = None, None

    count = 0
    with open(str(log_path), "rb") as f:
        f.seek(saved_offset)
        data = f.read(_READ_CHUNK)

    new_offset = saved_offset + len(data)
    text = data.decode("utf-8", errors="replace")

    batch: dict = {}
    for m in _ACCESS_LOG_RE.finditer(text):
        ts_str = m.group(1)   # "2026/06/01 14"
        src_ip = m.group(2)
        proto  = m.group(3).upper()
        dst    = m.group(4)
        route  = m.group(6)
        outb   = route.split(" -> ")[-1].strip() if " -> " in route else route.strip()
        # hour key: "2026-06-01 14"
        hour = ts_str.replace("/", "-").replace("/", "-")[:13]
        # dst: strip IPv6 brackets
        dst = dst.strip("[]")
        if names is not None:
            dst = _dn.name_for(dst, names)
        # limit dst length
        dst = dst[:100]
        key = (hour, src_ip, dst, outb, proto)
        batch[key] = batch.get(key, 0) + 1
        count += 1

    if batch:
        entries = [(hour, src, dst, ob, pr, n)
                   for (hour, src, dst, ob, pr), n in batch.items()]
        _db.upsert_traffic_batch(entries)

    _db.set_log_checkpoint(new_offset, current_size)

    # Periodic purge
    if count > 0 and retention_days > 0:
        _db.purge_old_traffic(retention_days)

    return count
