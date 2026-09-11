#!/usr/bin/env python3
"""Continuous health monitor + auto-fix for the shunt.

Runs as a systemd daemon (internal 60s loop, Restart=always). Topology-aware.
Every cycle it validates the datapath and self-heals known failure modes, with
hysteresis (needs K consecutive failures before a disruptive action) so it
never flaps. Every action is logged to logs/health.log.

What it guards (the failure modes seen in production):
  * a core service died                       -> restart it
  * TPROXY fwmark rule / chain vanished        -> re-run iptables.sh up
    (the 2026-06-10 networkd incident class)
  * sing-box policy rules (table 2022) gone    -> restart sing-box
  * LAN interface lost its IP / default route  -> netplan apply
  * INLINE WAN went dead after a switch        -> auto-revert to known-good loop
    (the missing post-switch safety net that stranded the box)
  * disk filling up                            -> prune old backups/logs

It intentionally does NOTHING while a topology switch (xray-topology.service)
is running, to avoid fighting it.
"""
import json, re, socket, subprocess, sys, time
from pathlib import Path

BASE        = Path("/opt/shunt")
sys.path.insert(0, str(Path(__file__).resolve().parent))
import diagnose as dg  # noqa: E402
import provider as pv  # noqa: E402
CFG         = BASE / "config"
NET_CONF    = CFG / "network.conf"
STATE_FILE  = CFG / "health-state.json"
LOG         = BASE / "logs" / "health.log"
IPTABLES_SH = BASE / "scripts" / "iptables.sh"
APPLY_TOPO  = BASE / "scripts" / "apply_topology.py"
MGMT_AP     = BASE / "scripts" / "mgmt_ap.sh"
AP_IP       = "192.168.99.1"

INTERVAL        = 60     # seconds between cycles
WAN_FAIL_LIMIT  = 10**9   # inline static: never auto-revert to loop
LOOP_ROUTER     = "192.168.50.1"   # upstream router, loop topology only
LOOP_IP         = "192.168.50.2"
LEASES          = Path("/var/lib/misc/dnsmasq.leases")
NETIF_LEASES    = Path("/run/systemd/netif/leases")
WAN_CHANGES     = BASE / "logs" / "wan-changes.json"
WAN_CURRENT     = BASE / "logs" / "wan-current.json"
DIAGNOSIS       = BASE / "logs" / "diagnosis.json"
PROVIDER        = BASE / "logs" / "provider.json"
ATTENTION       = BASE / "logs" / "attention.json"
ATTENTION_MAX   = 20
WAN_CHANGES_MAX = 50
SHORT_LEASE_SEC = 30 * 60
SERVICES        = ["shunt", "shunt-web", "dnsmasq", "sing-box"]
DISK_PRUNE_PCT  = 90
ACCESS_LOG      = BASE / "logs" / "access.log"
ACCESS_MAX      = 200 * 1024 * 1024   # bytes (actual blocks) before rotation

def log(msg: str) -> None:
    line = f"{time.strftime('%F %T')} {msg}"
    try:
        with LOG.open("a") as f:
            f.write(line + "\n")
    except OSError:
        pass
    print(line, flush=True)

def run(*cmd, timeout=20):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        class R: returncode = 1; stdout = ""; stderr = str(e)
        return R()

def net_conf() -> dict:
    out = {}
    try:
        for ln in NET_CONF.read_text().splitlines():
            if "=" in ln and not ln.lstrip().startswith("#"):
                k, v = ln.split("=", 1); out[k.strip()] = v.strip()
    except OSError:
        pass
    return out

def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}

def save_state(s: dict) -> None:
    try:
        STATE_FILE.write_text(json.dumps(s))
    except OSError:
        pass

# ── primitive checks ──────────────────────────────────────────────────────────
def svc_active(s: str) -> bool:
    return run("systemctl", "is-active", s).stdout.strip() == "active"

def iface_ipv4(iface: str):
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", run("ip", "-4", "addr", "show", iface).stdout)
    return m.group(1) if m else None

def carrier(iface: str) -> bool:
    try:
        return (Path(f"/sys/class/net/{iface}/carrier").read_text().strip() == "1")
    except OSError:
        return False

def ping(host: str) -> bool:
    """
    Reaches a neighbour on a local segment. NOT a test of internet access --
    see reaches_internet() for why.
    """
    return subprocess.run(["ping", "-c", "1", "-W", "2", host], capture_output=True).returncode == 0

# Packets carrying this mark are returned from the TPROXY chains and from the
# tunnel's own routing rules, so a socket that sets it leaves through the WAN
# the way an ordinary host's would.
BYPASS_MARK = 0xff
# SO_MARK is Linux-only and absent from the socket module on other platforms,
# where the tests run. 36 is its value on every Linux architecture.
SO_MARK = getattr(socket, "SO_MARK", 36)

def reaches_internet(timeout: float = 4.0) -> bool:
    """
    True when a packet actually reaches the internet and something answers.

    Emphatically not ping. On this gateway the tunnel's tun device answers ICMP
    echo itself: `ping 192.0.2.1` -- a documentation address nobody on earth
    replies to -- succeeds, and so does every other address. The WAN check here
    used to be `ping 1.1.1.1`, which therefore could not fail, in either
    direction: it reported a healthy WAN through a whole outage, and it would
    have reported one with the cable out.

    So: a real TCP handshake, on a socket marked to bypass the interception,
    against two operators who are unlikely to be down together.
    """
    for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, SO_MARK, BYPASS_MARK)
            s.settimeout(timeout)
            s.connect((host, port))
            return True
        except OSError:
            continue
        finally:
            try:
                s.close()
            except OSError:
                pass
    return False

def neighbour_to_watch(topo: str, lan: str | None) -> str | None:
    """
    The neighbour worth pinging, derived rather than assumed.

    This used to be the constant 192.168.50.1 -- the upstream router in the loop
    topology. After the move to inline that address stopped being ours to reach,
    and the check logged "router unreachable" every single minute for days. A
    warning that is always true carries no information, and it buried the ones
    that did: during the last incident this line ran alongside the real failure
    and neither stood out.

    Inline: our downstream neighbour is whoever took a lease from our own DHCP.
    Loop:   it is the upstream router, where it has always been.
    Neither available: return None and skip the check, rather than warn about an
    address nobody expects to answer.
    """
    if topo != "inline":
        return LOOP_ROUTER
    prefix = ".".join(lan.split(".")[:3]) + "." if lan else None
    newest, newest_exp = None, -1
    try:
        for ln in LEASES.read_text().splitlines():
            f = ln.split()
            if len(f) < 3:
                continue
            exp, ip = f[0], f[2]
            if prefix and not ip.startswith(prefix):
                continue
            try:
                exp = int(exp)
            except ValueError:
                continue
            if exp > newest_exp:
                newest, newest_exp = ip, exp
    except OSError:
        return None
    return newest

def iface_cidr(iface: str):
    """Address with its prefix length -- the prefix matters as much as the
    address, because a provider that moves you between /16 and /19 has moved
    you between different pieces of its network, not just renumbered you."""
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)",
                  run("ip", "-4", "-o", "addr", "show", iface).stdout)
    return m.group(1) if m else None

def parse_duration(v: str):
    """systemd writes leases as '10min', '8min 45s', '1h 30min'. Returns seconds."""
    total, seen = 0, False
    for num, unit in re.findall(r"(\d+)\s*(usec|msec|min|h|m|s)?", v):
        if not num:
            continue
        seen = True
        total += int(num) * {"h": 3600, "min": 60, "m": 60, "s": 1,
                             "msec": 0, "usec": 0, "": 1}[unit]
    return total if seen else None

def lease_lifetime(iface: str):
    """How long the provider's lease lasts, or None when it cannot be read."""
    try:
        idx = Path(f"/sys/class/net/{iface}/ifindex").read_text().strip()
        for ln in (NETIF_LEASES / idx).read_text().splitlines():
            if ln.startswith("LIFETIME="):
                return parse_duration(ln.split("=", 1)[1].strip())
    except OSError:
        return None
    return None

def lease_issuer(iface: str) -> dict:
    """Which DHCP server handed out the current lease, and which gateway it named."""
    try:
        idx = Path(f"/sys/class/net/{iface}/ifindex").read_text().strip()
        out = {}
        for ln in (NETIF_LEASES / idx).read_text().splitlines():
            if ln.startswith("SERVER_ADDRESS="):
                out["server"] = ln.split("=", 1)[1].strip()
            elif ln.startswith("ROUTER="):
                out["gateway"] = ln.split("=", 1)[1].strip()
        return out
    except OSError:
        return {}

def note_wan_address(state: dict, wan: str) -> dict:
    """
    Say out loud when the ground moves.

    A changed WAN address resets every connection through the gateway at once --
    every call drops, every download restarts. The box knew this each time and
    said nothing, so the only visible evidence was a household asking why the
    video froze. On a provider handing out ten-minute leases this is not a rare
    event to file away; it is the first thing to check.
    """
    cur = iface_cidr(wan)
    if not cur:
        return state
    prev = state.get("wan_cidr")
    if prev and prev != cur:
        old_net = prev.split("/")[1]
        new_net = cur.split("/")[1]
        extra = "" if old_net == new_net else f" (и размер сети: /{old_net} → /{new_net})"
        log(f"WAN address changed {prev} → {cur}{extra} — "
            f"every connection through the gateway was reset")
        # Who issued it matters as much as what it is. When the address arrives
        # from a *different* DHCP server, with a different gateway, that is the
        # provider moving the subscriber -- a session rebuilt after a payment or
        # an outage -- not a lease ticking over. Saying so turns a mystery into
        # a sentence: this box saw exactly that on 2026-09-10, and working out
        # why took a conversation that the record should have made unnecessary.
        issuer = lease_issuer(wan)
        was = state.get("wan_issuer", {})
        moved = bool(was.get("server") and issuer.get("server")
                     and was["server"] != issuer["server"])
        record = {"ts": int(time.time()), "when": time.strftime("%F %T"),
                  "from": prev, "to": cur,
                  "server_from": was.get("server"), "server_to": issuer.get("server"),
                  "different_server": moved}
        if moved:
            log(f"the new address came from a different DHCP server "
                f"({was.get('server')} → {issuer.get('server')}) — that is the "
                f"provider rebuilding the session, not a lease renewal")
        try:
            hist = json.loads(WAN_CHANGES.read_text()) if WAN_CHANGES.exists() else []
        except (OSError, ValueError):
            hist = []
        hist.append(record)
        try:
            WAN_CHANGES.write_text(json.dumps(hist[-WAN_CHANGES_MAX:]))
        except OSError:
            pass
    # How long the address has held. Without it the interface can only warn
    # about what a short lease might do; with it, it can say what it has
    # actually done -- which on this provider is nothing at all for a day and
    # a half, across some three hundred renewals.
    if prev != cur or not WAN_CURRENT.exists():
        try:
            WAN_CURRENT.write_text(json.dumps({"cidr": cur, "since": int(time.time())}))
        except OSError:
            pass
    state["wan_cidr"] = cur
    state["wan_issuer"] = lease_issuer(wan) or state.get("wan_issuer", {})

    life = lease_lifetime(wan)
    if life and life != state.get("lease_seconds"):
        state["lease_seconds"] = life
        if life <= SHORT_LEASE_SEC:
            # Stated as a fact, not as a warning: renewal keeps the address, and
            # saying otherwise turned a normal short lease into an alarm.
            log(f"NOTE: the provider's lease lasts {life // 60} min, renewed at "
                f"half that. Renewal keeps the address; changes are logged "
                f"separately when they happen.")
    return state

def has_fwmark_rule() -> bool:
    return "fwmark 0x1 lookup 100" in run("ip", "rule", "show").stdout

def has_singbox_rules() -> bool:
    return "lookup 2022" in run("ip", "rule", "show").stdout

def default_route_ok() -> bool:
    return "default via" in run("ip", "route", "show", "default").stdout

def topo_switch_running() -> bool:
    return run("systemctl", "is-active", "xray-topology.service").stdout.strip() == "active"

# ── auto-fixes ────────────────────────────────────────────────────────────────
def fix_service(s: str) -> None:
    log(f"AUTO-FIX: service {s} not active -> restart")
    run("systemctl", "restart", s, timeout=40)

def fix_iptables() -> None:
    log("AUTO-FIX: TPROXY fwmark rule missing -> iptables.sh up")
    run("bash", str(IPTABLES_SH), "up", timeout=60)

def fix_singbox() -> None:
    log("AUTO-FIX: sing-box policy rules missing -> restart sing-box")
    run("systemctl", "restart", "sing-box", timeout=40)

def fix_netplan() -> None:
    log("AUTO-FIX: LAN address/route missing -> netplan apply")
    run("netplan", "apply", timeout=60)

def revert_to_loop(reason: str) -> None:
    log(f"AUTO-FIX: {reason} -> reverting to known-good loop (safe_harbor)")
    # reuse the proven recovery in apply_topology
    run("/usr/bin/python3", "-c",
        "import sys; sys.path.insert(0,'/opt/shunt/scripts'); "
        "import apply_topology as A; ok,info=A.safe_harbor_loop(); print('safe_harbor', ok, info)",
        timeout=180)

def rotate_access_log() -> None:
    """Keep access.log bounded. xray holds the fd open and has no log-reopen
    signal, so a plain rename/delete would NOT free the space (xray keeps
    writing to the old inode). Truncate to free blocks, then restart xray so it
    reopens cleanly at offset 0 (avoids a sparse file). Rare (200MB), the
    analytics ingester resets its checkpoint on shrink. Measured by actual
    blocks (st_blocks) so a sparse size never causes a loop."""
    try:
        st = ACCESS_LOG.stat()
        if st.st_blocks * 512 <= ACCESS_MAX:
            return
    except OSError:
        return
    log(f"AUTO-FIX: access.log ~{st.st_blocks*512//(1024*1024)}MB > limit -> truncate + xray reopen")
    run("truncate", "-s", "0", str(ACCESS_LOG))
    run("systemctl", "restart", "shunt", timeout=40)

def ap_up_check() -> None:
    """The out-of-band rescue AP must always be up (it's the lifeline during
    risky ops and after reboots). Re-establish it if hostapd died or the AP
    interface lost its IP. Skipped if no wireless dongle is present."""
    wlx = [p.name for p in Path("/sys/class/net").glob("wlx*")]
    if not wlx:
        return  # no AP-capable dongle plugged in
    running = subprocess.run(["pgrep", "-f", "mgmt-ap-hostapd.conf"],
                             capture_output=True).returncode == 0
    has_ip = any(AP_IP in run("ip", "-4", "addr", "show", i).stdout for i in wlx)
    if not (running and has_ip):
        log("AUTO-FIX: management AP down -> mgmt_ap.sh up")
        run("bash", str(MGMT_AP), "up", timeout=70)

def prune_disk() -> None:
    log("AUTO-FIX: disk >%d%% -> pruning old backups/logs" % DISK_PRUNE_PCT)
    # keep only the newest gateway backup, truncate big rotated logs
    run("bash", "-c",
        "ls -1dt /home/user/gateway-backup-* 2>/dev/null | tail -n +2 | xargs -r rm -rf; "
        "find /opt/shunt/logs -name '*.log.*' -delete 2>/dev/null; "
        "truncate -s 0 /opt/shunt/logs/access.log 2>/dev/null || true", timeout=60)

# ── one monitoring cycle ──────────────────────────────────────────────────────
def raise_attention(kind: str, text: str, detail: str = "") -> None:
    """
    Put something where a person will see it, not only in a log file.

    `egress dead` went into a log every minute for hours during the outage and
    nobody read it, because nothing had ever asked anyone to. Entries here reach
    the interface, and the web process turns new ones into whatever alerting the
    operator configured. Deduplicated by kind: the same concern restated sixty
    times an hour is the noise this replaces, not an improvement on it.
    """
    try:
        items = json.loads(ATTENTION.read_text()) if ATTENTION.exists() else []
    except (OSError, ValueError):
        items = []
    if not isinstance(items, list):
        items = []
    now = int(time.time())
    for it in items:
        if isinstance(it, dict) and it.get("kind") == kind and not it.get("cleared"):
            it["last_seen"] = now
            it["count"] = it.get("count", 1) + 1
            it["text"] = text
            it["detail"] = detail
            break
    else:
        items.append({"kind": kind, "text": text, "detail": detail,
                      "first_seen": now, "last_seen": now, "count": 1,
                      "cleared": False})
    try:
        ATTENTION.write_text(json.dumps(items[-ATTENTION_MAX:], ensure_ascii=False))
    except OSError:
        pass


def clear_attention(kind: str) -> None:
    """Mark a concern resolved rather than deleting it: 'it came back' is a
    different sentence from 'it never happened', and the difference matters."""
    try:
        items = json.loads(ATTENTION.read_text()) if ATTENTION.exists() else []
    except (OSError, ValueError):
        return
    changed = False
    for it in items:
        if isinstance(it, dict) and it.get("kind") == kind and not it.get("cleared"):
            it["cleared"] = True
            it["cleared_at"] = int(time.time())
            changed = True
    if changed:
        try:
            ATTENTION.write_text(json.dumps(items, ensure_ascii=False))
        except OSError:
            pass


def run_diagnosis(state: dict, wan: str) -> dict:
    """
    Walk the ladder, announce what moved, and keep the verdict where it can be
    read by the interface and by the watchdog.
    """
    if not wan:
        return state
    d = dg.ladder(wan)
    try:
        DIAGNOSIS.write_text(json.dumps(d, ensure_ascii=False))
    except OSError:
        pass

    for msg in dg.environment_changes(state.get("environment") or {}, d["environment"]):
        log("ENVIRONMENT: " + msg)
        raise_attention("environment", msg)
    state["environment"] = d["environment"]

    if d["healthy"]:
        clear_attention("path")
    else:
        raise_attention("path", d["summary"],
                        "неисправность %s" % (d["owner"] or "—"))
    return state

def check_provider(state: dict, wan: str, lan: str) -> dict:
    """
    Check the assumptions the configuration makes against the provider making
    them false.

    September's outage was a right setting whose precondition had stopped
    holding, and nothing was written down that could notice. These checks are
    that writing-down: the first is the outage itself -- is the gateway's own
    address excepted from interception, or is every packet for it being
    swallowed?
    """
    if not wan:
        return state
    fp = pv.fingerprint(wan)
    chain = run("iptables", "-t", "mangle", "-L", "XRAY_PREROUTING",
                "-v", "-n", "-x").stdout
    lan_cidr = None
    if lan:
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)",
                      run("ip", "-4", "-o", "addr", "show", lan).stdout)
        lan_cidr = m.group(1) if m else None
    checks = pv.audit(fp, chain, lan_cidr,
                      doh_ok=dg.resolves(server="127.0.0.1", port=5053),
                      resolver_ok=(dg.resolves(server=fp["resolvers"][0], port=53)
                                   if fp.get("resolvers") else None))
    profiles, is_new = pv.remember(fp)
    try:
        PROVIDER.write_text(json.dumps(
            {"ts": int(time.time()), "fingerprint": fp, "checks": checks,
             "known_providers": len(profiles), "is_new": is_new},
            ensure_ascii=False))
    except OSError:
        pass

    if is_new and state.get("provider_seen"):
        log("PROVIDER: похоже на другого провайдера (DHCP-сервер %s, "
            "резолверы %s)" % (fp.get("dhcp_server"), ", ".join(fp.get("resolvers") or [])))
        raise_attention("provider",
                        "Похоже, сменился провайдер",
                        "DHCP-сервер %s, резолверы %s. Проверьте допущения — "
                        "в прошлый раз их сломалось три сразу."
                        % (fp.get("dhcp_server"), ", ".join(fp.get("resolvers") or []) or "—"))
    state["provider_seen"] = True

    bad = pv.failing(checks)
    if bad:
        first = bad[0]
        log("ASSUMPTION: %s — %s" % (first["title"], first["detail"]))
        raise_attention("assumption", "Нарушено допущение: %s" % first["title"],
                        "%s. %s" % (first["detail"], first["remedy"]))
    else:
        clear_attention("assumption")
    return state

def cycle(state: dict) -> dict:
    if topo_switch_running():
        return state   # never interfere mid-switch

    conf = net_conf()
    topo = conf.get("TOPOLOGY", "loop")
    lan  = conf.get("LAN_IF", "")
    wan  = conf.get("WAN_IF", "")

    # 1) core services
    for s in SERVICES:
        if not svc_active(s):
            fix_service(s)

    # 2) datapath rules (covers the networkd-incident class)
    if not has_fwmark_rule():
        fix_iptables()
    if not has_singbox_rules():
        fix_singbox()

    # 3) LAN addressing
    if lan and topo == "loop":
        if iface_ipv4(lan) != LOOP_IP or not default_route_ok():
            fix_netplan()

    # 3b) the ladder: what is actually wrong, in the order things depend on
    #     each other, so a consequence never gets reported as a cause.
    state = run_diagnosis(state, wan)
    state = check_provider(state, wan, lan)

    # 4) topology-specific reachability + the post-switch safety net
    if wan:
        state = note_wan_address(state, wan)
    if topo == "inline" and wan:
        wan_dead = ((not carrier(wan)) or (iface_ipv4(wan) is None)
                    or (not reaches_internet()))
        n = state.get("wan_fail", 0) + 1 if wan_dead else 0
        state["wan_fail"] = n
        if wan_dead:
            log(f"WARN: inline WAN '{wan}' unhealthy ({n}/{WAN_FAIL_LIMIT})")
            if n == 1:   # snapshot forensics at the first sign, before reverting
                run("/usr/bin/python3", "-c",
                    "import sys; sys.path.insert(0,'/opt/shunt/scripts'); "
                    "import apply_topology as A,json; "
                    "A.capture_debug(json.load(open('/opt/shunt/config/topology-target.json')), 'health-monitor-inline-degraded')",
                    timeout=40)
        if n >= WAN_FAIL_LIMIT:
            revert_to_loop(f"inline WAN dead {n} cycles")
            state["wan_fail"] = 0
    else:
        state["wan_fail"] = 0

    # 5) rescue AP must stay up (survives reboots / accidental power cycles)
    # ap_up_check()  # disabled 2026-06-19: wlx repurposed as Home client

    # 6) keep access.log bounded (prevents the disk-fill we just cleaned up)
    rotate_access_log()

    # 6) disk pressure
    try:
        pct = int(run("bash", "-c", "df --output=pcent / | tail -1 | tr -dc 0-9").stdout.strip() or "0")
        if pct >= DISK_PRUNE_PCT:
            prune_disk()
    except Exception:
        pass

    # 7) heartbeat (neighbour reachability — informational, can't fix a cut cable)
    neighbour = neighbour_to_watch(topo, iface_ipv4(lan) if lan else None)
    if neighbour != state.get("neighbour"):
        log(f"neighbour to watch is now {neighbour or 'unknown — check skipped'}")
        state["neighbour"] = neighbour
    if neighbour and not ping(neighbour):
        log(f"WARN: neighbour {neighbour} unreachable")

    return state

def main():
    log("health-monitor started")
    state = load_state()
    while True:
        try:
            state = cycle(state)
            save_state(state)
        except Exception as e:
            log(f"cycle error (non-fatal): {e}")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
