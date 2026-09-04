#!/usr/bin/env python3
"""Continuous health monitor + auto-fix for the xray-gateway.

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
import json, re, subprocess, time
from pathlib import Path

BASE        = Path("/opt/xray-proxy")
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
ROUTER          = "192.168.50.1"
LOOP_IP         = "192.168.50.2"
SERVICES        = ["xray-proxy", "xray-web", "dnsmasq", "sing-box"]
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
    return subprocess.run(["ping", "-c", "1", "-W", "2", host], capture_output=True).returncode == 0

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
        "import sys; sys.path.insert(0,'/opt/xray-proxy/scripts'); "
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
    run("systemctl", "restart", "xray-proxy", timeout=40)

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
        "find /opt/xray-proxy/logs -name '*.log.*' -delete 2>/dev/null; "
        "truncate -s 0 /opt/xray-proxy/logs/access.log 2>/dev/null || true", timeout=60)

# ── one monitoring cycle ──────────────────────────────────────────────────────
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

    # 4) topology-specific reachability + the post-switch safety net
    if topo == "inline" and wan:
        wan_dead = (not carrier(wan)) or (iface_ipv4(wan) is None) or (not ping("1.1.1.1"))
        n = state.get("wan_fail", 0) + 1 if wan_dead else 0
        state["wan_fail"] = n
        if wan_dead:
            log(f"WARN: inline WAN '{wan}' unhealthy ({n}/{WAN_FAIL_LIMIT})")
            if n == 1:   # snapshot forensics at the first sign, before reverting
                run("/usr/bin/python3", "-c",
                    "import sys; sys.path.insert(0,'/opt/xray-proxy/scripts'); "
                    "import apply_topology as A,json; "
                    "A.capture_debug(json.load(open('/opt/xray-proxy/config/topology-target.json')), 'health-monitor-inline-degraded')",
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

    # 7) heartbeat (router reachability — informational, can't fix a cut cable)
    if not ping(ROUTER):
        log(f"WARN: router {ROUTER} unreachable")

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
