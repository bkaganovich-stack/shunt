#!/usr/bin/env python3
"""Switch the gateway between LOOP and INLINE network topologies, with a
watchdog that auto-reverts if the internet doesn't come up.

Usage: apply_topology.py            # reads /opt/shunt/config/topology-target.json

LOOP   : single NIC inside the router's LAN (hairpin). Router does upstream NAT.
INLINE : gateway between ISP and router. WAN_IF = DHCP client to the ISP,
         LAN_IF = static, gateway runs DHCP for the router's WAN port and
         MASQUERADEs everything out WAN_IF (double-NAT — router stays a router).

Run detached via systemd-run so a web-service restart can't kill the watchdog.
Progress is written to STATUS_FILE and polled by the UI.

The target spec (topology-target.json) is written by the API and looks like:
  {"topology":"inline","wan_if":"enp1s0","wan_mode":"dhcp",
   "lan_if":"enx...","lan_ip":"192.168.100.1","lan_cidr":24,
   "dhcp_start":"192.168.100.10","dhcp_end":"192.168.100.50",
   "nameservers":["9.9.9.9"]}
  {"topology":"loop","lan_if":"enx...","lan_ip":"192.168.50.2","lan_cidr":24,
   "router_ip":"192.168.50.1","nameservers":["9.9.9.9"]}
"""
import json, re, shutil, socket, subprocess, sys, time
from pathlib import Path

BASE         = Path("/opt/shunt")
CFG          = BASE / "config"
NET_CONF     = CFG / "network.conf"
TARGET_FILE  = CFG / "topology-target.json"
STATUS_FILE  = CFG / "topology-status.json"
ROLLBACK_DIR = CFG / "topology-rollback"
DEBUG_LOG    = BASE / "logs" / "topology-debug.log"
NETPLAN_DIR  = Path("/etc/netplan")
DNSMASQ_CONF = Path("/etc/dnsmasq.d/shunt.conf")
SINGBOX_CONF = Path("/etc/sing-box/config.json")
IPTABLES_SH  = BASE / "scripts" / "iptables.sh"

WAIT_LINK_SEC = 120   # time for the user to recable (plug ISP into WAN, etc.)
WAIT_IP_SEC   = 60    # DHCP lease acquisition on WAN
WATCHDOG_SEC  = 50    # internet-health probing before declaring success
CONFIRM_SEC   = 90    # post-success window: catch inline "comes up then drops"
PING_OK_NEED  = 3

_status: dict = {}

def set_status(stage: str, **kw) -> None:
    _status.update({"stage": stage, "ts": time.time()}, **kw)
    tmp = STATUS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(_status))
    tmp.rename(STATUS_FILE)

def run(*cmd, check=False, timeout=60):
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout)

def carrier(iface: str) -> bool:
    try:
        return Path(f"/sys/class/net/{iface}/carrier").read_text().strip() == "1"
    except OSError:
        return False

def ipv4_of(iface: str):
    r = run("ip", "-4", "addr", "show", iface)
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout)
    return m.group(1) if m else None

def ping(host: str, iface: str = None) -> bool:
    cmd = ["ping", "-c", "1", "-W", "2"]
    if iface: cmd += ["-I", iface]
    return subprocess.run(cmd + [host], capture_output=True).returncode == 0

def default_gw_via(iface: str):
    """The DHCP-learned gateway on a given interface (for WAN reachability)."""
    r = run("ip", "route", "show", "dev", iface)
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", r.stdout)
    if m: return m.group(1)
    # fall back: any default route
    r = run("ip", "route", "show", "default")
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", r.stdout)
    return m.group(1) if m else None

# ── config generation ────────────────────────────────────────────────────────
def write_netplan(yaml_text: str) -> None:
    for f in NETPLAN_DIR.glob("*.yaml"):
        f.unlink()
    target = NETPLAN_DIR / "00-installer-config.yaml"
    target.write_text(yaml_text)
    target.chmod(0o600)

def mac_of(iface: str) -> str:
    return Path(f"/sys/class/net/{iface}/address").read_text().strip()

def perm_mac_of(iface: str) -> str:
    """Permanent hardware MAC (for netplan `match`), independent of any clone
    currently set on the link. Falls back to the current MAC."""
    r = run("ethtool", "-P", iface, check=False)
    m = re.search(r"Permanent address:\s*([0-9a-f:]{17})", r.stdout)
    if m and m.group(1) != "00:00:00:00:00:00":
        return m.group(1)
    return mac_of(iface)

def netplan_inline(t: dict) -> str:
    ns = ", ".join(t.get("nameservers", ["9.9.9.9"]))
    wan, lan = t["wan_if"], t["lan_if"]
    # Optional MAC clone: present the router's WAN MAC to the ISP so a
    # MAC-bound provider keeps issuing the lease (match by the port's real
    # MAC, then override it). Without this, MAC-bound ISPs give no WAN lease.
    wan_clone = f"\n      macaddress: {t['wan_mac']}" if t.get("wan_mac") else ""
    # dhcp-identifier: mac → identify to the ISP by MAC (option 61), like the
    # router/dhcpcd do, so a MAC-keyed lease is recognised (DUID would look
    # like a new client). Proven: WAN leases 10.203.101.91 with the router MAC.
    wan_block = f"""    {wan}:
      match: {{macaddress: {perm_mac_of(wan)}}}
      set-name: {wan}{wan_clone}
      dhcp4: true
      dhcp-identifier: mac
      dhcp4-overrides: {{use-dns: false}}"""
    lan_block = f"""    {lan}:
      match: {{macaddress: {perm_mac_of(lan)}}}
      set-name: {lan}
      dhcp4: false
      addresses: [{t['lan_ip']}/{t['lan_cidr']}]
      nameservers: {{addresses: [{ns}]}}"""
    return ("# Generated by shunt apply_topology.py (INLINE) — do not edit.\n"
            "network:\n  version: 2\n  ethernets:\n" + wan_block + "\n" + lan_block + "\n")

def netplan_loop(t: dict) -> str:
    ns = ", ".join(t.get("nameservers", ["9.9.9.9"]))
    lan = t["lan_if"]
    return (f"""# Generated by shunt apply_topology.py (LOOP) — do not edit.
network:
  version: 2
  ethernets:
    {lan}:
      match: {{macaddress: {perm_mac_of(lan)}}}
      set-name: {lan}
      dhcp4: false
      addresses: [{t['lan_ip']}/{t['lan_cidr']}]
      routes: [{{to: default, via: {t['router_ip']}, metric: 50}}]
      nameservers: {{addresses: [{ns}]}}
""")

def write_net_conf(t: dict) -> None:
    lines = [f"# Updated by apply_topology.py {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
             f"TOPOLOGY={t['topology']}", f"LAN_IF={t['lan_if']}"]
    if t["topology"] == "inline":
        lines.append(f"WAN_IF={t['wan_if']}")
        lines.append(f"ROUTER_IP={t['lan_ip']}")   # gateway is the router on the LAN link
    else:
        lines.append(f"ROUTER_IP={t['router_ip']}")
    NET_CONF.write_text("\n".join(lines) + "\n")

def write_dnsmasq(t: dict) -> None:
    """Loop: DNS-only on the gateway IP. Inline: DNS + DHCP server on LAN_IF."""
    if t["topology"] == "inline":
        conf = (f"# Generated by shunt (INLINE) — do not edit manually\n"
                f"interface={t['lan_if']}\n"
                f"bind-interfaces\n"
                f"port=5335\n"
                f"no-resolv\n"
                f"cache-size=1000\n"
                f"server=9.9.9.9\n"
                f"# DHCP for the downstream router's WAN port\n"
                f"dhcp-authoritative\n"
                f"dhcp-range={t['dhcp_start']},{t['dhcp_end']},255.255.255.0,12h\n"
                f"dhcp-option=3,{t['lan_ip']}\n"        # gateway
                f"dhcp-option=6,{t['lan_ip']}\n")       # dns
    else:
        conf = (f"# Generated by shunt (LOOP) — do not edit manually\n"
                f"listen-address={t['lan_ip']}\n"
                f"bind-interfaces\n"
                f"port=5335\n"
                f"no-resolv\n"
                f"cache-size=1000\n"
                f"server={t['router_ip']}\n")
    DNSMASQ_CONF.write_text(conf)

def rebind_singbox(iface: str) -> None:
    if not SINGBOX_CONF.exists():
        return
    try:
        conf = json.loads(SINGBOX_CONF.read_text())
        changed = False
        if conf.get("route", {}).get("default_interface") not in (None, iface):
            conf["route"]["default_interface"] = iface; changed = True
        for o in conf.get("outbounds", []):
            if o.get("bind_interface") not in (None, iface):
                o["bind_interface"] = iface; changed = True
        if changed:
            SINGBOX_CONF.write_text(json.dumps(conf, ensure_ascii=False, indent=2))
            run("systemctl", "restart", "sing-box", timeout=30)
    except Exception as e:
        print(f"sing-box rebind failed (non-fatal): {e}", file=sys.stderr)

# ── backup / restore ──────────────────────────────────────────────────────────
def backup() -> None:
    if ROLLBACK_DIR.exists():
        shutil.rmtree(ROLLBACK_DIR)
    (ROLLBACK_DIR / "netplan").mkdir(parents=True)
    for f in NETPLAN_DIR.glob("*.yaml"):
        shutil.copy2(f, ROLLBACK_DIR / "netplan" / f.name)
    shutil.copy2(NET_CONF, ROLLBACK_DIR / "network.conf")
    if DNSMASQ_CONF.exists():
        shutil.copy2(DNSMASQ_CONF, ROLLBACK_DIR / "gateway.conf")
    if SINGBOX_CONF.exists():
        shutil.copy2(SINGBOX_CONF, ROLLBACK_DIR / "sing-box.json")

def wired_ifaces() -> list[str]:
    out = []
    for p in sorted(Path("/sys/class/net").iterdir()):
        n = p.name
        if n == "lo" or (p / "wireless").exists() or not (p / "device").exists():
            continue
        try:
            if (p / "type").read_text().strip() == "1":   # ARPHRD_ETHER
                out.append(n)
        except OSError:
            pass
    return out

def find_router_port(router_ip: str = "192.168.50.1", gw_ip: str = "192.168.50.2") -> Optional[str]:
    """The wired port through which the home router is ACTUALLY reachable.
    Tries each carrier-up port: assign the loop IP, ping the router, keep the
    one that answers. Critical so recovery never lands on the ISP-facing port
    (both ports carry a link during an inline cable-swap)."""
    for n in wired_ifaces():
        run("ip", "link", "set", n, "up", check=False)
        time.sleep(1)
        try:
            if (Path(f"/sys/class/net/{n}") / "carrier").read_text().strip() != "1":
                continue
        except OSError:
            continue
        run("ip", "addr", "flush", "dev", n, check=False)
        run("ip", "addr", "add", f"{gw_ip}/24", "dev", n, check=False)
        if subprocess.run(["ping", "-c", "2", "-W", "2", "-I", n, router_ip],
                          capture_output=True).returncode == 0:
            return n
        run("ip", "addr", "flush", "dev", n, check=False)  # not the router port
    return None

def safe_harbor_loop() -> tuple[bool, str]:
    """KNOWN-GOOD recovery: put the gateway back into loop on 192.168.50.2 via
    the port that can actually reach the home router. Automated equivalent of
    fixloop2.sh — ANY failed switch lands here, never stranded in inline."""
    lan = find_router_port()
    if not lan:
        return False, "ни один проводной порт не видит роутер 192.168.50.1 — подключите кабель из LAN роутера"
    t = {"topology": "loop", "lan_if": lan, "lan_ip": "192.168.50.2",
         "lan_cidr": 24, "router_ip": "192.168.50.1", "nameservers": ["9.9.9.9"]}
    for ifc in wired_ifaces():
        run("ip", "addr", "flush", "dev", ifc, check=False)
    write_netplan(netplan_loop(t)); write_net_conf(t); write_dnsmasq(t)
    run("netplan", "apply", timeout=60); time.sleep(3)
    # reset edge-firewall / inline rules to loop defaults
    for ch in ("INPUT", "FORWARD"):
        run("iptables", "-F", ch, check=False)
        run("iptables", "-P", ch, "ACCEPT", check=False)
    # drop any inline blanket MASQUERADE leftovers on the wired ports
    for ifc in wired_ifaces():
        for _ in range(5):
            if run("iptables", "-t", "nat", "-D", "POSTROUTING",
                   "-o", ifc, "-j", "MASQUERADE", check=False).returncode != 0:
                break
    run("bash", str(IPTABLES_SH), "up", timeout=60)
    rebind_singbox(lan)
    run("systemctl", "restart", "dnsmasq", timeout=30)
    run("systemctl", "restart", "sing-box", timeout=30)
    run("systemctl", "restart", "shunt", check=False, timeout=30)
    return True, lan

# ── watchdog ──────────────────────────────────────────────────────────────────
def internet_ok(t: dict) -> tuple[bool, str]:
    """Inline: WAN got a lease and its gateway + a public IP are reachable.
    Loop: router and a public IP reachable."""
    if t["topology"] == "inline":
        wan = t["wan_if"]
        wan_ip = ipv4_of(wan)
        if not wan_ip:
            return False, f"WAN {wan} не получил IP (кабель ISP? привязка MAC у провайдера?)"
        gw = default_gw_via(wan)
        if gw and ping(gw):
            if ping("1.1.1.1") or ping("9.9.9.9"):
                return True, "ok"
            return False, "WAN-шлюз пингуется, но интернет недоступен"
        return False, f"WAN-шлюз недоступен (IP={wan_ip})"
    else:
        if not ping(t["router_ip"]):
            return False, f"роутер {t['router_ip']} недоступен"
        if ping("1.1.1.1") or ping("9.9.9.9"):
            return True, "ok"
        return False, "роутер пингуется, но интернета нет"

def watchdog(t: dict) -> tuple[bool, str]:
    deadline = time.time() + WATCHDOG_SEC
    ok = 0; last = "нет ответа"
    while time.time() < deadline:
        good, detail = internet_ok(t)
        if good:
            ok += 1
            if ok >= PING_OK_NEED:
                return True, "ok"
        else:
            ok = 0; last = detail
        time.sleep(1)
    return False, last

def capture_debug(t: dict, tag: str = "") -> None:
    """Full forensic snapshot — used on failure AND when the post-switch
    confirm window catches inline degrading, to pinpoint what kills the WAN."""
    try:
        with DEBUG_LOG.open("a") as f:
            f.write(f"\n===== topology debug {time.strftime('%F %T')} target={t['topology']} {tag} =====\n")
            cmds = (["ip", "-br", "addr"], ["ip", "route", "show"],
                    ["ip", "route", "show", "table", "all"], ["ip", "rule", "show"],
                    ["iptables", "-t", "nat", "-S"], ["iptables", "-S"],
                    ["journalctl", "-u", "systemd-networkd", "-n", "25", "--no-pager"],
                    ["journalctl", "-u", "sing-box", "-n", "15", "--no-pager"])
            for cmd in cmds:
                r = run(*cmd); f.write(f"\n--- {' '.join(cmd)} ---\n{r.stdout}{r.stderr}")
            d = run("dmesg", "--ctime");
            f.write("\n--- dmesg tail (link/eth/dhcp) ---\n")
            f.write("\n".join(l for l in d.stdout.splitlines()
                              if any(k in l.lower() for k in ("enp1s0","eth","link","carrier","dhcp","duplicate","martian")))[-3000:])
    except Exception:
        pass

# ── main ──────────────────────────────────────────────────────────────────────
def main() -> int:
    try:
        t = json.loads(TARGET_FILE.read_text())
    except Exception as e:
        set_status("failed", ok=False, error=f"нет/битый target: {e}"); return 2

    topo = t.get("topology")
    if topo not in ("loop", "inline"):
        set_status("failed", ok=False, error=f"неизвестная топология {topo}"); return 2

    _status.update({"target": topo, "started": time.time()})
    set_status("validate", ok=None, error=None)
    for if_key in (["wan_if", "lan_if"] if topo == "inline" else ["lan_if"]):
        ifn = t.get(if_key)
        if not ifn or not Path(f"/sys/class/net/{ifn}").exists():
            set_status("failed", ok=False, error=f"интерфейс {if_key}={ifn} не найден"); return 1

    set_status("backup"); backup()

    try:
        set_status("apply")
        # Flush stale addresses on all wired ports first — netplan apply does
        # not always remove an address from a previous topology, which left the
        # inline 192.168.100.1 lingering on a "loop" interface.
        for ifc in wired_ifaces():
            run("ip", "addr", "flush", "dev", ifc, check=False)
        write_netplan(netplan_inline(t) if topo == "inline" else netplan_loop(t))
        write_net_conf(t)
        write_dnsmasq(t)
        run("netplan", "apply", timeout=60); time.sleep(2)

        # Wait for the operator to recable, then for addressing to settle.
        if topo == "inline":
            set_status("wait_link", hint="Подключите кабель ISP к WAN-порту и шлюз к WAN роутера")
            dl = time.time() + WAIT_LINK_SEC
            while not carrier(t["wan_if"]):
                if time.time() > dl:
                    raise RuntimeError(f"нет линка на WAN {t['wan_if']} за {WAIT_LINK_SEC}с — кабель ISP не подключён")
                time.sleep(1)
            set_status("wait_ip")
            dl = time.time() + WAIT_IP_SEC
            while not ipv4_of(t["wan_if"]):
                if time.time() > dl:
                    raise RuntimeError(f"WAN не получил DHCP за {WAIT_IP_SEC}с — провайдер может привязывать MAC; перезагрузите модем")
                time.sleep(1)
        else:
            set_status("wait_link")
            dl = time.time() + WAIT_LINK_SEC
            while not carrier(t["lan_if"]):
                if time.time() > dl:
                    raise RuntimeError(f"нет линка на LAN {t['lan_if']} за {WAIT_LINK_SEC}с")
                time.sleep(1)

        set_status("services")
        run("bash", str(IPTABLES_SH), "up", timeout=60)
        run("systemctl", "restart", "dnsmasq", timeout=30)
        rebind_singbox(t["wan_if"] if topo == "inline" else t["lan_if"])

        set_status("watchdog")
        ok, detail = watchdog(t)
        if not ok:
            capture_debug(t, "watchdog-failed")
            raise RuntimeError(f"проверка интернета не прошла за {WATCHDOG_SEC}с: {detail}")

        # Post-switch CONFIRM window: inline has "come up then dropped" before —
        # keep watching ~90s and snapshot the exact state the moment it degrades,
        # so the cause is captured (not lost when the process exits at "done").
        if topo == "inline":
            set_status("confirm")
            t0 = time.time()
            while time.time() - t0 < CONFIRM_SEC:
                good, why = internet_ok(t)
                if not good:
                    capture_debug(t, f"DEGRADED-after-{int(time.time()-t0)}s: {why}")
                    raise RuntimeError(f"inline деградировал через {int(time.time()-t0)}с после успеха: {why}")
                time.sleep(3)

        set_status("done", ok=True, finished=time.time(), active_topology=topo)
        shutil.rmtree(ROLLBACK_DIR, ignore_errors=True)
        return 0

    except Exception as e:
        # Persist the failure reason BEFORE recovery (the status file gets
        # overwritten by the next run, which previously lost inline failures).
        try:
            with DEBUG_LOG.open("a") as f:
                f.write(f"\n##### {time.strftime('%F %T')} target={topo} FAILED: {e}\n")
        except Exception:
            pass
        capture_debug(t)
        # ALWAYS recover into known-good loop on 192.168.50.2 — never roll back
        # into a half-applied inline (that stranded the box off-subnet before).
        set_status("rollback", error=str(e))
        try:
            ok, info = safe_harbor_loop()
            if ok:
                set_status("rolled_back", ok=False, error=str(e),
                           active_topology="loop", recovered_on=info, finished=time.time())
            else:
                set_status("rollback_failed", ok=False,
                           error=f"{e}; safe-harbor: {info}", finished=time.time())
        except Exception as e2:
            set_status("rollback_failed", ok=False,
                       error=f"{e}; ОШИБКА ОТКАТА: {e2}", finished=time.time())
        return 1

if __name__ == "__main__":
    sys.exit(main())
