"""
The network path, end to end, as one answer.

The 2026-09-09 outage took a day to find because nothing in this product could
say where a packet died. Every layer reported the layer below it as broken: the
watchdog restarted a healthy tunnel, the monitor called a healthy WAN dead, and
the interface showed a green light next to an address. What actually answered
the question was `tcpdump` and iptables rule counters, neither of which is
reachable from a browser.

This module is those answers, gathered honestly:

  link      what the cable and the driver say
  address   the address, the gateway, and how long the lease lasts
  route     where the kernel sends a packet, and which table won
  counters  which interception rules are eating traffic
  egress    whether the tunnel is carrying bytes, measured by counting bytes

Two rules of construction. **Parse, do not render.** The raw output of `ip rule`
and three routing tables misled the author three times in one day while he had
root; passing it through to a browser would only widen the audience for that.
And **say when you do not know**: every field here can be missing, and a missing
field is reported as missing rather than as a zero, because a confident zero is
what made the old WAN check worthless.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path

SYSFS = Path("/sys/class/net")
NETIF_LEASES = Path("/run/systemd/netif/leases")
LOGS = Path("/opt/shunt/logs")

# Routing tables, named. "table 2022" is not an answer anyone can act on; "the
# tunnel's own table" is. Numbers come from sing-box's auto_route (2022) and
# from this product's own policy routing (100).
TABLE_NAMES = {
    "main": "основная",
    "local": "локальная",
    "default": "по умолчанию",
    "100": "xray (перехват)",
    "2022": "sing-box (tun)",
}

# The rules worth counting, matched on what iptables prints rather than on line
# number, because the line number changes whenever the chain is edited. Each
# entry is (label, substring that identifies the rule in `iptables -L -n`).
WATCHED_RULES = [
    ("CGNAT провайдера — не перехватывать", "100.64.0.0/10"),
    ("ICMP мимо туннеля", "MARK set 0xff"),
    ("DNS к dnsmasq", "udp dpt:53"),
    ("FCM (Google Home)", "tcp dpt:5228"),
    ("TCP в xray", "TPROXY redirect 0.0.0.0:12345"),
]


def _run(*cmd, timeout=5) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _read(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _int(v: str | None) -> int | None:
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


# ── link ──────────────────────────────────────────────────────────────────────

def parse_link(iface: str, root: Path = SYSFS) -> dict:
    """
    What the cable and the driver say.

    `speed` is -1 or unreadable while the link is down, and on this box's r8169
    it has lied before -- it once reported 10baseT on a port negotiating a
    gigabit. So it is reported as read, not corrected, and carrier is reported
    separately: those two disagreeing is itself worth seeing.
    """
    d = root / iface
    if not d.exists():
        return {"iface": iface, "present": False}
    st = d / "statistics"
    speed = _int(_read(d / "speed"))
    return {
        "iface": iface,
        "present": True,
        "carrier": _read(d / "carrier") == "1",
        "operstate": _read(d / "operstate"),
        "speed_mbit": speed if speed and speed > 0 else None,
        "duplex": _read(d / "duplex"),
        "mtu": _int(_read(d / "mtu")),
        "rx_bytes": _int(_read(st / "rx_bytes")),
        "tx_bytes": _int(_read(st / "tx_bytes")),
        "rx_errors": _int(_read(st / "rx_errors")),
        "tx_errors": _int(_read(st / "tx_errors")),
        "rx_dropped": _int(_read(st / "rx_dropped")),
        "tx_dropped": _int(_read(st / "tx_dropped")),
    }


# ── address and lease ─────────────────────────────────────────────────────────

def parse_duration(v: str) -> int | None:
    """systemd durations: '10min', '8min 45s', '1h 30min'. Returns seconds."""
    total, seen = 0, False
    for num, unit in re.findall(r"(\d+)\s*(usec|msec|min|h|m|s)?", v):
        if not num:
            continue
        seen = True
        total += int(num) * {"h": 3600, "min": 60, "m": 60, "s": 1,
                             "msec": 0, "usec": 0, "": 1}[unit]
    return total if seen else None


def parse_lease_file(text: str) -> dict:
    """The lease as systemd-networkd wrote it: address, router, timers, DNS."""
    out: dict = {}
    for ln in text.splitlines():
        if "=" not in ln or ln.startswith("#"):
            continue
        k, v = ln.split("=", 1)
        k, v = k.strip(), v.strip()
        if k == "ADDRESS":
            out["address"] = v
        elif k == "ROUTER":
            out["gateway"] = v
        elif k == "SERVER_ADDRESS":
            out["server"] = v
        elif k == "DNS":
            out["dns"] = v.split()
        elif k in ("T1", "T2", "LIFETIME"):
            out[k.lower()] = parse_duration(v)
    return out


def parse_lease_timers(networkctl_json: str, uptime_sec: float) -> dict:
    """
    When the lease was taken and when its timers fire.

    networkd keeps these on the boot clock, so they are compared against uptime
    rather than the wall clock. A timer already in the past does not mean the
    lease expired -- networkd does not refresh this record on every renewal --
    so a stale timer is reported as stale rather than as a negative countdown.
    Guessing here would produce exactly the confident wrong number this module
    exists to stop printing.
    """
    try:
        lease = json.loads(networkctl_json)["DHCPv4Client"]["Lease"]
    except (ValueError, KeyError, TypeError):
        return {}
    got = lease.get("LeaseTimestampUSec")
    t1 = lease.get("Timeout1USec")
    t2 = lease.get("Timeout2USec")
    if not isinstance(got, (int, float)):
        return {}
    out: dict = {"acquired_secs_ago": max(0.0, uptime_sec - got / 1e6)}
    if isinstance(t1, (int, float)):
        left = t1 / 1e6 - uptime_sec
        out["renew_in"] = left if left >= 0 else None
        out["renew_timer_stale"] = left < 0
        out["t1_from_lease"] = (t1 - got) / 1e6
    if isinstance(t2, (int, float)):
        out["t2_from_lease"] = (t2 - got) / 1e6
    return out


def _times(n: int) -> str:
    """«1 раз», «2 раза», «5 раз» — иначе фраза спотыкается на числе."""
    if 11 <= n % 100 <= 14:
        return "%d раз" % n
    last = n % 10
    if last == 1:
        return "%d раз" % n
    if last in (2, 3, 4):
        return "%d раза" % n
    return "%d раз" % n


def lease_note(lease: dict, stable_since: float | None = None,
               changes_24h: int = 0, now: float | None = None,
               short_sec: int = 1800) -> str | None:
    """
    One sentence about the lease -- describing what happened, not what could.

    An earlier version of this said a short lease meant every renewal was a
    chance for the address to move, and that each move cut every connection. The
    second half is true; the first half made it sound like a coin flip every
    five minutes, and the gateway's own logs say otherwise: about three hundred
    renewals in twenty-five hours without a single change, and nine
    re-acquisitions in one afternoon of cable-pulling that returned the very
    same address every time. Renewal normally keeps the address -- the server
    holds the binding -- and an address only moves when the provider decides it
    should.

    So this reports the lease as a fact and the changes as a count. A number
    that is nearly always zero is reassurance; the same number at three is worth
    acting on. Neither is a warning about something that has not happened.
    """
    life, t1 = lease.get("lifetime"), lease.get("t1")
    if not life:
        return None
    now = now if now is not None else time.time()
    if life <= short_sec:
        head = "Аренда на %d мин, продление каждые %d мин." % (
            life // 60, (t1 or life // 2) // 60)
    else:
        head = "Аренда на %d ч." % (life // 3600)

    if changes_24h:
        return (head + " Продление обычно сохраняет адрес, но за последние "
                "сутки он сменился %s — а смена адреса разом обрывает все "
                "соединения через шлюз." % _times(changes_24h))
    if stable_since:
        hours = (now - stable_since) / 3600.0
        if hours >= 1:
            return (head + " Продление сохраняет адрес: за %d ч наблюдения "
                    "ни одной смены." % int(hours))
        return head + " Продление сохраняет адрес; наблюдение идёт меньше часа."
    return head + " Продление обычно сохраняет адрес."


def address_state(iface: str) -> dict:
    """Address, gateway and lease, with the lease explained rather than dumped."""
    out: dict = {"iface": iface}
    idx = _read(SYSFS / iface / "ifindex")
    text = _read(NETIF_LEASES / idx) if idx else None
    lease = parse_lease_file(text) if text else {}
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)",
                  _run("ip", "-4", "-o", "addr", "show", iface))
    out["cidr"] = m.group(1) if m else None
    out["lease"] = lease
    # What the address has actually done, from the monitor's record, so the note
    # can report rather than speculate.
    since, changed = None, 0
    try:
        cur = json.loads((LOGS / "wan-current.json").read_text())
        if cur.get("cidr") == out["cidr"]:
            since = cur.get("since")
    except (OSError, ValueError, AttributeError):
        pass
    try:
        hist = json.loads((LOGS / "wan-changes.json").read_text())
        cutoff = time.time() - 86400
        changed = sum(1 for h in hist
                      if isinstance(h, dict) and h.get("ts", 0) >= cutoff)
    except (OSError, ValueError, TypeError):
        pass
    out["stable_since"] = since
    out["changes_24h"] = changed
    out["note"] = lease_note(lease, stable_since=since, changes_24h=changed)
    uptime = _read(Path("/proc/uptime"))
    if uptime:
        try:
            out["timers"] = parse_lease_timers(
                _run("networkctl", "status", iface, "--json=short"),
                float(uptime.split()[0]))
        except (ValueError, IndexError):
            out["timers"] = {}
    return out


# ── where a packet goes ───────────────────────────────────────────────────────

def parse_route_get(json_text: str) -> dict:
    """`ip -j route get` for one destination, with the table named."""
    try:
        r = json.loads(json_text)[0]
    except (ValueError, IndexError, KeyError, TypeError):
        return {}
    table = r.get("table", "main")
    return {
        "dev": r.get("dev"),
        "gateway": r.get("gateway"),
        "src": r.get("prefsrc"),
        "table": table,
        "table_name": TABLE_NAMES.get(str(table), str(table)),
        "mark": r.get("mark"),
    }


def rules_choosing(table: str, ip_rule_output: str) -> list[str]:
    """
    The policy rules that point at a given table, as they are written.

    Not the whole rule list: the whole list is what misled everyone. Showing
    only the rules that select the table the kernel actually chose turns twenty
    lines of policy into the one or two that mattered.
    """
    want = str(table)
    out = []
    for ln in ip_rule_output.splitlines():
        ln = ln.strip()
        if re.search(r"lookup %s(\s|$)" % re.escape(want), ln):
            out.append(ln)
    return out[:6]


def where_does_it_go(dest: str) -> dict:
    """
    Two kernel answers for one destination: with the bypass mark and without.

    Both are true at once on this box, and which one applies depends on what
    netfilter did to the packet before the routing decision -- so printing one
    of them alone is how you end up certain and wrong. ICMP and the tunnel's own
    traffic carry the mark; ordinary forwarded traffic does not.
    """
    plain = parse_route_get(_run("ip", "-j", "route", "get", dest))
    marked = parse_route_get(_run("ip", "-j", "route", "get", dest, "mark", "0xff"))
    rules = _run("ip", "rule", "show")
    if plain:
        plain["chosen_by"] = rules_choosing(plain.get("table", "main"), rules)
    if marked:
        marked["chosen_by"] = rules_choosing(marked.get("table", "main"), rules)
    same = bool(plain and marked and plain.get("dev") == marked.get("dev"))
    return {"dest": dest, "intercepted": plain, "bypassed": marked,
            "same_either_way": same}


# ── rule counters ─────────────────────────────────────────────────────────────

def parse_rule_counters(iptables_output: str,
                        watched: list[tuple[str, str]] | None = None) -> list[dict]:
    """
    Packet and byte counts for the rules that decide where traffic goes.

    Matched on the text iptables prints, not on position: the chain is rebuilt
    on every restart and a line number means nothing across two of them. A rule
    that is missing entirely is reported as missing -- that is the shape of the
    bug that caused the outage, one absent line in this chain.
    """
    watched = watched or WATCHED_RULES
    rows = []
    for ln in iptables_output.splitlines():
        f = ln.split()
        if len(f) < 2 or not f[0].isdigit() or not f[1].isdigit():
            continue
        rows.append((int(f[0]), int(f[1]), ln))
    out = []
    for label, needle in watched:
        hit = next((r for r in rows if needle in r[2]), None)
        out.append({"label": label, "present": hit is not None,
                    "packets": hit[0] if hit else None,
                    "bytes": hit[1] if hit else None})
    return out


def parse_chain(iptables_output: str) -> list[dict]:
    """`iptables -L -n -v -x` as rows: target, protocol, source, destination, rest."""
    rows = []
    for ln in iptables_output.splitlines():
        f = ln.split()
        if len(f) < 9 or not f[0].isdigit() or not f[1].isdigit():
            continue
        rows.append({"packets": int(f[0]), "bytes": int(f[1]), "target": f[2],
                     "proto": f[3], "source": f[7], "dest": f[8],
                     "extra": " ".join(f[9:]), "raw": ln.strip()})
    return rows


def _covers(cidr: str, ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def interception_verdict(dest_ip: str, chain_output: str) -> dict:
    """
    Whether a packet to this destination is taken into the tunnel, and by which
    rule -- the layer that decides first, and the one nobody could see.

    This is the question the outage turned on. A rule missing from this chain
    meant every packet for the gateway's own address was swallowed by TPROXY,
    and no amount of looking at routes would have shown it, because netfilter
    acts before the routing decision is made.

    Rules that depend on the protocol or the port rather than the address are
    reported as such instead of being silently ignored: a page that answers
    "not intercepted" when the answer is "depends what you send" would be the
    same kind of confident wrong the rest of this module exists to avoid.
    """
    conditional = []
    for r in parse_chain(chain_output):
        if r["source"] not in ("0.0.0.0/0", "::/0"):
            continue                              # source rules: not about this
        if r["extra"] and ("dpt:" in r["extra"] or "spt:" in r["extra"]) \
                or r["proto"] == "icmp":
            conditional.append(r)
            continue
        if r["extra"].startswith("mark match"):
            continue
        if r["dest"] in ("0.0.0.0/0", "::/0") or _covers(r["dest"], dest_ip):
            if r["target"] == "RETURN":
                return {"intercepted": False, "rule": r["raw"],
                        "why": "исключение по адресу %s" % r["dest"],
                        "conditional": [c["raw"] for c in conditional]}
            if r["target"] == "TPROXY":
                return {"intercepted": True, "rule": r["raw"],
                        "why": "перехват в xray",
                        "conditional": [c["raw"] for c in conditional]}
    return {"intercepted": None, "rule": None,
            "why": "ни одно правило не подошло",
            "conditional": [c["raw"] for c in conditional]}


# ── egress ────────────────────────────────────────────────────────────────────

def parse_acct(iptables_output: str) -> dict:
    """Bytes the tunnel has carried, from the accounting chain's own counters."""
    out: dict = {}
    for ln in iptables_output.splitlines():
        f = ln.split()
        if len(f) < 2 or not f[0].isdigit() or not f[1].isdigit():
            continue
        if "vpn_up" in ln:
            out["up_bytes"] = int(f[1])
        elif "vpn_down" in ln:
            out["down_bytes"] = int(f[1])
    return out


def egress_rate(sample_seconds: float = 1.0) -> dict:
    """
    Whether the tunnel is carrying anything, established by watching it carry.

    `systemctl is-active` was the old answer and it was the wrong question: the
    service was active through an outage in which nothing moved. Two samples of
    the byte counters a second apart cannot be wrong about that.
    """
    def read():
        return parse_acct(_run("iptables", "-t", "mangle", "-L", "XRAY_ACCT",
                               "-v", "-n", "-x"))
    a = read()
    if not a:
        return {"available": False}
    time.sleep(sample_seconds)
    b = read()
    up = b.get("up_bytes", 0) - a.get("up_bytes", 0)
    down = b.get("down_bytes", 0) - a.get("down_bytes", 0)
    return {
        "available": True,
        "up_bytes_total": b.get("up_bytes"),
        "down_bytes_total": b.get("down_bytes"),
        "up_bps": int(up * 8 / sample_seconds),
        "down_bps": int(down * 8 / sample_seconds),
        "carrying": (up + down) > 0,
    }


# ── the whole picture ─────────────────────────────────────────────────────────

def snapshot(wan: str, lan: str | None = None, sample_seconds: float = 1.0) -> dict:
    """Everything above, in one reply, for one poll of the interface."""
    out = {
        "ts": int(time.time()),
        "wan": {"link": parse_link(wan), "address": address_state(wan)},
        "counters": parse_rule_counters(
            _run("iptables", "-t", "mangle", "-L", "XRAY_PREROUTING",
                 "-v", "-n", "-x")),
        "egress": egress_rate(sample_seconds),
    }
    if lan:
        out["lan"] = {"link": parse_link(lan)}
    return out
