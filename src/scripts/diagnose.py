"""
Notice when the ground moves, and say so.

The product knew it was broken for hours. `egress dead` and `inline WAN
unhealthy` went into a log file every minute while the automatic response --
restart AdGuard -- could not possibly have helped, because the fault was two
layers below it. Three things were missing, and they are what this module is.

**An order.** A gateway has preconditions, and they hold in sequence: a cable,
an address, a gateway on the wire, a path to the internet, a name that resolves,
a tunnel that carries. The FIRST unmet one is the answer; everything below it is
consequence. Reporting a consequence as a cause is what sent a day into chasing
a tunnel that was fine.

**A distinction.** "No cable" is not "the provider is down" and neither is "the
tunnel is dead". Each rung says whose problem it is, and nothing on this box
tries to fix a rung it cannot reach.

**A limit.** Five identical restarts are not a fix in progress; they are a
message that the diagnosis is wrong. A remedy that has not worked stops being
applied and starts being reported.

One measurement note, learned the hard way twice. This does not ping the
provider's gateway: it answers no ICMP at all, so a ping reports 100% loss
while the internet works perfectly -- and before ICMP was fixed it reported 0%
because the tunnel's own tun device was answering. Both readings were fiction.
Presence on the wire is read from the neighbour table, and reachability is a
real TCP connection.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import time
from pathlib import Path

SYSFS = Path("/sys/class/net")
NETIF_LEASES = Path("/run/systemd/netif/leases")

# Packets carrying this mark are returned from the interception chains, so a
# socket that sets it leaves the way an ordinary host's would.
BYPASS_MARK = 0xff
SO_MARK = getattr(socket, "SO_MARK", 36)

CGNAT = ipaddress.ip_network("100.64.0.0/10")
APIPA = ipaddress.ip_network("169.254.0.0/16")


def _run(*cmd, timeout=8) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _read(p: Path) -> str | None:
    try:
        return p.read_text().strip()
    except OSError:
        return None


# ── what kind of network are we on ────────────────────────────────────────────

def classify_address(cidr: str | None) -> str:
    """
    Which kind of address the provider handed us.

    This is the line that would have ended the September incident in minutes.
    The gateway moved from a provider on RFC1918 to one on CGNAT, and the TPROXY
    exception list covered only RFC1918 -- so every packet for the box's own
    address was swallowed. Nothing said the ground had moved.
    """
    if not cidr:
        return "нет адреса"
    try:
        ip = ipaddress.ip_interface(cidr).ip
    except ValueError:
        return "непонятный адрес"
    if ip in APIPA:
        return "link-local (DHCP не ответил)"
    if ip in CGNAT:
        return "CGNAT провайдера (100.64.0.0/10)"
    if ip.is_private:
        return "частный адрес (RFC1918)"
    if ip.is_loopback:
        return "loopback"
    return "публичный адрес"


def lease_band(seconds: int | None) -> str:
    if not seconds:
        return "неизвестно"
    if seconds <= 1800:
        return "короткая (до 30 мин)"
    if seconds <= 86400:
        return "обычная (до суток)"
    return "длинная (больше суток)"


def environment(iface: str) -> dict:
    """Everything about the uplink whose change is worth announcing."""
    cidr = None
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)",
                  _run("ip", "-4", "-o", "addr", "show", iface))
    if m:
        cidr = m.group(1)
    lease: dict = {}
    idx = _read(SYSFS / iface / "ifindex")
    if idx:
        for ln in (_read(NETIF_LEASES / idx) or "").splitlines():
            if ln.startswith("LIFETIME="):
                lease["lifetime"] = _duration(ln.split("=", 1)[1])
            elif ln.startswith("SERVER_ADDRESS="):
                lease["server"] = ln.split("=", 1)[1].strip()
    gw = ""
    g = re.search(r"default via (\S+)", _run("ip", "route", "show", "default"))
    if g:
        gw = g.group(1)
    return {
        "cidr": cidr,
        "class": classify_address(cidr),
        "prefix": cidr.split("/")[1] if cidr and "/" in cidr else None,
        "gateway": gw,
        "lease_seconds": lease.get("lifetime"),
        "lease_band": lease_band(lease.get("lifetime")),
        "dhcp_server": lease.get("server"),
    }


def _duration(v: str) -> int | None:
    total, seen = 0, False
    for num, unit in re.findall(r"(\d+)\s*(usec|msec|min|h|m|s)?", v):
        if not num:
            continue
        seen = True
        total += int(num) * {"h": 3600, "min": 60, "m": 60, "s": 1,
                             "msec": 0, "usec": 0, "": 1}[unit]
    return total if seen else None


def environment_changes(old: dict, new: dict) -> list[str]:
    """
    Plain sentences about what moved, in the order a person would want them.

    Only things that change how the gateway must be configured. A new address in
    the same class and the same prefix is routine and says nothing here; the
    class changing is the sentence that was missing in September.
    """
    if not old:
        return []
    out = []
    if old.get("class") != new.get("class"):
        out.append("Провайдер сменил тип адреса: %s → %s. Списки исключений, "
                   "которые перечисляют сети по адресам, надо перепроверить."
                   % (old.get("class"), new.get("class")))
    elif old.get("prefix") != new.get("prefix") and new.get("prefix"):
        out.append("Размер сети провайдера изменился: /%s → /%s."
                   % (old.get("prefix"), new.get("prefix")))
    if old.get("gateway") != new.get("gateway") and new.get("gateway"):
        out.append("Сменился шлюз провайдера: %s → %s."
                   % (old.get("gateway") or "—", new.get("gateway")))
    if old.get("lease_band") != new.get("lease_band"):
        out.append("Аренда стала другой по порядку величины: %s → %s."
                   % (old.get("lease_band"), new.get("lease_band")))
    if old.get("dhcp_server") != new.get("dhcp_server") and new.get("dhcp_server"):
        out.append("Адрес выдал другой DHCP-сервер: %s → %s — похоже на "
                   "пересборку сессии провайдером, а не на продление аренды."
                   % (old.get("dhcp_server") or "—", new.get("dhcp_server")))
    return out


# ── the ladder ────────────────────────────────────────────────────────────────

def has_carrier(iface: str) -> bool:
    return _read(SYSFS / iface / "carrier") == "1"


def gateway_on_the_wire(gw: str) -> tuple[bool, str]:
    """
    Is the provider's router present on the segment?

    From the neighbour table, not from ping: this provider's gateway answers no
    ICMP whatsoever, so a ping says 100% loss while everything works. The ARP
    entry, with its MAC, says it is there.
    """
    if not gw:
        return False, "маршрута по умолчанию нет"
    for ln in _run("ip", "neigh", "show").splitlines():
        if ln.startswith(gw + " "):
            state = ln.split()[-1]
            if state in ("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"):
                return True, "виден на канальном уровне (%s)" % state
            return False, "в таблице соседей, но %s" % state
    return False, "не отвечает на ARP"


def reaches_internet(timeout: float = 4.0) -> bool:
    """A real TCP handshake, on a socket marked to bypass the interception."""
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


def resolves(name: str = "example.com", server: str = "127.0.0.1",
             port: int = 5335, timeout: float = 3.0) -> bool:
    """One real DNS query to the resolver the household's devices land on."""
    import random
    import struct
    txid = random.randint(1, 65535)
    label = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(10))
    q = (struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
         + bytes([len(label)]) + label.encode()
         + b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
         + b"\x00" + struct.pack("!HH", 1, 1))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(q, (server, port))
        data, _ = s.recvfrom(2048)
        return len(data) >= 12 and data[:2] == q[:2]
    except OSError:
        return False
    finally:
        s.close()


def egress_carries(socks: str = "127.0.0.1:1081", timeout: int = 8) -> bool:
    """Does the tunnel actually carry a request, rather than merely be running."""
    for url, want in (("http://cp.cloudflare.com/generate_204", "204"),
                      ("https://api.ipify.org", "200")):
        out = _run("curl", "-s", "-o", "/dev/null", "-m", str(timeout),
                   "-w", "%{http_code}", "--socks5", socks, url, timeout=timeout + 4)
        if out.strip() == want:
            return True
    return False


# Each rung: who owns the problem when it is the first one unmet, and whether
# anything on this box could plausibly fix it.
RUNGS = [
    ("cable",    "Кабель в порт WAN",        "снаружи",  False),
    ("address",  "Адрес от провайдера",      "снаружи",  False),
    ("gateway",  "Шлюз провайдера на связи", "снаружи",  False),
    ("internet", "Путь в интернет",          "снаружи",  False),
    ("dns",      "Имена разрешаются",        "на шлюзе", True),
    ("egress",   "Туннель несёт трафик",     "на шлюзе", True),
]


def ladder(iface: str, socks: str = "127.0.0.1:1081") -> dict:
    """
    Walk the preconditions in order and stop at the first unmet one.

    Everything below the first failure is consequence, not evidence, and is
    reported as "не проверялось" rather than as a second problem. During the
    September outage every layer reported the layer below it as broken because
    nothing did this.
    """
    env = environment(iface)
    checks = {
        "cable":    lambda: (has_carrier(iface), "несущая есть" if has_carrier(iface)
                             else "несущей нет — кабель не воткнут или порт мёртв"),
        "address":  lambda: (bool(env["cidr"]),
                             env["cidr"] or "DHCP не дал адрес"),
        "gateway":  lambda: gateway_on_the_wire(env["gateway"]),
        "internet": lambda: (reaches_internet(), "TCP наружу проходит"),
        "dns":      lambda: (resolves(), "резолвер отвечает"),
        "egress":   lambda: (egress_carries(socks), "туннель отвечает"),
    }
    rungs, first = [], None
    for key, title, owner, fixable in RUNGS:
        if first is not None:
            rungs.append({"key": key, "title": title, "ok": None,
                          "detail": "не проверялось — выше по цепочке уже обрыв",
                          "owner": owner, "fixable_here": fixable})
            continue
        ok, detail = checks[key]()
        if not ok and not detail:
            detail = "не прошло"
        rungs.append({"key": key, "title": title, "ok": bool(ok),
                      "detail": detail, "owner": owner, "fixable_here": fixable})
        if not ok:
            first = key
    healthy = first is None
    row = next((r for r in rungs if r["key"] == first), None) if first else None
    return {
        "ts": int(time.time()),
        "healthy": healthy,
        "environment": env,
        "rungs": rungs,
        "first_unmet": first,
        "owner": row["owner"] if row else None,
        "fixable_here": bool(row["fixable_here"]) if row else False,
        "summary": ("всё в порядке" if healthy else
                    "%s — %s" % (row["title"], row["detail"])),
    }


# ── remedies that stop repeating ──────────────────────────────────────────────

def remedy_allowed(state: dict, remedy: str, diagnosis: dict,
                   max_attempts: int = 3, window_sec: int = 1800) -> tuple[bool, str]:
    """
    Whether to apply an automatic fix, and if not, why not.

    Two reasons to refuse. The fault is not ours to fix -- restarting the tunnel
    while the cable is out is theatre, and it filled a log with noise during the
    last outage. Or the same remedy has already been tried and has not worked;
    at that point applying it again is not a fix in progress, it is evidence
    that the diagnosis is wrong, and the right move is to say so.
    """
    if diagnosis.get("healthy"):
        return False, "чинить нечего"
    if not diagnosis.get("fixable_here"):
        return False, ("не наша неисправность (%s): %s"
                       % (diagnosis.get("owner"), diagnosis.get("summary")))
    rec = (state.get("remedies") or {}).get(remedy) or {}
    now = time.time()
    attempts = [t for t in rec.get("attempts", []) if now - t < window_sec]
    if len(attempts) >= max_attempts:
        return False, ("уже %d попытки за %d мин не помогли — диагноз неверен, "
                       "повторять бессмысленно"
                       % (len(attempts), window_sec // 60))
    return True, "попытка %d из %d" % (len(attempts) + 1, max_attempts)


def record_remedy(state: dict, remedy: str, window_sec: int = 1800) -> dict:
    rec = (state.setdefault("remedies", {})).setdefault(remedy, {})
    now = time.time()
    rec["attempts"] = [t for t in rec.get("attempts", []) if now - t < window_sec]
    rec["attempts"].append(now)
    rec["last"] = now
    return state


def clear_remedy(state: dict, remedy: str) -> dict:
    (state.setdefault("remedies", {})).pop(remedy, None)
    return state
