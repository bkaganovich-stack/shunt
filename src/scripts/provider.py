"""
What this gateway assumes about its provider, checked against the provider.

The September outage was not caused by a wrong setting. It was caused by a
right setting whose precondition had quietly stopped holding: the interception
chain excepted RFC1918, the box had been on RFC1918 for its whole life, and then
it was not. Three assumptions broke at once -- the WAN address family, public
DoH being reachable, a lease measured in days -- and not one of them was written
down anywhere, so nothing could notice.

This module writes them down as checks rather than as prose. Each one names the
assumption, tests it against what the provider is actually doing right now, and
says what to do when it fails. The headline check is the outage itself: is the
gateway's own address excepted from interception? If the answer is no, every
packet arriving for the box is swallowed, DNS included, and every layer above
will report the layer below as broken for as long as it takes someone to think
of looking here.

The fingerprint alongside it is the "named set" -- the traits that identify one
provider and distinguish it from the next. It exists so that "this is a
different provider" is a sentence the box can say, rather than a conclusion a
person reaches on the second day.
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import time
from pathlib import Path

SYSFS = Path("/sys/class/net")
NETIF_LEASES = Path("/run/systemd/netif/leases")
PROFILES = Path("/opt/shunt/logs/provider-profiles.json")
PROFILES_MAX = 10


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


# ── the traits that identify a provider ───────────────────────────────────────

def fingerprint(iface: str) -> dict:
    """
    The observable traits of whoever is on the other end of the WAN port.

    Deliberately not the address: that changes within one provider and would
    make every renewal look like a new company. The DHCP server, the gateway's
    network and the resolvers it hands out are what actually differ between one
    provider and the next.
    """
    cidr = None
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)",
                  _run("ip", "-4", "-o", "addr", "show", iface))
    if m:
        cidr = m.group(1)
    lease: dict = {}
    idx = _read(SYSFS / iface / "ifindex")
    for ln in ((_read(NETIF_LEASES / idx) or "").splitlines() if idx else []):
        if "=" not in ln:
            continue
        k, v = ln.split("=", 1)
        lease[k.strip()] = v.strip()
    gw = ""
    g = re.search(r"default via (\S+)", _run("ip", "route", "show", "default"))
    if g:
        gw = g.group(1)
    net = None
    if cidr:
        try:
            net = str(ipaddress.ip_interface(cidr).network)
        except ValueError:
            net = None
    mac = _read(SYSFS / iface / "address")
    perm = None
    pm = re.search(r"permaddr (\S+)", _run("ip", "link", "show", iface))
    if pm:
        perm = pm.group(1)
    return {
        "iface": iface,
        "network": net,
        "gateway": gw,
        "dhcp_server": lease.get("SERVER_ADDRESS"),
        "resolvers": (lease.get("DNS") or "").split(),
        "lease_seconds": _duration(lease.get("LIFETIME", "")),
        "mac": mac,
        "permanent_mac": perm,
        "mac_cloned": bool(perm and mac and perm.lower() != mac.lower()),
    }


def _duration(v: str) -> int | None:
    total, seen = 0, False
    for num, unit in re.findall(r"(\d+)\s*(usec|msec|min|h|m|s)?", v or ""):
        if not num:
            continue
        seen = True
        total += int(num) * {"h": 3600, "min": 60, "m": 60, "s": 1,
                             "msec": 0, "usec": 0, "": 1}[unit]
    return total if seen else None


def same_provider(a: dict, b: dict) -> bool:
    """
    Whether two fingerprints are plausibly the same provider.

    The DHCP server is the strongest single signal -- it survives address
    changes and renewals -- with the resolvers as a second opinion. This is
    deliberately loose: being told "this looks like a different provider" when
    it is only a different access node costs a glance, while missing an actual
    change costs a day.
    """
    if not a or not b:
        return False
    if a.get("dhcp_server") and a.get("dhcp_server") == b.get("dhcp_server"):
        return True
    ra, rb = set(a.get("resolvers") or []), set(b.get("resolvers") or [])
    return bool(ra and ra == rb)


# ── the assumptions, checked ──────────────────────────────────────────────────

def chain_excepts(address: str, chain_output: str) -> tuple[bool | None, str]:
    """
    Would a packet addressed to us be delivered, or swallowed by interception?

    The whole September outage, reduced to one question. The chain excepted
    RFC1918 and the box had moved to CGNAT, so every packet for its own address
    went into the tunnel instead of to the socket waiting for it.
    """
    try:
        ip = ipaddress.ip_address(address.split("/")[0])
    except ValueError:
        return None, "адрес не разобран"
    for ln in chain_output.splitlines():
        f = ln.split()
        if len(f) < 9 or not f[0].isdigit() or not f[1].isdigit():
            continue
        target, proto, src, dst = f[2], f[3], f[7], f[8]
        extra = " ".join(f[9:])
        if src not in ("0.0.0.0/0", "::/0"):
            continue
        if "dpt:" in extra or "spt:" in extra or extra.startswith("mark match"):
            continue                       # port and mark rules: a different question
        if dst in ("0.0.0.0/0", "::/0"):
            covers = True
        else:
            try:
                covers = ip in ipaddress.ip_network(dst, strict=False)
            except ValueError:
                continue
        if not covers:
            continue
        # An exception has to be unconditional to count. The TPROXY rules, by
        # contrast, are written per protocol -- one for tcp and one for udp --
        # so a protocol-scoped interception is still interception, while a
        # protocol-scoped RETURN would only except that protocol and must not
        # be read as covering the address.
        if target == "RETURN" and proto == "all":
            return True, "исключён правилом для %s" % dst
        if target == "TPROXY":
            return False, ("попадает под перехват (%s%s)"
                           % (dst, "" if proto == "all" else ", %s" % proto))
    return False, "ни одно исключение не покрывает этот адрес"


def audit(fp: dict, chain_output: str, lan_cidr: str | None,
          doh_ok: bool | None = None, resolver_ok: bool | None = None) -> list[dict]:
    """
    Every assumption this gateway makes about its provider, with a verdict.

    Ordered by what it costs to be wrong. The first one is the outage.
    """
    out = []

    net = fp.get("network")
    if net:
        own = net.split("/")[0]
        # The address itself, not the network address, is what packets arrive for.
        addr = None
        try:
            addr = str(ipaddress.ip_network(net).network_address + 1)
        except ValueError:
            pass
        holds, detail = chain_excepts(addr or own, chain_output)
        out.append({
            "id": "own_address_excepted",
            "title": "Собственная сеть шлюза исключена из перехвата",
            "holds": holds,
            "detail": "%s — %s" % (net, detail),
            "remedy": ("Добавить %s в список исключений XRAY_PREROUTING. Без "
                       "этого каждый пакет, адресованный самому шлюзу, уходит "
                       "в туннель вместо доставки — включая ответы DNS." % net),
        })

    if net and lan_cidr:
        try:
            wan_net = ipaddress.ip_network(net)
            lan_net = ipaddress.ip_network(lan_cidr, strict=False)
            overlap = wan_net.overlaps(lan_net)
        except ValueError:
            overlap = None
        out.append({
            "id": "lan_wan_overlap",
            "title": "Сеть провайдера не пересекается с локальной",
            "holds": (not overlap) if overlap is not None else None,
            "detail": "провайдер %s, локальная %s" % (net, lan_cidr),
            "remedy": "Сменить адресацию локальной сети — при пересечении "
                      "маршрутизация становится неоднозначной.",
        })

    out.append({
        "id": "doh_reachable",
        "title": "Публичный DoH доступен у этого провайдера",
        "holds": doh_ok,
        "detail": "проверен локальный DoH-прокси" if doh_ok is not None
                  else "не проверялось",
        "remedy": "Если недоступен — имена должны разрешаться резолверами "
                  "провайдера, иначе туннель не поднимется: он сам ждёт имени.",
    })

    res = fp.get("resolvers") or []
    out.append({
        "id": "provider_resolvers",
        "title": "Провайдер выдал резолверы, и они отвечают",
        "holds": (bool(res) and resolver_ok) if resolver_ok is not None
                 else (True if res else False),
        "detail": (", ".join(res) if res else "в аренде резолверов нет"),
        "remedy": "Это единственная служба имён, не зависящая от туннеля. "
                  "Без неё холодный старт упирается в замкнутый круг.",
    })

    # Recorded, not judged. Cloning the WAN MAC is a deliberate act -- it was
    # done here on purpose when the provider changed -- so flagging it as a
    # broken assumption would put a permanent red mark on a page for something
    # nobody should act on. A warning that is always true teaches the reader to
    # ignore warnings. What matters is that the dependency is written down for
    # the day the hardware is replaced.
    out.append({
        "id": "mac_registration",
        "title": "MAC на WAN",
        "holds": None,
        "informational": True,
        "detail": ("подменён намеренно: %s вместо аппаратного %s"
                   % (fp.get("mac"), fp.get("permanent_mac")))
                  if fp.get("mac_cloned") else
                  ("аппаратный: %s" % (fp.get("mac") or "неизвестен")),
        "remedy": ("Провайдер может привязывать сессию к MAC. При замене железа "
                   "этот адрес надо перенести на новую карту, иначе адрес не "
                   "выдадут." if fp.get("mac_cloned") else
                   "Подмены нет — при замене железа MAC изменится; если "
                   "провайдер привязывается к нему, сессию придётся пересоздать."),
    })
    return out


def failing(checks: list[dict]) -> list[dict]:
    return [c for c in checks if c.get("holds") is False]


# ── remembering providers ─────────────────────────────────────────────────────

def load_profiles(path: Path = PROFILES) -> list[dict]:
    try:
        v = json.loads(path.read_text())
        return v if isinstance(v, list) else []
    except (OSError, ValueError):
        return []


def remember(fp: dict, path: Path = PROFILES, now: float | None = None) -> tuple[list[dict], bool]:
    """
    Record this provider, and say whether it is one we have seen before.

    Returns (profiles, is_new). A provider we already know gets its last_seen
    touched; a new one is appended -- and "the provider changed" is then a thing
    the box can state on the day it happens rather than a thing worked out
    afterwards from a journal.
    """
    now = int(now if now is not None else time.time())
    profiles = load_profiles(path)
    for p in profiles:
        if same_provider(p.get("fingerprint") or {}, fp):
            p["last_seen"] = now
            p["fingerprint"] = fp
            _save(profiles, path)
            return profiles, False
    profiles.append({"first_seen": now, "last_seen": now, "fingerprint": fp})
    profiles = profiles[-PROFILES_MAX:]
    _save(profiles, path)
    return profiles, True


def _save(profiles: list[dict], path: Path) -> None:
    try:
        path.write_text(json.dumps(profiles, ensure_ascii=False))
    except OSError:
        pass
