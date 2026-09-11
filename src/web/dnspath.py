"""
DNS that shows whether it works.

The setting was never the problem. During the outage the resolver configuration
was correct and the resolution path was dead, and nothing in the product could
tell the two apart -- so the operator stared at a form full of right answers
while no name resolved.

What was there instead was worse than nothing. `get_dns_status` "tested" each
upstream by calling connect() on a UDP socket, which touches no network at all
and cannot fail: on this gateway it reported 192.0.2.1 and 203.0.113.99 -- two
documentation addresses nobody on earth answers -- as reachable in 0 ms, while
reporting the one resolver the box actually uses as unreachable, because the
`127.0.0.1#5053` form made the address parser throw. A perfect inversion,
presented with a green tick.

So everything here sends a real query and waits for a real answer. A resolver is
answering because it answered; a latency is a measured round trip; and when
something cannot be determined it says so rather than defaulting to good news.
"""
from __future__ import annotations

import random
import re
import socket
import string
import struct
import time
from pathlib import Path

SYSFS = Path("/sys/class/net")
NETIF_LEASES = Path("/run/systemd/netif/leases")
DOH_PROXY = Path("/opt/shunt/doh_proxy.py")

# What the DoH proxy forwards to, when its source cannot be read.
DOH_FALLBACK = ["1.1.1.1", "1.0.0.1"]

# Probing with a fixed name measures the cache, not the path. A random label
# under a domain that exists returns NXDOMAIN from the far end, which proves the
# whole chain answered -- which is the question being asked.
PROBE_SUFFIX = "example.com"


def parse_server(spec: str) -> tuple[str, int]:
    """'1.1.1.1' or dnsmasq's '127.0.0.1#5053' -> (address, port)."""
    addr, sep, port = str(spec).strip().partition("#")
    if sep and port.isdigit():
        return addr, int(port)
    return addr, 53


def random_name(suffix: str = PROBE_SUFFIX) -> str:
    label = "".join(random.choice(string.ascii_lowercase) for _ in range(12))
    return f"{label}.{suffix}"


def encode_query(name: str, txid: int | None = None, qtype: int = 1) -> bytes:
    """A standard recursive A query. No library: one packet, written out."""
    txid = random.randint(1, 65535) if txid is None else txid
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("idna" if not p.isascii() else "ascii")
                     for p in name.rstrip(".").split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def _skip_name(data: bytes, i: int) -> int:
    while i < len(data):
        n = data[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:          # compression pointer ends the name
            return i + 2
        i += 1 + n
    return i


def decode_response(data: bytes, expect_txid: int | None = None) -> dict:
    """Transaction id, rcode and any A records, without trusting the sender."""
    if len(data) < 12:
        return {"ok": False, "error": "ответ короче заголовка"}
    txid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    if expect_txid is not None and txid != expect_txid:
        return {"ok": False, "error": "чужой идентификатор ответа"}
    rcode = flags & 0x0F
    i = 12
    for _ in range(qd):
        i = _skip_name(data, i) + 4
    addrs = []
    for _ in range(an):
        i = _skip_name(data, i)
        if i + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4 and i + 4 <= len(data):
            addrs.append(socket.inet_ntoa(data[i:i + 4]))
        i += rdlen
    return {"ok": True, "rcode": rcode, "answers": addrs,
            "authoritative": bool(flags & 0x0400)}


# RCODEs worth naming. Anything that comes back at all proves the resolver is
# alive; what it says is a separate question, and both belong on the page.
RCODE_NAMES = {0: "ответ", 1: "ошибка формата", 2: "сбой у резолвера",
               3: "имя не существует", 4: "не поддерживается", 5: "отказано"}


def probe(spec: str, name: str | None = None, timeout: float = 2.0,
          source_ip: str | None = None) -> dict:
    """
    Ask one resolver one question and report what actually came back.

    Not "is the port open" and emphatically not connect() on a UDP socket --
    that is what used to be here and it could not fail.
    """
    addr, port = parse_server(spec)
    name = name or random_name()
    txid = random.randint(1, 65535)
    out: dict = {"server": spec, "address": addr, "port": port}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        if source_ip:
            s.bind((source_ip, 0))
        t0 = time.time()
        s.sendto(encode_query(name, txid), (addr, port))
        data, _ = s.recvfrom(4096)
        ms = (time.time() - t0) * 1000
        r = decode_response(data, expect_txid=txid)
        if not r["ok"]:
            out.update(answering=False, error=r["error"])
            return out
        out.update(answering=True, latency_ms=round(ms, 1), rcode=r["rcode"],
                   rcode_name=RCODE_NAMES.get(r["rcode"], "код %d" % r["rcode"]),
                   answers=r["answers"])
        return out
    except socket.timeout:
        out.update(answering=False, error="не ответил за %.0f с" % timeout)
        return out
    except OSError as e:
        out.update(answering=False, error=str(e) or type(e).__name__)
        return out
    finally:
        s.close()


def lease_resolvers(iface: str) -> list[str]:
    """
    The resolvers the provider handed out with the lease.

    These matter more than they look: they are the only name service that does
    not depend on the tunnel, and the tunnel cannot come up until a name
    resolves. During the outage they were reachable the whole time and nothing
    offered them.
    """
    try:
        idx = (SYSFS / iface / "ifindex").read_text().strip()
        for ln in (NETIF_LEASES / idx).read_text().splitlines():
            if ln.startswith("DNS="):
                return [p for p in ln.split("=", 1)[1].split() if p]
    except OSError:
        pass
    return []


def doh_upstreams(path: Path = DOH_PROXY) -> list[str]:
    """Where the local DoH proxy forwards, read from the proxy itself."""
    try:
        m = re.search(r"^UP\s*=\s*\[(.+?)\]", path.read_text(), re.M | re.S)
        if m:
            found = re.findall(r'"(\d+\.\d+\.\d+\.\d+)"', m.group(1))
            if found:
                return found
    except OSError:
        pass
    return list(DOH_FALLBACK)


def inventory(settings: dict, iface: str, lan_ip: str | None = None) -> list[dict]:
    """
    Every resolver on this box worth asking about, and its part in the chain.

    Deduplicated by address, because the same resolver appearing twice with two
    different verdicts is how a page loses a reader's trust.
    """
    dns = settings.get("dns", {}) or {}
    seen: dict[str, dict] = {}

    def add(spec: str, role: str, label: str, in_use: bool):
        key = "%s:%d" % parse_server(spec)
        if key in seen:
            seen[key]["roles"].append(role)
            return
        seen[key] = {"server": spec, "roles": [role], "label": label,
                     "in_use": in_use}

    # Deliberately NOT probing lan_ip:53. dnsmasq listens on 5335; devices
    # reach it because nat PREROUTING redirects port 53, and PREROUTING does
    # not apply to packets this box sends itself. Probing it from here answers
    # "silent" while every device on the LAN resolves perfectly -- a false
    # alarm dressed as a measurement. That hop is checked by redirect_state()
    # instead, which counts the packets actually being redirected.
    add("127.0.0.1#5335", "dnsmasq", "dnsmasq — сюда попадают устройства", True)
    for u in dns.get("upstream", []):
        add(u, "upstream", "верхний резолвер dnsmasq", True)
    for u in dns.get("upstream_ru", []):
        add(u, "upstream_ru", "верхний резолвер для .ru и .local", True)
    for u in doh_upstreams():
        add(u, "doh", "куда ходит DoH-прокси (через туннель)", True)
    configured = {parse_server(x)[0] for x in
                  list(dns.get("upstream", [])) + list(dns.get("upstream_ru", []))}
    for u in lease_resolvers(iface):
        add(u, "lease", "выдан провайдером в аренде" +
            ("" if u in configured else " — не используется"), u in configured)
    return list(seen.values())


def parse_redirect(nat_output: str) -> dict:
    """
    The rule that puts every device's DNS into dnsmasq, and how much it has
    carried.

    This is the right way to check that hop. dnsmasq listens on 5335 and the
    devices ask port 53; what joins the two is a REDIRECT in nat PREROUTING,
    which a query sent from the gateway itself never passes through. Counting
    the packets it has redirected says the hop works; asking lan_ip:53 from
    here says it does not, and would be wrong.
    """
    udp = tcp = None
    for ln in nat_output.splitlines():
        f = ln.split()
        if len(f) < 2 or not f[0].isdigit() or not f[1].isdigit():
            continue
        if "REDIRECT" not in ln or "dpt:53" not in ln:
            continue
        if " udp " in ln and udp is None:
            udp = int(f[0])
        elif " tcp " in ln and tcp is None:
            tcp = int(f[0])
    present = udp is not None or tcp is not None
    return {"present": present, "udp_packets": udp, "tcp_packets": tcp,
            "carrying": bool((udp or 0) + (tcp or 0))}


def describe_chain(settings: dict, lan_ip: str | None = None) -> list[dict]:
    """
    The upstream chain written out, so nobody has to reconstruct it.

    Three hops on this gateway, and during the outage every one of them was
    blamed for the others.
    """
    dns = settings.get("dns", {}) or {}
    hops = [{
        "step": "Устройства в сети",
        "to": "%s:53 → dnsmasq на 5335" % (lan_ip or "?"),
        "via": "перенаправление в nat PREROUTING",
        "note": "устройства спрашивают порт 53, слушает dnsmasq на 5335; "
                "их соединяет правило перенаправления",
    }]
    ru = list(dns.get("upstream_ru", []))
    if ru:
        hops.append({
            "step": "Имена .ru и .local",
            "to": ", ".join(ru),
            "via": "напрямую, мимо туннеля",
            "note": "резолверы провайдера — единственный путь, не зависящий "
                    "от туннеля",
        })
    up = list(dns.get("upstream", []))
    if up:
        local = [u for u in up if parse_server(u)[0].startswith("127.")]
        hops.append({
            "step": "Все остальные имена",
            "to": ", ".join(up),
            "via": "DoH-прокси" if local else "напрямую",
            "note": "" if not local else
                    "дальше по HTTPS на %s через туннель"
                    % ", ".join(doh_upstreams()),
        })
    return hops
