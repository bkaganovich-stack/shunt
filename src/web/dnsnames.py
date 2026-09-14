"""
Giving the addresses in the traffic log their names back.

access.log records destinations as addresses and never as names. The cause is
`routeOnly` on the inbound: the sniffer reads the name, uses it to choose a
route, and discards it. Turning that off was tried, measured against Xray
26.3.27 on the live gateway, and changed nothing -- the access line is written
from the original destination whatever sniffing decides afterwards. So the
names have to come from somewhere else.

They already pass through this box. Every client on the network resolves
through dnsmasq and `doh_proxy.py`, and the answer that comes back carries both
the name that was asked for and the addresses it maps to. Reading it costs a
parse of a packet that is already in memory.

Two things this file is careful about, both learned before writing it:

**Stale names are worse than none.** A CDN address is handed to a different
site within the hour, and a page that confidently says "instagram" about an
address now serving something else is worse than one that says 157.240.205.60.
So entries expire, and the most recent answer always wins.

**The resolver must not depend on this.** A DNS proxy that has to write
something down before it can answer is a DNS proxy that fails when the disk is
busy -- and on this gateway a failed resolver means no tunnel, because the
tunnel needs a name of its own. Recording is in memory, bounded, and dumped on
a timer; every path through it swallows its own errors.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import time
from pathlib import Path

# tmpfs on purpose: this is a cache that can be rebuilt by a minute of traffic,
# and it must not add disk writes to the resolver's path or a file to rotate.
DUMP = Path("/run/shunt-dns-names.json")

TTL_SECONDS = 3600      # an address may belong to someone else after an hour
MAX_ENTRIES = 20000     # ~2 MB of JSON; a household resolves far fewer

A, AAAA, CNAME = 1, 28, 5


def _read_name(buf: bytes, off: int) -> int:
    """Skip over a DNS name and return the offset after it. Handles pointers."""
    while True:
        if off >= len(buf):
            raise ValueError("truncated name")
        n = buf[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:            # compression pointer ends the name
            return off + 2
        off += 1 + n
        if n & 0xC0:                    # reserved label type
            raise ValueError("bad label")


def _question_name(buf: bytes, off: int) -> tuple[str, int]:
    labels = []
    while True:
        if off >= len(buf):
            raise ValueError("truncated question")
        n = buf[off]
        if n == 0:
            return ".".join(labels).lower(), off + 1
        if n & 0xC0:
            # A question name is never compressed; anything else is malformed.
            raise ValueError("compressed question")
        labels.append(buf[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n


def parse_answer(raw: bytes) -> tuple[str, list[str]]:
    """
    The name that was asked for, and the addresses the answer gave it.

    Deliberately keyed on the QUESTION rather than on each record's owner. After
    a CNAME chain the A record belongs to the last alias -- `instagram.com` ends
    at something like `z-p42-instagram.c10r.facebook.com` -- and the household
    asked for the first one. Recording the alias would technically describe the
    packet and would be useless on a page a person reads.
    """
    if len(raw) < 12:
        return "", []
    qd, an = struct.unpack("!HH", raw[4:8])
    if qd < 1 or an < 1:
        return "", []
    off = 12
    try:
        name, off = _question_name(raw, off)
        off += 4                                    # QTYPE + QCLASS
        for _ in range(qd - 1):                     # multi-question is legal
            _, off = _question_name(raw, off)
            off += 4
        ips = []
        for _ in range(an):
            off = _read_name(raw, off)
            if off + 10 > len(raw):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", raw[off:off + 10])
            off += 10
            rdata = raw[off:off + rdlen]
            off += rdlen
            if rtype == A and rdlen == 4:
                ips.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif rtype == AAAA and rdlen == 16:
                ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
    except (ValueError, struct.error, OSError):
        return "", []
    return name, ips


class NameMap:
    """A bounded, expiring address-to-name map."""

    def __init__(self, ttl: int = TTL_SECONDS, limit: int = MAX_ENTRIES):
        self.ttl = ttl
        self.limit = limit
        self._m: dict[str, tuple[str, int]] = {}

    def record(self, name: str, ips: list[str], now: float | None = None) -> int:
        now = int(now if now is not None else time.time())
        if not name or not ips:
            return 0
        for ip in ips:
            # Last answer wins: the newest name for an address is the one the
            # household is actually talking to.
            self._m[ip] = (name, now)
        if len(self._m) > self.limit:
            self._evict(now)
        return len(ips)

    def lookup(self, ip: str, now: float | None = None) -> str:
        now = int(now if now is not None else time.time())
        hit = self._m.get(ip)
        if not hit:
            return ""
        name, seen = hit
        return name if now - seen <= self.ttl else ""

    def _evict(self, now: int) -> None:
        # Snapshot first. This runs on the resolver's own threads, and
        # rebuilding a dict while another thread assigns into it raises
        # "dictionary changed size during iteration" -- which on this gateway
        # would be a DNS failure, and a DNS failure is no tunnel at all. A
        # snapshot can lose an entry written mid-rebuild; that is a cache miss
        # and nobody notices.
        fresh = {ip: v for ip, v in list(self._m.items())
                 if now - v[1] <= self.ttl}
        if len(fresh) > self.limit:
            # Still over after expiry: drop the oldest down to the limit.
            ordered = sorted(fresh.items(), key=lambda kv: kv[1][1], reverse=True)
            fresh = dict(ordered[:self.limit])
        self._m = fresh

    def prune(self, now: float | None = None) -> int:
        now = int(now if now is not None else time.time())
        before = len(self._m)
        self._m = {ip: v for ip, v in list(self._m.items())
                   if now - v[1] <= self.ttl}
        return before - len(self._m)

    def __len__(self) -> int:
        return len(self._m)

    # ── crossing the process boundary ────────────────────────────────────────
    # The resolver records; the interface and the block probe read. A file on
    # tmpfs is the whole mechanism: no database on the resolver's path, and
    # nothing to rotate.

    def dump(self, path: Path | None = None) -> bool:
        # Resolved at call time, not bound as a default: a default argument is
        # captured when the function is defined, so the module-level path could
        # never be changed afterwards -- not by a test and not by an operator.
        path = Path(path) if path is not None else DUMP
        try:
            tmp = Path(str(path) + ".tmp")
            tmp.write_text(json.dumps(
                {ip: [n, t] for ip, (n, t) in list(self._m.items())}))
            os.replace(tmp, path)          # readers never see half a file
            return True
        except OSError:
            return False

    @classmethod
    def load(cls, path: Path | None = None, ttl: int = TTL_SECONDS,
             now: float | None = None) -> "NameMap":
        path = Path(path) if path is not None else DUMP
        m = cls(ttl=ttl)
        try:
            raw = json.loads(path.read_text())
        except (OSError, ValueError):
            return m
        now = int(now if now is not None else time.time())
        if isinstance(raw, dict):
            m._m = {ip: (v[0], int(v[1])) for ip, v in raw.items()
                    if isinstance(v, list) and len(v) == 2
                    and now - int(v[1]) <= ttl}
        return m


def name_for(ip: str, cached: NameMap | None = None,
             now: float | None = None) -> str:
    """Convenience for callers holding one map: the name, or the address."""
    if cached is None:
        return ip
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return ip                      # already a name
    return cached.lookup(ip, now) or ip
