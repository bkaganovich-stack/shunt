"""
Freeze detection from the household's own traffic.

The direct path here does not always refuse. More often it lets a connection
start and then stops it: the TLS handshake completes, the server begins to
answer, and after about sixteen kilobytes nothing more arrives -- ever. The page
"hangs". Measured on 2026-09-23 against Cloudflare, Hetzner, DigitalOcean and
Amazon, often only for some connections to an address and not others.

Nothing on any list describes this, and a probe that judges by the HTTP status
cannot see it either: the status line arrives before the freeze, so a frozen
site answers "200" (blockprobe.py records it as open). What does show it is the
socket xray itself holds towards the destination, because a freeze discards
everything the server sends, acknowledgements included. Whatever our side sends
afterwards -- the next HTTP/2 frame, or the FIN when the client gives up -- is
never acknowledged, and the kernel retransmits it with a growing backoff. A
connection that is merely idle has nothing outstanding and never looks like that.

One false friend: a long-lived connection that dies silently while idle -- the
provider's carrier-grade NAT forgets it -- ends the same way. It is told apart by
when the data stopped. A freeze stops the data in the first seconds of a
connection's life; an idle death stops it minutes or hours in.

This module is the pure part: parse `ss`, follow sockets from birth to death,
and turn what it saw into entries in the same record the block probe keeps
(settings["discovered"]), marked source "live". The loop that samples and
applies lives in main.py.
"""
from __future__ import annotations

import ipaddress
import re
import time

# Every five seconds. The evidence outlives that by far -- a frozen connection
# lasts until its client gives up, tens of seconds, and the kernel then
# retransmits the unacknowledged FIN for minutes -- and at two seconds the
# sampler cost 2-3% of a core on a two-core box for nothing it would not see.
SAMPLE_EVERY = 5.0      # seconds between samples
STALL_WITHIN = 30.0     # the data must stop this early in a socket's life
HANDSHAKE_BYTES = 8192  # below this the cut came before any real answer

DEFAULTS = {
    "enabled": True,
    "min_events": 3,        # frozen connections to one address before it is routed
    "window_hours": 24,     # ...within this long
    "ttl_days": 14,         # then back to direct, to find out whether it still freezes
    "apply_every_min": 30,  # at most one rebuild per this long: each one drops every connection
}

# States in which our side has closed. An unacknowledged FIN there is the most
# common form of the evidence: a frozen client sends nothing until it gives up.
_CLOSING = ("FIN-WAIT-1", "CLOSING", "LAST-ACK")


def settings_of(settings: dict) -> dict:
    return {**DEFAULTS, **(settings.get("freeze_detector") or {})}


def _field(block: str, key: str) -> str | None:
    m = re.search(r"\b" + key + r":(\S+)", block)
    return m.group(1) if m else None


def _host(endpoint: str) -> str:
    host = endpoint.rsplit(":", 1)[0].strip("[]")
    return host[7:] if host.startswith("::ffff:") else host


def parse_ss(text: str, owned: bool = False) -> list[dict]:
    """
    Sockets from `ss -tniHa`, one dict each. Lines it cannot read are skipped.

    `owned` says the listing was already narrowed to xray's sockets -- the
    sampler selects them by the fwmark xray puts on every direct connection,
    which also survives the socket being orphaned. Without it, ownership is
    read from the `users:` column of `ss -p`.
    """
    out = []
    for block in re.split(r"\n(?=\S)", text.strip()):
        head = block.split()
        if len(head) < 5 or head[0] == "LISTEN":
            continue
        out.append({
            "key": (head[3], head[4]),
            "state": head[0],
            "remote": _host(head[4]),
            "port": head[4].rsplit(":", 1)[-1],
            "xray": owned or '"xray"' in block,
            "rcv": int(_field(block, "bytes_received") or 0),
            "unacked": int(_field(block, "unacked") or 0),
            "backoff": int(_field(block, "backoff") or 0),
            "lastrcv": int(_field(block, "lastrcv") or 0),
        })
    return out


class Tracker:
    """
    Follows xray's outgoing sockets from birth and reports the ones that froze.

    Only sockets born while it watches are judged: for anything already open
    when it started there is no birth time, and without one a freeze cannot be
    told from an idle death. The owner is checked at birth only, because the
    evidence often arrives after xray has let go of the socket -- an orphaned
    FIN-WAIT-1 no longer names a process.
    """

    def __init__(self) -> None:
        self.started = False
        self.preexisting: set = set()
        self.born: dict = {}
        self.peak: dict = {}
        self.reported: set = set()

    def observe(self, sockets: list[dict], now: float) -> list[dict]:
        seen = set()
        events = []
        if not self.started:
            self.preexisting = {s["key"] for s in sockets}
            self.started = True
            return events
        for s in sockets:
            k = s["key"]
            seen.add(k)
            if k in self.preexisting or s["state"] == "SYN-SENT":
                continue
            if k not in self.born:
                if not s["xray"]:
                    continue
                self.born[k] = now
            self.peak[k] = max(self.peak.get(k, 0), s["rcv"])
            if k in self.reported:
                continue
            dead = ((s["state"] in _CLOSING and s["unacked"] > 0 and s["backoff"] >= 1)
                    or (s["state"] == "ESTAB" and s["unacked"] > 0 and s["backoff"] >= 2))
            if not dead:
                continue
            # When the last data arrived, measured from the socket's birth. A
            # socket that never received anything has no such moment and counts
            # as stopping at once.
            stopped = now - s["lastrcv"] / 1000.0 - self.born[k] if self.peak[k] else 0.0
            self.reported.add(k)
            if stopped > STALL_WITHIN:
                continue                      # it worked for a while: an idle death
            if not _routable(s["remote"]):
                continue
            rcv = self.peak[k]
            events.append({"ip": s["remote"], "port": s["port"], "rcv": rcv, "at": now,
                           "stage": "handshake" if rcv < HANDSHAKE_BYTES else "freeze"})
        # Forget what has gone, so the tables stay the size of the live set.
        for table in (self.born, self.peak):
            for k in [k for k in table if k not in seen]:
                del table[k]
        self.reported &= seen
        self.preexisting &= seen
        return events


def _routable(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_multicast or a.is_reserved
                or a.is_link_local)


def _describe(row: dict) -> str:
    kb = round(row.get("last_rcv", 0) / 1024)
    n = len(row.get("events", []))
    if row.get("stage") == "handshake":
        return "обрыв после рукопожатия ×%d" % n
    return "замерзает на ~%d КБ ×%d" % (kb, n)


def record(known: list[dict], events: list[dict], cfg: dict,
           now: float | None = None) -> tuple[list[dict], bool]:
    """
    Fold freeze events into the discovered record. Returns (record, routing_changed).

    An address is routed once `min_events` frozen connections to it fell inside
    the window: the freeze is often partial, so one frozen connection is
    evidence, and three are a pattern. An entry somebody switched off keeps
    collecting evidence but is never routed -- the switch is the operator's.
    """
    now = int(now if now is not None else time.time())
    window = int(cfg["window_hours"]) * 3600
    rows = [dict(r) for r in known]
    by_ip = {r.get("domain"): r for r in rows}
    changed = False
    for ev in events:
        row = by_ip.get(ev["ip"])
        if row is None:
            row = {"domain": ev["ip"], "enabled": True, "first_seen": now, "routed": False}
            rows.append(row)
            by_ip[ev["ip"]] = row
        elif row.get("source") != "live" and row.get("routed"):
            continue                          # already in the tunnel on other evidence
        row["source"] = "live"
        row["verdict"] = "frozen"
        row["events"] = [t for t in row.get("events", []) if now - t <= window][-19:] + [int(ev["at"])]
        row["last_rcv"] = ev["rcv"]
        row["stage"] = ev["stage"]
        row["last_checked"] = now
        row["direct"] = _describe(row)
        row["tunnel"] = "по живому трафику"
        if (not row.get("routed") and row.get("enabled", True)
                and len(row["events"]) >= int(cfg["min_events"])):
            row["routed"] = True
            row["routed_since"] = now
            changed = True
    return rows, changed


def expire(known: list[dict], cfg: dict, now: float | None = None) -> tuple[list[dict], bool]:
    """
    Send live-routed addresses back to direct after `ttl_days`.

    Once an address is in the tunnel its direct connections stop, so no new
    evidence can arrive either way. The only honest way to learn whether it
    still freezes is to let it go direct again; if it does, three frozen
    connections put it back.
    """
    now = int(now if now is not None else time.time())
    ttl = int(cfg["ttl_days"]) * 86400
    rows = [dict(r) for r in known]
    changed = False
    for r in rows:
        if r.get("source") == "live" and r.get("routed") and now - int(r.get("routed_since", now)) > ttl:
            r["routed"] = False
            r["events"] = []
            r["direct"] = "срок истёк — снова напрямую, на проверку"
            changed = True
    return rows, changed
