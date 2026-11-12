#!/usr/bin/env python3
"""
A device that opens connections in a loop, and what to do about it.

On 2026-11-12 one Windows PC behind the router opened 120 connections a second
for four hours: forty addresses on port 443, each in turn, SYN, ACK, FIN,
nothing sent. The exit's connection table (8192 entries) was full two minutes
in and stayed full; the tunnel dropped every new connection while each health
check on this box answered "the internet is unreachable, not our fault".
Nothing here counted connections, so nothing could say what was happening.

**Why not a plain limit per address.** Measured over the four ordinary days
before it: the house opened up to 770 connections a minute to a single address
(DNS over HTTPS to 1.1.1.1) and 412 to another, for five to seven minutes at a
time. The flood sent 180 a minute to each of its addresses. A limit low enough
to stop the flood breaks name resolution; one high enough to spare it stops
nothing. Volume per address does not tell the two apart.

**What does.** The flood is many addresses hammered at once, steadily, for
minutes on end. In those four days no minute had more than three addresses
above sixty connections; the flood had forty, in every minute. So the rule is
about breadth and persistence, and the response closes those addresses for
that source only -- every other connection in the house is untouched.

The quarantine keeps itself: an entry lasts ten minutes and is renewed by the
kernel only while that address is still being tried more than twenty times a
minute. When the program is closed, the entries expire on their own.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ACCESS_LOG = Path("/opt/shunt/logs/access.log")

WINDOW_MIN    = 3      # consecutive complete minutes that must all qualify
HOT_PER_MIN   = 60     # connections a minute that make one address "hot"
MIN_HOT_DESTS = 10     # hot addresses at once, from one source, to call it a flood
VOLUME_PER_MIN = 4000  # from one source, to anything: reported, never blocked
TAIL_BYTES    = 8 * 1024 * 1024
STALE_SEC     = 150    # a log nobody has written to says nothing about now
MAX_TARGETS   = 256

TABLE         = "shunt_flood"
QUARANTINE_MIN = 10
STILL_HOT     = "20/minute"

# 2026/11/12 16:05:11.042367 from 192.168.100.45:58135 accepted tcp:1.2.3.4:443 [tproxy-in -> proxy]
_LINE = re.compile(
    r"^(\d{4}/\d\d/\d\d \d\d:\d\d):\S+ from (?:tcp:|udp:)?(\S+):\d+ accepted tcp:(\S+):(\d+)\b")


def _nft(*args: str, stdin: str | None = None, timeout: int = 10):
    try:
        return subprocess.run(["nft", *args], input=stdin, capture_output=True,
                              text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(args, 1, "", str(e))


# ── reading ───────────────────────────────────────────────────────────────────

def parse(lines) -> dict:
    """minute -> source -> Counter{(destination, port): connections}."""
    out: dict = defaultdict(lambda: defaultdict(Counter))
    for ln in lines:
        m = _LINE.match(ln)
        if not m:
            continue
        minute, src, dst, port = m.groups()
        out[minute][src.strip("[]")][(dst.strip("[]"), int(port))] += 1
    return out


def tail_lines(path: Path = ACCESS_LOG, size: int = TAIL_BYTES) -> list[str]:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            f.seek(max(0, end - size))
            data = f.read()
    except OSError:
        return []
    lines = data.decode("utf-8", "replace").splitlines()
    return lines[1:] if end > size else lines   # the first one is cut in half


def _minutes_before(newest: str, n: int) -> list[str]:
    t = datetime.strptime(newest, "%Y/%m/%d %H:%M")
    return [(t - timedelta(minutes=i)).strftime("%Y/%m/%d %H:%M")
            for i in range(n, 0, -1)]


def detect(stats: dict, newest: str | None = None) -> dict | None:
    """
    Is one source flooding, judged on the last complete minutes.

    The newest minute in the log is still being written and is left out. A
    minute with no lines counts as a quiet one, so a gap ends a flood rather
    than hiding it.
    """
    if not stats:
        return None
    newest = newest or max(stats)
    window = _minutes_before(newest, WINDOW_MIN)
    sources = set()
    for mn in window:
        sources.update(stats.get(mn, {}))
    best = None
    for src in sources:
        hot_sets, totals = [], []
        for mn in window:
            c = stats.get(mn, {}).get(src, Counter())
            hot_sets.append({d for d, n in c.items() if n >= HOT_PER_MIN})
            totals.append(sum(c.values()))
        per_min = sum(totals) // len(totals)
        if all(len(h) >= MIN_HOT_DESTS for h in hot_sets):
            targets = sorted(set.intersection(*hot_sets))
            v = {"kind": "pattern", "source": src, "per_minute": per_min,
                 "targets": targets[:MAX_TARGETS], "target_count": len(targets)}
        elif all(t >= VOLUME_PER_MIN for t in totals):
            v = {"kind": "volume", "source": src, "per_minute": per_min,
                 "targets": [], "target_count": 0}
        else:
            continue
        if best is None or (v["kind"], v["per_minute"]) > (best["kind"], best["per_minute"]):
            best = v
    return best


def check(path: Path = ACCESS_LOG, now: float | None = None) -> dict | None:
    """The verdict for right now, or None when there is nothing to say."""
    import time
    try:
        if (now or time.time()) - path.stat().st_mtime > STALE_SEC:
            return None
    except OSError:
        return None
    return detect(parse(tail_lines(path)))


# ── quarantine ────────────────────────────────────────────────────────────────

def _blockable(src: str, dst: str) -> bool:
    try:
        return (ipaddress.ip_address(src).version == 4
                and ipaddress.ip_address(dst).version == 4)
    except ValueError:
        return False   # a name, not an address: nothing to key a rule on


def ruleset() -> str:
    key = "ip saddr . ip daddr . tcp dport"
    return f"""
add table inet {TABLE}
add set inet {TABLE} quarantine {{ type ipv4_addr . ipv4_addr . inet_service; flags dynamic,timeout; timeout {QUARANTINE_MIN}m; size 4096; }}
add set inet {TABLE} still_hot {{ type ipv4_addr . ipv4_addr . inet_service; flags dynamic,timeout; timeout 2m; size 4096; }}
add chain inet {TABLE} pre {{ type filter hook prerouting priority -160; policy accept; }}
add chain inet {TABLE} held
flush chain inet {TABLE} pre
flush chain inet {TABLE} held
add rule inet {TABLE} pre tcp flags & (syn | ack) == syn {key} @quarantine jump held
add rule inet {TABLE} held add @still_hot {{ {key} limit rate over {STILL_HOT} }} update @quarantine {{ {key} timeout {QUARANTINE_MIN}m }}
add rule inet {TABLE} held counter drop
"""


def ensure_table() -> bool:
    return _nft("-f", "-", stdin=ruleset()).returncode == 0


def quarantine(source: str, targets) -> int:
    """Close these destinations for this source. Returns how many were added."""
    elems = ["%s . %s . %d timeout %dm" % (source, d, p, QUARANTINE_MIN)
             for d, p in targets if _blockable(source, d)]
    if not elems or not ensure_table():
        return 0
    r = _nft("add", "element", "inet", TABLE, "quarantine",
             "{ " + ", ".join(elems) + " }")
    return len(elems) if r.returncode == 0 else 0


def quarantined() -> list[tuple[str, str, int]]:
    r = _nft("-j", "list", "set", "inet", TABLE, "quarantine")
    if r.returncode != 0:
        return []
    out = []
    try:
        for item in json.loads(r.stdout).get("nftables", []):
            for e in (item.get("set") or {}).get("elem", []) or []:
                e = e.get("elem", e) if isinstance(e, dict) else e
                val = e.get("val", e) if isinstance(e, dict) else e
                parts = val.get("concat") if isinstance(val, dict) else None
                if parts and len(parts) == 3:
                    out.append((str(parts[0]), str(parts[1]), int(parts[2])))
    except (ValueError, TypeError, AttributeError):
        return []
    return out


def release() -> None:
    """Take the quarantine away entirely (also on package removal)."""
    _nft("delete", "table", "inet", TABLE)


# ── wording ───────────────────────────────────────────────────────────────────

def describe(v: dict | None, held: list, blocking: bool) -> tuple[str, str]:
    """(headline, detail) for the interface, in the operator's language."""
    src = (v or {}).get("source") or (held[0][0] if held else "?")
    if v and v["kind"] == "volume":
        return ("Поток соединений с адреса %s: около %d в минуту"
                % (src, v["per_minute"]),
                "Это в несколько раз больше обычного для всей сети. Найдите "
                "устройство с этим адресом (если это роутер — устройство за "
                "ним) и программу на нём. Ничего не заблокировано.")
    n = (v or {}).get("target_count") or len(held)
    rate = (" около %d в минуту," % v["per_minute"]) if v else ""
    head = ("Поток соединений с адреса %s:%s одни и те же %d адресов по кругу"
            % (src, rate, n))
    sample = ", ".join("%s:%d" % (d, p) for d, p in
                       ((v or {}).get("targets") or [(h[1], h[2]) for h in held])[:5])
    tail = ("Похоже на программу, которая без остановки проверяет список "
            "серверов (VPN- или прокси-клиент). Найдите устройство с этим "
            "адресом (если это роутер — устройство за ним) и закройте её. "
            "Например: %s." % sample)
    if blocking:
        tail += (" Эти адреса для этого источника временно закрыты (%d шт.), "
                 "остальной трафик не затронут; закрытие снимется само через "
                 "%d минут после остановки потока." % (len(held) or n, QUARANTINE_MIN))
    else:
        tail += " Ничего не заблокировано."
    return head, tail


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "release":
        release()
        print("quarantine removed")
    elif cmd == "replay":
        # Every window in a log, for checking the thresholds against history:
        #   zcat access.log.*.gz | connflood.py replay
        st = parse(sys.stdin)
        hits = [(mn, v) for mn in sorted(st) if (v := detect(st, mn))]
        print("%d minutes, %d would trigger" % (len(st), len(hits)))
        for mn, v in hits[:3] + hits[-1:]:
            print(mn, v["kind"], v["source"], v["per_minute"], v["target_count"])
    else:
        print(json.dumps({"flood": check(), "quarantined": quarantined()},
                         ensure_ascii=False, indent=1))
