"""
Freeze detection from live sockets (src/web/freezewatch.py).

The cases are the ones measured on the gateway on 2026-09-23: a connection the
direct path froze after ~16 KB and the client then abandoned (FIN never
acknowledged), a long-lived connection that died idle in the provider's NAT
(same ending, different cause), and the ordinary endings that must not count.
The WAN address is a documentation range; destinations must be public, and
Python counts the documentation ranges as private, so 93.184.216.34 stands in.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "web"))
import freezewatch as fw
import blockprobe as bp

WAN = "198.51.100.7"


def sock(port, remote="93.184.216.34:443", state="ESTAB", owner="xray", rcv=0,
         unacked=0, backoff=0, lastrcv=0):
    users = f' users:(("{owner}",pid=42,fd=7))' if owner else ""
    return (f"{state} 0 0 {WAN}:{port} {remote}{users}\n"
            f"\t cubic rto:204 bytes_received:{rcv} unacked:{unacked} backoff:{backoff} "
            f"lastrcv:{lastrcv}")


def ss(*socks):
    return "\n".join(socks) + "\n"


def run(tracker, frames):
    """Feed (time, text) frames; return all events."""
    out = []
    for t, text in frames:
        out += tracker.observe(fw.parse_ss(text), t)
    return out


class TestParse:
    def test_fields(self):
        [s] = fw.parse_ss(ss(sock(40001, "[::ffff:93.184.216.34]:443", "FIN-WAIT-1", rcv=30048,
                                  unacked=1, backoff=2, lastrcv=21000)))
        assert s["state"] == "FIN-WAIT-1" and s["remote"] == "93.184.216.34" and s["port"] == "443"
        assert s["xray"] and (s["rcv"], s["unacked"], s["backoff"], s["lastrcv"]) == (30048, 1, 2, 21000)

    def test_orphan_has_no_owner(self):
        [s] = fw.parse_ss(ss(sock(40001, state="FIN-WAIT-1", owner=None)))
        assert not s["xray"]


class TestTracker:
    def test_frozen_then_abandoned_is_reported(self):
        # Born at t=10, data until ~t=12 (16 KB), client gives up at t=32: our FIN
        # sits unacknowledged in an orphaned FIN-WAIT-1.
        ev = run(fw.Tracker(), [
            (0, ss()),
            (10, ss(sock(40001, rcv=6000))),
            (12, ss(sock(40001, rcv=28000))),
            (20, ss(sock(40001, rcv=28000, lastrcv=8000))),
            (34, ss(sock(40001, state="FIN-WAIT-1", owner=None, rcv=28000, unacked=1,
                         backoff=1, lastrcv=22000))),
        ])
        assert len(ev) == 1
        assert ev[0]["ip"] == "93.184.216.34" and ev[0]["stage"] == "freeze" and ev[0]["rcv"] == 28000

    def test_reported_once(self):
        frames = [(0, ss()), (10, ss(sock(40001, rcv=20000)))]
        dead = sock(40001, state="FIN-WAIT-1", owner=None, rcv=20000, unacked=1, backoff=2,
                    lastrcv=20000)
        frames += [(30, ss(dead)), (32, ss(dead)), (34, ss(dead))]
        assert len(run(fw.Tracker(), frames)) == 1

    def test_idle_death_is_not_a_freeze(self):
        # Worked for two minutes, then the NAT forgot it: same ending, late stop.
        ev = run(fw.Tracker(), [
            (0, ss()),
            (10, ss(sock(40001, rcv=6000))),
            (130, ss(sock(40001, rcv=15000, lastrcv=0))),
            (400, ss(sock(40001, rcv=15000, unacked=1, backoff=3, lastrcv=270000))),
        ])
        assert ev == []

    def test_clean_endings_do_not_count(self):
        ev = run(fw.Tracker(), [
            (0, ss()),
            (10, ss(sock(40001, rcv=5000), sock(40002, rcv=5000))),
            (12, ss(sock(40001, state="CLOSE-WAIT", rcv=90000),
                    sock(40002, state="TIME-WAIT", owner=None, rcv=90000))),
            (14, ss(sock(40002, state="FIN-WAIT-1", owner=None, rcv=90000, unacked=1,
                         backoff=0))),     # FIN out, not yet overdue
        ])
        assert ev == []

    def test_sockets_open_before_watching_are_ignored(self):
        old = sock(40001, rcv=6000)
        ev = run(fw.Tracker(), [
            (0, ss(old)),
            (40, ss(sock(40001, rcv=6000, unacked=1, backoff=4, lastrcv=35000))),
        ])
        assert ev == []

    def test_other_processes_are_ignored(self):
        # The AdGuard client's own connections come from the same address.
        ev = run(fw.Tracker(), [
            (0, ss()),
            (10, ss(sock(40001, owner="adguardvpn-cli", rcv=20000))),
            (30, ss(sock(40001, owner="adguardvpn-cli", state="FIN-WAIT-1", rcv=20000,
                         unacked=1, backoff=2, lastrcv=20000))),
        ])
        assert ev == []

    def test_unanswered_attempts_are_not_freezes(self):
        ev = run(fw.Tracker(), [
            (0, ss()),
            (10, ss(sock(40001, state="SYN-SENT", unacked=1, backoff=3))),
        ])
        assert ev == []

    def test_cut_after_handshake(self):
        ev = run(fw.Tracker(), [
            (0, ss()),
            (10, ss(sock(40001, rcv=0))),
            (20, ss(sock(40001, rcv=0, unacked=1, backoff=2, lastrcv=0))),
        ])
        assert len(ev) == 1 and ev[0]["stage"] == "handshake"

    def test_private_destinations_are_ignored(self):
        ev = run(fw.Tracker(), [
            (0, ss()),
            (10, ss(sock(40001, remote="10.0.0.5:443", rcv=20000))),
            (30, ss(sock(40001, remote="10.0.0.5:443", state="FIN-WAIT-1", owner=None,
                         rcv=20000, unacked=1, backoff=2, lastrcv=20000))),
        ])
        assert ev == []


CFG = fw.settings_of({})


def events(ip, *times, rcv=16000):
    return [{"ip": ip, "port": "443", "rcv": rcv, "at": t, "stage": "freeze"} for t in times]


class TestRecord:
    def test_three_events_route_the_address(self):
        rows, changed = fw.record([], events("93.184.216.34", 100, 200), CFG, now=300)
        assert not changed and not rows[0]["routed"]
        rows, changed = fw.record(rows, events("93.184.216.34", 400), CFG, now=400)
        row = rows[0]
        assert changed and row["routed"] and row["source"] == "live" and row["verdict"] == "frozen"
        assert row["routed_since"] == 400 and "×3" in row["direct"]
        assert bp.routed_addresses(rows) == ["93.184.216.34"]

    def test_old_events_fall_out_of_the_window(self):
        day = 86400
        rows, _ = fw.record([], events("93.184.216.34", 0, 10), CFG, now=10)
        rows, changed = fw.record(rows, events("93.184.216.34", day + 100), CFG, now=day + 100)
        assert not changed and len(rows[0]["events"]) == 1

    def test_switched_off_entry_collects_but_never_routes(self):
        known = [{"domain": "93.184.216.34", "enabled": False, "routed": False}]
        rows, changed = fw.record(known, events("93.184.216.34", 1, 2, 3), CFG, now=3)
        assert not changed and not rows[0]["routed"] and len(rows[0]["events"]) == 3

    def test_entry_routed_by_the_probe_is_left_alone(self):
        known = [{"domain": "93.184.216.34", "enabled": True, "routed": True, "verdict": "blocked"}]
        rows, changed = fw.record(known, events("93.184.216.34", 1, 2, 3), CFG, now=3)
        assert not changed and rows[0]["verdict"] == "blocked" and "source" not in rows[0]


class TestExpire:
    def test_back_to_direct_after_ttl(self):
        rows, _ = fw.record([], events("93.184.216.34", 1, 2, 3), CFG, now=3)
        same, changed = fw.expire(rows, CFG, now=3 + 13 * 86400)
        assert not changed and same[0]["routed"]
        gone, changed = fw.expire(rows, CFG, now=3 + 15 * 86400)
        assert changed and not gone[0]["routed"] and gone[0]["events"] == []


class TestProbeLeavesLiveEntriesAlone:
    def test_live_entries_are_not_reprobed(self):
        known = [{"domain": "93.184.216.34", "enabled": True, "routed": True, "source": "live"},
                 {"domain": "example.org", "enabled": True, "routed": True}]
        chosen = bp.probe_set(["93.184.216.34", "example.net"], known, limit=10)
        assert "93.184.216.34" not in chosen and "example.org" in chosen


class TestOwnedListing:
    def test_mark_selected_listing_counts_as_xray(self):
        # The sampler narrows `ss` by xray's fwmark, so no users: column appears.
        [s] = fw.parse_ss(ss(sock(40001, owner=None)), owned=True)
        assert s["xray"]
        ev = run(fw.Tracker(), [(0, "\n"), (10, ss(sock(40001, owner=None, rcv=20000))),
                                (30, ss(sock(40001, owner=None, state="FIN-WAIT-1", rcv=20000,
                                             unacked=1, backoff=2, lastrcv=20000)))])
        assert ev == []            # parsed without owned=True: nobody's socket, ignored


class TestOnlyTls:
    def test_other_ports_are_not_judged(self):
        # 22, 21, 179, 554: a scanner in the house, not a page that hangs.
        ev = run(fw.Tracker(), [
            (0, ss()),
            (10, ss(sock(40001, remote="93.184.216.34:22", rcv=0))),
            (20, ss(sock(40001, remote="93.184.216.34:22", rcv=0, unacked=1, backoff=3))),
        ])
        assert ev == []


def hs_events(ip, *times):
    return [{"ip": ip, "port": "443", "rcv": 0, "at": t, "stage": "handshake"} for t in times]


class TestSilentAddresses:
    def test_silent_address_waits_for_the_tunnel(self):
        rows, changed = fw.record([], hs_events("93.184.216.34", 1, 2, 3), CFG, now=3)
        assert not changed and not rows[0]["routed"] and fw.pending(rows) == ["93.184.216.34"]

    def test_answers_through_tunnel_is_routed(self):
        rows, _ = fw.record([], hs_events("93.184.216.34", 1, 2, 3), CFG, now=3)
        rows, changed = fw.confirm(rows, "93.184.216.34", True, now=10)
        assert changed and rows[0]["routed"] and fw.pending(rows) == []

    def test_dead_everywhere_stays_direct(self):
        rows, _ = fw.record([], hs_events("93.184.216.34", 1, 2, 3), CFG, now=3)
        rows, changed = fw.confirm(rows, "93.184.216.34", False, now=10)
        assert not changed and not rows[0]["routed"] and rows[0]["check"] == "dead"
        assert rows[0]["events"] == [] and fw.pending(rows) == []

    def test_one_real_answer_is_enough_to_skip_the_check(self):
        evs = hs_events("93.184.216.34", 1, 2) + events("93.184.216.34", 3)
        rows, changed = fw.record([], evs, CFG, now=3)
        assert changed and rows[0]["routed"]


class TestPrune:
    def test_single_find_that_never_recurred_is_dropped(self):
        rows, _ = fw.record([], events("93.184.216.34", 100), CFG, now=100)
        kept, _ = fw.expire(rows, CFG, now=100 + 3600)
        assert len(kept) == 1
        kept, _ = fw.expire(rows, CFG, now=100 + 25 * 3600)
        assert kept == []

    def test_routed_and_switched_off_entries_are_kept(self):
        rows, _ = fw.record([], events("93.184.216.34", 1, 2, 3), CFG, now=3)
        rows.append({"domain": "93.184.216.35", "source": "live", "enabled": False, "routed": False,
                     "events": [1], "last_checked": 1})
        kept, _ = fw.expire(rows, CFG, now=3 + 2 * 86400)
        assert [r["domain"] for r in kept] == ["93.184.216.34", "93.184.216.35"]
