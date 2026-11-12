"""
A device opening connections in a loop (2.32.10): told apart from ordinary
traffic by breadth and persistence, not by volume to one address.
"""
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "scripts"))
import connflood as cf  # noqa: E402
import health_monitor as hm  # noqa: E402

SRC = "192.168.100.45"


def lines(minute, dest, n, src=SRC, port=443, route="proxy"):
    return ["2026/11/12 %s:%02d.000001 from %s:%d accepted tcp:%s:%d [tproxy-in -> %s]"
            % (minute, i % 60, src, 40000 + i, dest, port, route) for i in range(n)]


def flood(minutes, dests=40, each=180):
    out = []
    for mn in minutes:
        for d in range(dests):
            out += lines(mn, "45.10.0.%d" % d, each)
    return out


class TestParse:
    def test_reads_source_destination_and_minute(self):
        st = cf.parse(lines("12:14", "1.2.3.4", 3))
        assert st["2026/11/12 12:14"][SRC][("1.2.3.4", 443)] == 3

    def test_other_lines_are_skipped(self):
        assert not cf.parse(["garbage", "2026/11/12 12:14:01 [Warning] something"])

    def test_udp_is_not_counted(self):
        assert not cf.parse(["2026/11/12 12:14:01.1 from 1.1.1.2:5 accepted udp:8.8.8.8:53 [x -> y]"])


class TestDetect:
    def test_the_flood_of_november_12(self):
        st = cf.parse(flood(["12:11", "12:12", "12:13"]) + lines("12:14", "9.9.9.9", 1))
        v = cf.detect(st)
        assert v["kind"] == "pattern" and v["source"] == SRC
        assert v["target_count"] == 40 and v["per_minute"] == 7200

    def test_two_minutes_are_not_enough(self):
        st = cf.parse(flood(["12:12", "12:13"]) + lines("12:14", "9.9.9.9", 1))
        assert cf.detect(st) is None

    def test_the_minute_still_being_written_is_left_out(self):
        st = cf.parse(flood(["12:12", "12:13", "12:14"]))
        assert cf.detect(st) is None

    def test_a_gap_ends_it(self):
        st = cf.parse(flood(["12:10", "12:11", "12:13"]) + lines("12:14", "9.9.9.9", 1))
        assert cf.detect(st) is None

    def test_dns_over_https_is_ordinary(self):
        # Measured: 770 a minute to 1.1.1.1 and 392 to 1.0.0.1 for seven minutes.
        ls = lines("12:14", "9.9.9.9", 1)
        for mn in ("12:11", "12:12", "12:13"):
            ls += lines(mn, "1.1.1.1", 770) + lines(mn, "1.0.0.1", 392)
            ls += lines(mn, "142.251.20.94", 244)
        assert cf.detect(cf.parse(ls)) is None

    def test_many_addresses_a_few_times_each_is_ordinary(self):
        ls = lines("12:14", "9.9.9.9", 1)
        for mn in ("12:11", "12:12", "12:13"):
            for d in range(200):
                ls += lines(mn, "45.10.1.%d" % d, 5)
        assert cf.detect(cf.parse(ls)) is None

    def test_only_addresses_hot_in_every_minute_are_targets(self):
        ls = flood(["12:11", "12:12", "12:13"], dests=12) + lines("12:14", "9.9.9.9", 1)
        ls += lines("12:12", "8.8.4.4", 100)
        v = cf.detect(cf.parse(ls))
        assert ("8.8.4.4", 443) not in v["targets"] and v["target_count"] == 12

    def test_sources_are_judged_separately(self):
        ls = lines("12:14", "9.9.9.9", 1)
        for mn in ("12:11", "12:12", "12:13"):
            for d in range(12):
                ls += lines(mn, "45.10.0.%d" % d, 40, src="192.168.50.%d" % (10 + d % 2))
        assert cf.detect(cf.parse(ls)) is None

    def test_sheer_volume_is_reported_without_targets(self):
        ls = lines("12:14", "9.9.9.9", 1)
        for mn in ("12:11", "12:12", "12:13"):
            for d in range(250):
                ls += lines(mn, "45.10.%d.%d" % (d // 250, d % 250), 20)
        v = cf.detect(cf.parse(ls))
        assert v["kind"] == "volume" and v["targets"] == []

    def test_a_stale_log_says_nothing(self, tmp_path):
        f = tmp_path / "access.log"
        f.write_text("\n".join(flood(["12:11", "12:12", "12:13"]) + lines("12:14", "9.9.9.9", 1)))
        assert cf.check(f)["kind"] == "pattern"
        assert cf.check(f, now=f.stat().st_mtime + 600) is None
        assert cf.check(tmp_path / "missing.log") is None


class TestQuarantine:
    def test_rules_drop_only_new_connections_in_the_set(self):
        r = cf.ruleset()
        assert "priority -160" in r            # before the TPROXY rules at -150
        assert "tcp flags & (syn | ack) == syn" in r
        assert "@quarantine jump held" in r and "counter drop" in r
        assert "limit rate over 20/minute" in r

    def test_elements_carry_source_destination_and_port(self):
        calls = []

        def fake(*a, stdin=None, timeout=10):
            calls.append((a, stdin))
            class R: returncode = 0; stdout = ""
            return R()
        with patch.object(cf, "_nft", fake):
            n = cf.quarantine(SRC, [("45.10.0.1", 443), ("example.org", 443), ("2a00::1", 443)])
        assert n == 1
        assert "192.168.100.45 . 45.10.0.1 . 443 timeout 10m" in calls[-1][0][-1]
        assert "example.org" not in calls[-1][0][-1]

    def test_reads_the_set_back(self):
        js = ('{"nftables":[{"metainfo":{}},{"set":{"name":"quarantine","elem":['
              '{"elem":{"val":{"concat":["192.168.100.45","45.10.0.1",443]},"timeout":600,"expires":599}}]}}]}')

        class R: returncode = 0; stdout = js
        with patch.object(cf, "_nft", lambda *a, **k: R()):
            assert cf.quarantined() == [("192.168.100.45", "45.10.0.1", 443)]

    def test_no_table_means_nothing_held(self):
        class R: returncode = 1; stdout = ""
        with patch.object(cf, "_nft", lambda *a, **k: R()):
            assert cf.quarantined() == []


class TestWatchdog:
    V = {"kind": "pattern", "source": SRC, "per_minute": 7200,
         "targets": [("45.10.0.1", 443)], "target_count": 40}
    HELD = [(SRC, "45.10.0.1", 443)]

    def _run(self, state, conf, verdict, held, quarantine_ok=1):
        seen = {"raised": [], "cleared": [], "q": [], "released": 0}
        heldbox = [list(held)]

        def q(src, targets):
            seen["q"].append((src, targets))
            if quarantine_ok:
                heldbox[0] = list(self.HELD)
            return quarantine_ok

        def rel():
            seen["released"] += 1
        with patch.object(hm.cf, "check", return_value=verdict), \
             patch.object(hm.cf, "quarantined", side_effect=lambda: heldbox[0]), \
             patch.object(hm.cf, "quarantine", side_effect=q), \
             patch.object(hm.cf, "release", side_effect=rel), \
             patch.object(hm, "raise_attention", side_effect=lambda *a: seen["raised"].append(a)), \
             patch.object(hm, "clear_attention", side_effect=lambda k: seen["cleared"].append(k)), \
             patch.object(hm, "log", lambda m: None):
            state = hm.check_flood(state, conf)
        return state, seen

    def test_a_flood_is_named_and_held(self):
        st, seen = self._run({}, {}, self.V, [])
        assert seen["q"] == [(SRC, [("45.10.0.1", 443)])]
        kind, head, detail = seen["raised"][0]
        assert kind == "flood" and SRC in head and "7200" in head
        assert "временно закрыты" in detail
        assert st["flood_active"]

    def test_switched_off_it_only_reports(self):
        st, seen = self._run({}, {"FLOOD_QUARANTINE": "off"}, self.V, self.HELD)
        assert seen["q"] == [] and seen["released"] == 1
        assert "Ничего не заблокировано" in seen["raised"][0][2]

    def test_held_and_silent_is_still_a_concern(self):
        # Once held, the flood leaves the log; that is not the end of it.
        st, seen = self._run({"flood_active": True}, {}, None, self.HELD)
        assert seen["raised"] and not seen["cleared"]

    def test_it_clears_when_nothing_is_held(self):
        st, seen = self._run({"flood_active": True}, {}, None, [])
        assert seen["cleared"] == ["flood"] and not st["flood_active"]

    def test_quiet_stays_quiet(self):
        st, seen = self._run({}, {}, None, [])
        assert not seen["raised"] and not seen["cleared"]
