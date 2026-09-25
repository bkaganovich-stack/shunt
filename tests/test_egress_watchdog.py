"""
Tests for what the egress watchdog leaves on the overview.
Run:  python -m pytest tests/ -v
"""
import json
import sys

import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "scripts"))

import egress_watchdog as wd  # noqa: E402


UPLINK_DOWN = {"healthy": False, "fixable_here": False, "owner": "снаружи",
               "summary": "Путь в интернет — TCP наружу не проходит"}
TUNNEL_DOWN = {"healthy": False, "fixable_here": True, "owner": "на шлюзе",
               "summary": "Туннель несёт трафик — туннель молчит"}
HEALTHY = {"healthy": True, "summary": "всё в порядке"}


class TestWatchdogAttention:
    def _run(self, monkeypatch, tmp_path, ladders):
        wd.ATTENTION = tmp_path / "attention.json"
        wd.STATE = tmp_path / "state.json"
        wd.LOG = tmp_path / "agwatch.log"
        monkeypatch.setattr(wd, "wan_iface", lambda: "wan0")
        # Restarts are exhausted, so every failure ends in an attention item.
        monkeypatch.setattr(wd.dg, "remedy_allowed",
                            lambda *a, **k: (False, "лимит попыток исчерпан"))
        restarts = []
        monkeypatch.setattr(wd.subprocess, "run",
                            lambda *a, **k: restarts.append(a))
        monkeypatch.setattr(wd, "measure_mbit", lambda n: 50.0)
        for d in ladders:
            monkeypatch.setattr(wd.dg, "ladder", lambda wan, d=d: d)
            assert wd.main() == 0
        assert restarts == []

    def _active(self):
        items = json.loads(wd.ATTENTION.read_text())
        return sorted(i["kind"] for i in items if not i.get("cleared"))

    def test_provider_outage_is_cleared_when_the_tunnel_works_again(
            self, monkeypatch, tmp_path):
        # 21 September: the uplink item outlived the outage by three days.
        self._run(monkeypatch, tmp_path, [UPLINK_DOWN, UPLINK_DOWN, HEALTHY])
        assert self._active() == []

    def test_tunnel_failure_is_still_cleared_on_recovery(
            self, monkeypatch, tmp_path):
        self._run(monkeypatch, tmp_path, [TUNNEL_DOWN, HEALTHY])
        assert self._active() == []

    def test_outage_shows_while_it_lasts(self, monkeypatch, tmp_path):
        self._run(monkeypatch, tmp_path, [UPLINK_DOWN, UPLINK_DOWN])
        items = json.loads(wd.ATTENTION.read_text())
        assert [(i["kind"], i["count"]) for i in items] == [("uplink", 2)]

    def test_only_the_current_side_is_shown(self, monkeypatch, tmp_path):
        # Provider comes back but the tunnel stays down: the item blaming the
        # provider would now be wrong.
        self._run(monkeypatch, tmp_path, [UPLINK_DOWN, TUNNEL_DOWN])
        assert self._active() == ["egress"]
        self._run(monkeypatch, tmp_path, [UPLINK_DOWN])
        assert self._active() == ["uplink"]

    def test_other_writers_items_are_left_alone(self, monkeypatch, tmp_path):
        wd.ATTENTION = tmp_path / "attention.json"
        wd.ATTENTION.write_text(json.dumps([
            {"kind": "assumption", "text": "t", "first_seen": 1,
             "last_seen": 1, "count": 1, "cleared": False}]))
        self._run(monkeypatch, tmp_path, [UPLINK_DOWN, HEALTHY])
        assert self._active() == ["assumption"]


class TestSlowTunnel:
    """25 September: the ladder said healthy while the whole house got 1 Mbit/s."""

    def _run(self, monkeypatch, tmp_path, speeds, gap=60):
        wd.ATTENTION = tmp_path / "attention.json"
        wd.STATE = tmp_path / "state.json"
        wd.LOG = tmp_path / "agwatch.log"
        monkeypatch.setattr(wd, "wan_iface", lambda: "wan0")
        monkeypatch.setattr(wd.dg, "ladder", lambda wan: HEALTHY)
        monkeypatch.setattr(wd, "adguard_endpoint", lambda: "134.195.11.231")
        feed = list(speeds)
        probes = []

        def measure(n):
            probes.append(n)
            return feed.pop(0)
        monkeypatch.setattr(wd, "measure_mbit", measure)
        clock = [1_000_000]
        monkeypatch.setattr(wd.time, "time", lambda: clock[0])
        runs = 0
        while feed:
            assert wd.main() == 0
            clock[0] += gap
            runs += 1
            assert runs < 100, "measurements never ran"
        return probes

    def _active(self):
        if not wd.ATTENTION.exists():
            return []
        return [i for i in json.loads(wd.ATTENTION.read_text()) if not i.get("cleared")]

    def test_two_slow_samples_raise_a_notice_naming_the_server(
            self, monkeypatch, tmp_path):
        self._run(monkeypatch, tmp_path, [0.3, 0.4])
        [item] = self._active()
        assert item["kind"] == "slow"
        assert "0.4" in item["text"] and "134.195.11.231" in item["detail"]

    def test_one_slow_sample_is_confirmed_a_minute_later_not_announced(
            self, monkeypatch, tmp_path):
        probes = self._run(monkeypatch, tmp_path, [0.3, 15.0])
        assert self._active() == []
        # the confirmation came on the next run and used the other host
        assert probes == [0, 1]

    def test_fast_tunnel_is_measured_every_fifteen_minutes_only(
            self, monkeypatch, tmp_path):
        # 31 one-minute runs with a fast tunnel: at 0, 15 and 30 minutes.
        wd.STATE = tmp_path / "state.json"
        speeds = [20.0] * 3
        probes = []
        monkeypatch.setattr(wd, "measure_mbit", lambda n: probes.append(n) or speeds[0])
        monkeypatch.setattr(wd, "wan_iface", lambda: "wan0")
        monkeypatch.setattr(wd.dg, "ladder", lambda wan: HEALTHY)
        wd.ATTENTION = tmp_path / "attention.json"
        wd.LOG = tmp_path / "agwatch.log"
        clock = [1_000_000]
        monkeypatch.setattr(wd.time, "time", lambda: clock[0])
        for _ in range(31):
            wd.main()
            clock[0] += 60
        assert len(probes) == 3

    def test_recovery_clears_the_notice(self, monkeypatch, tmp_path):
        self._run(monkeypatch, tmp_path, [0.3, 0.4, 0.2, 14.0])
        assert self._active() == []

    def test_a_broken_tunnel_is_not_measured(self, monkeypatch, tmp_path):
        wd.ATTENTION = tmp_path / "attention.json"
        wd.STATE = tmp_path / "state.json"
        wd.LOG = tmp_path / "agwatch.log"
        monkeypatch.setattr(wd, "wan_iface", lambda: "wan0")
        monkeypatch.setattr(wd.dg, "ladder", lambda wan: TUNNEL_DOWN)
        monkeypatch.setattr(wd.dg, "remedy_allowed",
                            lambda *a, **k: (False, "лимит"))
        monkeypatch.setattr(wd, "measure_mbit",
                            lambda n: pytest.fail("measured a dead tunnel"))
        assert wd.main() == 0
