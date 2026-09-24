"""
Tests for what the egress watchdog leaves on the overview.
Run:  python -m pytest tests/ -v
"""
import json
import sys
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
