"""
GET/PUT /api/egresses: the order and the own cascade's switches.
"""
import copy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "web"))
from fastapi.testclient import TestClient  # noqa: E402
import main as m  # noqa: E402


@pytest.fixture
def api(monkeypatch):
    state = copy.deepcopy(m.DEFAULT_SETTINGS)
    state.update(adguard={"enabled": True, "socks_host": "127.0.0.1", "socks_port": 1081},
                 fptn={"enabled": True}, auto_fallback=True)
    saved, runs, applied = [], [], []
    monkeypatch.setattr(m, "load_settings", lambda: copy.deepcopy(state))
    monkeypatch.setattr(m, "save_settings", lambda s: (saved.append(s), state.clear(), state.update(s)))
    monkeypatch.setattr(m.subprocess, "run",
                        lambda a, **k: runs.append(a) or SimpleNamespace(stdout="active", returncode=0))
    monkeypatch.setattr(m, "apply_config", lambda s, why, **k: applied.append(why) or (True, None))
    monkeypatch.setattr(m._eg, "configured", lambda ident, base=None: ident != "trusttunnel")
    alive = {"127.0.0.1:1081": True, "192.168.244.6:1083": True}

    async def quick(host, port):
        return alive.get("%s:%s" % (host, port), False)
    monkeypatch.setattr(m, "_quick_alive", quick)
    m.app.dependency_overrides[m.auth_dep] = lambda: "test"
    yield TestClient(m.app), state, runs, applied, alive
    m.app.dependency_overrides.clear()


def test_listing_is_in_the_users_order_with_state(api):
    client, *_ = api
    d = client.get("/api/egresses").json()
    assert [e["id"] for e in d["egresses"]] == ["adguard", "amnezia", "trusttunnel", "fptn"]
    row = {e["id"]: e for e in d["egresses"]}
    assert row["adguard"]["primary"] and row["adguard"]["active"] and row["adguard"]["alive"]
    assert not row["amnezia"]["enabled"] and row["amnezia"]["configured"]
    assert not row["trusttunnel"]["configured"]
    assert d["active"] == "adguard"


def test_enabling_a_cascade_egress_starts_its_unit(api):
    client, state, runs, applied, _ = api
    r = client.put("/api/egresses", json={"enabled": {"amnezia": True}})
    assert r.status_code == 200, r.text
    assert state["egresses"]["amnezia"]["enabled"]
    assert ["systemctl", "enable", "--now", "shunt-egress@amnezia.service"] in runs
    assert applied == []          # still a reserve: nothing re-routed


def test_moving_a_live_egress_to_the_top_takes_over_at_once(api):
    client, state, runs, applied, _ = api
    client.put("/api/egresses", json={"enabled": {"amnezia": True}})
    r = client.put("/api/egresses", json={"order": ["amnezia", "adguard", "trusttunnel", "fptn"]})
    assert r.json()["active"] == "amnezia" and applied == ["egress_order"]


def test_a_dead_new_primary_is_left_to_the_fallback_loop(api):
    client, state, runs, applied, alive = api
    client.put("/api/egresses", json={"enabled": {"amnezia": True}})
    alive["192.168.244.6:1083"] = False
    state["egress_active"] = "adguard"
    r = client.put("/api/egresses", json={"order": ["amnezia", "adguard", "trusttunnel", "fptn"]})
    assert r.json()["active"] == "adguard" and applied == []


@pytest.mark.parametrize("body", [
    {"order": ["adguard", "amnezia"]},                       # incomplete
    {"order": ["adguard", "adguard", "trusttunnel", "fptn"]},  # duplicate
    {"enabled": {"adguard": False}},                          # not ours to switch here
    {"enabled": {"trusttunnel": True}},                       # no config issued yet
])
def test_bad_requests_change_nothing(api, body):
    client, state, runs, applied, _ = api
    before = copy.deepcopy(state)
    assert client.put("/api/egresses", json=body).status_code == 400
    assert state == before and runs == [] and applied == []
