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


AWG_OK = """[Interface]
PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5PQ==
Address = 10.8.0.10/32
Jc = 5
H1 = 359814363-368086978

[Peer]
PublicKey = cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHViPQ==
Endpoint = 203.0.113.52:45587
AllowedIPs = 0.0.0.0/0
"""
TT_OK = 'hostname = "static.example.net"\naddresses = ["static.example.net:443"]\nusername = "shunt"\npassword = "secret-pw"\n'


@pytest.fixture
def cfgdir(api, monkeypatch, tmp_path):
    monkeypatch.setattr(m._eg, "EGRESS_DIR", tmp_path / "egress")
    return tmp_path / "egress"


def test_config_is_saved_private_with_the_previous_one_kept(api, cfgdir):
    import os, stat
    client, state, runs, *_ = api
    (cfgdir / "amnezia").mkdir(parents=True)
    (cfgdir / "amnezia" / "awg.conf").write_text("old\n")
    state["egresses"]["amnezia"]["enabled"] = True
    r = client.post("/api/egresses/amnezia/config", json={"text": AWG_OK.replace("\n", "\r\n")})
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True, "restarted": True}
    f = cfgdir / "amnezia" / "awg.conf"
    assert f.read_text() == AWG_OK and stat.S_IMODE(os.stat(f).st_mode) == 0o600
    assert (cfgdir / "amnezia" / "awg.conf.prev").read_text() == "old\n"
    assert stat.S_IMODE(os.stat(cfgdir / "amnezia").st_mode) == 0o700
    assert ["systemctl", "restart", "shunt-egress@amnezia.service"] in runs
    assert "PrivateKey" not in r.text


def test_trusttunnel_export_is_accepted_and_never_echoed(api, cfgdir):
    client, *_ = api
    r = client.post("/api/egresses/trusttunnel/config", json={"text": TT_OK})
    assert r.status_code == 200 and "secret-pw" not in r.text
    assert (cfgdir / "trusttunnel" / "endpoint.toml").read_text() == TT_OK
    listing = client.get("/api/egresses").text
    assert "secret-pw" not in listing


@pytest.mark.parametrize("ident,text", [
    ("amnezia", "hello"),
    ("amnezia", AWG_OK.replace("PrivateKey", "Comment")),
    ("amnezia", AWG_OK.replace("Endpoint = 203.0.113.52:45587\n", "")),
    ("trusttunnel", 'hostname = "x"\n'),
    ("adguard", TT_OK),
    ("fptn", TT_OK),
])
def test_bad_config_never_replaces_a_working_one(api, cfgdir, ident, text):
    client, state, runs, *_ = api
    (cfgdir / "amnezia").mkdir(parents=True)
    (cfgdir / "amnezia" / "awg.conf").write_text("working\n")
    assert client.post("/api/egresses/%s/config" % ident, json={"text": text}).status_code == 400
    assert (cfgdir / "amnezia" / "awg.conf").read_text() == "working\n" and runs == []


def test_probe_reads_the_world_side_of_the_egress(api, monkeypatch):
    client, *_ = api
    answers = iter(['{"ip": "45.91.138.73", "org": "AS202051 NETGRID HOST LTD", "city": "Miami", "country": "US"}',
                    "204 0.681", "5000000 1.25", "abcd= %d\n" % 0])

    async def run(*cmd, timeout=20):
        return next(answers)
    monkeypatch.setattr(m, "_run", run)
    d = client.get("/api/egresses/amnezia/probe").json()
    assert (d["ip"], d["country"], d["ttfb_ms"], d["mbit"], d["alive"]) == ("45.91.138.73", "US", 681, 32.0, True)
    assert d["handshake_age"] is None
    assert client.get("/api/egresses/nope/probe").status_code == 404
