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
    {"enabled": {"nope": True}},                              # no such egress
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


def test_adguard_and_fptn_switch_here_too(api):
    client, state, runs, applied, _ = api
    r = client.put("/api/egresses", json={"enabled": {"fptn": False}})
    assert r.status_code == 200 and state["fptn"]["enabled"] is False
    assert ["systemctl", "disable", "--now", "shunt-fptn-egress.service"] in runs
    r = client.put("/api/egresses", json={"enabled": {"amnezia": True}})
    r = client.put("/api/egresses", json={"enabled": {"adguard": False}})
    assert r.status_code == 200 and state["adguard"]["enabled"] is False
    assert r.json()["active"] == "amnezia" and applied == ["egress_order"]


def test_the_last_tunnel_cannot_be_switched_off(api):
    client, state, runs, applied, _ = api
    client.put("/api/egresses", json={"enabled": {"fptn": False}})
    runs.clear()
    before = copy.deepcopy(state)
    r = client.put("/api/egresses", json={"enabled": {"adguard": False}})
    assert r.status_code == 400 and "напрямую" in r.json()["detail"]
    assert state == before and runs == []


def test_params_are_validated_saved_apart_and_reconnect(api):
    client, state, runs, *_ = api
    state["egresses"]["amnezia"]["enabled"] = True
    body = {"params": {"mtu": 1380, "i1": {"enabled": True, "value": "<b 0xc3><r 8>"}}}
    r = client.put("/api/egresses/amnezia/params", json=body)
    assert r.status_code == 200, r.text
    assert state["egresses"]["amnezia"]["params"] == body["params"]
    assert ["systemctl", "restart", "shunt-egress@amnezia.service"] in runs
    assert client.put("/api/egresses/amnezia/params", json={"params": {"mtu": 900}}).status_code == 400
    assert client.put("/api/egresses/adguard/params", json={"params": {}}).status_code == 400
    row = next(e for e in client.get("/api/egresses").json()["egresses"] if e["id"] == "amnezia")
    assert row["params"]["mtu"] == 1380


def test_restore_swaps_current_and_previous(api, cfgdir):
    client, state, runs, *_ = api
    d = cfgdir / "trusttunnel"; d.mkdir(parents=True)
    (d / "endpoint.toml").write_text("new\n"); (d / "endpoint.toml.prev").write_text("old\n")
    r = client.post("/api/egresses/trusttunnel/restore")
    assert r.status_code == 200
    assert (d / "endpoint.toml").read_text() == "old\n" and (d / "endpoint.toml.prev").read_text() == "new\n"
    (d / "endpoint.toml.prev").unlink()
    assert client.post("/api/egresses/trusttunnel/restore").status_code == 400


def test_listing_counts_rules_pinned_to_an_egress(api):
    client, state, *_ = api
    state["profile_overrides"] = {"all_except_ru": {"name": "Всё, кроме России", "custom_rules": [
        {"kind": "domain", "value": "sony.com", "route": "egress:amnezia"},
        {"kind": "domain", "value": "4pda.to", "route": "egress:amnezia"},
        {"kind": "domain", "value": "x.org", "route": "tunnel"}]}}
    row = next(e for e in client.get("/api/egresses").json()["egresses"] if e["id"] == "amnezia")
    assert row["pinned"] == [{"profile": "all_except_ru", "name": "Всё, кроме России", "count": 2}]


def test_config_facts_show_what_the_file_sets_and_nothing_secret(api, cfgdir):
    client, *_ = api
    (cfgdir / "amnezia").mkdir(parents=True)
    (cfgdir / "amnezia" / "awg.conf").write_text(AWG_OK.replace("Jc = 5", "MTU = 1380\nI1 = <b 0xff>\nJc = 5"))
    (cfgdir / "trusttunnel").mkdir(parents=True)
    (cfgdir / "trusttunnel" / "endpoint.toml").write_text(TT_OK + 'upstream_protocol = "http2"\nanti_dpi = false\n')
    d = client.get("/api/egresses")
    rows = {e["id"]: e for e in d.json()["egresses"]}
    assert rows["amnezia"]["config_facts"] == {"mtu": 1380, "i1": "<b 0xff>"}
    assert rows["trusttunnel"]["config_facts"] == {"protocol": "http2", "anti_dpi": False}
    assert "PrivateKey" not in d.text and "cHJpdmF0" not in d.text and "secret-pw" not in d.text


# ── Key-based egresses (2.30) ────────────────────────────────────────────────
SS = "ss://Y2hhY2hhMjA6czFAMS4xLjEuMToyMjI=#Frankfurt"
SS2 = "ss://Y2hhY2hhMjA6czJAMi4yLjIuMjoyMjI="


def _add(client, key=SS, name=""):
    r = client.post("/api/egresses/keys", json={"key": key, "name": name})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_a_key_is_added_as_a_reserve_with_its_own_port(api):
    client, state, runs, applied, alive = api
    ident = _add(client)
    assert ident.startswith("key-") and applied == ["egress_key_add"]
    k = state["vpn_servers"][0]
    assert k["name"] == "Frankfurt" and k["enabled"] and k["socks_port"] == 11001
    assert state["egress_order"][-1] == ident
    row = {e["id"]: e for e in client.get("/api/egresses").json()["egresses"]}[ident]
    assert row["kind"] == "key" and row["label"] == "Frankfurt" and row["enabled"]
    assert row["key"] == {"protocol": "Shadowsocks", "server": "1.1.1.1", "port": 222}
    assert not row["primary"] and not row["active"]
    assert SS not in str(client.get("/api/egresses").json())     # the key never goes back


@pytest.mark.parametrize("key, why", [
    ("", "ss://"), ("wireguard://abc", "ss://"), ("ss://%%%", "не разбирается")])
def test_bad_keys_are_refused(api, key, why):
    client, state, *_ = api
    r = client.post("/api/egresses/keys", json={"key": key})
    assert r.status_code == 400 and why in r.json()["detail"]
    assert not state.get("vpn_servers")


def test_the_same_key_twice_is_refused(api):
    client, *_ = api
    _add(client)
    r = client.post("/api/egresses/keys", json={"key": SS})
    assert r.status_code == 400 and "уже" in r.json()["detail"]


def test_keys_take_part_in_order_and_switches(api):
    client, state, runs, applied, alive = api
    ident = _add(client)
    alive["127.0.0.1:11001"] = True
    order = [ident, "adguard", "amnezia", "trusttunnel", "fptn"]
    r = client.put("/api/egresses", json={"order": order})
    assert r.status_code == 200 and r.json()["active"] == ident
    r = client.put("/api/egresses", json={"enabled": {ident: False}})
    assert r.status_code == 200 and state["vpn_servers"][0]["enabled"] is False
    assert r.json()["active"] == "adguard"
    assert not [a for a in runs if ident in " ".join(a)]          # no unit to start


def test_rename_keeps_the_house_running_but_a_new_key_restarts(api):
    client, state, runs, applied, _ = api
    ident = _add(client); applied.clear()
    r = client.put("/api/egresses/%s/key" % ident, json={"name": "  Дом  "})
    assert r.json() == {"ok": True, "restarted": False, "label": "Дом"} and applied == []
    r = client.put("/api/egresses/%s/key" % ident, json={"key": SS2})
    assert r.json()["restarted"] and applied == ["egress_key_change"]
    assert state["vpn_servers"][0]["key"] == SS2 and state["vpn_servers"][0]["prev_key"] == SS
    assert client.get("/api/egresses").json()["egresses"][-1]["prev_available"]
    r = client.post("/api/egresses/%s/restore" % ident)
    assert r.status_code == 200 and state["vpn_servers"][0]["key"] == SS


def test_deleting_a_key_moves_its_pinned_rules_to_the_tunnel(api):
    client, state, runs, applied, _ = api
    ident = _add(client)
    state["profile_overrides"] = {"all_except_ru": {"custom_rules": [
        {"kind": "domain", "value": "a.example", "route": "egress:" + ident},
        {"kind": "domain", "value": "b.example", "route": "direct"}]}}
    r = client.delete("/api/egresses/" + ident)
    assert r.status_code == 200 and r.json()["unpinned"] == 1
    assert state["vpn_servers"] == [] and ident not in state["egress_order"]
    assert [x["route"] for x in state["profile_overrides"]["all_except_ru"]["custom_rules"]] == ["tunnel", "direct"]


def test_the_last_way_out_cannot_be_deleted(api):
    client, state, *_ = api
    ident = _add(client)
    state["adguard"]["enabled"] = False
    state["fptn"]["enabled"] = False
    r = client.delete("/api/egresses/" + ident)
    assert r.status_code == 400 and state["vpn_servers"]


def test_only_keys_can_be_deleted(api):
    client, *_ = api
    assert client.delete("/api/egresses/adguard").status_code == 404


def test_probes_through_a_key_port_stay_out_of_the_connection_log():
    line = "2026/10/12 18:00:00.1 from 127.0.0.1:50000 accepted tcp:www.google.com:443 [in-key-aaaa1111 -> egress-key-aaaa1111]"
    assert m.parse_access_log_line(line) is None
    line = "2026/10/12 18:00:00.1 from 192.168.100.45:50000 accepted tcp:1.2.3.4:443 [tproxy-in -> proxy]"
    assert m.parse_access_log_line(line)["outbound"] == "proxy"


def test_status_names_a_key_egress_by_its_server_never_its_key(api, monkeypatch):
    client, state, *_ = api
    for name, val in (("get_speeds", {}), ("get_xray_state", "running"), ("_get_lan_ip", "192.168.100.1"),
                      ("get_system_info", {}), ("_recent_wan_change", None), ("_active_attention", [])):
        monkeypatch.setattr(m, name, lambda *a, _v=val, **k: _v)
    d = client.get("/api/status").json()
    assert d["egress"]["label"] == "AdGuard VPN" and d["vpn"] is None
    ident = _add(client)
    state["adguard"]["enabled"] = False
    state["fptn"]["enabled"] = False
    r = client.get("/api/status")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["egress"] == {"kind": "key", "id": ident, "label": "Frankfurt", "location": "Shadowsocks · 1.1.1.1"}
    assert d["vpn"]["server"] == "1.1.1.1" and d["vpn_server_count"] == 1
    assert "czE" not in r.text                                   # no part of the key
