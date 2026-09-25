"""
Tests for the AdGuard licence readout and the FPTN token upload.
Run:  python -m pytest tests/ -v
"""
import copy
import os
import stat
import sys
from types import SimpleNamespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/web"))
from fastapi.testclient import TestClient  # noqa: E402
import pytest  # noqa: E402
import main as m  # noqa: E402

PREMIUM = ("Logged in as \x1b[1muser@example.com\x1b[0m\n"
           "You are using the \x1b[1mPREMIUM\x1b[0m version\n"
           "Up to \x1b[1m10\x1b[0m devices simultaneously\n"
           "Your subscription is valid until 2027-07-22\n")
TOKEN = "fptnb:" + "A" * 1400 + "=="


class TestLicenceParse:
    def test_premium(self):
        lic = m._parse_adguard_license(PREMIUM)
        assert lic["logged_in"] and lic["account"] == "user@example.com"
        assert (lic["plan"], lic["devices"], lic["valid_until"]) == ("PREMIUM", 10, "2027-07-22")

    def test_not_logged_in_is_not_guessed(self):
        lic = m._parse_adguard_license("You are not logged in. Run `adguardvpn-cli login`\n")
        assert not lic["logged_in"] and lic["plan"] is None and lic["valid_until"] is None
        assert "not logged in" in lic["text"]


@pytest.fixture
def api(monkeypatch, tmp_path):
    state = copy.deepcopy(m.DEFAULT_SETTINGS)
    state["fptn"] = {"enabled": True}
    monkeypatch.setattr(m, "load_settings", lambda: copy.deepcopy(state))
    monkeypatch.setattr(m, "FPTN_TOKEN", tmp_path / "fptn-client" / "token")
    runs = []
    def run(args, **k):
        runs.append(args)
        return SimpleNamespace(stdout="inactive", stderr="", returncode=0)
    monkeypatch.setattr(m.subprocess, "run", run)
    m.app.dependency_overrides[m.auth_dep] = lambda: "test"
    yield TestClient(m.app), state, runs
    m.app.dependency_overrides.clear()


class TestFptnToken:
    def test_saves_privately_keeps_previous_and_reconnects(self, api):
        client, _, runs = api
        m.FPTN_TOKEN.parent.mkdir()
        m.FPTN_TOKEN.write_text("fptn:old\n")
        r = client.post("/api/fptn/token", json={"token": "  " + TOKEN[:700] + "\n" + TOKEN[700:] + " "})
        assert r.status_code == 200, r.text
        assert r.json() == {"ok": True, "restarted": True}
        assert m.FPTN_TOKEN.read_text() == TOKEN + "\n"
        assert stat.S_IMODE(os.stat(m.FPTN_TOKEN).st_mode) == 0o600
        assert m.FPTN_TOKEN.with_name("token.prev").read_text() == "fptn:old\n"
        assert ["systemctl", "restart", "shunt-fptn-egress"] in runs
        assert TOKEN not in r.text

    def test_rejects_what_is_not_a_token(self, api):
        client, _, runs = api
        for bad in ("", "hello", "https://t.me/fptn_bot", "fptn:short"):
            r = client.post("/api/fptn/token", json={"token": bad})
            assert r.status_code == 400
        assert not m.FPTN_TOKEN.exists() and runs == []

    def test_disabled_fptn_is_not_started(self, api):
        client, state, runs = api
        state["fptn"]["enabled"] = False
        r = client.post("/api/fptn/token", json={"token": TOKEN})
        assert r.json() == {"ok": True, "restarted": False}
        assert runs == []


def _plain_token(servers, censored=()):
    import base64
    import json
    body = {"version": 1, "service_name": "FPTN.ONLINE", "username": "u-secret",
            "password": "p-secret",
            "servers": [{"name": n, "host": "192.0.2.%d" % i, "port": 443}
                        for i, n in enumerate(servers, 1)],
            "censored_zone_servers": [{"name": n, "host": "192.0.2.99", "port": 443}
                                      for n in censored]}
    return "fptn:" + base64.b64encode(json.dumps(body).encode()).decode()


class TestFptnServersFromToken:
    """25 September: the built-in list had lost six servers and kept three dead ones."""

    def test_list_comes_from_the_token_without_credentials(self, api):
        client, _, _ = api
        m.FPTN_TOKEN.parent.mkdir()
        m.FPTN_TOKEN.write_text(_plain_token(
            ["Ireland-Premium", "Czechia-Premium", "USA-2"], ["Russia-Moscow"]) + "\n")
        r = client.get("/api/fptn")
        d = r.json()
        assert d["servers_source"] == "token"
        assert d["servers"] == {"premium": ["Ireland-Premium", "Czechia-Premium"],
                                "regular": ["USA-2"]}
        assert "secret" not in r.text and "192.0.2" not in r.text

    def test_only_names_in_the_token_can_be_chosen(self, api, monkeypatch, tmp_path):
        client, _, _ = api
        monkeypatch.setattr(m, "FPTN_SERVER_FILE", tmp_path / "fptn-server")
        m.FPTN_TOKEN.parent.mkdir()
        m.FPTN_TOKEN.write_text(_plain_token(["Ireland-Premium"]))
        assert client.post("/api/fptn", json={"server": "Austria-Premium"}).status_code == 400
        assert client.post("/api/fptn", json={"server": "Ireland-Premium"}).status_code == 200
        assert m.FPTN_SERVER_FILE.read_text().strip() == "Ireland-Premium"

    def test_unreadable_token_falls_back_to_the_builtin_list(self, api):
        client, _, _ = api
        m.FPTN_TOKEN.parent.mkdir()
        m.FPTN_TOKEN.write_text("fptnb:not-brotli-at-all\n")
        d = client.get("/api/fptn").json()
        assert d["servers_source"] == "builtin" and d["servers"] == m.FPTN_SERVERS
