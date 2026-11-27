"""
Remote access: the reverse ssh to the owner's server (docs/REMOTE_ACCESS.md).
Run:  python -m pytest tests/test_remote_access.py -v

Nothing here starts ssh or reaches the network: the runner's process and
probe calls are replaced, the SOCKS helper talks to a socket pair.
"""
import copy
import shutil
import socket
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "web"))
sys.path.insert(0, str(ROOT / "src" / "scripts"))

import remote_access as ra             # noqa: E402
import remote_access_runner as rr      # noqa: E402
import socks_connect as sc             # noqa: E402

PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGz2bq7Zk8x6Ow0kQ4mZ5QXx3Vf0xW9H2xvJ5Jb2S1cF shunt-ra@gw"
HOSTKEY_B64 = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
CFG = {**ra.DEFAULTS, "enabled": True, "host": "rendezvous.example", "port": 22}


# ── settings and validation ─────────────────────────────────────────────────

class TestValidate:
    def test_off_by_default(self):
        assert ra.config({})["enabled"] is False
        assert ra.config({"remote_access": {"host": "x.example"}})["enabled"] is False

    @pytest.mark.parametrize("host", ["riga.example.net", "203.0.113.7", "2001:db8::1", "srv1"])
    def test_accepts_names_and_addresses(self, host):
        clean, errors = ra.validate({"host": host})
        assert errors == [] and clean["host"] == host

    @pytest.mark.parametrize("host", ["a b", "host\n    ProxyCommand sh", "x:22", "%h", "-oProxyCommand=x",
                                      "user@host", "a..b", "fe80::1%h\n    ProxyCommand id",
                                      "fe80::1%eth0", "203.0.113.7 22"])
    def test_refuses_anything_that_could_reach_the_ssh_config(self, host):
        clean, errors = ra.validate({"host": host})
        assert errors and "host" not in clean

    def test_ports_and_user(self):
        assert ra.validate({"port": 0})[1]
        assert ra.validate({"port": "22"})[0]["port"] == 22
        assert ra.validate({"remote_port": 22})[1]            # privileged: refused
        assert ra.validate({"remote_port": 2222})[0]["remote_port"] == 2222
        assert ra.validate({"user": "Root; x"})[1]
        assert ra.validate({"user": "shunt-gw"})[0]["user"] == "shunt-gw"
        assert ra.validate({"via": "a b"})[1]

    def test_per_road_hosts(self):
        clean, errors = ra.validate({"hosts": {"amnezia": " 10.8.0.1 ", "trusttunnel": "",
                                               "house": "riga.example"}})
        assert errors == []
        # Empty means "use the shared address" and is not stored.
        assert clean["hosts"] == {"amnezia": "10.8.0.1", "house": "riga.example"}
        assert ra.validate({"hosts": None})[0]["hosts"] == {}

    @pytest.mark.parametrize("hosts", [{"amnezia": "10.8.0.1\n    ProxyCommand sh"},
                                       {"amnezia": "fe80::1%eth0"}, {"amnezia": "10.8.0.1:22"},
                                       {"amnezia": "a b"}, {"a b": "10.8.0.1"},
                                       {"auto": "10.8.0.1"}, {"x\nHost *": "10.8.0.1"},
                                       ["amnezia", "10.8.0.1"], "10.8.0.1"])
    def test_per_road_hosts_refused_like_the_shared_one(self, hosts):
        clean, errors = ra.validate({"hosts": hosts})
        assert errors and "hosts" not in clean

    def test_missing_lists_every_gap(self):
        assert ra.missing({"host": ""}, False, False) == ["адрес сервера", "ключ шлюза", "ключ сервера"]
        assert ra.missing({"host": "x"}, True, True) == []


# ── what goes to the server and into ssh ─────────────────────────────────────

class TestSshSide:
    def test_authorized_keys_line_allows_one_loopback_port_and_nothing_else(self):
        line = ra.authorized_keys_line(PUB, 2222)
        opts, key = line.split(" ", 1)
        assert key == PUB
        assert opts.split(",")[0] == "restrict"
        assert 'permitlisten="127.0.0.1:2222"' in opts      # governs the -R
        assert 'permitopen="127.0.0.1:2222"' in opts        # the probe's -W
        assert 'command="/bin/false"' in opts
        assert "pty" not in opts and "agent" not in opts and "x11" not in opts

    def test_house_road_has_no_proxy(self):
        text = ra.ssh_config(CFG, None)
        assert "ProxyCommand" not in text
        for opt in ("StrictHostKeyChecking yes", "BatchMode yes", "ExitOnForwardFailure yes",
                    "IdentitiesOnly yes", "GlobalKnownHostsFile /dev/null",
                    "PasswordAuthentication no", "ForwardAgent no", "PermitLocalCommand no",
                    f"HostKeyAlias {ra.HOST_ALIAS}", "HostName rendezvous.example"):
            assert "    " + opt in text.splitlines(), opt

    def test_egress_road_goes_through_its_socks_port(self):
        text = ra.ssh_config(CFG, ("192.168.244.6", 1083))
        line = [l for l in text.splitlines() if "ProxyCommand" in l][0]
        assert line.endswith("socks_connect.py 192.168.244.6 1083 %h %p")
        assert "/usr/bin/python3 -I" in line

    def test_road_override_changes_the_address_not_the_trust(self):
        cfg = {**CFG, "hosts": {"amnezia": "10.8.0.1"}}
        text = ra.ssh_config(ra.for_road(cfg, "amnezia"), ("192.168.244.6", 1083))
        assert "    HostName 10.8.0.1\n" in text
        assert f"    HostKeyAlias {ra.HOST_ALIAS}\n" in text
        assert "StrictHostKeyChecking yes" in text
        # Other roads keep the shared address; cfg itself is not changed.
        assert "HostName rendezvous.example" in ra.ssh_config(ra.for_road(cfg, "trusttunnel"), None)
        assert "HostName rendezvous.example" in ra.ssh_config(ra.for_road(cfg, ra.HOUSE), None)
        assert cfg["host"] == "rendezvous.example"

    def test_hand_edited_bad_override_is_never_written(self):
        cfg = {**CFG, "hosts": {"amnezia": "10.8.0.1\n    ProxyCommand sh", "trusttunnel": 7}}
        assert ra.host_for(cfg, "amnezia") == "rendezvous.example"
        assert ra.host_for(cfg, "trusttunnel") == "rendezvous.example"
        assert ra.config({"remote_access": {"hosts": "junk"}})["hosts"] == {}

    def test_config_hosts_are_not_shared_with_defaults(self):
        ra.config({})["hosts"]["x"] = "y"
        assert ra.DEFAULTS["hosts"] == {} and ra.config({})["hosts"] == {}

    def test_forward_binds_loopback_at_both_ends(self):
        argv = ra.master_argv(CFG)
        assert argv[:3] == ["ssh", "-F", str(ra.SSH_CONFIG)]
        assert "-N" in argv and "-M" in argv
        assert argv[argv.index("-R") + 1] == "127.0.0.1:2222:127.0.0.1:22"
        probe = ra.probe_argv(CFG)
        assert probe[probe.index("-W") + 1] == "127.0.0.1:2222"
        assert "ControlMaster=no" in probe

    @pytest.mark.parametrize("text", [
        f"# rendezvous.example:22 SSH-2.0-OpenSSH_9.6\nrendezvous.example ssh-ed25519 {HOSTKEY_B64}\n",
        f"|1|abc=|def= ssh-ed25519 {HOSTKEY_B64}",
        f"@cert-authority *.example ssh-ed25519 {HOSTKEY_B64} comment",
        f"ssh-ed25519 {HOSTKEY_B64}",
    ])
    def test_host_key_is_filed_under_the_alias(self, text):
        assert ra.normalize_host_key(text) == f"{ra.HOST_ALIAS} ssh-ed25519 {HOSTKEY_B64}"

    @pytest.mark.parametrize("text", ["", "hello", "ssh-ed25519 short", "ssh-dss " + HOSTKEY_B64])
    def test_garbage_is_not_a_host_key(self, text):
        assert ra.normalize_host_key(text) is None


# ── roads, errors, the status line ──────────────────────────────────────────

class TestLadder:
    socks = staticmethod(lambda e: {"amnezia": ("192.168.244.6", 1083),
                                    "trusttunnel": ("192.168.244.10", 1084)}[e])

    def test_auto_walks_the_egresses_then_the_house(self):
        roads = ra.roads(CFG, ["amnezia", "trusttunnel"], self.socks)
        assert roads == [("amnezia", ("192.168.244.6", 1083)),
                         ("trusttunnel", ("192.168.244.10", 1084)), ("house", None)]

    def test_no_egress_still_leaves_the_house(self):
        assert ra.roads(CFG, [], self.socks) == [("house", None)]

    def test_pinned(self):
        assert ra.roads({**CFG, "via": "house"}, ["amnezia"], self.socks) == [("house", None)]
        assert ra.roads({**CFG, "via": "trusttunnel"}, ["amnezia", "trusttunnel"], self.socks) == \
            [("trusttunnel", ("192.168.244.10", 1084))]
        # Pinned to an egress that is switched off: nothing, and the status says so.
        assert ra.roads({**CFG, "via": "trusttunnel"}, ["amnezia"], self.socks) == []

    @pytest.mark.parametrize("stderr,reason,fatal", [
        ("Host key verification failed.", "hostkey", False),
        ("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@", "hostkey", False),
        ("shunt-gw@shunt-rendezvous: Permission denied (publickey).", "auth", True),
        ("Error: remote port forwarding failed for listen port 2222", "forward", True),
        ("socks: proxy 192.168.244.6:1083 does not answer ([Errno 111] Connection refused)\n"
         "kex_exchange_identification: Connection closed by remote host", "socks", False),
        ("ssh: connect to host x port 22: Connection timed out", "unreachable", False),
        ("ssh: Could not resolve hostname x: Name or service not known", "unreachable", False),
        ("something new", "unknown", False),
    ])
    def test_classify(self, stderr, reason, fatal):
        assert ra.classify(stderr) == (reason, fatal)
        assert ra.is_fatal(reason) is fatal

    def test_status_says_working_only_with_a_check_time(self):
        line = ra.status_text({"state": "up", "road": "amnezia", "checked_at": 100}, 112,
                              {"amnezia": "AmneziaWG"})
        assert line == "Работает через AmneziaWG, проверено 12 с назад"
        assert ra.status_text({"state": "connecting", "road": "house"}, 0) == \
            "Подключаюсь к серверу через путь дома…"
        assert ra.status_text({"state": "failing", "reason": "auth", "retry_at": 160}, 100) == \
            "Не работает: сервер не принял ключ шлюза, следующая попытка через 60 с"
        assert ra.status_text({"state": "off"}, 0) == "Удалённый доступ выключен"
        assert ra.status_text({"state": "no_config", "missing": ["ключ сервера"]}, 0) == \
            "Не настроен: ключ сервера"
        assert "Работает" not in ra.status_text({"state": "failing"}, 0)

    def test_backoff_grows_and_stops(self):
        b, seen = ra.BACKOFF_MIN, []
        for _ in range(10):
            seen.append(b)
            b = ra.next_backoff(b)
        assert seen[:3] == [10, 20, 40] and max(seen) == ra.BACKOFF_MAX

    def test_password_auth_warning(self):
        assert ra.password_auth_on("port 22\npasswordauthentication yes\n")
        assert ra.password_auth_on("kbdinteractiveauthentication yes")
        assert not ra.password_auth_on("passwordauthentication no\nkbdinteractiveauthentication no")


# ── the SOCKS helper ────────────────────────────────────────────────────────

class TestSocks:
    def test_request_leaves_the_name_to_the_proxy(self):
        assert sc.connect_request("riga.example", 22) == \
            b"\x05\x01\x00\x03\x0criga.example\x00\x16"
        assert sc.connect_request("203.0.113.7", 2222) == \
            b"\x05\x01\x00\x01\xcb\x00\x71\x07\x08\xae"

    def _serve(self, reply_code):
        a, b = socket.socketpair()
        got = {}

        def server():
            got["hello"] = b.recv(3)
            b.sendall(b"\x05\x00")
            got["req"] = b.recv(64)
            b.sendall(bytes([5, reply_code, 0, 1]) + b"\x00" * 6)
            if reply_code == 0:
                b.sendall(b"SSH-2.0-test\r\n")
        t = threading.Thread(target=server)
        t.start()
        return a, b, t, got

    def test_negotiate_then_data_flows(self):
        a, b, t, got = self._serve(0)
        sc.negotiate(a, "riga.example", 22)
        t.join()
        assert got["hello"] == b"\x05\x01\x00"
        assert got["req"] == sc.connect_request("riga.example", 22)
        assert a.recv(64) == b"SSH-2.0-test\r\n"
        a.close(); b.close()

    def test_refusal_is_reported(self):
        a, b, t, _ = self._serve(5)
        with pytest.raises(sc.SocksError, match="connection refused"):
            sc.negotiate(a, "riga.example", 22)
        t.join()
        a.close(); b.close()

    def test_dead_proxy_prints_a_socks_line(self, capsys):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()                                   # nothing listens there now
        assert sc.main(["x", "127.0.0.1", str(port), "riga.example", "22"]) == 1
        err = capsys.readouterr().err
        assert err.startswith("socks: ") and ra.classify(err)[0] == "socks"


# ── the runner ──────────────────────────────────────────────────────────────

def test_banner_must_be_the_gateways_own():
    assert rr.banner_matches(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n",
                             "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
    assert not rr.banner_matches(b"SSH-2.0-OpenSSH_8.4p1 Debian\r\n",
                                 "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
    assert not rr.banner_matches(b"", None)
    assert not rr.banner_matches(b"HTTP/1.1 400\r\n", None)
    assert rr.banner_matches(b"SSH-2.0-x\r\n", None)


class FakeProc:
    def __init__(self, exit_after=None, stderr=b""):
        self.polls, self.exit_after = 0, exit_after
        self.stderr = SimpleNamespace(read=self._read)
        self._err = [stderr, b""]
        self.code = None
        self.terminated = False

    def _read(self, n):
        return self._err.pop(0) if self._err else b""

    def poll(self):
        self.polls += 1
        if self.code is None and self.exit_after is not None and self.polls > self.exit_after:
            self.code = 255
        return self.code

    def terminate(self):
        self.terminated = True
        self.code = -15

    kill = terminate

    def wait(self, timeout=None):
        return self.code


class FakeRunner(rr.Runner):
    """The ladder and status logic as they are; ssh, sleep and files faked."""

    def __init__(self, settings, plan, probes=(), has_key=True, has_host_key=True):
        super().__init__()
        self._settings, self.plan, self.probes = settings, list(plan), list(probes)
        self._has = (has_key, has_host_key)
        self.statuses, self.spawned, self.procs, self.t = [], [], [], 1000.0
        self.dialled = []

    def now(self): return self.t
    def sleep(self, s): self.t += s
    def settings(self): return copy.deepcopy(self._settings)
    def has_key(self): return self._has[0]
    def has_host_key(self): return self._has[1]
    def write_status(self, st): self.statuses.append(st)
    def prepare(self, cfg, proxy):
        self.spawned.append(proxy)
        self.dialled.append(cfg["host"])

    def spawn_master(self, cfg):
        p = self.plan.pop(0)
        self.procs.append(p)
        return p

    def probe(self, cfg):
        return self.probes.pop(0) if self.probes else False

    def egress_roads(self, settings, cfg):
        return ra.roads(cfg, ["amnezia", "trusttunnel"],
                        lambda e: {"amnezia": ("192.168.244.6", 1083),
                                   "trusttunnel": ("192.168.244.10", 1084)}[e])


ON = {"remote_access": {**CFG}}


class TestRunner:
    def test_off_and_unconfigured_say_so_and_start_nothing(self):
        r = FakeRunner({}, [])
        assert r.cycle() == 60 and r.statuses[-1] == {"state": "off"} and r.spawned == []
        r = FakeRunner(ON, [], has_host_key=False)
        r.cycle()
        assert r.statuses[-1] == {"state": "no_config", "missing": ["ключ сервера"]}
        assert r.spawned == []

    def test_walks_the_ladder_and_reports_the_last_reason(self):
        r = FakeRunner(ON, [FakeProc(0, b"socks: proxy dead"),
                            FakeProc(0, b"ssh: connect to host x port 22: Connection timed out"),
                            FakeProc(0, b"Connection refused")])
        wait = r.cycle()
        assert r.spawned == [("192.168.244.6", 1083), ("192.168.244.10", 1084), None]
        last = r.statuses[-1]
        assert last["state"] == "failing" and last["reason"] == "unreachable"
        assert last["tried"] == [["amnezia", "socks"], ["trusttunnel", "unreachable"],
                                 ["house", "unreachable"]]
        assert wait == ra.BACKOFF_MIN
        # A second failed walk waits longer.
        r.plan = [FakeProc(0, b"x timed out")] * 3
        assert r.cycle() == 2 * ra.BACKOFF_MIN

    def test_each_road_dials_its_own_address(self):
        settings = {"remote_access": {**CFG, "hosts": {"amnezia": "10.8.0.1",
                                                        "trusttunnel": "10.9.0.1"}}}
        r = FakeRunner(settings, [FakeProc(0, b"timed out")] * 3)
        r.cycle()
        assert r.dialled == ["10.8.0.1", "10.9.0.1", "rendezvous.example"]
        assert r.spawned == [("192.168.244.6", 1083), ("192.168.244.10", 1084), None]

    def test_a_refused_key_stops_the_walk(self):
        r = FakeRunner(ON, [FakeProc(0, b"Permission denied (publickey).")])
        r.cycle()
        assert len(r.spawned) == 1 and r.statuses[-1]["reason"] == "auth"

    def test_up_only_after_a_passed_check_then_two_misses_end_it(self):
        proc = FakeProc()
        r = FakeRunner(ON, [proc], probes=[False, True, True, False, False])
        assert r.cycle() == 5                      # it worked: start over at once
        states = [s["state"] for s in r.statuses]
        assert states[0] == "connecting"
        assert states.count("up") == 2             # after the first pass, after the second
        assert r.statuses[1]["checked_at"] >= r.statuses[1]["since"]
        assert proc.terminated                     # the session was cut, not left running
        assert r.backoff == ra.BACKOFF_MIN

    def test_a_session_that_never_passes_is_a_failure(self):
        proc = FakeProc()
        r = FakeRunner({"remote_access": {**CFG, "via": "house"}}, [proc], probes=[])
        r.cycle()
        assert r.statuses[-1]["reason"] == "probe" and proc.terminated
        assert "up" not in [s["state"] for s in r.statuses]

    def test_pinned_egress_switched_off(self):
        r = FakeRunner({"remote_access": {**CFG, "via": "fptn"}}, [])
        r.cycle()
        assert r.spawned == [] and r.statuses[-1]["reason"] == "no_roads"


# ── the unit and the package ────────────────────────────────────────────────

class TestPackaging:
    unit = (ROOT / "systemd/shunt-remote-access.service").read_text()

    def test_unit_never_enters_a_namespace(self):
        for word in ("NetworkNamespacePath", "JoinsNamespaceOf", "PrivateNetwork", "ip netns"):
            assert word not in self.unit
        assert "ConditionPathExists=/var/lib/shunt-ra/id_ed25519" in self.unit
        assert "NoNewPrivileges=yes" in self.unit and "ProtectSystem=strict" in self.unit

    def test_package_leaves_it_disabled_and_never_restarts_it(self):
        postinst = (ROOT / "packaging/templates/postinst").read_text()
        units_block = postinst.split('UNITS="', 1)[1].split('"', 1)[0]
        assert "shunt-remote-access" not in units_block
        assert "enable shunt-remote-access" not in postinst
        assert "restart shunt-remote-access" not in postinst
        assert "shunt-remote-access.service" in (ROOT / "packaging/templates/prerm").read_text()

    def test_fail_closed_plumbing_untouched(self):
        for f in ("src/scripts/egress-netns.sh", "src/scripts/iptables.sh"):
            text = (ROOT / f).read_text()
            assert "shunt-ra" not in text and "remote_access" not in text


# ── the web API ─────────────────────────────────────────────────────────────

@pytest.fixture
def api(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    import main as m
    state = copy.deepcopy(m.DEFAULT_SETTINGS)
    home = tmp_path / "shunt-ra"
    home.mkdir()
    monkeypatch.setattr(ra, "HOME", home)
    monkeypatch.setattr(ra, "KEY", home / "id_ed25519")
    monkeypatch.setattr(ra, "KNOWN_HOSTS", home / "known_hosts")
    monkeypatch.setattr(ra, "STATUS", tmp_path / "status.json")
    monkeypatch.setattr(m, "load_settings", lambda: copy.deepcopy(state))
    monkeypatch.setattr(m, "save_settings", lambda s: (state.clear(), state.update(s)))
    monkeypatch.setattr(m._eg, "configured", lambda ident, base=None: True)
    runs = []
    real_run = m.subprocess.run

    def run(argv, **kw):
        if argv[0] == "ssh-keygen" and shutil.which("ssh-keygen"):
            return real_run(argv, **kw)
        runs.append(argv)
        return SimpleNamespace(stdout="inactive\n", stderr="", returncode=0)
    monkeypatch.setattr(m.subprocess, "run", run)
    m.app.dependency_overrides[m.auth_dep] = lambda: "test"
    yield TestClient(m.app), state, runs
    m.app.dependency_overrides.clear()


needs_keygen = pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="no ssh-keygen")


class TestApi:
    def test_fresh_install_is_off(self, api):
        client, _, runs = api
        d = client.get("/api/remote-access").json()
        assert d["enabled"] is False and d["status_text"] == "Удалённый доступ выключен"
        assert d["has_key"] is False and d["authorized_keys"] == ""
        assert [r["id"] for r in d["roads"]][:2] == ["auto", "house"]

    def test_cannot_switch_on_half_configured(self, api):
        client, state, runs = api
        r = client.post("/api/remote-access", json={"enabled": True, "host": "riga.example"})
        assert r.status_code == 400 and "ключ шлюза" in r.json()["detail"]
        assert "remote_access" not in state
        assert not any("enable" in a for a in runs)

    def test_bad_values_are_refused(self, api):
        client, *_ = api
        assert client.post("/api/remote-access", json={"host": "a\nb"}).status_code == 400
        assert client.post("/api/remote-access", json={"via": "nonesuch"}).status_code == 400

    def test_hosts_for_unknown_roads_are_refused(self, api):
        client, state, _ = api
        r = client.post("/api/remote-access", json={"hosts": {"nonesuch": "10.8.0.1"}})
        assert r.status_code == 400 and "remote_access" not in state
        assert client.post("/api/remote-access",
                           json={"hosts": {"amnezia": "a\nb"}}).status_code == 400

    def test_hosts_are_saved_and_shown(self, api):
        client, state, _ = api
        r = client.post("/api/remote-access", json={"host": "riga.example",
                                                    "hosts": {"amnezia": "10.8.0.1", "house": ""}})
        assert r.status_code == 200, r.text
        assert state["remote_access"]["hosts"] == {"amnezia": "10.8.0.1"}
        assert client.get("/api/remote-access").json()["hosts"] == {"amnezia": "10.8.0.1"}
        # Leaving hosts out of a save keeps them; an empty map clears them.
        client.post("/api/remote-access", json={"port": 22})
        assert state["remote_access"]["hosts"] == {"amnezia": "10.8.0.1"}
        client.post("/api/remote-access", json={"hosts": {}})
        assert state["remote_access"]["hosts"] == {}

    @needs_keygen
    def test_key_is_made_here_and_only_the_public_half_comes_back(self, api):
        client, *_ = api
        d = client.post("/api/remote-access/key", json={}).json()
        assert d["has_key"] and d["public_key"].startswith("ssh-ed25519 ")
        assert d["authorized_keys"].startswith('restrict,port-forwarding,permitlisten="127.0.0.1:2222"')
        assert "PRIVATE" not in str(d)
        assert (ra.KEY.stat().st_mode & 0o077) == 0
        # A second press does not silently replace it.
        assert client.post("/api/remote-access/key", json={}).status_code == 409

    @needs_keygen
    def test_switch_on_and_off(self, api):
        client, state, runs = api
        client.post("/api/remote-access/key", json={})
        r = client.post("/api/remote-access/host-key",
                        json={"text": f"riga.example ssh-ed25519 {HOSTKEY_B64}"})
        assert r.status_code == 200, r.text
        assert ra.KNOWN_HOSTS.read_text() == f"{ra.HOST_ALIAS} ssh-ed25519 {HOSTKEY_B64}\n"
        assert r.json()["host_key_fingerprint"].startswith("SHA256:")
        r = client.post("/api/remote-access", json={"enabled": True, "host": "riga.example"})
        assert r.status_code == 200, r.text
        assert state["remote_access"]["enabled"] is True
        assert ["systemctl", "enable", ra.UNIT] in runs and ["systemctl", "restart", ra.UNIT] in runs
        # Saving the same values again must not cut a session in use.
        runs.clear()
        client.post("/api/remote-access", json={"host": "riga.example", "port": 22})
        assert ["systemctl", "restart", ra.UNIT] not in runs
        # A new address for one road needs a new session.
        client.post("/api/remote-access", json={"hosts": {"amnezia": "10.8.0.1"}})
        assert ["systemctl", "restart", ra.UNIT] in runs
        runs.clear()
        # Switched on but the unit is not running: never "Работает".
        assert "Работает" not in client.get("/api/remote-access").json()["status_text"]
        client.post("/api/remote-access", json={"enabled": False})
        assert ["systemctl", "disable", "--now", ra.UNIT] in runs
        assert state["remote_access"]["enabled"] is False

    def test_host_key_garbage_refused(self, api):
        client, *_ = api
        assert client.post("/api/remote-access/host-key", json={"text": "hello"}).status_code == 400
