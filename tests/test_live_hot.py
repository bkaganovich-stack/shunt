"""
Freeze-detector rules going into the running xray without a restart.

The compiler places live finds in one tagged rule right before the tagged
catch-all; _hot_update_live swaps that pair through xray's API -- new pair
appended first, old pair removed after -- and refuses whenever anything else
differs, because this path must never leave the file and the running xray
disagreeing. Restarts drop every connection in the house; on 2026-09-24 the
detector caused nine in one morning.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "web"))
import main as m
import pytest

_tmp = Path(tempfile.mkdtemp(prefix="live_hot_"))


def _settings(**kw):
    s = dict(m.DEFAULT_SETTINGS)
    s.update(custom_rules={"always_direct": [], "always_vpn": []}, devices={}, vpn_servers=[],
             active_vpn_id=None, profile="blocked_only")
    s.update(kw)
    return s


LIVE, PROBE, OFF = "93.184.216.34", "93.184.216.35", "93.184.216.36"
DISC = [{"domain": LIVE, "routed": True, "enabled": True, "source": "live"},
        {"domain": PROBE, "routed": True, "enabled": True},
        {"domain": OFF, "routed": True, "enabled": False, "source": "live"}]


def rules_of(s, arp=()):
    with patch.object(m, "get_arp_table", return_value=list(arp)):
        return m.build_xray_config(s)["routing"]["rules"]


class TestCompiler:
    def test_live_rule_sits_right_before_the_catch_all(self):
        rules = rules_of(_settings(discovered=DISC))
        assert rules[-1]["ruleTag"] == m.CATCH_TAG and rules[-1]["network"] == "tcp,udp"
        assert rules[-2]["ruleTag"] == m.LIVE_TAG and rules[-2]["ip"] == [LIVE]
        # the probe's address stays where it was; the switched-off one is nowhere
        probe_rules = [r for r in rules if PROBE in (r.get("ip") or [])]
        assert probe_rules and "ruleTag" not in probe_rules[0]
        assert not any(OFF in (r.get("ip") or []) for r in rules)
        assert sum(LIVE in (r.get("ip") or []) for r in rules) == 1

    def test_no_live_finds_no_live_rule(self):
        rules = rules_of(_settings(discovered=DISC[1:]))
        assert rules[-1]["ruleTag"] == m.CATCH_TAG
        assert not any(r.get("ruleTag") == m.LIVE_TAG for r in rules)

    def test_api_is_routing_only_on_loopback(self):
        with patch.object(m, "get_arp_table", return_value=[]):
            api = m.build_xray_config(_settings())["api"]
        assert api == {"tag": "api", "listen": m.XRAY_API, "services": ["RoutingService"]}
        assert api["listen"].startswith("127.0.0.1:")

    def test_device_policy_copies_are_never_tagged(self):
        # A device policy reuses the profile compiler with a source condition;
        # sharing the tag would let a removal by tag take its rules out too.
        devs = {"aa:bb:cc:00:01:01": {"policy": "blocked_only", "ips": ["192.168.1.2"]}}
        rules = rules_of(_settings(discovered=DISC, devices=devs),
                         arp=[{"mac": "aa:bb:cc:00:01:01", "ips": ["192.168.1.2"], "state": "REACHABLE"}])
        tagged = [r for r in rules if "ruleTag" in r]
        assert len(tagged) == 2 and not any("source" in r for r in tagged)
        assert any(r.get("source") for r in rules)


def cfg(live=(), suffix="", api=True, extra=False):
    rules = [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]
    if extra:
        rules.append({"type": "field", "domain": ["domain:example.org"], "outboundTag": "proxy"})
    if live:
        rules.append({"type": "field", "ip": list(live), "outboundTag": "proxy", "ruleTag": m.LIVE_TAG + suffix})
    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "direct", "ruleTag": m.CATCH_TAG + suffix})
    c = {"inbounds": [], "outbounds": [], "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules}}
    if api:
        c["api"] = {"tag": "api", "listen": m.XRAY_API, "services": ["RoutingService"]}
    return c


class FakeApi:
    def __init__(self, running, fail=()):
        self.running, self.fail, self.calls, self.added = list(running), set(fail), [], None

    def __call__(self, command, *args):
        self.calls.append((command,) + args)
        if command in self.fail:
            self.fail.discard(command)            # fail once
            return subprocess.CompletedProcess([], 1, "", "boom")
        if command == "lsrules":
            return subprocess.CompletedProcess([], 0, json.dumps([{"ruleTag": t} for t in self.running]), "")
        if command == "adrules":
            self.added = json.load(open(args[-1]))["routing"]["rules"]
        return subprocess.CompletedProcess([], 0, "", "")


@pytest.fixture
def xcfg(tmp_path, monkeypatch):
    p = tmp_path / "xray.json"
    monkeypatch.setattr(m, "XCFG", p)
    return p


def hot(xcfg, cur, new, api):
    xcfg.write_text(json.dumps(cur))
    with patch.object(m, "build_xray_config", return_value=new), patch.object(m, "_xray_api", api):
        return m._hot_update_live({})


class TestHotUpdate:
    def test_swap_appends_first_then_removes_the_running_pair(self, xcfg):
        api = FakeApi(["freeze-live-111", "catch-all-111"])
        new = cfg(live=["198.18.0.1", LIVE])
        done, _ = hot(xcfg, cfg(live=[LIVE], suffix="-111"), new, api)
        assert done
        assert [c[0] for c in api.calls] == ["lsrules", "adrules", "rmrules"]
        assert "-append" in api.calls[1]
        assert set(api.calls[2][1:]) == {"freeze-live-111", "catch-all-111"}
        assert api.added[0]["ip"] == ["198.18.0.1", LIVE]
        assert api.added[0]["ruleTag"].startswith(m.LIVE_TAG + "-") and api.added[1]["ruleTag"].startswith(m.CATCH_TAG + "-")
        assert json.loads(xcfg.read_text()) == new

    def test_first_find_after_a_restart(self, xcfg):
        api = FakeApi(["catch-all"])
        done, _ = hot(xcfg, cfg(), cfg(live=[LIVE]), api)
        assert done and api.calls[2] == ("rmrules", "catch-all")

    def test_nothing_changed_touches_nothing(self, xcfg):
        api = FakeApi(["catch-all"])
        done, detail = hot(xcfg, cfg(live=[LIVE]), cfg(live=[LIVE]), api)
        assert done and detail == "unchanged" and api.calls == []

    def test_any_other_difference_waits_for_a_full_apply(self, xcfg):
        api = FakeApi(["catch-all"])
        cur = cfg()
        done, _ = hot(xcfg, cur, cfg(live=[LIVE], extra=True), api)
        assert not done and api.calls == [] and json.loads(xcfg.read_text()) == cur

    def test_running_config_without_api(self, xcfg):
        api = FakeApi(["catch-all"])
        done, _ = hot(xcfg, cfg(api=False), cfg(live=[LIVE]), api)
        assert not done and api.calls == []

    def test_failed_append_leaves_everything_as_it_was(self, xcfg):
        api = FakeApi(["catch-all"], fail={"adrules"})
        cur = cfg()
        done, _ = hot(xcfg, cur, cfg(live=[LIVE]), api)
        assert not done and [c[0] for c in api.calls] == ["lsrules", "adrules"]
        assert json.loads(xcfg.read_text()) == cur

    def test_failed_removal_takes_the_new_pair_back_out(self, xcfg):
        api = FakeApi(["catch-all"], fail={"rmrules"})
        cur = cfg()
        done, _ = hot(xcfg, cur, cfg(live=[LIVE]), api)
        assert not done
        assert [c[0] for c in api.calls] == ["lsrules", "adrules", "rmrules", "rmrules"]
        assert set(api.calls[3][1:]) == {r["ruleTag"] for r in api.added}
        assert json.loads(xcfg.read_text()) == cur
