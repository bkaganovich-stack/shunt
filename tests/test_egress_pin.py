"""
Profile rules pinned to one egress (route "egress:<id>").

The use that motivated it: Sony and 4pda refuse AdGuard's shared Datacamp
address but not the own cascade's, while the house as a whole stays on
AdGuard. The pinned rule rides its egress while xray's observatory sees it
answer and falls back to the household tunnel the moment it stops -- checked
against Xray 26.3.27 on the gateway before this was written.
"""
import copy
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "web"))
import main as m  # noqa: E402
import profiles  # noqa: E402

SONY = {"kind": "domain", "value": "sony.com", "route": "egress:amnezia"}


def settings(rules=(SONY,), amnezia=True, **kw):
    s = copy.deepcopy(m.DEFAULT_SETTINGS)
    s.update(custom_rules={"always_direct": [], "always_vpn": []}, devices={}, vpn_servers=[],
             active_vpn_id=None, profile="all_except_ru",
             adguard={"enabled": True, "socks_host": "127.0.0.1", "socks_port": 1081},
             egresses={"amnezia": {"enabled": amnezia}, "trusttunnel": {"enabled": False}})
    cfg = profiles.effective(s, "all_except_ru")
    cfg["custom_rules"] = list(rules)
    s["profile_overrides"] = {"all_except_ru": cfg}
    s.update(kw)
    return s


@pytest.fixture(autouse=True)
def cascade_configured(monkeypatch):
    monkeypatch.setattr(m._eg, "configured", lambda ident, base=None: True)


def build(s):
    with patch.object(m, "get_arp_table", return_value=[]):
        return m.build_xray_config(s)


class TestValidation:
    def test_an_egress_by_name_is_a_route(self):
        assert profiles.valid_route("egress:amnezia") and profiles.valid_route("tunnel")
        assert not profiles.valid_route("egress:nope") and not profiles.valid_route("egress:")

    def test_unknown_egress_is_refused_on_save(self):
        s = settings()
        with pytest.raises(ValueError):
            profiles.update(s, "all_except_ru", {"custom_rules": [dict(SONY, route="egress:nope")]})

    def test_editor_is_offered_every_egress_in_order(self):
        ids = [e["id"] for e in profiles.catalog(settings())["egresses"]]
        assert ids == ["adguard", "amnezia", "trusttunnel", "fptn", "warp"]


class TestCompiled:
    def test_pinned_rule_goes_to_a_balancer_with_the_tunnel_as_fallback(self):
        cfg = build(settings())
        rule = next(r for r in cfg["routing"]["rules"] if r.get("domain") == ["domain:sony.com"])
        assert rule == {"type": "field", "domain": ["domain:sony.com"], "balancerTag": "pin-amnezia"}
        assert cfg["routing"]["balancers"] == [{"tag": "pin-amnezia", "selector": ["egress-amnezia"],
                                                 "fallbackTag": "proxy", "strategy": {"type": "random"}}]
        ob = next(o for o in cfg["outbounds"] if o["tag"] == "egress-amnezia")
        assert ob["settings"]["servers"] == [{"address": "192.168.244.6", "port": 1083}]
        # Only the pinned egresses are probed, not every key's outbound.
        assert cfg["observatory"]["subjectSelector"] == ["egress-amnezia"]
        # the household still rides the active egress
        assert next(o for o in cfg["outbounds"] if o["tag"] == "proxy")["settings"]["servers"][0]["port"] == 1081

    def test_switched_off_egress_leaves_the_rule_on_the_ordinary_tunnel(self):
        cfg = build(settings(amnezia=False))
        rule = next(r for r in cfg["routing"]["rules"] if r.get("domain") == ["domain:sony.com"])
        assert rule["outboundTag"] == "proxy" and "balancerTag" not in rule
        assert "balancers" not in cfg["routing"] and "observatory" not in cfg

    def test_without_pinned_rules_nothing_extra_is_built(self):
        cfg = build(settings(rules=()))
        assert "balancers" not in cfg["routing"] and "observatory" not in cfg
        assert not any(o["tag"].startswith("egress-") for o in cfg["outbounds"])

    def test_emergency_profile_stays_direct(self):
        s = settings(profile="direct")
        cfg = build(s)
        assert not any("balancerTag" in r for r in cfg["routing"]["rules"])

    def test_two_rules_one_egress_one_balancer(self):
        rules = (SONY, {"kind": "domain", "value": "4pda.to", "route": "egress:amnezia"})
        cfg = build(settings(rules=rules))
        assert [b["tag"] for b in cfg["routing"]["balancers"]] == ["pin-amnezia"]
        assert sum(o["tag"] == "egress-amnezia" for o in cfg["outbounds"]) == 1


class TestPreview:
    def test_preview_names_the_egress_and_the_fallback(self, monkeypatch):
        monkeypatch.setattr(m.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("203.0.113.9", 0))])
        r = m.route_test("www.sony.com", settings())
        assert r["outbound"] == "proxy" and r["egress"] == "amnezia"
        assert "AmneziaWG" in r["note"] and "активный выход" in r["note"]


class TestQuicOnTcpOnlyEgress:
    """2.32.2: QUIC for sites pinned to WARP (TCP only) is refused, so browsers use TCP."""
    GOOGLE = [{"kind": "domain", "value": d, "route": "egress:warp"} for d in ("google.com", "youtube.com")]

    def warp(self, rules):
        s = settings(rules)
        s["egresses"]["warp"] = {"enabled": True}
        return s

    def test_quic_is_blocked_ahead_of_the_pin(self):
        rules = build(self.warp(self.GOOGLE))["routing"]["rules"]
        i_block = next(i for i, r in enumerate(rules) if r.get("domain") == ["domain:google.com"] and r.get("network") == "udp")
        i_pin = next(i for i, r in enumerate(rules) if r.get("domain") == ["domain:google.com"] and r.get("balancerTag"))
        assert i_block < i_pin and rules[i_block]["outboundTag"] == "block" and rules[i_block]["port"] == "443"

    def test_googles_front_ends_are_blocked_once_for_unreadable_hellos(self):
        rules = build(self.warp(self.GOOGLE))["routing"]["rules"]
        ip_blocks = [r for r in rules if r.get("ip") == m.GOOGLE_FRONTENDS]
        assert len(ip_blocks) == 1 and ip_blocks[0]["network"] == "udp" and ip_blocks[0]["outboundTag"] == "block"
        assert "34.117.0.0/16" not in m.GOOGLE_FRONTENDS          # Google Cloud customers keep QUIC

    def test_an_egress_that_carries_udp_keeps_quic(self):
        rules = build(settings([SONY]))["routing"]["rules"]
        assert not any(r.get("outboundTag") == "block" and r.get("network") == "udp" for r in rules)

    def test_a_switched_off_warp_pin_blocks_nothing(self):
        s = settings(self.GOOGLE)
        s["egresses"]["warp"] = {"enabled": False}
        assert not any(r.get("network") == "udp" and r.get("outboundTag") == "block"
                       for r in build(s)["routing"]["rules"])

    def test_dns_split_ignores_the_quic_rules(self):
        import dnssplit
        rules = m._compiled_rules(self.warp(self.GOOGLE), "proxy")
        assert dnssplit.Matcher(rules, {}).route("www.google.com") == "balancer:pin-warp"
