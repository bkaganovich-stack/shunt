"""
A blocked-address list that sweeps up a shared front end.

`geoip:ru-blocked-community` lists 64.233.161.0/24 and 64.233.162.0/24 whole.
Those two /24s serve `clients6.google.com` -- the RPC hosts behind Drive,
Tasks, Keep and Gemini -- and none of that is blocked. The result was a service
routed by the luck of the DNS round robin: the same name went through the
tunnel or straight out depending on which of its dozen addresses came back.
"""
import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "web"))
import main as m


class TestWhatCountsAsCollateral:
    def test_a_whole_google_24_is_collateral(self):
        assert m.shared_edge_collateral(["64.233.162.0/24"]) == ["64.233.162.0/24"]

    def test_a_single_address_is_a_target_and_is_left_alone(self):
        # Somebody naming one YouTube front end on purpose. Honoured.
        assert m.shared_edge_collateral(["142.251.150.2/32"]) == []

    def test_the_boundary_is_the_prefix_not_the_company(self):
        assert m.shared_edge_collateral(["64.233.161.0/29"]) == []
        assert m.shared_edge_collateral(["64.233.161.0/27"]) == ["64.233.161.0/27"]

    def test_a_coarse_network_outside_google_is_not_touched(self):
        # Meta's 157.240.0.0/16 is exactly what the address lists are FOR.
        assert m.shared_edge_collateral(["157.240.0.0/16", "128.116.0.0/17"]) == []

    def test_network_objects_are_accepted_as_well_as_text(self):
        got = m.shared_edge_collateral([ipaddress.ip_network("64.233.162.0/24")])
        assert got == ["64.233.162.0/24"]

    def test_rubbish_does_not_raise(self):
        assert m.shared_edge_collateral(["", None, "not-a-network", 5]) == []

    def test_the_answer_is_sorted_and_free_of_duplicates(self):
        got = m.shared_edge_collateral(["64.233.162.0/24", "64.233.161.0/24",
                                        "64.233.162.0/24"])
        assert got == ["64.233.161.0/24", "64.233.162.0/24"]

    def test_ipv6_is_compared_against_ipv6_only(self):
        # subnet_of raises across families; the guard is what keeps it quiet.
        assert m.shared_edge_collateral(["2a00:1450:4010::/48"]) == []


class TestTheRuleItGenerates:
    def test_nothing_found_means_no_rule_at_all(self, monkeypatch):
        monkeypatch.setattr(m, "shared_edge_nets", lambda: [])
        assert m._shared_edge_rules() == []

    def test_what_is_found_becomes_one_direct_rule(self, monkeypatch):
        monkeypatch.setattr(m, "shared_edge_nets",
                            lambda: [ipaddress.ip_network("64.233.162.0/24")])
        assert m._shared_edge_rules() == [
            {"type": "field", "ip": ["64.233.162.0/24"], "outboundTag": "direct"}]


class TestWhereItSitsInTheChain:
    """
    Behind the domain lists and ahead of the address lists. Both halves matter:
    ahead of the address lists or it changes nothing, behind the domain lists or
    it starts sending youtube.com straight out.
    """

    def _rules(self, monkeypatch, profile="blocked_only"):
        monkeypatch.setattr(m, "shared_edge_nets",
                            lambda: [ipaddress.ip_network("64.233.162.0/24")])
        cfg = m.build_xray_config({"profile": profile})
        return cfg["routing"]["rules"]

    def test_it_sits_between_the_two_kinds_of_list(self, monkeypatch):
        rules = self._rules(monkeypatch)
        def index(pred):
            return next(i for i, r in enumerate(rules) if pred(r))
        by_name = index(lambda r: r.get("domain") == m.BLOCKED_LISTS)
        by_edge = index(lambda r: r.get("ip") == ["64.233.162.0/24"])
        by_addr = index(lambda r: r.get("ip") == m.BLOCKED_IP_LISTS)
        assert by_name < by_edge < by_addr

    def test_an_empty_answer_adds_no_rule_to_the_datapath(self, monkeypatch):
        monkeypatch.setattr(m, "shared_edge_nets", lambda: [])
        rules = m.build_xray_config({"profile": "blocked_only"})["routing"]["rules"]
        assert all(r.get("outboundTag") != "direct" or r.get("ip") != []
                   for r in rules)
        assert not any(r.get("ip") == ["64.233.162.0/24"] for r in rules)
