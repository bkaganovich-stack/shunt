"""
Tests for the provider assumptions audit.

The chain fixture is real output from the live gateway. The point of the first
class below is that it reproduces the September outage from the packet's point
of view: with the CGNAT exception present the gateway's own address is
delivered, and without it the same address is swallowed.

Run:  python -m pytest tests/ -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "scripts"))

import provider as pv  # noqa: E402


CHAIN = """\
Chain XRAY_PREROUTING (1 references)
    pkts      bytes target     prot opt in     out     source               destination
    2528   421475 RETURN     all  --  *      *       192.168.244.0/30     0.0.0.0/0
      51    26623 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0            mark match 0xff
 1354357 2553026217 RETURN     all  --  *      *       0.0.0.0/0            100.64.0.0/10
    1593   127440 RETURN     all  --  *      *       0.0.0.0/0            10.0.0.0/8
    7906   458468 RETURN     all  --  *      *       0.0.0.0/0            172.16.0.0/12
   14454  1637354 RETURN     all  --  *      *       0.0.0.0/0            192.168.0.0/16
     874    57502 RETURN     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:53
  462150 483505490 TPROXY     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            TPROXY redirect 0.0.0.0:12345 mark 0x1/0xffffffff
"""

CHAIN_BEFORE_THE_FIX = "\n".join(
    l for l in CHAIN.splitlines() if "100.64.0.0/10" not in l)


class TestTheOutageAsACheck:
    def test_the_gateways_own_cgnat_address_is_delivered_now(self):
        holds, detail = pv.chain_excepts("100.113.192.178", CHAIN)
        assert holds is True and "100.64.0.0/10" in detail

    def test_without_that_one_line_it_is_swallowed(self):
        # This is the September outage, stated as an assertion. Every packet for
        # the box's own address went into the tunnel instead of to the socket
        # waiting for it, DNS answers included, and every layer above reported
        # the layer below as broken.
        holds, detail = pv.chain_excepts("100.113.192.178", CHAIN_BEFORE_THE_FIX)
        assert holds is False and "перехват" in detail

    def test_an_rfc1918_provider_was_always_covered(self):
        # Which is why nobody noticed the assumption existed.
        assert pv.chain_excepts("10.1.2.3", CHAIN_BEFORE_THE_FIX)[0] is True

    def test_a_public_wan_address_is_not_excepted_by_any_of_these(self):
        assert pv.chain_excepts("93.184.216.34", CHAIN)[0] is False

    def test_port_rules_do_not_count_as_an_exception(self):
        # "udp dpt:53 RETURN" excepts a protocol, not an address, and treating
        # it as one would report a swallowed gateway as healthy.
        only_ports = "\n".join(l for l in CHAIN.splitlines()
                               if "dpt:" in l or "TPROXY" in l or "pkts" in l)
        assert pv.chain_excepts("100.113.192.178", only_ports)[0] is False

    def test_a_nonsense_address_is_unknown_not_false(self):
        holds, _ = pv.chain_excepts("not-an-address", CHAIN)
        assert holds is None


class TestAudit:
    FP = {"network": "100.113.192.0/19", "gateway": "100.113.192.1",
          "dhcp_server": "100.116.0.1", "resolvers": ["213.234.193.1", "85.21.2.1"],
          "lease_seconds": 600, "mac": "a8:5e:45:ac:fa:88",
          "permanent_mac": "00:01:2e:81:14:20", "mac_cloned": True}

    def test_the_outage_check_comes_first(self):
        checks = pv.audit(self.FP, CHAIN, "192.168.100.1/24")
        assert checks[0]["id"] == "own_address_excepted"
        assert checks[0]["holds"] is True

    def test_it_fails_loudly_when_the_exception_is_gone(self):
        checks = pv.audit(self.FP, CHAIN_BEFORE_THE_FIX, "192.168.100.1/24")
        bad = pv.failing(checks)
        assert bad and bad[0]["id"] == "own_address_excepted"
        assert "в туннель вместо доставки" in bad[0]["remedy"]

    def test_an_overlapping_lan_is_caught(self):
        fp = dict(self.FP, network="192.168.100.0/24")
        checks = pv.audit(fp, CHAIN, "192.168.100.1/24")
        row = next(c for c in checks if c["id"] == "lan_wan_overlap")
        assert row["holds"] is False

    def test_a_normal_lan_is_not_flagged(self):
        checks = pv.audit(self.FP, CHAIN, "192.168.100.1/24")
        row = next(c for c in checks if c["id"] == "lan_wan_overlap")
        assert row["holds"] is True

    def test_a_cloned_mac_is_recorded_not_judged(self):
        # Cloning was deliberate here. Marking it as a broken assumption would
        # put a permanent red mark on the page for something nobody should act
        # on -- and a warning that is always true teaches people to ignore
        # warnings. What matters is that the dependency is written down for the
        # day the hardware is replaced.
        row = next(c for c in pv.audit(self.FP, CHAIN, None)
                   if c["id"] == "mac_registration")
        assert row["holds"] is None and row["informational"] is True
        assert "00:01:2e:81:14:20" in row["detail"]
        assert row not in pv.failing(pv.audit(self.FP, CHAIN, None))

    def test_an_unspoofed_mac_still_names_the_dependency(self):
        fp = dict(self.FP, mac_cloned=False, permanent_mac="a8:5e:45:ac:fa:88")
        row = next(c for c in pv.audit(fp, CHAIN, None)
                   if c["id"] == "mac_registration")
        assert row["holds"] is None
        assert "привязывается" in row["remedy"]

    def test_no_resolvers_in_the_lease_is_a_failure(self):
        fp = dict(self.FP, resolvers=[])
        row = next(c for c in pv.audit(fp, CHAIN, None)
                   if c["id"] == "provider_resolvers")
        assert row["holds"] is False
        assert "замкнутый круг" in row["remedy"]

    def test_unprobed_assumptions_are_unknown_not_true(self):
        row = next(c for c in pv.audit(self.FP, CHAIN, None)
                   if c["id"] == "doh_reachable")
        assert row["holds"] is None
        assert row not in pv.failing(pv.audit(self.FP, CHAIN, None))


class TestProviderIdentity:
    A = {"dhcp_server": "100.116.0.1", "resolvers": ["213.234.193.1"],
         "network": "100.116.0.0/16"}
    # Same provider, after a session rebuild: address and prefix moved, the
    # DHCP server did not.
    A_LATER = {"dhcp_server": "100.116.0.1", "resolvers": ["213.234.193.1"],
               "network": "100.113.192.0/19"}
    B = {"dhcp_server": "10.0.0.1", "resolvers": ["10.0.0.1"],
         "network": "10.0.0.0/8"}

    def test_a_moved_address_is_not_a_new_provider(self):
        assert pv.same_provider(self.A, self.A_LATER) is True

    def test_a_different_company_is(self):
        assert pv.same_provider(self.A, self.B) is False

    def test_matching_resolvers_are_a_second_opinion(self):
        a = {"dhcp_server": None, "resolvers": ["1.1.1.1", "1.0.0.1"]}
        b = {"dhcp_server": None, "resolvers": ["1.0.0.1", "1.1.1.1"]}
        assert pv.same_provider(a, b) is True

    def test_nothing_known_is_not_a_match(self):
        assert pv.same_provider({}, {}) is False
        assert pv.same_provider({"resolvers": []}, {"resolvers": []}) is False

    def test_a_known_provider_is_touched_not_duplicated(self, tmp_path):
        f = tmp_path / "p.json"
        pv.remember(self.A, f, now=1000)
        profiles, is_new = pv.remember(self.A_LATER, f, now=2000)
        assert is_new is False and len(profiles) == 1
        assert profiles[0]["first_seen"] == 1000
        assert profiles[0]["last_seen"] == 2000
        assert profiles[0]["fingerprint"]["network"] == "100.113.192.0/19"

    def test_a_new_provider_is_announced_as_new(self, tmp_path):
        f = tmp_path / "p.json"
        pv.remember(self.A, f, now=1000)
        profiles, is_new = pv.remember(self.B, f, now=2000)
        assert is_new is True and len(profiles) == 2

    def test_the_list_stays_bounded(self, tmp_path):
        f = tmp_path / "p.json"
        for i in range(pv.PROFILES_MAX + 5):
            pv.remember({"dhcp_server": "10.0.%d.1" % i, "resolvers": []},
                        f, now=1000 + i)
        assert len(pv.load_profiles(f)) == pv.PROFILES_MAX

    def test_a_damaged_file_is_not_a_crash(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text("{not json")
        assert pv.load_profiles(f) == []
        _, is_new = pv.remember(self.A, f, now=1)
        assert is_new is True
