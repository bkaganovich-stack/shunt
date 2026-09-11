"""
Tests for the network-path view.

Every fixture below is real output, copied from the live gateway on
2026-09-11 -- not invented. Parsers written against imagined output are how you
end up with a page that is confidently wrong, which is the thing this feature
exists to stop.

Run:  python -m pytest tests/ -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "web"))

import netpath as np  # noqa: E402


IPTABLES_PREROUTING = """\
Chain XRAY_PREROUTING (1 references)
    pkts      bytes target     prot opt in     out     source               destination
    2528   421475 RETURN     all  --  *      *       192.168.244.0/30     0.0.0.0/0
      51    26623 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0            mark match 0xff
      93     2976 RETURN     all  --  *      *       0.0.0.0/0            224.0.0.0/4
 1354357 2553026217 RETURN     all  --  *      *       0.0.0.0/0            100.64.0.0/10
    1593   127440 RETURN     all  --  *      *       0.0.0.0/0            10.0.0.0/8
     874    57502 RETURN     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:53
    1712   146761 MARK       icmp --  *      *       0.0.0.0/0            0.0.0.0/0            MARK set 0xff
    7455   422614 RETURN     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:5228
  462150 483505490 TPROXY     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            TPROXY redirect 0.0.0.0:12345 mark 0x1/0xffffffff
"""

IPTABLES_ACCT = """\
Chain XRAY_ACCT (2 references)
    pkts      bytes target     prot opt in     out     source               destination
  291723 466971106            tcp  --  *      lo      0.0.0.0/0            0.0.0.0/0            tcp dpt:1081 /* vpn_up */
  345436 1770577943            tcp  --  lo     *       0.0.0.0/0            0.0.0.0/0            tcp spt:1081 /* vpn_down */
"""

IP_RULE = """\
0:\tfrom all lookup local
40:\tfrom all fwmark 0xff lookup main
40:\tfrom 192.168.244.0/30 lookup main
50:\tfrom all to 1.1.1.1 lookup main
100:\tfrom all fwmark 0x1 lookup 100
9000:\tfrom all to 172.19.0.0/30 lookup 2022
9001:\tfrom all lookup 2022 suppress_prefixlength 0
32766:\tfrom all lookup main
"""

LEASE_FILE = """\
ADDRESS=100.113.192.178
NETMASK=255.255.224.0
ROUTER=100.113.192.1
SERVER_ADDRESS=100.116.0.1
T1=5min
T2=8min 45s
LIFETIME=10min
DNS=213.234.193.1 85.21.2.1
HOSTNAME=node
"""

NETWORKCTL_JSON = ('{"DHCPv4Client": {"Lease": {"LeaseTimestampUSec": 91535390529,'
                   ' "Timeout1USec": 91835390529, "Timeout2USec": 92060390529}}}')


class TestRuleCounters:
    def test_the_rule_whose_absence_caused_the_outage_is_watched(self):
        rows = np.parse_rule_counters(IPTABLES_PREROUTING)
        cgnat = next(r for r in rows if "CGNAT" in r["label"])
        assert cgnat["present"] is True
        assert cgnat["packets"] == 1354357

    def test_a_missing_rule_is_reported_missing_not_zero(self):
        # One absent line in this chain is exactly what cost a day. "Zero
        # packets" and "no such rule" have to look different.
        without = "\n".join(l for l in IPTABLES_PREROUTING.splitlines()
                            if "100.64.0.0/10" not in l)
        cgnat = next(r for r in np.parse_rule_counters(without)
                     if "CGNAT" in r["label"])
        assert cgnat["present"] is False
        assert cgnat["packets"] is None

    def test_position_in_the_chain_does_not_matter(self):
        # The chain is rebuilt on every restart; a line number means nothing
        # across two of them, so matching must be on what the rule says.
        lines = IPTABLES_PREROUTING.splitlines()
        shuffled = "\n".join(lines[:2] + list(reversed(lines[2:])))
        a = {r["label"]: r["packets"] for r in np.parse_rule_counters(IPTABLES_PREROUTING)}
        b = {r["label"]: r["packets"] for r in np.parse_rule_counters(shuffled)}
        assert a == b

    def test_headers_are_not_mistaken_for_rules(self):
        rows = np.parse_rule_counters(IPTABLES_PREROUTING)
        assert all(r["packets"] != 0 or r["present"] for r in rows)
        assert len(rows) == len(np.WATCHED_RULES)

    def test_empty_input_reports_everything_missing(self):
        rows = np.parse_rule_counters("")
        assert rows and all(r["present"] is False for r in rows)


class TestEgress:
    def test_bytes_come_from_the_accounting_chain(self):
        a = np.parse_acct(IPTABLES_ACCT)
        assert a == {"up_bytes": 466971106, "down_bytes": 1770577943}

    def test_no_chain_is_not_zero_bytes(self):
        assert np.parse_acct("") == {}


class TestLease:
    def test_the_provider_lease_is_read_whole(self):
        l = np.parse_lease_file(LEASE_FILE)
        assert l["address"] == "100.113.192.178"
        assert l["gateway"] == "100.113.192.1"
        assert l["lifetime"] == 600 and l["t1"] == 300 and l["t2"] == 525
        assert l["dns"] == ["213.234.193.1", "85.21.2.1"]

    def test_a_short_lease_states_the_facts(self):
        note = np.lease_note(np.parse_lease_file(LEASE_FILE))
        assert "10 мин" in note and "каждые 5 мин" in note

    def test_a_quiet_address_is_reassurance_not_a_warning(self):
        # The gateway's own record: ~305 renewals in 25 hours, zero changes.
        # An earlier version of this sentence implied a coin flip every five
        # minutes, which the logs flatly contradict.
        import time as _t
        note = np.lease_note(np.parse_lease_file(LEASE_FILE),
                             stable_since=_t.time() - 25.5 * 3600)
        assert "25 ч" in note and "ни одной смены" in note
        assert "обрывает" not in note

    def test_the_consequence_is_named_only_when_it_happened(self):
        note = np.lease_note(np.parse_lease_file(LEASE_FILE), changes_24h=2)
        assert "2 раза" in note
        assert "обрывает все соединения" in note

    def test_a_short_watch_does_not_claim_much(self):
        import time as _t
        note = np.lease_note(np.parse_lease_file(LEASE_FILE),
                             stable_since=_t.time() - 600)
        assert "меньше часа" in note

    def test_without_a_record_it_says_only_what_is_generally_true(self):
        note = np.lease_note(np.parse_lease_file(LEASE_FILE))
        assert "обычно сохраняет адрес" in note

    def test_a_long_lease_says_so_briefly(self):
        note = np.lease_note({"lifetime": 86400, "t1": 43200})
        assert "24 ч" in note

    def test_the_count_agrees_with_russian_grammar(self):
        for n, want in ((1, "1 раз"), (2, "2 раза"), (5, "5 раз"),
                        (11, "11 раз"), (22, "22 раза")):
            assert np._times(n) == want

    def test_no_lease_no_claim(self):
        assert np.lease_note({}) is None

    def test_timers_are_read_off_the_boot_clock(self):
        t = np.parse_lease_timers(NETWORKCTL_JSON, uptime_sec=91600.0)
        assert round(t["t1_from_lease"]) == 300
        assert round(t["t2_from_lease"]) == 525
        assert 200 < t["renew_in"] < 240

    def test_a_timer_in_the_past_is_stale_not_negative(self):
        # networkd does not refresh this record on every renewal, so the timer
        # goes stale while the lease is perfectly alive. Printing a negative
        # countdown would be a confident wrong number.
        t = np.parse_lease_timers(NETWORKCTL_JSON, uptime_sec=180000.0)
        assert t["renew_in"] is None
        assert t["renew_timer_stale"] is True

    def test_garbage_is_not_a_crash(self):
        assert np.parse_lease_timers("not json", 1.0) == {}
        assert np.parse_lease_timers('{"other": 1}', 1.0) == {}


class TestRouteGet:
    def test_the_table_is_named_not_numbered(self):
        r = np.parse_route_get(
            '[{"dst":"8.8.8.8","gateway":"172.19.0.2","dev":"tun0",'
            '"table":"2022","prefsrc":"172.19.0.1"}]')
        assert r["dev"] == "tun0"
        assert r["table"] == "2022"
        assert r["table_name"] == "sing-box (tun)"

    def test_a_route_with_no_table_is_the_main_one(self):
        r = np.parse_route_get(
            '[{"dst":"213.234.193.1","gateway":"100.113.192.1","dev":"enp1s0",'
            '"prefsrc":"100.113.192.178","mark":255}]')
        assert r["table_name"] == "основная"
        assert r["mark"] == 255

    def test_unparseable_output_is_empty_not_invented(self):
        assert np.parse_route_get("") == {}
        assert np.parse_route_get("[]") == {}


class TestWhichRulesChoseTheTable:
    def test_only_the_rules_pointing_at_that_table_are_shown(self):
        # The whole rule list is what misled everyone; the subset that selects
        # the table the kernel actually chose is the part that mattered.
        got = np.rules_choosing("2022", IP_RULE)
        assert len(got) == 2
        assert all("2022" in g for g in got)

    def test_a_table_number_is_not_matched_inside_another(self):
        got = np.rules_choosing("100", IP_RULE)
        assert got == ["100:\tfrom all fwmark 0x1 lookup 100"]

    def test_main_collects_its_several_rules(self):
        got = np.rules_choosing("main", IP_RULE)
        assert len(got) == 4


class TestLink:
    def test_a_missing_interface_says_so(self, tmp_path):
        assert np.parse_link("nosuch", root=tmp_path) == {
            "iface": "nosuch", "present": False}

    def test_fields_are_read_from_sysfs(self, tmp_path):
        d = tmp_path / "enp1s0"
        (d / "statistics").mkdir(parents=True)
        for name, val in (("carrier", "1"), ("operstate", "up"),
                          ("speed", "1000"), ("duplex", "full"), ("mtu", "1500")):
            (d / name).write_text(val + "\n")
        for name, val in (("rx_bytes", "25832155119"), ("tx_bytes", "5474072331"),
                          ("rx_errors", "0"), ("tx_errors", "0"),
                          ("rx_dropped", "16040"), ("tx_dropped", "0")):
            (d / "statistics" / name).write_text(val + "\n")
        l = np.parse_link("enp1s0", root=tmp_path)
        assert l["carrier"] is True and l["speed_mbit"] == 1000
        assert l["duplex"] == "full" and l["mtu"] == 1500
        assert l["rx_dropped"] == 16040

    def test_a_down_port_reports_no_speed_rather_than_minus_one(self, tmp_path):
        # The driver writes -1 while the link is down. Passing that through
        # would put "-1 Mbit/s" in front of a person.
        d = tmp_path / "enp1s0"
        (d / "statistics").mkdir(parents=True)
        (d / "carrier").write_text("0\n")
        (d / "speed").write_text("-1\n")
        l = np.parse_link("enp1s0", root=tmp_path)
        assert l["carrier"] is False and l["speed_mbit"] is None


class TestInterception:
    def test_the_gateways_own_cgnat_address_is_not_intercepted(self):
        v = np.interception_verdict("100.113.192.178", IPTABLES_PREROUTING)
        assert v["intercepted"] is False
        assert "100.64.0.0/10" in v["why"]

    def test_without_that_rule_the_gateways_own_traffic_is_swallowed(self):
        # This is the 2026-09-09 outage in one assertion: delete the line and
        # every packet for the box's own address goes into the tunnel instead
        # of being delivered. Nothing in the product could show this before.
        crippled = "\n".join(l for l in IPTABLES_PREROUTING.splitlines()
                             if "100.64.0.0/10" not in l)
        v = np.interception_verdict("100.113.192.178", crippled)
        assert v["intercepted"] is True

    def test_an_ordinary_foreign_address_is_intercepted(self):
        v = np.interception_verdict("140.82.121.4", IPTABLES_PREROUTING)
        assert v["intercepted"] is True
        assert "xray" in v["why"]

    def test_a_private_destination_is_excepted(self):
        v = np.interception_verdict("10.1.2.3", IPTABLES_PREROUTING)
        assert v["intercepted"] is False

    def test_port_and_protocol_rules_are_reported_not_ignored(self):
        # "Not intercepted" would be a lie when the answer is "depends what you
        # send" -- DNS, ICMP and FCM are excepted by port or protocol.
        v = np.interception_verdict("140.82.121.4", IPTABLES_PREROUTING)
        joined = " ".join(v["conditional"])
        assert "dpt:53" in joined and "icmp" in joined and "dpt:5228" in joined

    def test_an_empty_chain_admits_it_does_not_know(self):
        v = np.interception_verdict("1.2.3.4", "")
        assert v["intercepted"] is None

    def test_source_scoped_rules_do_not_answer_for_everyone(self):
        # The FPTN netns exception is scoped to one source subnet; treating it
        # as a general answer would exempt the whole internet.
        chain = ("    2528   421475 RETURN     all  --  *      *       "
                 "192.168.244.0/30     0.0.0.0/0\n"
                 "  462150 483505490 TPROXY     tcp  --  *      *       "
                 "0.0.0.0/0            0.0.0.0/0            "
                 "TPROXY redirect 0.0.0.0:12345 mark 0x1/0xffffffff\n")
        assert np.interception_verdict("8.8.8.8", chain)["intercepted"] is True


class TestChainParsing:
    def test_columns_are_read_as_iptables_prints_them(self):
        rows = np.parse_chain(IPTABLES_PREROUTING)
        cgnat = next(r for r in rows if r["dest"] == "100.64.0.0/10")
        assert cgnat["target"] == "RETURN" and cgnat["packets"] == 1354357
        assert cgnat["source"] == "0.0.0.0/0"

    def test_the_header_lines_are_not_rules(self):
        rows = np.parse_chain(IPTABLES_PREROUTING)
        assert all(r["target"] in ("RETURN", "TPROXY", "MARK") for r in rows)
