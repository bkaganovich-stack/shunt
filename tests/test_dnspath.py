"""
Tests for the DNS view.

The response fixtures are real packets captured off the live gateway on
2026-09-11 — dnsmasq answering for a name that exists, dnsmasq answering for one
that does not (with an SOA in the authority section and a compression pointer in
it), and the provider's resolver answering for ya.ru. A DNS parser tested only
against packets it built itself is a parser tested against its own assumptions.

Run:  python -m pytest tests/ -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "web"))

import dnspath as dp  # noqa: E402


# dnsmasq → example.com, two A records
REAL_ANSWER = bytes.fromhex(
    "123481800001000200000000076578616d706c6503636f6d0000010001c00c0001000100"
    "00006200046814179ac00c00010001000000620004ac4293f3")

# dnsmasq → a name that does not exist: no answers, an SOA in authority,
# compression pointers throughout
REAL_NODATA = bytes.fromhex(
    "1234818000010000000100000c65686f726676646263746f68076578616d706c6503636f"
    "6d0000010001c0190006000100000708003207656c6c696f7474026e730a636c6f756466"
    "6c617265c02103646e73c0418fe0888d000027100000096000093a8000000708")

# provider's resolver → ya.ru, three A records
REAL_PROVIDER = bytes.fromhex(
    "1234818000010003000000000279610272750000010001c00c00010001000001d7000405"
    "fffff2c00c00010001000001d700044d582cf2c00c00010001000001d700044d5837f2")


class TestServerSpec:
    def test_dnsmasqs_port_form_is_understood(self):
        # 127.0.0.1#5053 is what this gateway actually runs on, and it is what
        # the old checker choked on while waving through addresses that answer
        # nothing.
        assert dp.parse_server("127.0.0.1#5053") == ("127.0.0.1", 5053)

    def test_a_bare_address_is_port_53(self):
        assert dp.parse_server("1.1.1.1") == ("1.1.1.1", 53)

    def test_rubbish_after_the_hash_does_not_become_a_port(self):
        assert dp.parse_server("1.1.1.1#abc") == ("1.1.1.1", 53)

    def test_whitespace_is_not_part_of_the_address(self):
        assert dp.parse_server("  8.8.8.8 ") == ("8.8.8.8", 53)


class TestQueryEncoding:
    def test_a_query_is_a_query(self):
        q = dp.encode_query("example.com", txid=0x1234)
        assert q[:2] == b"\x12\x34"
        assert q[2:4] == b"\x01\x00"          # recursion desired
        assert q[4:6] == b"\x00\x01"          # one question
        assert b"\x07example\x03com\x00" in q
        assert q[-4:] == b"\x00\x01\x00\x01"  # A, IN

    def test_the_transaction_id_varies_when_not_given(self):
        ids = {dp.encode_query("example.com")[:2] for _ in range(20)}
        assert len(ids) > 1

    def test_probe_names_are_random(self):
        # A fixed name measures the cache; the question is whether the path
        # works, so every probe asks something nobody has asked before.
        assert len({dp.random_name() for _ in range(20)}) == 20
        assert dp.random_name().endswith("." + dp.PROBE_SUFFIX)


class TestResponseDecoding:
    def test_a_real_answer_yields_its_addresses(self):
        r = dp.decode_response(REAL_ANSWER, expect_txid=0x1234)
        assert r["ok"] and r["rcode"] == 0
        assert r["answers"] == ["104.20.23.154", "172.66.147.243"]

    def test_a_real_empty_answer_is_still_an_answer(self):
        # The resolver replied. That it had nothing to say about the name is a
        # different fact, and conflating the two is how a working resolver gets
        # reported as dead.
        r = dp.decode_response(REAL_NODATA, expect_txid=0x1234)
        assert r["ok"] and r["answers"] == []

    def test_the_providers_resolver_parses_too(self):
        r = dp.decode_response(REAL_PROVIDER, expect_txid=0x1234)
        assert r["answers"] == ["5.255.255.242", "77.88.44.242", "77.88.55.242"]

    def test_a_reply_to_someone_elses_question_is_refused(self):
        r = dp.decode_response(REAL_ANSWER, expect_txid=0x9999)
        assert r["ok"] is False

    def test_a_truncated_packet_is_not_a_crash(self):
        for n in (0, 3, 11, 20, 40):
            assert dp.decode_response(REAL_ANSWER[:n])["ok"] in (True, False)

    def test_a_lying_answer_count_does_not_run_off_the_end(self):
        # Hostile or damaged input: the header claims records that are not
        # there. Parsing must stop, not read past the buffer.
        bad = bytearray(REAL_ANSWER)
        bad[6:8] = b"\xff\xff"
        r = dp.decode_response(bytes(bad), expect_txid=0x1234)
        assert r["ok"] and len(r["answers"]) <= 2

    def test_the_rcode_is_named(self):
        assert dp.RCODE_NAMES[3] == "имя не существует"
        assert dp.RCODE_NAMES[2] == "сбой у резолвера"


class TestInventory:
    def _settings(self):
        return {"dns": {"upstream": ["127.0.0.1#5053"],
                        "upstream_ru": ["213.234.193.1", "85.21.2.1"]}}

    def test_every_resolver_in_the_chain_is_listed(self, monkeypatch):
        monkeypatch.setattr(dp, "lease_resolvers",
                            lambda i: ["213.234.193.1", "85.21.2.1"])
        monkeypatch.setattr(dp, "doh_upstreams", lambda: ["1.1.1.1", "1.0.0.1"])
        inv = dp.inventory(self._settings(), "enp1s0", lan_ip="192.168.100.1")
        servers = {i["server"] for i in inv}
        assert "127.0.0.1#5335" in servers       # dnsmasq, where devices land
        assert "127.0.0.1#5053" in servers       # the DoH proxy
        assert "213.234.193.1" in servers        # the .ru upstream
        assert "1.1.1.1" in servers              # where DoH forwards

    def test_one_resolver_appears_once_with_both_its_roles(self, monkeypatch):
        # The provider's resolvers are both the .ru upstream and what the lease
        # offered. Listing them twice with two verdicts is how a page stops
        # being believed.
        monkeypatch.setattr(dp, "lease_resolvers",
                            lambda i: ["213.234.193.1", "85.21.2.1"])
        monkeypatch.setattr(dp, "doh_upstreams", lambda: [])
        inv = dp.inventory(self._settings(), "enp1s0")
        row = [i for i in inv if i["server"] == "213.234.193.1"]
        assert len(row) == 1
        assert set(row[0]["roles"]) == {"upstream_ru", "lease"}

    def test_a_lease_resolver_nobody_configured_is_marked_unused(self, monkeypatch):
        monkeypatch.setattr(dp, "lease_resolvers", lambda i: ["9.9.9.9"])
        monkeypatch.setattr(dp, "doh_upstreams", lambda: [])
        inv = dp.inventory(self._settings(), "enp1s0")
        row = next(i for i in inv if i["server"] == "9.9.9.9")
        assert row["in_use"] is False
        assert "не используется" in row["label"]


class TestChain:
    def test_the_three_hops_are_spelled_out(self, monkeypatch):
        monkeypatch.setattr(dp, "doh_upstreams", lambda: ["1.1.1.1", "1.0.0.1"])
        hops = dp.describe_chain(
            {"dns": {"upstream": ["127.0.0.1#5053"],
                     "upstream_ru": ["213.234.193.1"]}},
            lan_ip="192.168.100.1")
        assert len(hops) == 3
        assert "192.168.100.1:53" in hops[0]["to"]
        assert "213.234.193.1" in hops[1]["to"]
        assert "туннел" in hops[1]["note"]
        assert "DoH" in hops[2]["via"] and "1.1.1.1" in hops[2]["note"]

    def test_without_split_dns_there_is_no_ru_hop(self, monkeypatch):
        monkeypatch.setattr(dp, "doh_upstreams", lambda: ["1.1.1.1"])
        hops = dp.describe_chain({"dns": {"upstream": ["8.8.8.8"]}},
                                 lan_ip="192.168.100.1")
        assert len(hops) == 2
        assert hops[1]["via"] == "напрямую"


class TestLeaseResolvers:
    def test_they_are_read_from_the_lease(self, tmp_path, monkeypatch):
        (tmp_path / "net").mkdir()
        (tmp_path / "net" / "enp1s0").mkdir()
        (tmp_path / "net" / "enp1s0" / "ifindex").write_text("2\n")
        (tmp_path / "leases").mkdir()
        (tmp_path / "leases" / "2").write_text(
            "ADDRESS=100.113.192.178\nDNS=213.234.193.1 85.21.2.1\n")
        monkeypatch.setattr(dp, "SYSFS", tmp_path / "net")
        monkeypatch.setattr(dp, "NETIF_LEASES", tmp_path / "leases")
        assert dp.lease_resolvers("enp1s0") == ["213.234.193.1", "85.21.2.1"]

    def test_no_lease_is_an_empty_list_not_an_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dp, "SYSFS", tmp_path)
        monkeypatch.setattr(dp, "NETIF_LEASES", tmp_path)
        assert dp.lease_resolvers("enp1s0") == []


class TestDohUpstreams:
    def test_read_from_the_proxy_itself(self, tmp_path):
        f = tmp_path / "doh_proxy.py"
        f.write_text('UP  = [("1.1.1.1", "/dns-query"), ("1.0.0.1", "/dns-query")]\n')
        assert dp.doh_upstreams(f) == ["1.1.1.1", "1.0.0.1"]

    def test_an_unreadable_proxy_falls_back_rather_than_claiming_none(self, tmp_path):
        assert dp.doh_upstreams(tmp_path / "nope.py") == dp.DOH_FALLBACK


NAT_PREROUTING = """\
Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source               destination
       0        0 RETURN     udp  --  *      *       192.168.244.0/30     0.0.0.0/0            udp dpt:53
   84213  6217344 REDIRECT   udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:53 redir ports 5335
     118    10456 REDIRECT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:53 redir ports 5335
"""


class TestClientHop:
    def test_the_redirect_is_counted_not_assumed(self):
        # dnsmasq listens on 5335 and devices ask port 53; what joins them is
        # this rule. Probing lan_ip:53 from the gateway answers "silent" while
        # every device resolves fine, because PREROUTING never sees a packet
        # the box sent itself.
        r = dp.parse_redirect(NAT_PREROUTING)
        assert r["present"] and r["carrying"]
        assert r["udp_packets"] == 84213 and r["tcp_packets"] == 118

    def test_a_missing_redirect_is_visible(self):
        # Without it the household's DNS goes nowhere, and the resolver probes
        # would all still be green.
        assert dp.parse_redirect("")["present"] is False

    def test_a_rule_that_has_never_fired_is_present_but_not_carrying(self):
        fresh = NAT_PREROUTING.replace("84213  6217344", "    0        0") \
                              .replace("118    10456", "  0        0")
        r = dp.parse_redirect(fresh)
        assert r["present"] is True and r["carrying"] is False

    def test_the_gateways_own_lan_address_is_not_probed(self, monkeypatch):
        # Guarding the decision above: adding it back would put a permanent
        # false alarm on the page.
        monkeypatch.setattr(dp, "lease_resolvers", lambda i: [])
        monkeypatch.setattr(dp, "doh_upstreams", lambda: [])
        inv = dp.inventory({"dns": {}}, "enp1s0", lan_ip="192.168.100.1")
        assert all(i["server"] != "192.168.100.1" for i in inv)
