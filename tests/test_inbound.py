"""
Tests for inbound access.

The `ss` fixture is real output from the live gateway, noise included: the
per-flow UDP sockets xray opens show foreign addresses in the local column, and
they are not listeners. A parser written against a tidy imagined listing would
have shown the household a page full of things that are not listening.

Run:  python -m pytest tests/ -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "web"))

import inbound as ib  # noqa: E402


SS = """\
tcp LISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=135226,fd=4),("systemd",pid=1,fd=242))
tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=135226,fd=3))
tcp LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:(("python3",pid=207553,fd=13))
tcp LISTEN 0 4096 127.0.0.1:5053 0.0.0.0:* users:(("python3",pid=1234,fd=5))
udp UNCONN 0 0 192.168.244.1:53 0.0.0.0:* users:(("python3",pid=207819,fd=3))
udp UNCONN 0 0 0.0.0.0%enx6c1ff7c1784f:67 0.0.0.0:* users:(("dnsmasq",pid=48212,fd=4))
udp UNCONN 0 0 0.0.0.0%wlp2s0:67 0.0.0.0:* users:(("dnsmasq",pid=207684,fd=4))
udp UNCONN 0 0 100.113.192.178%enp1s0:68 0.0.0.0:* users:(("systemd-network",pid=830,fd=38))
udp UNCONN 0 0 127.0.0.1:58756 0.0.0.0:* users:(("adguardvpn-cli",pid=48413,fd=142))
udp UNCONN 0 0 127.0.0.1:42382 0.0.0.0:* users:(("adguardvpn-cli",pid=48413,fd=144))
udp UNCONN 0 0 104.18.95.41:443 0.0.0.0:* users:(("xray",pid=207544,fd=402))
udp UNCONN 0 0 17.253.125.29:443 0.0.0.0:* users:(("xray",pid=207544,fd=110))
udp UNCONN 0 0 95.31.7.160:123 0.0.0.0:* users:(("xray",pid=207544,fd=452))
"""

LOCAL = {"100.113.192.178", "192.168.100.1", "192.168.99.1", "192.168.244.1",
         "172.19.0.1"}


class TestWhetherInboundCanWorkAtAll:
    def test_cgnat_says_no_and_says_why(self):
        # The fact that decides whether this whole feature does anything on this
        # gateway. Said once at the top, not discovered after an evening.
        r = ib.reachability("100.113.192.178/19")
        assert r["reachable"] is False
        assert "100.64.0.0/10" in r["why"]
        assert "не будет" in r["why"]

    def test_a_public_address_says_yes_and_means_it(self):
        r = ib.reachability("93.184.216.34/24")
        assert r["reachable"] is True
        assert "доходят" in r["why"]

    def test_rfc1918_points_at_the_router_in_front(self):
        r = ib.reachability("192.168.1.50/24")
        assert r["reachable"] is False and "ещё один маршрутизатор" in r["why"]

    def test_no_address_is_unknown_not_no(self):
        assert ib.reachability(None)["reachable"] is None
        assert ib.reachability("rubbish")["reachable"] is None


class TestValidation:
    LAN = "192.168.100.1/24"
    GW = {"192.168.100.1", "100.113.192.178", "127.0.0.1"}

    def _rule(self, **kw):
        r = {"id": "1", "name": "Сервер", "proto": "tcp", "wan_port": 8443,
             "to_ip": "192.168.100.50", "to_port": 443, "enabled": True}
        r.update(kw)
        return r

    def test_a_normal_forward_is_accepted(self):
        assert ib.validate_rule(self._rule(), self.LAN, self.GW) == []

    def test_pointing_at_the_gateway_is_refused(self):
        # The worst thing this feature could do is expose the admin interface
        # or SSH through a mistyped destination.
        errs = ib.validate_rule(self._rule(to_ip="192.168.100.1"), self.LAN, self.GW)
        assert errs and "сам шлюз" in errs[0]

    def test_pointing_outside_the_lan_is_refused(self):
        errs = ib.validate_rule(self._rule(to_ip="8.8.8.8"), self.LAN, self.GW)
        assert any("вне локальной сети" in e for e in errs)

    def test_ports_must_be_ports(self):
        for bad in (0, 65536, -1, "abc", None):
            assert ib.validate_rule(self._rule(wan_port=bad), self.LAN, self.GW)

    def test_protocol_is_tcp_or_udp(self):
        assert ib.validate_rule(self._rule(proto="icmp"), self.LAN, self.GW)
        assert ib.validate_rule(self._rule(proto="udp"), self.LAN, self.GW) == []

    def test_the_same_external_port_cannot_be_claimed_twice(self):
        existing = [self._rule(id="other", name="Другое")]
        errs = ib.validate_rule(self._rule(id="new"), self.LAN, self.GW, existing)
        assert any("уже занят" in e for e in errs)

    def test_the_same_port_on_the_other_protocol_is_fine(self):
        existing = [self._rule(id="other", proto="udp")]
        assert ib.validate_rule(self._rule(id="new", proto="tcp"),
                                self.LAN, self.GW, existing) == []

    def test_editing_a_rule_does_not_collide_with_itself(self):
        existing = [self._rule(id="1")]
        assert ib.validate_rule(self._rule(id="1", to_port=8443),
                                self.LAN, self.GW, existing) == []


class TestCostSentence:
    def test_on_a_public_address_it_states_the_exposure(self):
        s = ib.cost_sentence({"wan_port": 22, "proto": "tcp",
                              "to_ip": "192.168.100.50", "to_port": 22},
                             "93.184.216.34/24")
        assert "доступен из интернета" in s

    def test_on_cgnat_it_refuses_to_pretend(self):
        s = ib.cost_sentence({"wan_port": 22, "proto": "tcp",
                              "to_ip": "192.168.100.50", "to_port": 22},
                             "100.113.192.178/19")
        assert "снаружи он не откроется" in s and "CGNAT" in s


class TestConfFile:
    RULES = [
        {"proto": "tcp", "wan_port": 8443, "to_ip": "192.168.100.50",
         "to_port": 443, "enabled": True},
        {"proto": "udp", "wan_port": 51820, "to_ip": "192.168.100.60",
         "to_port": 51820, "enabled": True},
        {"proto": "tcp", "wan_port": 9000, "to_ip": "192.168.100.70",
         "to_port": 9000, "enabled": False},
    ]

    def test_only_enabled_rules_reach_the_datapath(self):
        # A rule switched off in the interface must not be open on the wire.
        conf = ib.render_conf(self.RULES)
        assert "9000" not in conf
        assert "8443" in conf and "51820" in conf

    def test_the_format_round_trips(self):
        back = ib.parse_conf(ib.render_conf(self.RULES))
        assert len(back) == 2
        assert back[0] == {"proto": "tcp", "wan_port": 8443,
                           "to_ip": "192.168.100.50", "to_port": 443}

    def test_an_empty_list_is_a_file_with_no_rules_not_no_file(self):
        conf = ib.render_conf([])
        assert conf.startswith("#") and ib.parse_conf(conf) == []

    def test_comments_and_junk_lines_are_skipped(self):
        assert ib.parse_conf("# comment\n\ngarbage\ntcp 1 2.2.2.2 3\n") == [
            {"proto": "tcp", "wan_port": 1, "to_ip": "2.2.2.2", "to_port": 3}]


class TestListeners:
    def test_the_real_services_are_found(self):
        out = ib.parse_listeners(SS, LOCAL, lan_ip="192.168.100.1",
                                 wan_ip="100.113.192.178")
        ports = {(r["proto"], r["port"]) for r in out["listeners"]}
        assert ("tcp", 22) in ports and ("tcp", 80) in ports
        assert ("udp", 67) in ports and ("udp", 53) in ports

    def test_xrays_per_flow_sockets_are_not_listeners(self):
        # They show foreign addresses in the local column. Listing them would
        # tell the household that 104.18.95.41 is listening on their gateway.
        out = ib.parse_listeners(SS, LOCAL)
        assert all(r["address"] not in ("104.18.95.41", "17.253.125.29",
                                        "95.31.7.160")
                   for r in out["listeners"])
        assert all(r["port"] != 443 for r in out["listeners"])

    def test_loopback_sockets_are_counted_not_listed(self):
        # Fifty of them on the real box. "And fifty more you cannot reach" is
        # the honest summary; a list of them is just frightening.
        out = ib.parse_listeners(SS, LOCAL)
        assert out["loopback_only"] == 3
        assert all(not r["address"].startswith("127.") for r in out["listeners"])

    def test_one_row_per_service_not_per_socket(self):
        # sshd binds v4 and v6 separately; saying so twice teaches nothing.
        out = ib.parse_listeners(SS, LOCAL)
        assert len([r for r in out["listeners"] if r["port"] == 22]) == 1

    def test_a_wildcard_bind_is_not_called_exposed(self):
        out = ib.parse_listeners(SS, LOCAL)
        web = next(r for r in out["listeners"] if r["port"] == 80)
        assert web["wildcard"] is True
        assert "закрыт правилом WAN" in web["exposure"]

    def test_an_interface_scoped_bind_names_the_interface(self):
        out = ib.parse_listeners(SS, LOCAL)
        dhcp = next(r for r in out["listeners"] if r["port"] == 67)
        assert "enx6c1ff7c1784f" in dhcp["where"] or "wlp2s0" in dhcp["where"]

    def test_the_process_is_named(self):
        out = ib.parse_listeners(SS, LOCAL)
        web = next(r for r in out["listeners"] if r["port"] == 80)
        assert web["process"] == "python3"

    def test_empty_input_is_empty_not_an_error(self):
        assert ib.parse_listeners("", LOCAL) == {
            "listeners": [], "loopback_only": 0, "transient": 0}

    def test_ephemeral_udp_sockets_are_not_services(self):
        # Found by running it: xray keeps dozens of per-flow UDP sockets bound
        # to the wildcard on high ports, and they arrived looking exactly like
        # listeners. Nothing serves from the range the kernel hands to clients.
        noisy = SS + ("udp UNCONN 0 0 *:52117 *:* users:((\"xray\",pid=1,fd=9))\n"
                      "udp UNCONN 0 0 *:60745 *:* users:((\"xray\",pid=1,fd=8))\n")
        out = ib.parse_listeners(noisy, LOCAL, ephemeral=(32768, 60999))
        assert all(r["port"] not in (52117, 60745) for r in out["listeners"])
        assert out["transient"] >= 2

    def test_the_range_is_read_from_the_kernel_not_guessed(self, tmp_path):
        f = tmp_path / "range"
        f.write_text("10000\t20000\n")
        assert ib.ephemeral_range(str(f)) == (10000, 20000)
        assert ib.ephemeral_range(str(tmp_path / "nope")) == (32768, 60999)

    def test_a_high_tcp_listener_is_still_a_service(self):
        # The SOCKS port is 1080 and sing-box could as easily sit above 32768;
        # TCP rows are LISTEN already, so the range does not apply to them.
        high = SS + 'tcp LISTEN 0 4096 0.0.0.0:40000 0.0.0.0:* users:(("sing-box",pid=2,fd=1))\n'
        out = ib.parse_listeners(high, LOCAL, ephemeral=(32768, 60999))
        assert any(r["port"] == 40000 for r in out["listeners"])
