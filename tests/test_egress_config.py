"""
The cascade egresses (src/scripts/egress_config.py, egress-netns.sh).

Configurations here are invented; the shapes are the ones the cascade server
issues: awg-add.sh client configs (AmneziaWG 2.0, H ranges) and the
TrustTunnel endpoint's toml export after the client's setup wizard.
"""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "scripts"))
import egress_config as ec  # noqa: E402

AWG = """[Interface]
PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5PQ==
Address = 10.8.0.10/32
DNS = 10.99.0.2
MTU = 1380
Jc = 5
Jmin = 77
Jmax = 741
S1 = 35
S2 = 93
S3 = 60
S4 = 9
H1 = 359814363-368086978
H2 = 732412281-755285864
H3 = 1249487119-1296230570
H4 = 1828440046-1859616757

[Peer]
PublicKey = cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHViPQ==
PresharedKey = cHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHM9PQ==
Endpoint = 203.0.113.52:45587
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

WIZARD = """loglevel = "info"
vpn_mode = "general"
killswitch_enabled = true
killswitch_allow_ports = []
post_quantum_group_enabled = true
exclusions = []

[endpoint]
hostname = "static.example.net"
addresses = ["static.example.net:443"]
custom_sni = ""
has_ipv6 = true
username = "shunt"
password = "endpoint-secret"
skip_verification = false
certificate = ""
upstream_protocol = "http2"
anti_dpi = false
dns_upstreams = []

[listener]

[listener.tun]
bound_if = ""
included_routes = ["0.0.0.0/0", "2000::/3"]
change_system_dns = true
"""


def no_dns(host):
    return {"static.example.net": "203.0.113.52", "riga.example.net": "203.0.113.52"}.get(host, host)


class TestAwg:
    def test_quick_only_keys_leave_obfuscation_stays(self):
        setconf, facts = ec.split_awg(AWG, resolve=no_dns)
        assert not re.search(r"(?m)^(Address|DNS|MTU)\s*=", setconf)
        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "PrivateKey", "PresharedKey"):
            assert re.search(r"(?m)^%s = " % key, setconf), key
        assert "H1 = 359814363-368086978" in setconf
        assert facts == {"address": "10.8.0.10/32", "mtu": "1380", "dns": "10.99.0.2",
                         "endpoint_ip": "203.0.113.52", "endpoint_port": "45587"}

    def test_i_packets_pass_through_untouched(self):
        cfg = AWG.replace("H4 = ", "I1 = <b 0xc0ff>\nH4 = ")
        setconf, _ = ec.split_awg(cfg, resolve=no_dns)
        assert "I1 = <b 0xc0ff>" in setconf

    def test_hostname_endpoint_is_pinned_to_its_address(self):
        # The namespace routes the endpoint via the veth by address.
        cfg = AWG.replace("203.0.113.52:45587", "riga.example.net:45587")
        setconf, facts = ec.split_awg(cfg, resolve=no_dns)
        assert "Endpoint = 203.0.113.52:45587" in setconf
        assert facts["endpoint_ip"] == "203.0.113.52"

    def test_dual_stack_address_keeps_the_v4_one(self):
        _, facts = ec.split_awg(AWG.replace("10.8.0.10/32", "fd00::a/128, 10.8.0.10/32"),
                                resolve=no_dns)
        assert facts["address"] == "10.8.0.10/32"

    @pytest.mark.parametrize("drop", ["Address = 10.8.0.10/32\n", "Endpoint = 203.0.113.52:45587\n"])
    def test_incomplete_config_is_refused(self, drop):
        with pytest.raises(ValueError):
            ec.split_awg(AWG.replace(drop, ""), resolve=no_dns)


class TestTrustTunnel:
    def out(self, **kw):
        args = dict(socks="192.168.244.10:1084", user="shunt", password="socks-secret",
                    protocol="http3", resolve=no_dns)
        args.update(kw)
        return ec.tt_client(WIZARD, **args)

    def test_tun_listener_becomes_socks_with_credentials(self):
        s = self.out()
        assert "[listener.tun]" not in s and "included_routes" not in s
        assert '[listener.socks]\naddress = "192.168.244.10:1084"' in s
        assert 'username = "shunt"' in s.split("[listener.socks]")[1]
        assert 'password = "socks-secret"' in s

    def test_endpoint_is_pinned_and_hostname_kept_for_tls(self):
        s = self.out()
        assert 'addresses = ["203.0.113.52:443"]' in s
        assert 'hostname = "static.example.net"' in s
        assert 'password = "endpoint-secret"' in s

    def test_no_host_level_side_effects(self):
        s = self.out()
        assert "killswitch_enabled = false" in s and "has_ipv6 = false" in s
        assert "change_system_dns" not in s

    @pytest.mark.parametrize("proto", ["http2", "http3"])
    def test_protocol_choice(self, proto):
        assert 'upstream_protocol = "%s"' % proto in self.out(protocol=proto)

    def test_bad_input_is_refused(self):
        with pytest.raises(ValueError):
            self.out(protocol="quic")
        with pytest.raises(ValueError):
            ec.tt_client("loglevel = \"info\"\n", "192.168.244.10:1084", "u", "p", resolve=no_dns)


class TestPlumbing:
    def test_tproxy_exclusion_covers_every_egress_subnet(self):
        text = (ROOT / "src/scripts/iptables.sh").read_text()
        assert "-s 192.168.244.0/28 -j RETURN" in text
        script = (ROOT / "src/scripts/egress-netns.sh").read_text()
        import ipaddress
        excluded = ipaddress.ip_network("192.168.244.0/28")
        for sub in re.findall(r"SUB=(192\.168\.244\.\d+/30)", script):
            assert ipaddress.ip_network(sub).subnet_of(excluded), sub
        fptn = re.search(r"SUB=(\S+)", (ROOT / "src/scripts/fptn-egress.sh").read_text()).group(1)
        subs = re.findall(r"SUB=(192\.168\.244\.\d+/30)", script) + [fptn]
        assert len(set(subs)) == len(subs), "egress subnets overlap"

    def test_unit_does_not_loop_without_clients_or_config(self):
        unit = (ROOT / "systemd/shunt-egress@.service").read_text()
        assert "ConditionPathIsDirectory=/opt/shunt/egress/bin" in unit
        assert "ConditionDirectoryNotEmpty=/opt/shunt/config/egress/%i" in unit
        assert "RestartMaxDelaySec=600" in unit

    def test_private_key_does_not_outlive_setconf(self):
        script = (ROOT / "src/scripts/egress-netns.sh").read_text()
        setconf = script.index('awg" setconf awg0')
        assert script.index('rm -f "$RUN/setconf.conf"') > setconf

    def test_bridge_cannot_leave_through_the_veth(self):
        script = (ROOT / "src/scripts/egress-netns.sh").read_text()
        assert "--uid-owner $BRIDGE_UID" in script and "REJECT" in script
        assert "setpriv --reuid=$BRIDGE_UID" in script


class TestTrustTunnelLoopback:
    def test_loopback_listener_needs_no_credentials(self):
        s = ec.tt_client(WIZARD, "127.0.0.1:1085", protocol="http3", resolve=no_dns)
        sock = s.split("[listener.socks]")[1]
        assert 'address = "127.0.0.1:1085"' in sock and "username" not in sock

    def test_off_loopback_without_credentials_is_refused(self):
        with pytest.raises(ValueError):
            ec.tt_client(WIZARD, "192.168.244.10:1084", resolve=no_dns)

    def test_every_egress_is_a_plain_socks_address(self):
        # Probes, xray and the watchdog all speak to "the tunnel" with no auth.
        script = (ROOT / "src/scripts/egress-netns.sh").read_text()
        assert script.count('"auth": "noauth"') == 4        # AmneziaWG, TrustTunnel, a WARP port on each
        assert "127.0.0.1:1085" in script


class TestUserParams:
    """MTU and I1 set on the page are laid over the server's file, never into it."""

    def test_mtu_override(self):
        _, facts = ec.split_awg(AWG, resolve=no_dns, params={"mtu": 1280})
        assert facts["mtu"] == "1280"

    def test_i1_on_adds_it_before_the_peer(self):
        setconf, _ = ec.split_awg(AWG, resolve=no_dns, params={"i1": {"enabled": True, "value": "<b 0xc3><r 8>"}})
        iface = setconf.split("[Peer]")[0]
        assert "I1 = <b 0xc3><r 8>" in iface and iface.count("I1 =") == 1

    def test_i1_off_drops_the_files_own(self):
        cfg = AWG.replace("H4 = ", "I1 = <b 0xff>\nH4 = ")
        setconf, _ = ec.split_awg(cfg, resolve=no_dns, params={"i1": {"enabled": False, "value": "<b 0xc3>"}})
        assert "I1" not in setconf

    def test_no_params_leaves_the_file_as_issued(self):
        cfg = AWG.replace("H4 = ", "I1 = <b 0xff>\nH4 = ")
        setconf, facts = ec.split_awg(cfg, resolve=no_dns)
        assert "I1 = <b 0xff>" in setconf and facts["mtu"] == "1380"

    def test_trusttunnel_anti_dpi(self):
        s = ec.tt_client(WIZARD, "127.0.0.1:1085", resolve=no_dns, anti_dpi=True)
        assert "anti_dpi = true" in s


def test_warp_is_handed_names_not_addresses():
    # WARP's IPv4 exit is Iran to Google; given a name it leaves over IPv6 (USA).
    script = (ROOT / "src/scripts/egress-netns.sh").read_text()
    inbound = script[script.index('"tag": "warp-in"'):script.index('"outbounds"', script.index('"tag": "warp-in"'))]
    assert '"destOverride": ["http", "tls"]' in inbound and '"routeOnly": false' in inbound


def _bridges(script: str) -> dict:
    """Both bridge configs as the script writes them, variables filled in."""
    env = {"NSIP": "192.168.244.6", "PORT": "1083", "WARP_PORT": "1086", "DNS": "10.99.0.2",
           "WARP_RELAY_HOST": "10.99.0.2", "WARP_RELAY_PORT": "40001", "TT_NSIP": "192.168.244.10"}
    out = {}
    for fn in ("run_amnezia", "run_trusttunnel"):
        body = script[script.index(fn + "() {"):]
        doc = body[body.index("<<JSON\n") + 7:body.index("\nJSON\n")]
        doc = re.sub(r"\$\{DNS:-[^}]*\}", env["DNS"], doc)
        out[fn] = json.loads(re.sub(r"\$([A-Z_]+)", lambda m: env[m.group(1)], doc))
    return out


class TestBootAndWarpFallback:
    """2026-10-22: a power cut, an un-NATed AWG flow for 9 hours, WARP with it."""
    script = (ROOT / "src/scripts/egress-netns.sh").read_text()

    def test_setup_waits_for_the_wan_before_anything_leaves(self):
        setup = self.script[self.script.index("setup() {"):]
        assert setup.index("wait_wan || exit 1") < setup.index("MASQUERADE")

    def test_wan_wait_ends_before_systemd_gives_up_on_the_start(self):
        n = int(re.search(r"for _ in \$\(seq (\d+)\); do\n\s+WAN=", self.script).group(1))
        assert n < 90                                       # TimeoutStartSec default

    def test_no_route_in_main_means_unreachable_not_sing_box(self):
        assert 'ip rule add from "$SUB" priority 41 unreachable' in self.script
        assert 'ip rule del from "$SUB" priority 41 unreachable' in self.script

    def test_stale_flows_are_dropped_after_nat_is_in_place(self):
        setup = self.script[self.script.index("setup() {"):]
        assert setup.index("MASQUERADE") < setup.index('conntrack -D -s "$NSIP"')

    def test_bridges_may_reach_each_other_but_not_the_internet(self):
        assert '-o "$VETH_NS" -d "$EGRESS_NET" -j ACCEPT' in self.script
        assert 'route add "$EGRESS_NET" via "$HOSTIP"' in self.script
        assert "EGRESS_NET=192.168.244.0/28" in self.script

    def test_bridge_configs_are_valid_json(self):
        b = _bridges(self.script)
        assert set(b) == {"run_amnezia", "run_trusttunnel"}

    def test_warp_rides_awg_and_falls_back_to_trusttunnel(self):
        am = _bridges(self.script)["run_amnezia"]
        bal = am["routing"]["balancers"][0]
        assert bal["selector"] == ["relay-awg"] and bal["fallbackTag"] == "relay-tt"
        assert am["observatory"]["subjectSelector"] == ["relay-awg"]
        tags = {o["tag"]: o for o in am["outbounds"]}
        # Prefix match: no other outbound may answer to the observed selector.
        assert [t for t in tags if t.startswith("relay-awg")] == ["relay-awg"]
        assert tags["relay-tt"]["settings"]["servers"][0] == {"address": "192.168.244.10", "port": 1086}
        rule = am["routing"]["rules"][0]
        assert rule["inboundTag"] == ["warp-in"] and rule["balancerTag"] == "warp"

    def test_trusttunnel_warp_port_chains_through_its_client(self):
        tt = _bridges(self.script)["run_trusttunnel"]
        warp_in = [i for i in tt["inbounds"] if i["tag"] == "warp-in"][0]
        assert warp_in["port"] == 1086 and warp_in["sniffing"]["routeOnly"] is False
        warp = [o for o in tt["outbounds"] if o["tag"] == "warp"][0]
        assert warp["settings"]["servers"][0] == {"address": "10.99.0.2", "port": 40001}
        assert warp["proxySettings"] == {"tag": "out"}
        assert tt["routing"]["rules"][0] == {"type": "field", "inboundTag": ["warp-in"], "outboundTag": "warp"}
