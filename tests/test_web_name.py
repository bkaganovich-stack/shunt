"""
The web interface by name (http://shunt.lan) and the Host check that came
with it (2.32.9).
"""
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "web"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "scripts"))
import main as m  # noqa: E402


class TestDnsName:
    def _conf(self, dns, lan_ip="192.168.100.1"):
        with patch.object(m, "_get_lan_ip", return_value=lan_ip):
            return m.build_dnsmasq_conf(dns)

    def test_the_name_points_at_the_gateway(self):
        conf = self._conf({"upstream": ["127.0.0.1#5053"]})
        assert "address=/shunt.lan/192.168.100.1" in conf
        assert "address=/shunt/192.168.100.1" in conf

    def test_it_follows_the_gateway_address(self):
        # The second box lives on another subnet: the name goes where it is.
        conf = self._conf({}, lan_ip="192.168.50.181")
        assert "address=/shunt.lan/192.168.50.181" in conf

    def test_no_name_without_an_address(self):
        conf = self._conf({}, lan_ip=None)
        assert "shunt.lan" not in conf

    def test_users_own_record_wins(self):
        conf = self._conf({"local_records": [{"hostname": "shunt.lan", "ip": "10.0.0.7"}]})
        assert "address=/shunt.lan/10.0.0.7" in conf
        assert "address=/shunt.lan/192.168.100.1" not in conf
        assert "address=/shunt/192.168.100.1" in conf

    def test_gateway_hosts_file_stays_home(self):
        # "node" used to come back as 127.0.1.1 to every client on the LAN.
        assert "no-hosts" in self._conf({}).splitlines()

    def test_topology_writer_says_the_same(self, tmp_path):
        import apply_topology as at
        with patch.object(at, "DNSMASQ_CONF", tmp_path / "shunt.conf"):
            at.write_dnsmasq({"topology": "inline", "lan_if": "eth1", "lan_ip": "192.168.100.1",
                              "dhcp_start": "192.168.100.10", "dhcp_end": "192.168.100.50"})
            conf = (tmp_path / "shunt.conf").read_text()
            at.write_dnsmasq({"topology": "loop", "lan_ip": "192.168.50.2", "router_ip": "192.168.50.1"})
            loop = (tmp_path / "shunt.conf").read_text()
        assert "address=/shunt.lan/192.168.100.1" in conf and "no-hosts" in conf
        assert "address=/shunt.lan/192.168.50.2" in loop


class TestHostAllowed:
    def test_addresses_and_private_names_pass(self):
        for h in ("192.168.100.1", "192.168.100.1:80", "[fe80::1]:80", "[::1]",
                  "shunt", "shunt.lan", "SHUNT.LAN.", "shunt.lan:80", "node", "node.local",
                  "localhost", "x.home.arpa", "testserver", ""):
            assert m.host_allowed(h), h

    def test_public_names_are_refused(self):
        for h in ("evil.example", "rebind.attacker.com:80", "shunt.lan.evil.com"):
            assert not m.host_allowed(h), h

    def test_users_local_records_pass(self):
        assert m.host_allowed("gw.example.org", ["gw.example.org"])


class TestHostGuard:
    def setup_method(self):
        self.c = TestClient(m.app)

    def test_rebound_name_gets_421(self):
        with patch.object(m, "_local_record_names", return_value=[]):
            r = self.c.get("/api/auth-check", headers={"Host": "rebind.attacker.com"})
        assert r.status_code == 421
        assert "shunt.lan" in r.text

    def test_by_name_and_by_address_it_answers(self):
        for h in ("shunt.lan", "192.168.100.1"):
            r = self.c.get("/generate_204", headers={"Host": h})
            assert r.status_code == 204
            r = self.c.get("/api/auth-check", headers={"Host": h})
            assert r.status_code != 421, h

    def test_captive_probes_answer_under_any_name(self):
        r = self.c.get("/generate_204", headers={"Host": "connectivitycheck.gstatic.com"})
        assert r.status_code == 204

    def test_websocket_from_a_rebound_name_is_closed(self):
        import pytest
        from starlette.websockets import WebSocketDisconnect
        with patch.object(m, "_local_record_names", return_value=[]):
            with pytest.raises(WebSocketDisconnect):
                with self.c.websocket_connect("/ws/terminal", headers={"Host": "evil.example"}):
                    pass

    def test_status_carries_the_name(self):
        assert m.WEB_NAMES[0] == "shunt.lan"
