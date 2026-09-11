"""
Tests for the health monitor's neighbour check.
Run:  python -m pytest tests/ -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "scripts"))

import socket  # noqa: E402
import health_monitor as hm  # noqa: E402


class TestNeighbourToWatch:
    def _leases(self, tmp_path, text):
        f = tmp_path / "dnsmasq.leases"
        f.write_text(text)
        hm.LEASES = f
        return f

    def test_loop_watches_the_upstream_router(self):
        assert hm.neighbour_to_watch("loop", "192.168.50.2") == hm.LOOP_ROUTER

    def test_inline_watches_whoever_took_a_lease_from_us(self, tmp_path):
        self._leases(tmp_path,
                     "1789000000 aa:bb:cc:dd:ee:ff 192.168.100.45 router *\n")
        assert hm.neighbour_to_watch("inline", "192.168.100.1") == "192.168.100.45"

    def test_inline_ignores_leases_outside_our_own_subnet(self, tmp_path):
        # The management AP hands out leases too; watching one of those would
        # report the LAN healthy while the LAN is down.
        self._leases(tmp_path,
                     "1789000000 aa:bb:cc:dd:ee:01 192.168.99.7 phone *\n"
                     "1789000100 aa:bb:cc:dd:ee:02 192.168.100.45 router *\n")
        assert hm.neighbour_to_watch("inline", "192.168.100.1") == "192.168.100.45"

    def test_inline_takes_the_newest_of_several(self, tmp_path):
        self._leases(tmp_path,
                     "1789000000 aa:bb:cc:dd:ee:01 192.168.100.20 old *\n"
                     "1789009999 aa:bb:cc:dd:ee:02 192.168.100.45 new *\n")
        assert hm.neighbour_to_watch("inline", "192.168.100.1") == "192.168.100.45"

    def test_nothing_to_watch_is_not_a_warning(self, tmp_path):
        # The whole point of the change: an address nobody expects to answer
        # must produce silence, not a warning every minute for days.
        self._leases(tmp_path, "")
        assert hm.neighbour_to_watch("inline", "192.168.100.1") is None

    def test_a_missing_lease_file_is_not_a_crash(self, tmp_path):
        hm.LEASES = tmp_path / "does-not-exist"
        assert hm.neighbour_to_watch("inline", "192.168.100.1") is None

    def test_garbage_lines_are_skipped(self, tmp_path):
        self._leases(tmp_path,
                     "not a lease\n"
                     "duid 00:01:02\n"
                     "1789000000 aa:bb:cc:dd:ee:02 192.168.100.45 router *\n")
        assert hm.neighbour_to_watch("inline", "192.168.100.1") == "192.168.100.45"


class TestReachesInternet:
    def test_it_does_not_use_ping(self, monkeypatch):
        # The whole point: on this box the tunnel's tun answers ICMP for every
        # address, including ones nobody on earth replies to, so a ping-based
        # check cannot fail and never could.
        called = []
        monkeypatch.setattr(hm, "ping", lambda h: called.append(h) or True)
        monkeypatch.setattr(hm.socket, "socket", _FakeSocket.factory(ok=False))
        assert hm.reaches_internet() is False
        assert called == []

    def test_one_reachable_operator_is_enough(self, monkeypatch):
        monkeypatch.setattr(hm.socket, "socket", _FakeSocket.factory(ok_on=1))
        assert hm.reaches_internet() is True

    def test_both_unreachable_is_a_dead_wan(self, monkeypatch):
        monkeypatch.setattr(hm.socket, "socket", _FakeSocket.factory(ok=False))
        assert hm.reaches_internet() is False

    def test_the_probe_is_marked_to_bypass_interception(self, monkeypatch):
        # Without the mark the probe is intercepted and answered by the very
        # machinery it is supposed to be checking.
        seen = []
        monkeypatch.setattr(hm.socket, "socket",
                            _FakeSocket.factory(ok=True, record=seen))
        hm.reaches_internet()
        assert (socket.SOL_SOCKET, hm.SO_MARK, hm.BYPASS_MARK) in seen


class _FakeSocket:
    """Stands in for a TCP socket without touching the network."""

    def __init__(self, ok, ok_on, record, counter):
        self._ok, self._ok_on, self._record, self._counter = ok, ok_on, record, counter

    @classmethod
    def factory(cls, ok=True, ok_on=None, record=None):
        counter = {"n": 0}
        return lambda *a, **k: cls(ok, ok_on, record, counter)

    def setsockopt(self, *args):
        if self._record is not None:
            self._record.append(args)

    def settimeout(self, t):
        pass

    def connect(self, addr):
        self._counter["n"] += 1
        if self._ok_on is not None:
            if self._counter["n"] != self._ok_on:
                raise OSError("refused")
            return
        if not self._ok:
            raise OSError("refused")

    def close(self):
        pass


class TestLeaseDuration:
    def test_the_forms_systemd_actually_writes(self):
        assert hm.parse_duration("10min") == 600
        assert hm.parse_duration("8min 45s") == 525
        assert hm.parse_duration("1h 30min") == 5400
        assert hm.parse_duration("1h") == 3600

    def test_a_bare_number_is_seconds(self):
        assert hm.parse_duration("600") == 600

    def test_nothing_parseable_is_none_not_zero(self):
        # None means "could not read"; zero would mean "expires immediately",
        # and the caller treats those very differently.
        assert hm.parse_duration("") is None
        assert hm.parse_duration("forever") is None


class TestWanAddressChange:
    def _monitor(self, tmp_path, monkeypatch, addr):
        monkeypatch.setattr(hm, "WAN_CHANGES", tmp_path / "wan-changes.json")
        monkeypatch.setattr(hm, "iface_cidr", lambda i: addr)
        monkeypatch.setattr(hm, "lease_lifetime", lambda i: None)
        logged = []
        monkeypatch.setattr(hm, "log", lambda m: logged.append(m))
        return logged

    def test_the_first_sighting_is_not_a_change(self, tmp_path, monkeypatch):
        logged = self._monitor(tmp_path, monkeypatch, "100.113.192.178/19")
        st = hm.note_wan_address({}, "enp1s0")
        assert st["wan_cidr"] == "100.113.192.178/19"
        assert not [m for m in logged if "changed" in m]

    def test_a_new_address_is_announced(self, tmp_path, monkeypatch):
        logged = self._monitor(tmp_path, monkeypatch, "100.101.243.40/20")
        hm.note_wan_address({"wan_cidr": "100.116.44.163/16"}, "enp1s0")
        said = [m for m in logged if "changed" in m]
        assert said and "100.116.44.163/16" in said[0] and "100.101.243.40/20" in said[0]

    def test_a_changed_prefix_is_called_out_separately(self, tmp_path, monkeypatch):
        # /16 to /19 is a different piece of the provider's network, not just a
        # renumbering, and it is what happened here.
        logged = self._monitor(tmp_path, monkeypatch, "100.113.192.178/19")
        hm.note_wan_address({"wan_cidr": "100.116.44.163/16"}, "enp1s0")
        assert any("/16 → /19" in m for m in logged)

    def test_the_change_is_written_down_for_later(self, tmp_path, monkeypatch):
        import json
        self._monitor(tmp_path, monkeypatch, "100.101.243.40/20")
        hm.note_wan_address({"wan_cidr": "100.116.44.163/16"}, "enp1s0")
        hist = json.loads((tmp_path / "wan-changes.json").read_text())
        assert hist[-1]["from"] == "100.116.44.163/16"
        assert hist[-1]["to"] == "100.101.243.40/20"

    def test_history_stays_bounded(self, tmp_path, monkeypatch):
        import json
        monkeypatch.setattr(hm, "WAN_CHANGES", tmp_path / "wan-changes.json")
        monkeypatch.setattr(hm, "lease_lifetime", lambda i: None)
        monkeypatch.setattr(hm, "log", lambda m: None)
        st = {"wan_cidr": "10.0.0.0/8"}
        for i in range(hm.WAN_CHANGES_MAX + 10):
            monkeypatch.setattr(hm, "iface_cidr", lambda x, i=i: "10.0.0.%d/8" % (i + 1))
            st = hm.note_wan_address(st, "enp1s0")
        assert len(json.loads((tmp_path / "wan-changes.json").read_text())) == hm.WAN_CHANGES_MAX

    def test_a_short_lease_is_pointed_out_once(self, tmp_path, monkeypatch):
        logged = self._monitor(tmp_path, monkeypatch, "100.113.192.178/19")
        monkeypatch.setattr(hm, "lease_lifetime", lambda i: 600)
        st = hm.note_wan_address({}, "enp1s0")
        assert len([m for m in logged if "lease lasts" in m]) == 1
        hm.note_wan_address(st, "enp1s0")
        assert len([m for m in logged if "lease lasts" in m]) == 1

    def test_an_unreadable_address_changes_nothing(self, tmp_path, monkeypatch):
        self._monitor(tmp_path, monkeypatch, None)
        st = hm.note_wan_address({"wan_cidr": "100.116.44.163/16"}, "enp1s0")
        assert st["wan_cidr"] == "100.116.44.163/16"


class TestWhoIssuedTheAddress:
    def _setup(self, tmp_path, monkeypatch, addr, issuer):
        monkeypatch.setattr(hm, "WAN_CHANGES", tmp_path / "wan-changes.json")
        monkeypatch.setattr(hm, "WAN_CURRENT", tmp_path / "wan-current.json")
        monkeypatch.setattr(hm, "iface_cidr", lambda i: addr)
        monkeypatch.setattr(hm, "lease_lifetime", lambda i: None)
        monkeypatch.setattr(hm, "lease_issuer", lambda i: issuer)
        logged = []
        monkeypatch.setattr(hm, "log", lambda m: logged.append(m))
        return logged

    def test_a_different_server_is_called_out(self, tmp_path, monkeypatch):
        # What happened on 2026-09-10: the new address came from 100.105.144.1
        # instead of 100.116.0.1 -- the provider rebuilding the session after a
        # payment, not a lease renewal. Working that out took a conversation.
        import json
        logged = self._setup(tmp_path, monkeypatch, "100.101.243.40/20",
                             {"server": "100.105.144.1", "gateway": "100.101.240.1"})
        hm.note_wan_address({"wan_cidr": "100.116.44.163/16",
                             "wan_issuer": {"server": "100.116.0.1"}}, "enp1s0")
        hist = json.loads((tmp_path / "wan-changes.json").read_text())
        assert hist[-1]["different_server"] is True
        assert hist[-1]["server_from"] == "100.116.0.1"
        assert hist[-1]["server_to"] == "100.105.144.1"
        assert any("different DHCP server" in m for m in logged)

    def test_the_same_server_is_not_called_out(self, tmp_path, monkeypatch):
        import json
        logged = self._setup(tmp_path, monkeypatch, "100.116.44.200/16",
                             {"server": "100.116.0.1"})
        hm.note_wan_address({"wan_cidr": "100.116.44.163/16",
                             "wan_issuer": {"server": "100.116.0.1"}}, "enp1s0")
        hist = json.loads((tmp_path / "wan-changes.json").read_text())
        assert hist[-1]["different_server"] is False
        assert not any("different DHCP server" in m for m in logged)

    def test_an_unknown_previous_server_claims_nothing(self, tmp_path, monkeypatch):
        # First change after an upgrade: we never recorded the old issuer, so
        # "a different server" is not something we are entitled to say.
        import json
        self._setup(tmp_path, monkeypatch, "10.0.0.2/24", {"server": "10.0.0.1"})
        hm.note_wan_address({"wan_cidr": "10.0.0.1/24"}, "enp1s0")
        hist = json.loads((tmp_path / "wan-changes.json").read_text())
        assert hist[-1]["different_server"] is False

    def test_the_issuer_is_remembered_for_next_time(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch, "10.0.0.2/24", {"server": "10.0.0.1"})
        st = hm.note_wan_address({}, "enp1s0")
        assert st["wan_issuer"]["server"] == "10.0.0.1"
