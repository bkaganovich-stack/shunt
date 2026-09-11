"""
Tests for the diagnosis ladder.

Run:  python -m pytest tests/ -v
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "scripts"))

import diagnose as dg  # noqa: E402


class TestAddressClass:
    def test_the_two_that_mattered(self):
        # The September outage in one line: the provider moved the gateway from
        # one of these to the other, the exception list covered only the first,
        # and nothing said so.
        assert dg.classify_address("10.1.2.3/24") == "частный адрес (RFC1918)"
        assert "CGNAT" in dg.classify_address("100.113.192.178/19")

    def test_a_public_address_is_named_as_such(self):
        assert dg.classify_address("93.184.216.34/24") == "публичный адрес"

    def test_link_local_means_dhcp_never_answered(self):
        assert "DHCP" in dg.classify_address("169.254.10.5/16")

    def test_no_address_and_nonsense_are_different_answers(self):
        assert dg.classify_address(None) == "нет адреса"
        assert dg.classify_address("not-an-address") == "непонятный адрес"


class TestEnvironmentChanges:
    BEFORE = {"class": "частный адрес (RFC1918)", "prefix": "24",
              "gateway": "10.0.0.1", "lease_band": "длинная (больше суток)",
              "dhcp_server": "10.0.0.1"}

    def test_a_class_change_is_announced_first_and_plainly(self):
        after = dict(self.BEFORE, **{"class": "CGNAT провайдера (100.64.0.0/10)"})
        msgs = dg.environment_changes(self.BEFORE, after)
        assert msgs and "сменил тип адреса" in msgs[0]
        assert "исключений" in msgs[0]

    def test_a_prefix_change_within_a_class_is_worth_one_line(self):
        after = dict(self.BEFORE, prefix="19")
        msgs = dg.environment_changes(self.BEFORE, after)
        assert any("/24 → /19" in m for m in msgs)

    def test_a_class_change_does_not_also_report_the_prefix(self):
        # Two sentences about one event read as two events.
        after = dict(self.BEFORE, prefix="19",
                     **{"class": "CGNAT провайдера (100.64.0.0/10)"})
        msgs = dg.environment_changes(self.BEFORE, after)
        assert len([m for m in msgs if "Размер сети" in m]) == 0

    def test_a_lease_that_changed_by_an_order_of_magnitude(self):
        after = dict(self.BEFORE, lease_band="короткая (до 30 мин)")
        assert any("по порядку величины" in m
                   for m in dg.environment_changes(self.BEFORE, after))

    def test_a_new_dhcp_server_is_called_a_session_rebuild(self):
        after = dict(self.BEFORE, dhcp_server="100.105.144.1")
        msgs = dg.environment_changes(self.BEFORE, after)
        assert any("пересборку сессии" in m for m in msgs)

    def test_nothing_moved_means_nothing_said(self):
        assert dg.environment_changes(self.BEFORE, dict(self.BEFORE)) == []

    def test_the_first_ever_reading_is_not_a_change(self):
        assert dg.environment_changes({}, self.BEFORE) == []


class TestLadder:
    def _patch(self, monkeypatch, *, carrier=True, cidr="100.1.2.3/19",
               gw_ok=True, internet=True, dns=True, egress=True):
        monkeypatch.setattr(dg, "environment", lambda i: {
            "cidr": cidr, "class": dg.classify_address(cidr),
            "prefix": "19", "gateway": "100.1.0.1",
            "lease_seconds": 600, "lease_band": "короткая (до 30 мин)",
            "dhcp_server": "100.1.0.1"})
        monkeypatch.setattr(dg, "has_carrier", lambda i: carrier)
        monkeypatch.setattr(dg, "gateway_on_the_wire",
                            lambda g: (gw_ok, "виден" if gw_ok else "не отвечает на ARP"))
        monkeypatch.setattr(dg, "reaches_internet", lambda *a, **k: internet)
        monkeypatch.setattr(dg, "resolves", lambda *a, **k: dns)
        monkeypatch.setattr(dg, "egress_carries", lambda *a, **k: egress)

    def test_all_well_says_so(self, monkeypatch):
        self._patch(monkeypatch)
        d = dg.ladder("enp1s0")
        assert d["healthy"] and d["first_unmet"] is None
        assert all(r["ok"] for r in d["rungs"])

    def test_a_missing_cable_is_not_a_provider_outage(self, monkeypatch):
        # Reporting one as the other sends the reader hunting a bug that does
        # not exist -- which is exactly what happened in September.
        self._patch(monkeypatch, carrier=False)
        d = dg.ladder("enp1s0")
        assert d["first_unmet"] == "cable"
        assert d["owner"] == "снаружи" and d["fixable_here"] is False
        assert "кабель" in d["summary"].lower()

    def test_nothing_below_the_break_is_claimed_as_evidence(self, monkeypatch):
        # Everything under the first failure is consequence. Calling it a
        # second problem is how one fault became four reports.
        self._patch(monkeypatch, carrier=False)
        d = dg.ladder("enp1s0")
        below = [r for r in d["rungs"] if r["key"] != "cable"]
        assert all(r["ok"] is None for r in below)
        assert all("не проверялось" in r["detail"] for r in below)

    def test_a_dead_tunnel_over_a_healthy_uplink_is_ours(self, monkeypatch):
        self._patch(monkeypatch, egress=False)
        d = dg.ladder("enp1s0")
        assert d["first_unmet"] == "egress"
        assert d["owner"] == "на шлюзе" and d["fixable_here"] is True

    def test_a_dead_uplink_is_reported_before_the_tunnel(self, monkeypatch):
        # The tunnel cannot work without the uplink, so blaming it is blaming
        # a symptom. This ordering is the whole point.
        self._patch(monkeypatch, internet=False, dns=False, egress=False)
        d = dg.ladder("enp1s0")
        assert d["first_unmet"] == "internet"
        assert d["fixable_here"] is False

    def test_no_address_comes_before_no_gateway(self, monkeypatch):
        self._patch(monkeypatch, cidr=None, gw_ok=False)
        assert dg.ladder("enp1s0")["first_unmet"] == "address"


class TestRemedyLimiting:
    def _diag(self, **kw):
        base = {"healthy": False, "fixable_here": True, "owner": "на шлюзе",
                "summary": "Туннель не несёт трафик"}
        base.update(kw)
        return base

    def test_a_fault_we_own_may_be_fixed(self):
        ok, why = dg.remedy_allowed({}, "restart-adguard", self._diag())
        assert ok and "1 из 3" in why

    def test_nothing_is_restarted_when_nothing_is_broken(self):
        ok, why = dg.remedy_allowed({}, "restart-adguard",
                                    self._diag(healthy=True))
        assert not ok and "чинить нечего" in why

    def test_a_fault_outside_is_not_ours_to_restart(self):
        # Restarting the tunnel while the cable is out is theatre, and it filled
        # the log with noise for hours.
        ok, why = dg.remedy_allowed({}, "restart-adguard", self._diag(
            fixable_here=False, owner="снаружи", summary="Кабель в порт WAN — несущей нет"))
        assert not ok and "не наша неисправность" in why

    def test_the_fourth_attempt_is_refused_and_says_why(self):
        state = {}
        d = self._diag()
        for _ in range(3):
            ok, _ = dg.remedy_allowed(state, "restart-adguard", d)
            assert ok
            dg.record_remedy(state, "restart-adguard")
        ok, why = dg.remedy_allowed(state, "restart-adguard", d)
        assert not ok
        assert "диагноз неверен" in why

    def test_attempts_age_out_of_the_window(self):
        state = {"remedies": {"restart-adguard":
                              {"attempts": [time.time() - 4000] * 5}}}
        ok, _ = dg.remedy_allowed(state, "restart-adguard", self._diag(),
                                  window_sec=1800)
        assert ok

    def test_success_clears_the_count(self):
        state = {}
        for _ in range(3):
            dg.record_remedy(state, "restart-adguard")
        dg.clear_remedy(state, "restart-adguard")
        ok, _ = dg.remedy_allowed(state, "restart-adguard", self._diag())
        assert ok

    def test_two_remedies_are_counted_separately(self):
        state = {}
        for _ in range(3):
            dg.record_remedy(state, "restart-adguard")
        ok, _ = dg.remedy_allowed(state, "reapply-iptables", self._diag())
        assert ok


class TestGatewayPresence:
    NEIGH = ("100.113.192.1 dev enp1s0 lladdr 68:ab:09:5f:f9:43 REACHABLE\n"
             "192.168.100.45 dev enx6c1f lladdr aa:bb:cc:dd:ee:ff STALE\n"
             "10.9.9.9 dev enp1s0  FAILED\n")

    def test_presence_is_read_from_the_neighbour_table(self, monkeypatch):
        # Not from ping: this provider's gateway answers no ICMP at all, so a
        # ping says 100% loss while everything works -- and before ICMP was
        # fixed it said 0% because the tunnel's tun was answering. Both fiction.
        monkeypatch.setattr(dg, "_run", lambda *a, **k: self.NEIGH)
        ok, detail = dg.gateway_on_the_wire("100.113.192.1")
        assert ok and "REACHABLE" in detail

    def test_a_stale_entry_still_counts_as_present(self, monkeypatch):
        monkeypatch.setattr(dg, "_run", lambda *a, **k: self.NEIGH)
        assert dg.gateway_on_the_wire("192.168.100.45")[0] is True

    def test_a_failed_entry_does_not(self, monkeypatch):
        monkeypatch.setattr(dg, "_run", lambda *a, **k: self.NEIGH)
        ok, detail = dg.gateway_on_the_wire("10.9.9.9")
        assert not ok and "FAILED" in detail

    def test_an_unknown_neighbour_says_arp_got_nothing(self, monkeypatch):
        monkeypatch.setattr(dg, "_run", lambda *a, **k: self.NEIGH)
        ok, detail = dg.gateway_on_the_wire("8.8.8.8")
        assert not ok and "ARP" in detail

    def test_no_default_route_is_its_own_answer(self):
        ok, detail = dg.gateway_on_the_wire("")
        assert not ok and "маршрута по умолчанию нет" in detail


class TestLeaseBand:
    def test_the_bands(self):
        assert dg.lease_band(600) == "короткая (до 30 мин)"
        assert dg.lease_band(43200) == "обычная (до суток)"
        assert dg.lease_band(604800) == "длинная (больше суток)"
        assert dg.lease_band(None) == "неизвестно"
