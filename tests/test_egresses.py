"""
The egress registry and the fallback ladder (src/web/egresses.py).
"""
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "web"))
import egresses as eg  # noqa: E402

ALL = lambda ident: True  # noqa: E731  every cascade egress configured


def settings(**kw):
    s = {"adguard": {"enabled": True}, "fptn": {"enabled": True},
         "egresses": {"amnezia": {"enabled": True}, "trusttunnel": {"enabled": True}}}
    s.update(kw)
    return s


def step(s, up, fails=0):
    return eg.decide(s, lambda e: e in up, fails, is_configured=ALL)


class TestOrder:
    def test_default_is_adguard_then_cascade_then_fptn(self):
        assert eg.order({}) == ["adguard", "amnezia", "trusttunnel", "fptn", "warp"]

    def test_saved_order_is_made_whole(self):
        s = {"egress_order": ["amnezia", "bogus", "amnezia", "fptn"]}
        assert eg.order(s) == ["amnezia", "fptn", "adguard", "trusttunnel", "warp"]

    def test_unconfigured_cascade_egress_is_never_a_candidate(self):
        s = settings()
        assert eg.candidates(s, is_configured=lambda e: e != "trusttunnel") == \
            ["adguard", "amnezia", "fptn"]

    def test_switched_off_egresses_drop_out(self):
        s = settings(adguard={"enabled": False})
        s["egresses"]["amnezia"]["enabled"] = False
        assert eg.candidates(s, is_configured=ALL) == ["trusttunnel", "fptn"]


class TestOutbound:
    def test_cascade_egress_is_a_plain_socks_outbound(self):
        ob = eg.outbound(settings(), "amnezia")
        assert ob == {"protocol": "socks", "tag": "proxy",
                      "settings": {"servers": [{"address": "192.168.244.6", "port": 1083}]}}

    def test_adguard_and_fptn_keep_their_own_addresses(self):
        s = settings(adguard={"enabled": True, "socks_host": "127.0.0.1", "socks_port": 1181})
        assert eg.socks(s, "adguard") == ("127.0.0.1", 1181)
        assert eg.socks(s, "fptn") == ("192.168.244.2", 1082)

    def test_active_falls_back_to_primary_when_choice_is_disabled(self):
        s = settings(egress_active="fptn", fptn={"enabled": False})
        assert eg.active(s, is_configured=ALL) == "adguard"
        assert eg.active({}, is_configured=ALL) is None


class TestLadder:
    def test_alive_primary_stays(self):
        assert step(settings(), {"adguard"}) == ("adguard", 0, "stay")

    def test_a_brief_hiccup_moves_nothing(self):
        s = settings()
        assert step(s, {"amnezia"}, fails=0) == ("adguard", 1, "stay")
        assert step(s, {"amnezia"}, fails=1) == ("adguard", 2, "stay")

    def test_third_miss_moves_to_the_first_live_reserve_in_order(self):
        assert step(settings(), {"trusttunnel", "fptn"}, fails=2) == ("trusttunnel", 3, "switch")

    def test_a_better_reserve_that_recovers_takes_over(self):
        s = settings(egress_active="trusttunnel")
        assert step(s, {"amnezia", "trusttunnel"}, fails=5) == ("amnezia", 6, "switch")

    def test_live_current_reserve_stays(self):
        s = settings(egress_active="amnezia")
        assert step(s, {"amnezia"}, fails=5) == ("amnezia", 6, "stay")

    def test_primary_back_restores(self):
        s = settings(egress_active="fptn")
        assert step(s, {"adguard", "fptn"}, fails=9) == ("adguard", 0, "restore")

    def test_nothing_alive_goes_direct(self):
        assert step(settings(), set(), fails=2)[2] == "direct"

    def test_leaving_direct_restores_the_profile_even_on_the_same_egress(self):
        s = settings(egress_active="amnezia", fallback_saved_profile="all_except_ru")
        assert step(s, {"amnezia"}, fails=7) == ("amnezia", 8, "switch")
        s = settings(fallback_saved_profile="all_except_ru")
        assert step(s, {"adguard"}, fails=7) == ("adguard", 0, "restore")

    def test_user_order_decides_the_primary(self):
        # AdGuard was carrying the house; the user moved AmneziaWG to the top.
        s = settings(egress_order=["amnezia", "adguard", "trusttunnel", "fptn"],
                     egress_active="adguard")
        assert step(s, {"amnezia", "adguard"}) == ("amnezia", 0, "restore")

    def test_nothing_enabled(self):
        s = settings(adguard={"enabled": False}, fptn={"enabled": False},
                     egresses={"amnezia": {"enabled": False}})
        assert step(s, {"adguard"}) == (None, 0, "none")


class TestWarp:
    """WARP on the Miami server rides AmneziaWG's tunnel (2.32)."""
    def test_it_is_only_on_while_its_carrier_is(self):
        on = {"egresses": {"amnezia": {"enabled": True}, "warp": {"enabled": True}}}
        assert eg.enabled(on, "warp", ALL)
        assert not eg.enabled({"egresses": {"warp": {"enabled": True}}}, "warp", ALL)
        assert not eg.enabled({"egresses": {"amnezia": {"enabled": True}}}, "warp", ALL)

    def test_it_is_configured_when_amnezia_is(self):
        assert eg.configured("warp", base=Path("/nonexistent")) is False

    def test_its_address_is_a_port_on_the_amnezia_bridge(self):
        assert eg.socks({}, "warp") == ("192.168.244.6", 1086)
        assert "unit" not in eg.CATALOG["warp"]        # toggling it never stops AmneziaWG
