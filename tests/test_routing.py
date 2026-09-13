"""
Tests for Shunt routing logic, custom rules, snapshots, and config builder.
Run:  python -m pytest tests/ -v
"""
import ipaddress
import json
import socket
import sys
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

# ── Bootstrap: point BASE to a temp dir so we don't need /opt/shunt ────
import importlib

# We need to set up a fake BASE before importing main
_tmp_base = tempfile.mkdtemp(prefix="xray_test_")
os.environ["_TEST_BASE"] = _tmp_base

# Patch the paths before import
import types

# Create necessary dirs/files in temp base
for d in ["config", "config/snapshots", "logs", "web/static", "bin", "scripts"]:
    Path(_tmp_base, d).mkdir(parents=True, exist_ok=True)

# Minimal .secret
Path(_tmp_base, ".secret").write_text("test-secret-key-for-unit-tests")

# Add web/ to path so we can import main
sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "web"))

# Patch BASE before importing
import builtins
_real_import = builtins.__import__

# Import main, overriding BASE
import main as m

# Override BASE to temp dir for tests
m.BASE     = Path(_tmp_base)
m.CFG_DIR  = Path(_tmp_base) / "config"
m.SNAP_DIR = Path(_tmp_base) / "config" / "snapshots"
m.SETTINGS = Path(_tmp_base) / "config" / "settings.json"
m.XCFG     = Path(_tmp_base) / "config" / "xray.json"
m.LOGS     = Path(_tmp_base) / "logs"
m.STATIC   = Path(_tmp_base) / "web" / "static"
m.SECRET   = "test-secret-key-for-unit-tests"

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Tests: validate_custom_rule
# ─────────────────────────────────────────────────────────────────────────────
class TestValidateCustomRule:
    def test_domain_prefix_valid(self):
        ok, err = m.validate_custom_rule("domain:example.com")
        assert ok, err

    def test_full_prefix_valid(self):
        ok, err = m.validate_custom_rule("full:example.com")
        assert ok, err

    def test_keyword_prefix_valid(self):
        ok, err = m.validate_custom_rule("keyword:google")
        assert ok, err

    def test_regexp_valid(self):
        ok, err = m.validate_custom_rule(r"regexp:^.*\.google\.com$")
        assert ok, err

    def test_regexp_invalid(self):
        ok, err = m.validate_custom_rule("regexp:[invalid")
        assert not ok
        assert "regexp" in err.lower()

    def test_ipv4_valid(self):
        ok, err = m.validate_custom_rule("1.2.3.4")
        assert ok, err

    def test_cidr_valid(self):
        ok, err = m.validate_custom_rule("192.168.1.0/24")
        assert ok, err

    def test_ipv6_cidr_valid(self):
        ok, err = m.validate_custom_rule("2001:db8::/32")
        assert ok, err

    def test_bare_domain_valid(self):
        ok, err = m.validate_custom_rule("yandex.ru")
        assert ok, err

    def test_empty_invalid(self):
        ok, err = m.validate_custom_rule("")
        assert not ok

    def test_garbage_invalid(self):
        ok, err = m.validate_custom_rule("not a domain!@#$%")
        assert not ok

    def test_domain_empty_value_invalid(self):
        ok, err = m.validate_custom_rule("domain:")
        assert not ok

# ─────────────────────────────────────────────────────────────────────────────
# Tests: _custom_rule_to_xray
# ─────────────────────────────────────────────────────────────────────────────
class TestCustomRuleToXray:
    def test_domain_prefix(self):
        kind, val = m._custom_rule_to_xray("domain:example.com")
        assert kind == "domain"
        assert val == "domain:example.com"

    def test_ip(self):
        kind, val = m._custom_rule_to_xray("1.2.3.4")
        assert kind == "ip"
        assert "1.2.3.4" in val

    def test_cidr(self):
        kind, val = m._custom_rule_to_xray("10.0.0.0/8")
        assert kind == "ip"
        assert "10.0.0.0/8" in val

    def test_bare_domain(self):
        kind, val = m._custom_rule_to_xray("ozon.ru")
        assert kind == "domain"
        assert val == "domain:ozon.ru"

# ─────────────────────────────────────────────────────────────────────────────
# Tests: build_xray_config
# ─────────────────────────────────────────────────────────────────────────────
class TestTrafficThatCarriesNoName:
    """
    Telegram broke within hours of the profile switch, and the reason is worth
    a class of its own: MTProto dials its data centres by address, so nothing
    is sniffed and no domain list decides any of it. A profile built only from
    domain lists sent it straight out to be blocked.
    """

    def _s(self, profile="blocked_only"):
        s = dict(m.DEFAULT_SETTINGS)
        s["profile"] = profile
        return s

    # The suite has no settings fixture that produces a working tunnel -- with
    # none configured every outbound collapses to direct, which would make
    # "goes through the tunnel" unfalsifiable here. So the tunnel is asserted
    # into existence for this class only.
    def _with_tunnel(self):
        return patch.object(m, "_get_active_vpn_outbound",
                            return_value=([{"protocol": "socks", "tag": "proxy"}],
                                          True, None))

    def test_the_profile_routes_addresses_and_not_only_names(self):
        with self._with_tunnel():
            cfg = m.build_xray_config(self._s())
        rules = cfg["routing"]["rules"]
        ip_rules = [r for r in rules if "geoip:ru-blocked" in r.get("ip", [])]
        dom_rules = [r for r in rules if "geosite:ru-blocked" in r.get("domain", [])]
        assert ip_rules, "no address-based blocklist rule"
        # The claim is not "some tag" but "addresses are treated like names".
        assert ip_rules[0]["outboundTag"] == dom_rules[0]["outboundTag"] == "proxy"

    def test_russian_addresses_are_still_decided_first(self):
        # order is independent of whether a tunnel exists
        # A Russian address on a blocklist is far more likely to be a service
        # that refuses foreign addresses than one worth tunnelling, so the
        # geoip:ru rule has to keep coming first.
        with self._with_tunnel():
            rules = m.build_xray_config(self._s())["routing"]["rules"]
        pos = {}
        for i, r in enumerate(rules):
            if "geoip:ru" in r.get("ip", []):        pos.setdefault("ru", i)
            if "geoip:ru-blocked" in r.get("ip", []): pos.setdefault("blocked", i)
        assert pos["ru"] < pos["blocked"]

    def test_the_tester_answers_for_a_bare_address(self):
        with self._with_tunnel(), \
             patch.object(m, "_ip_in_geoip_ru", return_value=False), \
             patch.object(m, "_ip_in_geoip", lambda ip, refs: "ru-blocked" in refs[0]):
            r = m.route_test("149.154.167.51", self._s())
        assert r["outbound"] == "proxy"
        assert "заблокированных адресов" in r["note"]

    def test_a_profile_that_tunnels_everything_needs_no_such_rule(self):
        with self._with_tunnel():
            cfg = m.build_xray_config(self._s(profile="all_except_ru"))
        assert not [r for r in cfg["routing"]["rules"]
                    if "geoip:ru-blocked" in r.get("ip", [])]


class TestRulesThatCanBeSwitchedOff:
    """
    A rule used to be a string, so the only way to stop it applying was to
    delete it -- which loses the rule and the reason it was written. The
    question these tests pin down is "what does off mean": not on the wire, not
    forgotten, and still mentioned when someone asks where a domain would go.
    """

    def test_a_bare_string_still_means_enabled(self):
        # Every settings.json written before this change is full of them.
        assert m._norm_rules(["domain:a.com"]) == [
            {"rule": "domain:a.com", "enabled": True}]

    def test_both_forms_can_sit_in_one_list(self):
        out = m._norm_rules(["domain:a.com",
                             {"rule": "domain:b.com", "enabled": False}])
        assert [r["enabled"] for r in out] == [True, False]

    def test_blank_and_broken_entries_are_dropped_not_crashed_on(self):
        assert m._norm_rules(["", "   ", {}, {"rule": ""}, None]) == []

    def test_a_switched_off_rule_is_not_on_the_wire(self):
        s = dict(m.DEFAULT_SETTINGS)
        s["custom_rules"] = {"always_direct": [
            {"rule": "domain:on.com", "enabled": True},
            {"rule": "domain:off.com", "enabled": False}], "always_vpn": []}
        cfg = m.build_xray_config(s)
        domains = [d for r in cfg["routing"]["rules"] for d in r.get("domain", [])]
        assert "domain:on.com" in domains
        assert "domain:off.com" not in domains

    def test_a_list_of_only_switched_off_rules_adds_no_rule_at_all(self):
        assert m._rules_to_xray_entry(
            [{"rule": "domain:off.com", "enabled": False}], "direct") == []

    def test_the_tester_says_a_switched_off_rule_would_have_matched(self):
        # The whole point of the switch is to turn a rule off and find out
        # whether anything needed it. A page that said nothing would look
        # exactly like the rule had been deleted.
        s = dict(m.DEFAULT_SETTINGS)
        s["profile"] = "all_except_ru"
        s["custom_rules"] = {"always_direct": [
            {"rule": "domain:example.com", "enabled": False}], "always_vpn": []}
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("no DNS")), \
             patch.object(m, "_ip_in_geoip_ru", return_value=False), \
             patch.object(m, "_domain_in_any_geosite", return_value=None):
            r = m.route_test("example.com", s)
        assert r["outbound"] != "direct" or r["matched_rule"] != "custom:always_direct"
        assert "выключенное правило" in r["note"]
        assert "domain:example.com" in r["note"]

    def test_an_enabled_rule_still_wins_and_says_nothing_extra(self):
        s = dict(m.DEFAULT_SETTINGS)
        s["custom_rules"] = {"always_direct": ["domain:example.com"], "always_vpn": []}
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("no DNS")):
            r = m.route_test("example.com", s)
        assert r["outbound"] == "direct"
        assert "выключенное" not in r["note"]


class TestBuildXrayConfig:
    def _base_settings(self, **kwargs) -> dict:
        s = dict(m.DEFAULT_SETTINGS)
        s.update(kwargs)
        return s

    def test_all_except_ru_has_geoip_rule(self):
        cfg = m.build_xray_config(self._base_settings(profile="all_except_ru"))
        rules = cfg["routing"]["rules"]
        geoip_rules = [r for r in rules if "geoip:ru" in r.get("ip", [])]
        assert geoip_rules, "Should have geoip:ru direct rule"
        assert geoip_rules[0]["outboundTag"] == "direct"

    def test_all_except_ru_catch_all_is_direct_without_vpn(self):
        cfg = m.build_xray_config(self._base_settings(profile="all_except_ru", vpn_key=None))
        last = cfg["routing"]["rules"][-1]
        assert last["outboundTag"] == "direct"

    def test_conferencing_leaves_without_the_tunnel(self):
        # The measured reason: same target, same probe -- direct lost nothing,
        # the tunnel lost 2-5% and added ~90 ms. Calls have no retransmit to
        # hide that behind.
        cfg = m.build_xray_config(self._base_settings(profile="all_except_ru"))
        rules = cfg["routing"]["rules"]
        zoom = [r for r in rules if "geosite:zoom" in r.get("domain", [])]
        teams = [r for r in rules if "52.112.0.0/14" in r.get("ip", [])]
        assert zoom and zoom[0]["outboundTag"] == "direct"
        assert teams and teams[0]["outboundTag"] == "direct"

    def test_conferencing_rules_precede_the_catch_all(self):
        # A rule after the catch-all is a rule that never runs.
        cfg = m.build_xray_config(self._base_settings(profile="all_except_ru"))
        rules = cfg["routing"]["rules"]
        zoom_idx = next(i for i, r in enumerate(rules)
                        if "geosite:zoom" in r.get("domain", []))
        assert zoom_idx < len(rules) - 1
        assert rules[-1].get("network") == "tcp,udp"

    def test_conferencing_can_be_turned_off(self):
        cfg = m.build_xray_config(
            self._base_settings(profile="all_except_ru", realtime_direct=False))
        rules = cfg["routing"]["rules"]
        assert not [r for r in rules if "geosite:zoom" in r.get("domain", [])]

    def test_an_explicit_choice_still_beats_the_conferencing_default(self):
        # Someone who deliberately sends Zoom through the tunnel -- for an exit
        # country, say -- must keep getting that.
        settings = self._base_settings(
            profile="all_except_ru",
            custom_rules={"always_direct": [], "always_vpn": ["domain:zoom.us"]})
        cfg = m.build_xray_config(settings)
        rules = cfg["routing"]["rules"]
        explicit = next(i for i, r in enumerate(rules)
                        if "domain:zoom.us" in r.get("domain", []))
        default = next(i for i, r in enumerate(rules)
                       if "geosite:zoom" in r.get("domain", []))
        assert explicit < default

    def test_custom_rules_injected_before_geoip(self):
        settings = self._base_settings(
            profile="all_except_ru",
            custom_rules={"always_direct": ["domain:mysite.ru"], "always_vpn": []}
        )
        cfg = m.build_xray_config(settings)
        rules = cfg["routing"]["rules"]
        # Find index of custom rule and geoip:ru rule
        custom_idx = next((i for i, r in enumerate(rules)
                           if "domain:mysite.ru" in r.get("domain", [])), -1)
        geoip_idx  = next((i for i, r in enumerate(rules)
                           if "geoip:ru" in r.get("ip", [])), -1)
        assert custom_idx != -1, "Custom rule not found in config"
        assert geoip_idx  != -1, "geoip:ru rule not found in config"
        assert custom_idx < geoip_idx, "Custom rule must precede geoip:ru"

    def test_custom_vpn_rules_injected(self):
        settings = self._base_settings(
            profile="all_except_ru",
            custom_rules={"always_direct": [], "always_vpn": ["192.168.5.0/24"]}
        )
        cfg = m.build_xray_config(settings)
        rules = cfg["routing"]["rules"]
        vpn_ip_rules = [r for r in rules
                        if "192.168.5.0/24" in r.get("ip", []) and r.get("outboundTag") in ("proxy", "direct")]
        assert vpn_ip_rules, "Custom VPN IP rule not found"

    def test_blocked_only_profile(self):
        # This asserted geosite:category-ru-blocked, which is the name upstream
        # renamed to ru-blocked -- so the test agreed with the code and both
        # were wrong, and xray refused the configuration in production while
        # the suite stayed green. The names are checked against the real file
        # now (see test_geosite.py); here we only state which lists the profile
        # is made of.
        cfg = m.build_xray_config(self._base_settings(profile="blocked_only"))
        rules = cfg["routing"]["rules"]
        assert any("geosite:ru-blocked" in r.get("domain", []) for r in rules)
        assert any("geosite:ru-available-only-inside" in r.get("domain", [])
                   for r in rules)

    def test_blocked_only_sends_everything_else_direct(self):
        cfg = m.build_xray_config(self._base_settings(profile="blocked_only"))
        assert cfg["routing"]["rules"][-1]["outboundTag"] == "direct"

    def test_all_except_ru_keeps_ru_only_services_off_the_tunnel(self):
        # ozon.ru, rzd.ru and pochta.ru refuse foreign addresses, so a US exit
        # breaks them in the profile that tunnels everything foreign too.
        cfg = m.build_xray_config(self._base_settings(profile="all_except_ru"))
        assert any("geosite:ru-available-only-inside" in r.get("domain", [])
                   for r in cfg["routing"]["rules"])

    def test_quic_sniffing_enabled(self):
        cfg = m.build_xray_config(self._base_settings())
        sniff = cfg["inbounds"][0]["sniffing"]
        assert "quic" in sniff["destOverride"]

    def test_no_vpn_key_direct_outbound_exists(self):
        cfg = m.build_xray_config(self._base_settings(vpn_key=None))
        tags = [ob["tag"] for ob in cfg["outbounds"]]
        assert "direct" in tags
        assert "proxy" not in tags

# ─────────────────────────────────────────────────────────────────────────────
# Tests: route_test (with mocked geo databases)
# ─────────────────────────────────────────────────────────────────────────────
class TestRouteTester:
    def _settings(self, **kwargs) -> dict:
        s = dict(m.DEFAULT_SETTINGS)
        s["vpn_key"] = None  # no VPN by default → final="direct"
        s.update(kwargs)
        return s

    def test_private_ip_direct(self):
        result = m.route_test("192.168.1.1", self._settings())
        assert result["outbound"] == "direct"
        assert "private" in result["matched_rule"]

    def test_private_ip_127(self):
        result = m.route_test("127.0.0.1", self._settings())
        assert result["outbound"] == "direct"

    def test_private_domain_localhost(self):
        result = m.route_test("localhost", self._settings())
        assert result["outbound"] == "direct"

    def test_custom_always_direct_domain(self):
        settings = self._settings(
            custom_rules={"always_direct": ["domain:mybank.ru"], "always_vpn": []}
        )
        result = m.route_test("mybank.ru", settings)
        assert result["outbound"] == "direct"
        assert "custom" in result["matched_rule"]

    def test_custom_always_direct_cidr(self):
        # Use a non-private IP range so private rule doesn't fire first
        settings = self._settings(
            custom_rules={"always_direct": ["203.0.113.0/24"], "always_vpn": []}
        )
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("no dns")), \
             patch.object(m, "_ip_in_geoip_ru", return_value=False), \
             patch.object(m, "_domain_in_geosite_ru", return_value=False):
            result = m.route_test("203.0.113.5", settings)
        assert result["outbound"] == "direct"
        assert "custom" in result["matched_rule"]

    def test_custom_always_vpn_overrides(self):
        # Even in all_except_ru, a custom_vpn rule sends to proxy/direct(no-vpn)
        settings = self._settings(
            vpn_key=None,  # no VPN, so "final" = "direct"
            custom_rules={"always_direct": [], "always_vpn": ["domain:leak.com"]}
        )
        # With no VPN key, "final"="direct", so custom_vpn still goes "direct"
        result = m.route_test("leak.com", settings)
        assert "custom:always_vpn" in result["matched_rule"]

    def test_apple_cdn_with_force_vpn(self):
        settings = self._settings(
            profile="all_except_ru",
            force_aaplimg_vpn=True,
        )
        result = m.route_test("osxapps.itunes.apple.com", settings)
        assert "apple-cdn" in result["matched_rule"]

    def test_apple_cdn_without_force_vpn(self):
        settings = self._settings(
            profile="all_except_ru",
            force_aaplimg_vpn=False,
        )
        # Should NOT match apple CDN override
        result = m.route_test("osxapps.itunes.apple.com", settings)
        assert "apple-cdn" not in result["matched_rule"]

    def test_geoip_ru_mock(self):
        """Verify that an IP in geoip:ru goes direct."""
        with patch.object(m, "_ip_in_geoip_ru", return_value=True), \
             patch.object(m, "_domain_in_geosite_ru", return_value=False):
            result = m.route_test("1.2.3.4", self._settings())
        assert result["outbound"] == "direct"
        assert "geoip:ru" in result["matched_rule"]

    def test_geosite_ru_mock(self):
        """Verify that a domain in geosite:category-ru goes direct."""
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("no DNS")), \
             patch.object(m, "_ip_in_geoip_ru", return_value=False), \
             patch.object(m, "_domain_in_any_geosite",
                          side_effect=lambda d, refs: refs[0]):
            result = m.route_test("vk.com", self._settings())
        assert result["outbound"] == "direct"
        assert "geosite:category-ru" in result["matched_rule"]

    def test_unknown_domain_catch_all_no_vpn(self):
        """Unknown domain without VPN → default route of profile."""
        settings = self._settings(profile="all_except_ru", vpn_key=None)
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("no DNS")), \
             patch.object(m, "_ip_in_geoip_ru", return_value=False), \
             patch.object(m, "_domain_in_geosite_ru", return_value=False):
            result = m.route_test("unknowndomain.xyz", settings)
        # no VPN → final = "direct" → catch-all for all_except_ru
        assert result["outbound"] == "direct"
        assert "catch-all" in result["matched_rule"]

    def test_profile_all_sends_everything_to_final(self):
        settings = self._settings(profile="all", vpn_key=None)
        result = m.route_test("google.com", settings)
        assert result["matched_rule"] == "catch-all"

    def test_invalid_target(self):
        result = m.route_test("not a domain!#$", self._settings())
        assert result.get("error") is not None

# ─────────────────────────────────────────────────────────────────────────────
# Tests: Snapshot management
# ─────────────────────────────────────────────────────────────────────────────
class TestSnapshots:
    def setup_method(self):
        # Clean snapshots dir before each test
        snap_dir = m.SNAP_DIR
        snap_dir.mkdir(parents=True, exist_ok=True)
        for f in snap_dir.glob("snap_*.json"):
            f.unlink()
        # Write a minimal settings.json and xray.json
        m.CFG_DIR.mkdir(parents=True, exist_ok=True)
        m.SETTINGS.write_text(json.dumps(m.DEFAULT_SETTINGS, indent=2))
        m.XCFG.write_text(json.dumps({"test": "config"}, indent=2))

    def test_create_snapshot_returns_id(self):
        snap_id = m.create_snapshot("test_reason")
        assert re.match(r'^\d{8}_\d{6}$', snap_id)

    def test_create_snapshot_file_exists(self):
        snap_id = m.create_snapshot("test_reason")
        assert m._snap_path(snap_id).exists()

    def test_list_snapshots_empty(self):
        snaps = m.list_snapshots()
        assert isinstance(snaps, list)

    def test_list_snapshots_after_create(self):
        import time as _t
        m.create_snapshot("reason_a")
        _t.sleep(1.05)  # ensure different second → unique snap_id
        m.create_snapshot("reason_b")
        snaps = m.list_snapshots()
        assert len(snaps) == 2
        assert snaps[0]["reason"] == "reason_b"  # most recent first

    def test_snapshot_contains_expected_fields(self):
        snap_id = m.create_snapshot("unit_test")
        snap = json.loads(m._snap_path(snap_id).read_text())
        assert "id" in snap
        assert "timestamp" in snap
        assert "reason" in snap
        assert "settings" in snap
        assert "xray_config" in snap

    def test_rotate_keeps_max_snapshots(self):
        for i in range(m.MAX_SNAPSHOTS + 3):
            m.create_snapshot(f"snap_{i}")
            import time as _t; _t.sleep(0.01)  # ensure unique timestamps
        snaps = m.list_snapshots()
        assert len(snaps) <= m.MAX_SNAPSHOTS

    def test_restore_snapshot_updates_settings(self):
        # Create snapshot of known state
        settings = dict(m.DEFAULT_SETTINGS)
        settings["profile"] = "blocked_only"
        m.SETTINGS.write_text(json.dumps(settings, indent=2))
        snap_id = m.create_snapshot("test_restore")
        # Change settings
        settings["profile"] = "all"
        m.SETTINGS.write_text(json.dumps(settings, indent=2))
        # Restore
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="active\n", stderr="")
            ok, msg = m.restore_snapshot(snap_id)
        assert ok, msg
        restored = json.loads(m.SETTINGS.read_text())
        assert restored["profile"] == "blocked_only"

    def test_restore_nonexistent_snapshot(self):
        ok, msg = m.restore_snapshot("99991231_235959")
        assert not ok
        assert "not found" in msg

    def test_delete_snapshot(self):
        snap_id = m.create_snapshot("delete_me")
        assert m._snap_path(snap_id).exists()
        m._snap_path(snap_id).unlink()
        assert not m._snap_path(snap_id).exists()

# ─────────────────────────────────────────────────────────────────────────────
# Tests: apply_config_safe auto-rollback
# ─────────────────────────────────────────────────────────────────────────────
class TestApplyConfigSafe:
    def setup_method(self):
        m.CFG_DIR.mkdir(parents=True, exist_ok=True)
        m.SNAP_DIR.mkdir(parents=True, exist_ok=True)
        m.SETTINGS.write_text(json.dumps(m.DEFAULT_SETTINGS, indent=2))
        m.XCFG.write_text(json.dumps({"orig": True}, indent=2))
        for f in m.SNAP_DIR.glob("snap_*.json"):
            f.unlink()

    def test_successful_apply(self):
        call_count = [0]
        def fake_run(cmd, **kw):
            r = MagicMock()
            if cmd[0] == "systemctl" and cmd[1] == "is-active":
                r.stdout = "active\n"; r.returncode = 0
            else:
                r.returncode = 0; r.stdout = ""; r.stderr = ""
            call_count[0] += 1
            return r
        with patch("subprocess.run", side_effect=fake_run), \
             patch("time.sleep"), \
             patch.object(m._geo, "missing", return_value=[]):
            ok, err = m.apply_config(m.DEFAULT_SETTINGS, "test")
        assert ok
        assert err == ""

    def test_a_renamed_geo_list_refuses_before_touching_anything(self):
        # The September failure, as a check. The old order wrote the file,
        # restarted xray, watched it fail and rolled back -- and said "xray
        # failed to start", which points at the tunnel rather than at a list.
        before = m.XCFG.read_text()
        with patch.object(m._geo, "missing",
                          return_value=["geosite:category-ru-blocked"]), \
             patch("subprocess.run") as run:
            ok, err = m.apply_config(m.DEFAULT_SETTINGS, "test_missing_list")
        assert not ok
        assert "geosite:category-ru-blocked" in err
        assert m.XCFG.read_text() == before      # nothing written
        # build_xray_config shells out while it works, so "nothing ran" is the
        # wrong claim; "the datapath was not restarted" is the one that matters.
        assert not [c for c in run.call_args_list
                    if list(c.args[0])[:2] == ["systemctl", "restart"]]

    def test_auto_rollback_on_failure(self):
        """If xray never becomes active, should auto-rollback."""
        m.XCFG.write_text(json.dumps({"original": "config"}, indent=2))

        def fake_run(cmd, **kw):
            r = MagicMock()
            if cmd[0] == "systemctl" and cmd[1] == "is-active":
                r.stdout = "failed\n"; r.returncode = 1
            else:
                r.returncode = 0; r.stdout = "active\n"; r.stderr = ""
            return r

        with patch("subprocess.run", side_effect=fake_run), \
             patch("time.sleep"), \
             patch.object(m._geo, "missing", return_value=[]):
            ok, err = m.apply_config(m.DEFAULT_SETTINGS, "test_rollback")
        assert not ok
        assert "rollback" in err.lower()

# ─────────────────────────────────────────────────────────────────────────────
# Tests: VPN key parsing
# ─────────────────────────────────────────────────────────────────────────────
class TestKeyParsing:
    def test_parse_ss_with_at(self):
        uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@1.2.3.4:1234#Test"
        ob, info = m.parse_key(uri)
        assert ob["protocol"] == "shadowsocks"
        assert info["server"] == "1.2.3.4"
        assert info["port"] == 1234
        assert info["name"] == "Test"

    def test_parse_unknown_protocol(self):
        import pytest
        with pytest.raises(ValueError):
            m.parse_key("https://example.com")

# ─────────────────────────────────────────────────────────────────────────────
# Tests: _varint protobuf helper
# ─────────────────────────────────────────────────────────────────────────────
class TestVarint:
    def test_single_byte(self):
        val, pos = m._varint(b'\x01', 0)
        assert val == 1; assert pos == 1

    def test_multibyte(self):
        # 300 = 0b100101100 → 0xAC 0x02
        val, pos = m._varint(b'\xac\x02', 0)
        assert val == 300; assert pos == 2

    def test_zero(self):
        val, pos = m._varint(b'\x00', 0)
        assert val == 0

import re  # needed for snapshot ID pattern checks


# ─────────────────────────────────────────────────────────────────────────────
# Tests: the route tester tells the truth about conferencing
# ─────────────────────────────────────────────────────────────────────────────
class TestRouteTestKnowsAboutCalls:
    def _s(self, **kw):
        s = dict(m.DEFAULT_SETTINGS)
        s.update(kw)
        return s

    def test_a_zoom_media_address_is_reported_direct(self, monkeypatch):
        # 170.114.52.2 is what zoom.us resolved to on the live gateway.
        r = m.route_test("170.114.52.2", self._s(profile="all_except_ru"))
        assert r["outbound"] == "direct"
        assert "realtime" in r["matched_rule"]

    def test_a_teams_domain_is_reported_direct(self):
        r = m.route_test("teams.microsoft.com", self._s(profile="all_except_ru"))
        assert r["outbound"] == "direct"

    def test_a_teams_media_address_is_reported_direct(self):
        r = m.route_test("52.113.194.132", self._s(profile="all_except_ru"))
        assert r["outbound"] == "direct"

    def test_turning_it_off_changes_the_answer_too(self):
        # The page and the rules have to move together in both directions.
        r = m.route_test("170.114.52.2",
                         self._s(profile="all_except_ru", realtime_direct=False))
        assert r["outbound"] != "direct" or r["matched_rule"] != "realtime"

    def test_an_explicit_rule_still_wins_in_the_tester(self):
        r = m.route_test("teams.microsoft.com", self._s(
            profile="all_except_ru",
            custom_rules={"always_direct": [], "always_vpn": ["domain:teams.microsoft.com"]}))
        assert "custom:always_vpn" in r["matched_rule"]

    def test_an_ordinary_foreign_address_is_untouched(self):
        r = m.route_test("140.82.121.4", self._s(profile="all_except_ru"))
        assert "realtime" not in (r["matched_rule"] or "")

    def test_every_generated_conferencing_matcher_is_covered_by_the_tester(self):
        # The guard against the drift that just happened: if someone adds an
        # address block to the rules, the tester matches it by construction.
        for cidr in m.REALTIME_IPS:
            first = str(__import__("ipaddress").ip_network(cidr)[1])
            assert m._matches_realtime(None, [first]) == cidr, cidr
