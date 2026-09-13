"""
Tests for reading geosite.dat / geoip.dat and checking a configuration against
them.

The regression these exist for is not hypothetical: `blocked_only` asked for
`geosite:category-ru-blocked`, upstream renamed the list to `ru-blocked`, and
xray answered by refusing the entire configuration -- so the profile stopped
working and the message said "xray failed to start".

Run:  python -m pytest tests/ -v
"""
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "web"))

import geosite as gs  # noqa: E402


def _entry(name: str, domains: list[str] = ()) -> bytes:
    """One GeoSite message: country_code = 1, domain = 2."""
    body = b"\x0a" + bytes([len(name)]) + name.encode()
    for d in domains:
        dom = b"\x08\x02\x12" + bytes([len(d)]) + d.encode()   # type=2, value
        body += b"\x12" + bytes([len(dom)]) + dom
    return b"\x0a" + bytes([len(body)]) + body


def _dat(tmp_path, entries) -> Path:
    p = tmp_path / "geosite.dat"
    p.write_bytes(b"".join(_entry(n, d) for n, d in entries))
    return p


class TestReadingTheFile:
    def test_names_come_back_upper_cased(self, tmp_path):
        # xray compares them upper-cased, so a rule saying geosite:ru-blocked
        # and a file saying RU-BLOCKED are the same list.
        f = _dat(tmp_path, [("ru-blocked", ["claude.ai"]), ("category-ru", ["ozon.ru"])])
        assert gs.categories(f) == frozenset({"RU-BLOCKED", "CATEGORY-RU"})

    def test_a_missing_file_is_empty_not_a_crash(self, tmp_path):
        assert gs.categories(tmp_path / "nope.dat") == frozenset()

    def test_a_truncated_download_does_not_raise(self, tmp_path):
        p = tmp_path / "geosite.dat"
        p.write_bytes(_dat(tmp_path, [("ru-blocked", ["a.example"])]).read_bytes()[:-4])
        gs.categories(p)          # whatever it finds, it must not throw

    def test_the_answer_is_cached_until_the_file_changes(self, tmp_path):
        f = _dat(tmp_path, [("ru-blocked", [])])
        assert "RU-BLOCKED" in gs.categories(f)
        f.write_bytes(_entry("something-else", []))
        # mtime_ns and size both move, so the cache must not be believed
        assert "SOMETHING-ELSE" in gs.categories(f)


CFG = {"routing": {"rules": [
    {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
    {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
    {"type": "field", "domain": ["geosite:category-ru",
                                 "geosite:ru-available-only-inside"],
     "outboundTag": "direct"},
    {"type": "field", "domain": ["geosite:ru-blocked",
                                 "domain:example.com"], "outboundTag": "proxy"},
]}}


class TestWhatAConfigurationAsksFor:
    def test_only_geo_references_are_collected(self):
        refs = gs.referenced(CFG)
        assert ("geosite", "RU-BLOCKED") in refs
        assert ("geoip", "RU") in refs
        # domain:example.com is a literal, not a list
        assert all(name != "EXAMPLE.COM" for _, name in refs)

    def test_attributes_are_stripped(self):
        cfg = {"routing": {"rules": [
            {"domain": ["geosite:cn@ads"], "outboundTag": "block"}]}}
        assert gs.referenced(cfg) == {("geosite", "CN")}

    def test_a_config_with_no_rules_asks_for_nothing(self):
        assert gs.referenced({}) == set()
        assert gs.referenced({"routing": {"rules": []}}) == set()


class TestTheRegression:
    def _files(self, tmp_path, site_names):
        site = _dat(tmp_path, [(n, []) for n in site_names])
        ip = tmp_path / "geoip.dat"
        ip.write_bytes(b"".join(_entry(n, []) for n in ("private", "ru")))
        return site, ip

    def test_the_renamed_list_is_named_in_the_answer(self, tmp_path):
        # September's actual failure: the config asked for category-ru-blocked,
        # the file had ru-blocked, and xray refused everything.
        site, ip = self._files(tmp_path, ["category-ru", "ru-available-only-inside",
                                          "ru-blocked"])
        cfg = {"routing": {"rules": [
            {"domain": ["geosite:category-ru-blocked"], "outboundTag": "proxy"}]}}
        assert gs.missing(cfg, site, ip) == ["geosite:category-ru-blocked"]

    def test_a_configuration_the_files_can_satisfy_reports_nothing(self, tmp_path):
        site, ip = self._files(tmp_path, ["category-ru", "ru-available-only-inside",
                                          "ru-blocked", "antifilter-download-community"])
        # deepcopy, not dict(): the rules list is nested, and a shallow copy
        # here appended to the shared fixture and leaked into every later test.
        cfg = copy.deepcopy(CFG)
        cfg["routing"]["rules"].append(
            {"domain": ["geosite:antifilter-download-community"], "outboundTag": "proxy"})
        assert gs.missing(cfg, site, ip) == []

    def test_a_missing_geoip_list_is_caught_too(self, tmp_path):
        # A geoip.dat that reads fine but no longer has the list asked for is
        # the same failure as the geosite one, and is named the same way.
        site, _ = self._files(tmp_path, ["category-ru", "ru-available-only-inside",
                                         "ru-blocked"])
        ip = tmp_path / "geoip.dat"
        ip.write_bytes(_entry("private", []))          # has private, lost ru
        assert gs.missing(CFG, site, ip) == ["geoip:ru"]

    def test_an_empty_geoip_file_is_reported_as_unreadable(self, tmp_path):
        site, _ = self._files(tmp_path, ["category-ru", "ru-available-only-inside",
                                         "ru-blocked"])
        empty = tmp_path / "empty-geoip.dat"
        empty.write_bytes(b"")
        gone = gs.missing(CFG, site, empty)
        assert len(gone) == 1 and "empty-geoip.dat" in gone[0]

    def test_an_absent_geo_file_is_one_problem_not_forty(self, tmp_path):
        # With no file nothing resolves, and the caller must not write a
        # configuration xray will reject. But saying so once, by file name,
        # is the difference between "the download is missing" and a reader
        # hunting forty renamed categories.
        gone = gs.missing(CFG, tmp_path / "a.dat", tmp_path / "b.dat")
        assert len(gone) == 2
        assert any("a.dat" in g for g in gone) and any("b.dat" in g for g in gone)
        assert not any(g.startswith("geosite:ru-blocked") for g in gone)
