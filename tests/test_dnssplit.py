"""
2.31: DNS follows the route -- names sent direct are resolved by the Russian
upstreams, names tunnelled under those zones go back to the default resolver.
"""
import copy
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "web"))
import dnssplit as ds  # noqa: E402
import geosite  # noqa: E402
import main as m  # noqa: E402

LISTS = {
    "CATEGORY-RU": {"domain": {"ru", "avito.st", "yandex.net", "vk.com"}, "full": {"exact.example"},
                    "plain": set(), "regex": set()},
    "RU-BLOCKED": {"domain": {"blocked.ru", "deep.blocked-under.vk.com"}, "full": set(),
                   "plain": set(), "regex": set()},
    "PRIVATE": {"domain": {"lan", "local"}, "full": set(), "plain": set(), "regex": set()},
}


def rules(*extra):
    """The shape _compiled_rules produces for all_except_ru, simplified."""
    return [
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct", "_reason": "geoip:private"},
        {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct", "_reason": "geosite:private"},
        *extra,
        {"type": "field", "domain": ["geosite:ru-blocked"], "outboundTag": "proxy", "_reason": "geosite_database"},
        {"type": "field", "domain": ["geosite:category-ru"], "outboundTag": "direct", "_reason": "geosite:category-ru"},
        {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct", "_reason": "geoip:ru"},
        {"type": "field", "network": "tcp,udp", "outboundTag": "proxy", "_reason": "catch-all"},
    ]


class TestMatcher:
    def test_first_matching_rule_decides_like_xray(self):
        mt = ds.Matcher(rules(), LISTS)
        assert mt.route("c70.img.avito.st") == "direct"
        assert mt.route("www.blocked.ru") == "proxy"          # tunnel list comes first
        assert mt.route("linkedin.com") == "proxy"            # catch-all
        assert mt.route("exact.example") == "direct" and mt.route("a.exact.example") == "proxy"

    def test_rules_that_need_more_than_a_name_are_skipped(self):
        dev = {"type": "field", "source": ["192.168.1.5"], "domain": ["domain:avito.st"], "outboundTag": "proxy"}
        port = {"type": "field", "network": "tcp", "port": "5228", "outboundTag": "direct"}
        assert ds.Matcher(rules(dev, port), LISTS).route("avito.st") == "direct"

    def test_pinned_rule_counts_as_tunnel(self):
        pin = {"type": "field", "domain": ["domain:sony.com"], "balancerTag": "pin-amnezia"}
        assert ds.Matcher(rules(pin), LISTS).route("account.sony.com") == "balancer:pin-amnezia"

    def test_keyword_regexp_and_attribute_refs(self):
        r = rules({"type": "field", "domain": ["keyword:shop", "regexp:^cdn[0-9]+\\.x\\.com$",
                                               "geosite:category-ru@ads"], "outboundTag": "direct"})
        mt = ds.Matcher(r, LISTS)
        assert mt.route("myshop.com") == "direct" and mt.route("cdn12.x.com") == "direct"


class TestSplit:
    def test_russian_names_go_to_russian_resolvers_and_tunnelled_ones_back(self):
        direct, back = ds.split(rules(), LISTS)
        assert {"avito.st", "yandex.net", "vk.com", "exact.example"} <= set(direct)
        assert "ru" not in direct                              # emitted separately, as before
        assert "blocked.ru" in back                            # was resolved in Russia before 2.31
        assert "deep.blocked-under.vk.com" in back
        assert "lan" not in direct                             # private names are no one's

    def test_a_tunnel_rule_ahead_keeps_a_russian_list_name_abroad(self):
        user = {"type": "field", "domain": ["domain:vk.com"], "outboundTag": "proxy", "_reason": "profile:custom:1"}
        direct, back = ds.split(rules(user), LISTS)
        assert "vk.com" not in direct and "vk.com" not in back   # not under any direct zone

    def test_user_direct_rule_on_any_zone(self):
        user = {"type": "field", "domain": ["domain:scdn.co", "full:one.example"], "outboundTag": "direct"}
        direct, _ = ds.split(rules(user), LISTS)
        assert {"scdn.co", "one.example"} <= set(direct)

    def test_redundant_zones_are_folded(self):
        lists = copy.deepcopy(LISTS)
        lists["CATEGORY-RU"]["domain"] |= {"img.avito.st", "x.blocked.ru"}
        lists["RU-BLOCKED"]["domain"] |= {"a.blocked.ru"}
        direct, back = ds.split(rules(), lists)
        assert "img.avito.st" not in direct                     # avito.st covers it
        assert "a.blocked.ru" not in back                       # blocked.ru covers it
        # x.blocked.ru: the tunnel list matches it first, so it is not direct at all
        assert "x.blocked.ru" not in direct

    def test_direct_name_under_a_tunnelled_zone_is_carved_back_in(self):
        lists = copy.deepcopy(LISTS)
        user = {"type": "field", "domain": ["domain:ok.blocked.ru"], "outboundTag": "direct"}
        direct, back = ds.split(rules(user), lists)
        assert "blocked.ru" in back and "ok.blocked.ru" in direct

    def test_dnsmasq_lines_stay_under_the_length_dnsmasq_accepts(self):
        zones = ["zone%04d.example.ru" % i for i in range(500)]
        lines = ds.dnsmasq_lines(zones, zones, ["213.234.193.1", "85.21.2.1"])
        assert max(map(len, lines)) < 1000
        assert lines[0].startswith("server=/zone0000.example.ru/") and lines[0].endswith("/213.234.193.1")
        assert lines[-1].endswith("/#")
        assert sum(l.count("example.ru") for l in lines if l.endswith("/#")) == 500


def _dat(entries):
    """A geosite.dat with the given {name: [(type, value)]}."""
    def varint(n):
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            out += bytes([b | (0x80 if n else 0)])
            if not n:
                return out

    def ld(field, payload):
        return varint(field << 3 | 2) + varint(len(payload)) + payload

    blob = b""
    for name, doms in entries.items():
        body = ld(1, name.encode())
        for t, v in doms:
            body += ld(2, varint(1 << 3) + varint(t) + ld(2, v.encode()))
        blob += ld(1, body)
    return blob


def test_geosite_entries_reads_the_named_lists_only(tmp_path):
    p = tmp_path / "geosite.dat"
    p.write_bytes(_dat({"CATEGORY-RU": [(2, "Avito.st"), (3, "full.example"), (0, "kw"), (1, "^r$")],
                        "OTHER": [(2, "other.com")]}))
    got = geosite.entries(p, ["category-ru"])
    assert got["CATEGORY-RU"] == {"domain": {"avito.st"}, "full": {"full.example"}, "plain": {"kw"}, "regex": {"^r$"}}
    both = geosite.entries(p, ["CATEGORY-RU", "OTHER"])
    assert both["OTHER"]["domain"] == {"other.com"}
    assert geosite.entries(tmp_path / "missing.dat", ["X"]) == {"X": geosite._empty()}


class TestConfig:
    def test_conf_carries_the_split_only_with_russian_upstreams(self, monkeypatch):
        monkeypatch.setattr(m, "_get_lan_ip", lambda: "192.168.100.1")
        dns = {"upstream": ["127.0.0.1#5053"], "upstream_ru": ["213.234.193.1"], "cache_size": 1000}
        conf = m.build_dnsmasq_conf(dns, (["avito.st"], ["blocked.ru"]))
        assert "server=/ru/213.234.193.1" in conf
        assert "server=/avito.st/213.234.193.1" in conf and "server=/blocked.ru/#" in conf
        assert "avito.st" not in m.build_dnsmasq_conf(dict(dns, upstream_ru=[]), (["avito.st"], []))

    def test_split_uses_the_house_profile_not_the_emergency_one(self, monkeypatch):
        seen = []
        monkeypatch.setattr(m, "_compiled_rules", lambda s, final, *a: seen.append(s["profile"]) or rules())
        monkeypatch.setattr(m._geo, "entries", lambda path, names: LISTS)
        m._dns_split_memo.clear()
        s = dict(m.DEFAULT_SETTINGS, dns={"upstream_ru": ["213.234.193.1"]})
        assert m._dns_split(dict(s, profile="direct", fallback_saved_profile="all_except_ru"))[0]
        assert seen == ["all_except_ru"]
        assert m._dns_split(dict(s, profile="direct", fallback_saved_profile=None)) is None
        assert m._dns_split(dict(s, dns={"upstream_ru": []})) is None

    def test_sync_restarts_dnsmasq_only_when_the_file_changes(self, monkeypatch, tmp_path):
        conf = tmp_path / "shunt.conf"
        runs = []
        monkeypatch.setattr(m, "DNS_CONF", conf)
        monkeypatch.setattr(m, "build_dnsmasq_conf_full", lambda s: "server=/avito.st/1.2.3.4\n")
        monkeypatch.setattr(m.subprocess, "run", lambda a, **k: runs.append(a) or SimpleNamespace(returncode=0, stderr=""))
        assert m._sync_dns({}) == "restarted" and conf.read_text() == "server=/avito.st/1.2.3.4\n"
        assert m._sync_dns({}) == "unchanged"
        assert runs == [["systemctl", "restart", "dnsmasq"]]
