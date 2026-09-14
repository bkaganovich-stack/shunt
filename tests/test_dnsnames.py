"""
Tests for recovering domain names from the resolver's own answers.

The packets here are built by hand rather than mocked, because the thing under
test IS the parsing: a mocked parser would pass while the real one choked on a
compression pointer, which is present in essentially every real answer.

Run:  python -m pytest tests/ -v
"""
import json
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "web"))

import dnsnames as dn  # noqa: E402


def _labels(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def _rr(rtype: int, rdata: bytes, ttl: int = 300, name_ptr: int = 0x0C) -> bytes:
    # 0xC000 | offset — the compression pointer every real resolver emits.
    return (struct.pack("!H", 0xC000 | name_ptr)
            + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata)


def response(qname: str, answers: list) -> bytes:
    body = _labels(qname) + struct.pack("!HH", 1, 1)
    rrs = b"".join(answers)
    return (struct.pack("!HHHHHH", 0xABCD, 0x8180, 1, len(answers), 0, 0)
            + body + rrs)


def a(ip: str) -> bytes:
    return _rr(dn.A, socket.inet_pton(socket.AF_INET, ip))


def aaaa(ip: str) -> bytes:
    return _rr(dn.AAAA, socket.inet_pton(socket.AF_INET6, ip))


def cname(target: str) -> bytes:
    return _rr(dn.CNAME, _labels(target))


class TestReadingAnAnswer:
    def test_a_plain_answer(self):
        assert dn.parse_answer(response("example.com", [a("93.184.216.34")])) \
            == ("example.com", ["93.184.216.34"])

    def test_several_addresses_for_one_name(self):
        name, ips = dn.parse_answer(
            response("ya.ru", [a("77.88.44.242"), a("5.255.255.242")]))
        assert name == "ya.ru"
        assert ips == ["77.88.44.242", "5.255.255.242"]

    def test_ipv6(self):
        name, ips = dn.parse_answer(response("ya.ru", [aaaa("2a02:6b8::2:242")]))
        assert (name, ips) == ("ya.ru", ["2a02:6b8::2:242"])

    def test_the_name_asked_for_wins_over_the_alias(self):
        # instagram.com ends at z-p42-instagram.c10r.facebook.com. The household
        # asked for the first one, and a page they read must say that.
        raw = response("instagram.com",
                       [cname("z-p42-instagram.c10r.facebook.com"),
                        a("157.240.205.174")])
        assert dn.parse_answer(raw) == ("instagram.com", ["157.240.205.174"])

    def test_names_are_lower_cased(self):
        assert dn.parse_answer(response("EXAMPLE.COM", [a("1.2.3.4")]))[0] \
            == "example.com"

    def test_an_answer_with_no_addresses_gives_nothing(self):
        assert dn.parse_answer(response("example.com", [cname("other.com")])) \
            == ("example.com", [])

    def test_rubbish_is_not_a_crash(self):
        # This runs inside the resolver. Anything it raises is a DNS outage,
        # and a DNS outage on this gateway is no tunnel at all.
        for bad in (b"", b"\x00", b"\xff" * 40, b"\xab\xcd\x81\x80\x00\x01\x00\x01",
                    response("example.com", [a("1.2.3.4")])[:-3]):
            assert dn.parse_answer(bad) == ("", []) or isinstance(
                dn.parse_answer(bad), tuple)

    def test_a_query_rather_than_an_answer_is_ignored(self):
        query = (struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
                 + _labels("example.com") + struct.pack("!HH", 1, 1))
        assert dn.parse_answer(query) == ("", [])


class TestTheMap:
    def test_record_and_look_up(self):
        m = dn.NameMap()
        m.record("example.com", ["1.2.3.4", "1.2.3.5"], now=100)
        assert m.lookup("1.2.3.4", now=100) == "example.com"
        assert m.lookup("1.2.3.5", now=100) == "example.com"
        assert m.lookup("9.9.9.9", now=100) == ""

    def test_a_name_expires(self):
        # A CDN address belongs to somebody else within the hour, and a page
        # that says "instagram" about it then is worse than one saying the
        # address.
        m = dn.NameMap(ttl=3600)
        m.record("example.com", ["1.2.3.4"], now=0)
        assert m.lookup("1.2.3.4", now=3599) == "example.com"
        assert m.lookup("1.2.3.4", now=3601) == ""

    def test_the_newest_answer_wins(self):
        m = dn.NameMap()
        m.record("old.com", ["1.2.3.4"], now=100)
        m.record("new.com", ["1.2.3.4"], now=200)
        assert m.lookup("1.2.3.4", now=200) == "new.com"

    def test_it_stays_bounded(self):
        m = dn.NameMap(limit=10)
        for i in range(50):
            m.record("h%d.com" % i, ["10.0.0.%d" % i], now=1000 + i)
        assert len(m) <= 10
        # and what survives is the most recent
        assert m.lookup("10.0.0.49", now=1050) == "h49.com"

    def test_expiry_is_what_frees_room_first(self):
        m = dn.NameMap(ttl=100, limit=10)
        for i in range(9):
            m.record("old%d.com" % i, ["10.0.1.%d" % i], now=0)
        for i in range(5):
            m.record("new%d.com" % i, ["10.0.2.%d" % i], now=1000)
        assert m.lookup("10.0.2.0", now=1000) == "new0.com"
        assert m.lookup("10.0.1.0", now=1000) == ""

    def test_prune_reports_what_it_dropped(self):
        m = dn.NameMap(ttl=10)
        m.record("a.com", ["1.1.1.1"], now=0)
        m.record("b.com", ["2.2.2.2"], now=100)
        assert m.prune(now=100) == 1
        assert len(m) == 1


class TestCrossingProcesses:
    def test_round_trip(self, tmp_path):
        p = tmp_path / "names.json"
        m = dn.NameMap()
        m.record("example.com", ["1.2.3.4"], now=500)
        assert m.dump(p) is True
        back = dn.NameMap.load(p, now=500)
        assert back.lookup("1.2.3.4", now=500) == "example.com"

    def test_stale_entries_do_not_survive_a_restart(self, tmp_path):
        p = tmp_path / "names.json"
        m = dn.NameMap()
        m.record("example.com", ["1.2.3.4"], now=0)
        m.dump(p)
        assert len(dn.NameMap.load(p, ttl=3600, now=99999)) == 0

    def test_a_damaged_file_is_an_empty_map_not_an_exception(self, tmp_path):
        p = tmp_path / "names.json"
        p.write_text("{not json")
        assert len(dn.NameMap.load(p)) == 0
        assert len(dn.NameMap.load(tmp_path / "absent.json")) == 0

    def test_a_reader_never_sees_half_a_file(self, tmp_path):
        # dump writes a temp file and renames it; a reader that opens the real
        # path during a dump gets either the old map or the new one.
        p = tmp_path / "names.json"
        m = dn.NameMap()
        m.record("a.com", ["1.1.1.1"], now=0)
        m.dump(p)
        first = json.loads(p.read_text())
        m.record("b.com", ["2.2.2.2"], now=1)
        m.dump(p)
        second = json.loads(p.read_text())
        assert len(first) == 1 and len(second) == 2

    def test_an_unwritable_path_is_reported_not_raised(self, tmp_path):
        assert dn.NameMap().dump(tmp_path / "no" / "such" / "dir.json") is False


class TestNamingAnAddress:
    def test_a_known_address_becomes_its_name(self):
        m = dn.NameMap()
        m.record("example.com", ["1.2.3.4"], now=0)
        assert dn.name_for("1.2.3.4", m, now=0) == "example.com"

    def test_an_unknown_address_stays_an_address(self):
        assert dn.name_for("1.2.3.4", dn.NameMap(), now=0) == "1.2.3.4"

    def test_something_that_is_already_a_name_is_left_alone(self):
        assert dn.name_for("example.com", dn.NameMap()) == "example.com"

    def test_no_map_means_no_change(self):
        assert dn.name_for("1.2.3.4", None) == "1.2.3.4"


class TestThePathIsNotFrozen:
    def test_the_dump_path_can_be_changed_after_import(self, tmp_path, monkeypatch):
        # It could not be: DUMP was a default argument, captured when the
        # function was defined, so pointing the module somewhere else did
        # nothing -- the ingester's own test caught this by writing a map the
        # ingester then failed to read.
        target = tmp_path / "elsewhere.json"
        monkeypatch.setattr(dn, "DUMP", target)
        m = dn.NameMap()
        m.record("example.com", ["1.2.3.4"], now=0)
        assert m.dump() is True
        assert target.exists()
        assert dn.NameMap.load(now=0).lookup("1.2.3.4", now=0) == "example.com"


class TestOnlyOneResolverRecords:
    """
    fptn-egress.sh generates the namespace resolver by rewriting doh_proxy.py's
    LISTEN line and nothing else, so everything else is inherited. Both share a
    filesystem, and the namespace one never sees a household query -- so its
    empty map overwrote the real one every thirty seconds. The symptom was a
    file resetting to {} while every piece of code tested correct in isolation.
    """

    def test_the_loopback_resolver_records(self):
        assert dn.should_record([("127.0.0.1", 53), ("127.0.0.1", 5053)]) is True

    def test_the_namespace_resolver_does_not(self):
        # This is the generated one: 192.168.244.1 is the veth inside the FPTN
        # namespace, and the line is the only thing the generator rewrites.
        assert dn.should_record([("192.168.244.1", 53)]) is False

    def test_ipv6_loopback_counts(self):
        assert dn.should_record([("::1", 53)]) is True

    def test_rubbish_does_not_record(self):
        # Wrong is better than double-writing the map.
        for bad in (None, [], "127.0.0.1", [("127.0.0.1",)], [42]):
            assert dn.should_record(bad) is False
