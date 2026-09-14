"""
Tests for deciding what is blocked by measuring it.

The case that motivated the whole thing is the first one: anthropic.com answers
403 directly and works through the tunnel, while claude.ai -- the same company --
is on the list already. A household cannot be asked to notice that.

Run:  python -m pytest tests/ -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "web"))

import blockprobe as bp  # noqa: E402


def obs(state, code=None):
    return {"state": state, "code": code, "detail": ""}


class TestTheVerdict:
    def test_refused_directly_and_working_through_the_tunnel_is_blocked(self):
        # api.anthropic.com, measured on the live gateway 2026-09-13.
        assert bp.classify(obs(bp.REFUSED, 403), obs(bp.OK, 404)) == bp.BLOCKED

    def test_unreachable_directly_and_working_through_the_tunnel_is_blocked(self):
        # Telegram's data centres: direct times out entirely.
        assert bp.classify(obs(bp.FAILED), obs(bp.OK, 200)) == bp.BLOCKED

    def test_working_both_ways_is_open(self):
        assert bp.classify(obs(bp.OK, 200), obs(bp.OK, 200)) == bp.OPEN

    def test_working_directly_is_open_whatever_the_tunnel_says(self):
        # Cloudflare answers 403 to a bare curl from a datacentre exit on sites
        # that are perfectly reachable. That is a fact about the exit, not about
        # the household, and must never route anything.
        assert bp.classify(obs(bp.OK, 200), obs(bp.REFUSED, 403)) == bp.OPEN
        assert bp.classify(obs(bp.OK, 301), obs(bp.FAILED)) == bp.OPEN

    def test_failing_both_ways_is_the_site_being_down(self):
        # The distinction one probe cannot make, and the reason there are two.
        assert bp.classify(obs(bp.FAILED), obs(bp.FAILED)) == bp.DOWN
        assert bp.classify(obs(bp.REFUSED, 403), obs(bp.REFUSED, 403)) == bp.DOWN

    def test_a_broken_exit_is_named_rather_than_blamed_on_the_site(self):
        assert bp.classify(obs(bp.FAILED), obs(bp.REFUSED, 502)) == bp.DOWN


class TestOneObservation:
    def test_a_status_code_becomes_ok(self):
        assert bp.probe("x", lambda h, t: (200, ""))["state"] == bp.OK

    def test_a_refusal_is_kept_apart_from_a_failure(self):
        assert bp.probe("x", lambda h, t: (403, ""))["state"] == bp.REFUSED
        assert bp.probe("x", lambda h, t: (451, ""))["state"] == bp.REFUSED
        r = bp.probe("x", lambda h, t: (None, "connection timed out"))
        assert r["state"] == bp.FAILED and "timed out" in r["detail"]

    def test_a_redirect_counts_as_reached(self):
        assert bp.probe("x", lambda h, t: (302, ""))["state"] == bp.OK


class TestChoosingWhatToProbe:
    def test_russian_names_are_not_probed(self):
        # geoip:ru decides these long before this runs, and a Russian service
        # refusing a foreign exit is expected rather than a block.
        got = bp.candidates(["ozon.ru", "example.com", "госуслуги.рф"], [])
        assert got == ["example.com"]

    def test_order_follows_what_the_household_actually_used(self):
        got = bp.candidates(["a.com", "b.com", "c.com"], [], limit=2)
        assert got == ["a.com", "b.com"]

    def test_domains_with_a_verdict_already_are_not_re_added(self):
        known = [{"domain": "a.com", "verdict": "open"}]
        assert bp.candidates(["a.com", "b.com"], known) == ["b.com"]

    def test_rubbish_is_dropped(self):
        assert bp.candidates(["", "   ", "localhost", None], []) == []


class TestTheRecord:
    def test_one_blocked_run_is_not_enough_to_route(self):
        # A site that was down for one probe must not move a household's
        # traffic into a tunnel.
        out = bp.merge([], {"a.com": (bp.BLOCKED, obs(bp.FAILED), obs(bp.OK, 200))})
        assert out[0]["streak"] == 1 and out[0]["routed"] is False
        assert bp.routed_domains(out) == []

    def test_two_in_a_row_routes_it_and_records_when(self):
        r = {"a.com": (bp.BLOCKED, obs(bp.REFUSED, 403), obs(bp.OK, 200))}
        out = bp.merge(bp.merge([], r, now=100), r, now=200)
        assert out[0]["routed"] is True and out[0]["routed_since"] == 200
        assert bp.routed_domains(out) == ["a.com"]

    def test_one_open_run_stops_routing_immediately(self):
        r = {"a.com": (bp.BLOCKED, obs(bp.FAILED), obs(bp.OK, 200))}
        out = bp.merge(bp.merge([], r), r)
        out = bp.merge(out, {"a.com": (bp.OPEN, obs(bp.OK, 200), obs(bp.OK, 200))})
        assert out[0]["routed"] is False and out[0]["streak"] == 0
        # and it stays in the list, with its history
        assert out[0]["domain"] == "a.com" and out[0]["first_seen"]

    def test_a_site_that_is_merely_down_changes_nothing(self):
        r = {"a.com": (bp.BLOCKED, obs(bp.FAILED), obs(bp.OK, 200))}
        routed = bp.merge(bp.merge([], r), r)
        after = bp.merge(routed, {"a.com": (bp.DOWN, obs(bp.FAILED), obs(bp.FAILED))})
        assert after[0]["routed"] is True      # still routed
        assert after[0]["streak"] == 2         # and the streak is untouched

    def test_a_switched_off_domain_is_not_routed_but_is_remembered(self):
        r = {"a.com": (bp.BLOCKED, obs(bp.FAILED), obs(bp.OK, 200))}
        out = bp.merge(bp.merge([], r), r)
        out[0]["enabled"] = False
        assert bp.routed_domains(out) == []
        assert out[0]["routed"] is True        # the measurement still says so

    def test_the_evidence_is_kept_not_just_the_verdict(self):
        out = bp.merge([], {"a.com": (bp.BLOCKED, obs(bp.REFUSED, 403), obs(bp.OK, 404))})
        assert out[0]["direct"] == 403 and out[0]["tunnel"] == 404


class TestARun:
    def _runners(self, direct_map, tunnel_map):
        return (lambda h, t: direct_map.get(h, (None, "timeout")),
                lambda h, t: tunnel_map.get(h, (None, "timeout")))

    def test_what_is_on_the_record_is_probed_again(self):
        known = [{"domain": "old.com", "enabled": True, "routed": True, "streak": 2}]
        assert bp.probe_set(["new.com"], known, limit=10) == ["old.com", "new.com"]

    def test_the_budget_is_not_exceeded(self):
        known = [{"domain": "a.com", "enabled": True}, {"domain": "b.com", "enabled": True}]
        assert len(bp.probe_set(["c.com", "d.com"], known, limit=2)) == 2

    def test_a_full_record_does_not_starve_new_names(self):
        # The quiet way for this to stop working: once the record reaches the
        # budget it fills every run and nothing new is ever looked at, while
        # the task keeps reporting success.
        known = [{"domain": "d%02d.com" % i, "enabled": True} for i in range(40)]
        got = bp.probe_set(["fresh.com"], known, limit=40)
        assert "fresh.com" in got and len(got) == 40

    def test_the_record_is_covered_oldest_first(self):
        known = [{"domain": "new.com", "enabled": True, "last_checked": 900},
                 {"domain": "old.com", "enabled": True, "last_checked": 100}]
        assert bp.probe_set([], known, limit=2)[0] == "old.com"

    def test_a_working_site_costs_one_probe_not_two(self):
        asked = []
        direct = lambda h, t: (200, "")
        def tunnel(h, t):
            asked.append(h); return (200, "")
        rec, counts = bp.run_once(["a.com"], [], direct, tunnel)
        assert asked == [], "tunnel was probed for a site that works directly"
        assert counts[bp.OPEN] == 1
        assert rec[0]["tunnel"] == "ok"

    def test_a_blocked_site_is_recorded_with_both_observations(self):
        d, t = self._runners({"a.com": (403, "")}, {"a.com": (200, "")})
        rec, counts = bp.run_once(["a.com"], [], d, t)
        assert counts[bp.BLOCKED] == 1
        assert rec[0]["direct"] == 403 and rec[0]["tunnel"] == 200
        assert rec[0]["routed"] is False        # one run is not enough

    def test_two_runs_route_it(self):
        d, t = self._runners({"a.com": (403, "")}, {"a.com": (200, "")})
        rec, _ = bp.run_once(["a.com"], [], d, t)
        rec, _ = bp.run_once(["a.com"], rec, d, t)
        assert bp.routed_domains(rec) == ["a.com"]

    def test_a_site_that_comes_back_stops_being_routed(self):
        d, t = self._runners({"a.com": (403, "")}, {"a.com": (200, "")})
        rec, _ = bp.run_once(["a.com"], [], d, t)
        rec, _ = bp.run_once(["a.com"], rec, d, t)
        ok_d, _ = self._runners({"a.com": (200, "")}, {})
        rec, counts = bp.run_once(["a.com"], rec, ok_d, t)
        assert counts[bp.OPEN] == 1
        assert bp.routed_domains(rec) == []


class TestTrafficThatHasNoName:
    """
    Most of what the traffic log holds is addresses, not names: xray records
    the destination it connected to, and a client that dialled an address never
    sent a name. The first live run found this the hard way -- 38 of 40
    candidates were addresses, every probe failed on a certificate that could
    not match, and the gateway reported the whole internet as down.
    """

    def test_an_address_is_recognised(self):
        assert bp.is_address("149.154.167.51")
        assert bp.is_address("2001:db8::1")
        assert not bp.is_address("example.com")

    def test_private_addresses_are_never_candidates(self):
        got = bp.candidates(["192.168.1.5", "127.0.0.1", "10.0.0.1",
                             "149.154.167.51"], [])
        assert got == ["149.154.167.51"]

    def test_addresses_and_names_are_routed_by_different_fields(self):
        r = {"149.154.167.51": (bp.BLOCKED, obs(bp.FAILED), obs(bp.OK, 200)),
             "anthropic.com":  (bp.BLOCKED, obs(bp.REFUSED, 403), obs(bp.OK, 404))}
        rec = bp.merge(bp.merge([], r), r)
        assert bp.routed_domains(rec) == ["anthropic.com"]
        assert bp.routed_addresses(rec) == ["149.154.167.51"]
        assert sorted(bp.routed(rec)) == ["149.154.167.51", "anthropic.com"]

    def test_certificate_checking_is_skipped_for_addresses_only(self):
        seen = {}
        def fake_run(cmd, **kw):
            seen[cmd[-1]] = "-k" in cmd
            class R: stdout = "200"; stderr = ""; returncode = 0
            return R()
        import subprocess as sp
        orig = sp.run
        sp.run = fake_run
        try:
            runner = bp.curl_runner(interface="enp1s0")
            runner("149.154.167.51", 5)
            runner("example.com", 5)
        finally:
            sp.run = orig
        assert seen["https://149.154.167.51/"] is True
        assert seen["https://example.com/"] is False


class TestTheBudgetIsSpentOnWhatCanChange:
    """
    The live gateway had the feature quietly stop working while reporting
    success. Its record had grown to 79 entries, 77 of them bare addresses and
    43 of those permanently `down`, and the next run would have spent 39 of its
    40 probes re-confirming them and looked at exactly one new name.

    Three things caused that and all three are asserted here: the candidate
    list ranked by volume alone, so addresses crowded out names; the record was
    re-probed oldest-first, so an entry that could teach nothing cost the same
    as one that could; and the pool the candidates came from was cut at 500
    rows, which is itself a ranking and threw the names away first.
    """

    def test_names_come_before_addresses(self):
        got = bp.candidates(["1.1.1.1", "2.2.2.2", "example.com"], [], limit=2)
        assert got == ["example.com", "1.1.1.1"]

    def test_addresses_still_get_the_leftover_budget(self):
        # Telegram dials data centres by address; dropping them outright would
        # give back the hole that cost the household Telegram in 2.12.0.
        got = bp.candidates(["1.1.1.1", "example.com"], [], limit=5)
        assert got == ["example.com", "1.1.1.1"]

    def test_volume_still_orders_within_a_kind(self):
        got = bp.candidates(["b.com", "a.com"], [], limit=2)
        assert got == ["b.com", "a.com"]

    def test_a_routed_entry_is_always_re_probed_first(self):
        # The only way a domain stops being routed is by being asked again.
        known = [{"domain": "old.com", "last_checked": 1, "routed": False},
                 {"domain": "routed.com", "last_checked": 9, "routed": True}]
        assert bp.probe_set([], known, limit=1) == ["routed.com"]

    def test_a_name_outranks_an_address(self):
        known = [{"domain": "9.9.9.9", "last_checked": 1},
                 {"domain": "late.com", "last_checked": 9}]
        assert bp.probe_set([], known, limit=1) == ["late.com"]

    def test_three_down_runs_park_an_entry(self):
        rec = []
        for _ in range(bp.DOWN_PARK):
            rec = bp.merge(rec, {"gone.com": (bp.DOWN, obs(bp.FAILED),
                                              obs(bp.FAILED))})
        assert rec[0]["down_streak"] == bp.DOWN_PARK
        assert bp.recheck_rank(rec[0]) == 3

    def test_a_parked_entry_still_runs_when_nothing_else_wants_the_budget(self):
        # Parked, not deleted: it keeps its history, and a quiet run picks it up.
        rec = []
        for _ in range(bp.DOWN_PARK):
            rec = bp.merge(rec, {"gone.com": (bp.DOWN, obs(bp.FAILED),
                                              obs(bp.FAILED))})
        assert bp.probe_set([], rec, limit=40) == ["gone.com"]

    def test_an_answer_of_any_kind_unparks_it(self):
        rec = []
        for _ in range(bp.DOWN_PARK):
            rec = bp.merge(rec, {"gone.com": (bp.DOWN, obs(bp.FAILED),
                                              obs(bp.FAILED))})
        rec = bp.merge(rec, {"gone.com": (bp.OPEN, obs(bp.OK, 200), obs(bp.OK))})
        assert rec[0]["down_streak"] == 0 and bp.recheck_rank(rec[0]) == 1

    def test_a_record_of_dead_addresses_no_longer_starves_the_run(self):
        # The live shape, in miniature: a record full of parked addresses and a
        # log full of names. Before the fix this run was all addresses.
        rec = []
        for _ in range(bp.DOWN_PARK):
            rec = bp.merge(rec, {"%d.0.0.1" % i: (bp.DOWN, obs(bp.FAILED),
                                                  obs(bp.FAILED))
                                 for i in range(1, 30)})
        log = ["%d.1.1.1" % i for i in range(1, 60)] + \
              ["name%d.com" % i for i in range(10)]
        got = bp.probe_set(log, rec, limit=10)
        assert [h for h in got if not bp.is_address(h)] == \
               ["name%d.com" % i for i in range(10)]
