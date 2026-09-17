"""
Finding out what is blocked by asking, instead of waiting for a list to say so.

The lists this gateway routes by are good and they will always lag. The gap has
a name: `claude.ai` is in `geosite:ru-blocked` and `anthropic.com` is not, so
the web interface went through the tunnel and the API went straight out and
answered 403. Of thirty companies probed by hand that have restricted Russian
users at some point, eleven were on the lists. No list closes that; measurement
does.

The method is the only part that matters, and it is a comparison rather than a
test. One direct probe cannot tell a block from an outage -- a site that is
simply down fails exactly like a site that refuses you. Two probes can:

    direct fails, tunnel works   -> blocked, whoever is doing the blocking
    both work                    -> open, nothing to do
    both fail                    -> the site is down; not our business
    direct works, tunnel fails   -> the exit is having trouble; also not ours

That table is the whole idea, and it is deliberately blind to WHO blocks. RKN
and a foreign company produce the same observation from here, which is the
point: the household wants what does not work to start working.

The limit, stated here rather than discovered later: a service that answers
403 over a healthy TLS session to a real browser but not to this probe -- or
the reverse -- is beyond us. We are a transparent proxy and do not read into
the stream; the probe is its own client and sees only what a bare client sees.
This catches "refuses to connect" and "refuses the probe". It does not catch
"serves a 403 only to a logged-in user".
"""
from __future__ import annotations

import ipaddress
import subprocess
import time

# What one probe can come back with. Deliberately three states rather than a
# status code: the decision below is about agreement between two paths, and
# a code means nothing on its own -- Cloudflare answers 403 to a bare curl on
# sites that work perfectly in a browser.
OK, REFUSED, FAILED = "ok", "refused", "failed"
UNCERTAIN = "uncertain"

BLOCKED, OPEN, DOWN, EXIT_TROUBLE = "blocked", "open", "down", "exit_trouble"

# 451 is literally "Unavailable For Legal Reasons"; 403 is what most geo-blocks
# answer. Both mean "reached it and was turned away", which is a different fact
# from "could not reach it" and is worth keeping apart in the record even though
# the verdict treats them alike.
REFUSAL_CODES = (403, 451)

# After this many consecutive `down` runs an entry stops competing for the
# budget. Measured on the live gateway: the record had grown to 79 entries, 77
# of them bare addresses and 43 of those permanently `down`, and the next run
# would have spent 39 of its 40 probes re-confirming them. `down` is the one
# verdict that teaches nothing -- neither path answered -- so an entry that has
# said it three times running is the cheapest thing to stop asking.
DOWN_PARK = 3


def classify(direct: dict, tunnel: dict) -> str:
    """The verdict for one domain, from the two observations."""
    d, t = direct.get("state"), tunnel.get("state")
    if d == OK:
        return OPEN
    if t == OK and d in (REFUSED, FAILED):
        return BLOCKED
    if d in (REFUSED, FAILED) and t in (REFUSED, FAILED):
        return DOWN
    return EXIT_TROUBLE


def probe(host: str, runner, timeout: int = 12) -> dict:
    """
    One observation of one host, by whichever path `runner` provides.

    The runner is injected so the decision logic above can be tested without a
    network, and so the two paths -- a bound interface and a SOCKS port -- are
    described in one place rather than twice.
    """
    code, err = runner(host, timeout)
    if code is None:
        return {"state": FAILED, "code": None, "detail": err[:120]}
    if code in REFUSAL_CODES:
        return {"state": REFUSED, "code": code, "detail": ""}
    if code == 429 or code >= 500:
        return {"state": UNCERTAIN, "code": code, "detail": "HTTP error; availability is inconclusive"}
    return {"state": OK, "code": code, "detail": ""}


def is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def curl_runner(via_socks: str = "", interface: str = ""):
    """A runner that shells out to curl. Returns (status_code|None, error)."""
    def run(host: str, timeout: int):
        # -L matters: without it a 301 scores as "reached it" even when the
        # redirect it points at is the refusal. Bounded, because a redirect
        # loop must not spend the run.
        #
        # What this still cannot see: a redirect that ends at a polite 200.
        # claude.ai answers 302 to https://claude.com/app-unavailable-in-region,
        # which is a page, not an error, so both paths look like success and the
        # domain is left direct. Catching that would mean comparing where the
        # two paths LAND, and the first thing that would catch is every locale
        # redirect in the world. The lists carry claude.ai already; this blind
        # spot is left open on purpose rather than papered over with a guess.
        cmd = ["curl", "-s", "-L", "-o", "/dev/null", "-w", "%{http_code}",
               "-m", str(timeout), "--max-redirs", "3"]
        if via_socks:  cmd += ["--socks5-hostname", via_socks]
        if interface:  cmd += ["--interface", interface]
        # Most of what the household's traffic log holds is addresses, not
        # names: xray records the destination it connected to, and a client
        # that dials an address never sent a name to record. An address has no
        # certificate that will match it, so verification is skipped for those
        # -- the question being asked is "does this connection get through",
        # not "is this the right server". Names are still verified.
        if is_address(host): cmd.append("-k")
        cmd.append("https://%s/" % host)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout + 5)
        except (OSError, subprocess.SubprocessError) as e:
            return None, str(e)
        out = (r.stdout or "").strip()
        if not out.isdigit() or out == "000":
            return None, (r.stderr or "no response").strip() or "no response"
        return int(out), ""
    return run


def candidates(hosts: list[str], known: list[dict], limit: int = 40,
               skip_suffixes: tuple = (".ru", ".su", ".рф")) -> list[str]:
    """
    Which hosts are worth two probes this run.

    Names first, then addresses, each ordered by how much the household actually
    used them -- a list that starts with the domain somebody opened once last
    week spends the run on nothing. Russian names are skipped: they are decided
    by geoip:ru long before any of this, and probing them would only find that a
    Russian service refuses a foreign exit -- true, expected, and not a block.
    """
    seen = {d.get("domain") for d in known}
    names: list[str] = []
    addrs: list[str] = []
    if limit <= 0:
        return []           # the record already fills the budget
    for h in hosts:
        h = (h or "").strip().lower().rstrip(".")
        if not h or "." not in h:
            continue
        if is_address(h):
            try:
                ip = ipaddress.ip_address(h)
            except ValueError:
                continue
            # Private and loopback addresses are decided by geoip:private long
            # before any of this and cannot be blocked by anybody.
            if ip.is_private or ip.is_loopback or ip.is_multicast:
                continue
        elif h.endswith(skip_suffixes):
            continue
        if h in seen:
            continue                      # already has a verdict; re-checked below
        if is_address(h):
            if h in addrs: continue
            addrs.append(h)
        else:
            if h in names: continue
            names.append(h)
        if len(names) >= limit:
            break                         # names alone fill it; addresses lose
    # Names first, addresses with whatever is left. Both are worth probing --
    # Telegram dials data centres by address and no domain rule can carry that
    # -- but the household's log is overwhelmingly addresses (470 of the 500
    # busiest destinations here), and ranked by volume alone they crowd out
    # every name. An address also answers the question badly: port 443 on a
    # bare address usually refuses because no site lives there, which is not a
    # block and cannot be told apart from one.
    return (names + addrs)[:limit]


def merge(known: list[dict], results: dict, min_streak: int = 2,
          now: float | None = None) -> list[dict]:
    """
    Fold this run's verdicts into the record.

    Hysteresis in one direction only. A domain has to look blocked on
    `min_streak` consecutive runs before it is routed, because a site that was
    down for one probe must not move the household's traffic into a tunnel. One
    `open` is enough to stop routing it again: being too eager to stop is the
    safe mistake, and the domain stays in the list with its history rather than
    disappearing.
    """
    now = int(now if now is not None else time.time())
    by_domain = {d["domain"]: dict(d) for d in known}

    for domain, (verdict, direct, tunnel) in results.items():
        row = by_domain.get(domain) or {
            "domain": domain, "enabled": True, "streak": 0,
            "first_seen": now, "routed": False,
        }
        row["last_checked"] = now
        row["verdict"] = verdict
        row["direct"] = direct.get("code") or direct.get("state")
        row["tunnel"] = tunnel.get("code") or tunnel.get("state")
        if verdict == BLOCKED:
            row["streak"] = int(row.get("streak", 0)) + 1
            if row["streak"] >= min_streak:
                if not row.get("routed"):
                    row["routed_since"] = now
                row["routed"] = True
        elif verdict == OPEN:
            row["streak"] = 0
            row["routed"] = False
        row["down_streak"] = (int(row.get("down_streak", 0)) + 1
                              if verdict == DOWN else 0)
        # DOWN and EXIT_TROUBLE say nothing about blocking, so they change
        # neither the streak nor the routing -- only the timestamp, so that the
        # page can show the domain was looked at and what was seen.
        by_domain[domain] = row

    return sorted(by_domain.values(), key=lambda r: r["domain"])


def recheck_rank(row: dict) -> int:
    """
    How much this entry deserves one of this run's probes.

    A record that is only ever re-probed oldest-first is fair and useless: every
    entry costs the same whether or not asking it again can change anything.
    These four bands say what can change.

      0  routed -- the one band that MUST be asked. A domain routed because it
         was blocked in June can only stop being routed by being asked again.
      1  a name that is not routed. The lists lag on names; this is the band the
         feature exists for.
      2  an address that is not routed. Worth keeping -- Telegram dials data
         centres by address -- but it answers the question poorly and must not
         crowd out names.
      3  parked: `down` on DOWN_PARK runs in a row. Neither path answered three
         times running, so a fourth ask is the least informative probe available.
         Kept in the record with its history, and picked up again only when the
         budget is not wanted by anything above it.
    """
    if row.get("routed"):
        return 0
    if int(row.get("down_streak", 0)) >= DOWN_PARK:
        return 3
    return 1 if not is_address(row.get("domain", "")) else 2


def probe_set(hosts: list[str], known: list[dict], limit: int = 40) -> list[str]:
    """
    Everything worth two probes this run: what is already on the record, plus
    new names from the household's traffic to fill the rest of the budget.

    Re-probing the record is not optional. A domain routed because it was
    blocked in June has to be able to stop being routed in September, and the
    only way that happens is by asking again. A feature that can only ever add
    to a list is a feature that slowly tunnels everything.
    """
    # A third of the budget is held back for names that have never been seen.
    # Without it the record starves the run the moment it reaches the budget:
    # forty known domains would fill every pass forever and nothing new would
    # ever be looked at, which is the quiet way for this feature to stop working
    # while still reporting success.
    reserve = max(1, limit // 3)
    # By what asking again can change, and within a band oldest first, so a long
    # record is covered over several runs rather than the same head every time.
    ranked = sorted((d for d in known if d.get("enabled", True)),
                    key=lambda d: (recheck_rank(d), d.get("last_checked", 0)))
    # Parked entries are held out of the claim on the budget entirely rather
    # than merely sorted last. A record that is nothing BUT parked entries --
    # which is what a gateway fed bare addresses for a week ends up with -- puts
    # them at the top of its own ordering and starves the run exactly as before.
    active = [d["domain"] for d in ranked if recheck_rank(d) < 3]
    parked = [d["domain"] for d in ranked if recheck_rank(d) == 3]
    on_record = active[:max(0, limit - reserve)]
    fresh = candidates(hosts, known, limit=limit - len(on_record))
    # If there were fewer new names than the reserve held back, the rest of the
    # budget goes back to the record rather than going unused -- and this is the
    # one path by which a parked entry is asked again.
    spare = limit - len(on_record) - len(fresh)
    if spare > 0:
        on_record += (active[len(on_record):] + parked)[:spare]
    return on_record + fresh


def run_once(hosts: list[str], known: list[dict], direct_runner, tunnel_runner,
             limit: int = 40, min_streak: int = 2, timeout: int = 12,
             now: float | None = None) -> tuple[list[dict], dict]:
    """One pass. Returns (record, counts) -- the counts are for the log line."""
    results = {}
    counts = {BLOCKED: 0, OPEN: 0, DOWN: 0, EXIT_TROUBLE: 0}
    for host in probe_set(hosts, known, limit):
        d = probe(host, direct_runner, timeout)
        # The tunnel probe is only asked for when the direct one gives a reason
        # to ask: if direct works the verdict is `open` whatever the tunnel
        # says, so probing it would spend a request to learn nothing.
        if d["state"] == OK:
            t = {"state": OK, "code": None, "detail": "not probed"}
            verdict = OPEN
        else:
            t = probe(host, tunnel_runner, timeout)
            verdict = classify(d, t)
        counts[verdict] = counts.get(verdict, 0) + 1
        results[host] = (verdict, d, t)
    return merge(known, results, min_streak=min_streak, now=now), counts


def routed(known: list[dict]) -> list[str]:
    """Everything this feature is currently sending through the tunnel."""
    return [d["domain"] for d in known
            if d.get("routed") and d.get("enabled", True)]


def routed_domains(known: list[dict]) -> list[str]:
    return [h for h in routed(known) if not is_address(h)]


def routed_addresses(known: list[dict]) -> list[str]:
    """
    The addresses, kept apart because xray routes them with a different field.
    Telegram is why this exists: MTProto dials data centres by address, so the
    thing most worth finding is precisely the thing a domain rule cannot carry.
    """
    return [h for h in routed(known) if is_address(h)]
