# Backlog

Ordered by what the last incident showed to be missing, not by how pleasant it
would be to build.

## Context: what the 2026-09-09 provider change cost

Moving from a provider handing out RFC1918 WAN addresses to one on CGNAT
(100.64.0.0/10) broke the gateway completely. The cause was one missing line in
the TPROXY exception list. Finding it took a day and a dozen trips to the
cable, and every layer of the product reported the layer below it as broken:

- the egress watchdog restarted a healthy AdGuard every two minutes;
- the health monitor logged `inline WAN unhealthy` while the WAN was fine;
- the interface showed a green WAN with an address and said nothing else.

Nothing in the product could answer the only question that mattered: **where
does the packet actually die?** `tcpdump` and iptables rule counters answered it
in minutes; neither is reachable from the interface. Everything below follows
from that.

---

## 1. Live view of the network path

The most valuable item, and the one that would have saved the day.

One page, updating live, showing the chain end to end rather than a summary of
its parts:

- **Link**: carrier, negotiated speed and duplex, MTU, errors and drops.
- **Address**: WAN address, gateway, and the DHCP lease with a countdown —
  a ten-minute lease renewing every five is a different machine to reason about
  than a one-day lease, and nothing says so today.
- **Where a packet goes**: an input for a destination, answered with the real
  routing decision and the policy rule that produced it. This is `ip route get`
  made legible, and it is the single most useful thing on the page: on a box
  with three routing tables and fifteen rules, "which table won" is not
  something anyone can work out by reading them.
- **Rule counters**: hits on the exception and interception rules that matter,
  so a rule eating traffic is visible rather than deduced.
- **Egress**: is the tunnel carrying anything, measured by carrying something —
  not by whether a service is `active`.

**Do not** render `ip rule` and three routing tables raw. They misled the author
of this file three times in one day while he had root and knew what he was
looking for.

## 2. DNS that shows whether it works

Configurable resolvers are half of it. The failure was never "the setting is
wrong and cannot be changed" — it was "there is no way to tell that the
configured path is dead".

- Per-resolver state: answering / silent / in use right now, with the last
  latency, probed rather than assumed.
- The upstream chain made explicit: which resolver dnsmasq forwards to, whether
  the DoH proxy is answering, what it falls back to.
- A test field: resolve a name here, see which resolver answered and how long
  it took.
- Resolvers offered from the DHCP lease as a one-click option. On this provider
  they are the only path that does not depend on the tunnel — and the tunnel
  cannot come up until a name resolves.

A form with fields and no verification would reproduce the same dead end in a
prettier wrapper.

## 3. Notice when the ground moves, and say so

The product knew it was broken. `egress dead`, `inline WAN unhealthy` — logged
every minute, for hours, to a file nobody was reading, while the automatic
response (restart AdGuard) could not possibly have helped.

- Detect that the WAN address has moved to a different class — RFC1918 to
  CGNAT, a new prefix, a lease whose length changed by an order of magnitude —
  and say so plainly. That single line would have ended this incident in
  minutes.
- Distinguish a fault from an unmet precondition. "No cable" is not "the
  provider is down", and reporting one as the other sends the reader hunting a
  bug that does not exist.
- Stop repeating an automatic remedy that has not worked. Five identical
  restarts are not a fix in progress; they are a message that the diagnosis is
  wrong.
- Escalate somewhere a person will see, not only into a log file.

## 4. Provider profiles

The gateway was configured for one provider's assumptions and silently depended
on them: WAN inside 10.0.0.0/8, public DoH reachable, a lease measured in days.
All three were wrong on the next provider, and none of them was written down.

Worth exploring as a named set — WAN address family, resolvers, DoH
reachability, lease behaviour, MAC registration — that the box detects, records
and can compare against on any change.

---

## Provider adaptation still outstanding

- **Release 2.2.0 and install it.** The CGNAT fix currently exists on the live
  gateway only as an edited file; `dpkg -V shunt` reports the divergence. Any
  reinstall or upgrade reverts it and reproduces the whole outage.
- **A DNS fallback that is not Cloudflare DoH.** It answers on this provider,
  but roughly two dozen TLS connections an hour are reset before completing.
  Resolution succeeds by retrying, which costs latency on every cold name. The
  lease resolvers already have a routing bypass; adding them to dnsmasq as a
  second upstream would make name resolution robust rather than persistent.

## Earlier items, unchanged

- **Sources**: the manifest format and registry ship as of 2.2.0, reading only.
  Import — the front door, the recipe format, and the preview a change to a
  household's routing deserves — is next, then egress as data, then the plugin
  contract for third-party clients. See the design note for the ordering.
- **APT repository hosting.** `packaging/mkrepo.sh` is written and verified
  end to end; distribution is by file for now.
- **Multi-subscription egress registry.** Parked: blocked on subscriptions
  worth trusting rather than on anything technical.
- **Tunnel throughput.** ~9 Mbit/s per flow is a 128 KB window over a 90-120 ms
  RTT, not a provider limit. Untried: AdGuard over QUIC rather than HTTP/2, and
  an exit closer than the United States.
