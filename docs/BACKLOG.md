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

## 1. Live view of the network path — shipped in 2.4.0

Built as the "Сетевой тракт" page. What it turned out to need that this list did
not anticipate: **the interception layer, first**. TPROXY decides before the
routing decision, so an `ip route get` answer alone describes a packet that was
already taken somewhere else -- which is precisely how three wrong conclusions
got made in one day. The page now answers in the order the decisions happen:
netfilter, then xray, then the kernel.

Still worth doing here later: per-destination history (was this answer different
an hour ago?), and the same view for a chosen LAN device rather than for the
gateway's own traffic.

The original item, for the record:

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

## What the 2026-09-11 call drops added

Zoom froze and Teams dropped through two calls, roughly every five minutes.
Four things turned up, and the shape of the search is the lesson:

- **Conferencing was in the tunnel**, all of it. Fixed: Zoom and Teams leave
  directly, with a toggle. The measurement that justified it -- direct 0% loss,
  tunnel 2-5% and +90 ms -- took two minutes to run and had never been run.
- **The WAN check could not fail.** `ping 1.1.1.1` succeeded because the
  tunnel's tun answers ICMP echo for every address, including documentation
  addresses nobody replies to. Fixed, and worth remembering as a class: a check
  that cannot fail is worse than no check, because it is believed.
- **ICMP was broken for everything behind the gateway.** The router pinged
  8.8.8.8 every fifteen seconds -- 5562 times in a day -- and sing-box refused
  every one, because its SOCKS outbound cannot carry ICMP. Fixed in 2.3.3: ICMP
  carries the bypass mark and leaves through the WAN. The router's connectivity
  check works again, which removes the most plausible remaining cause of a
  periodic disruption nobody on this box could see.
- **The five-minute period is not yet explained, and four candidates are dead.**
  Ruled out by measurement rather than argument: the offload watchdog (fires on
  exactly that period, but exits without touching the NIC unless the kernel has
  logged transmit faults, and it has not); head-of-line blocking in the tunnel
  (every loss is a single packet, never a run); AdGuard reconnecting (a
  connection through it lived fourteen minutes across three of its wake-ups);
  and xray's 300-second idle default, which looked like a perfect fit until
  setting it to 60 seconds failed to cut an active connection at all -- the
  296-second death that suggested it was a restart of xray, by this author, at
  that moment.

  What remains: whether the router was reacting to believing it had no
  internet. That is now unfalsifiable from this side, because the cause was
  removed -- which is the right order, but it means the next call is the test.

  The wider lesson is the measurement, not the answer. Four wrong ideas cost
  about ten minutes each because each one could be checked; the same four, a
  week ago, would have been argued about. Item 1 exists to make that cheap for
  someone who is not holding a root shell.

---

## 5. Inbound access, when the box is the edge

In inline topology the gateway *is* the edge router, and `iptables.sh` closes
the WAN unconditionally: replies and ping in, everything new dropped. That is
the right default and it should stay the default. But it also means there is no
way to let anything in — a console, a home server, a WireGuard endpoint —
without editing a shipped script, which the next upgrade overwrites.

So the item is **inbound access**, not a firewall editor:

- A short list of what the household deliberately exposes: external port,
  internal device and port, protocol, on or off. That is the whole feature.
- Say what it costs, at the moment of adding it, in the sentence a person can
  act on: this makes `<device>:<port>` reachable from the internet.
- The list is also the audit. Nothing exposed that is not on it, and the page
  shows the closed default as a first-class state rather than an empty table.

**Not** a general rule editor. Routing on this box depends on the exact order
of fifteen rules in two mangle chains, and the last outage was one missing rule
in one of them. Handing that ordering to a form multiplies the ways to produce
a gateway that is broken in a way nobody can see, in exchange for flexibility
a household never asked for. The diagnostic half of "what is the firewall
doing" belongs to item 1, which already shows rule counters.

Worth pairing with a plain view of **what listens on which interface** — the
admin interface on :80, SSH, dnsmasq, xray's ports. That is answerable today
only over SSH with `ss -tulnp`, and it is the question anyone asks first when
wondering whether the box is safe on a public address.

## Provider adaptation: done as of 2.3.1

The CGNAT fix, the two-writers fix and split DNS are all in the package now;
`dpkg -V shunt` on the live gateway reports nothing, so there is no edited file
left for the next upgrade to revert. Russian names resolve through the
provider's own resolvers, everything else through the DoH proxy, and both were
verified after the upgrade.

Still open on the DNS question, and worth measuring before acting:

- **Whether the DoH proxy should keep the foreign half at all.** AdGuard's own
  resolvers, reached through the tunnel, would remove one moving part. Held
  back deliberately: the current layout should be left alone long enough to
  know it is stable, since the failure mode it replaces cost a day.
- **Cloudflare's reset rate.** Roughly two dozen TLS connections an hour to
  the DoH endpoint are reset before completing on this provider. Resolution
  survives by retrying, which costs latency on every cold name. Not urgent now
  that Russian names never reach it.

## Earlier items, unchanged

- **Sources**: the manifest format and registry ship as of 2.2.0, reading only.
  Import — the front door, the recipe format, and the preview a change to a
  household's routing deserves — is next, then egress as data, then the plugin
  contract for third-party clients. See the design note for the ordering.
- **APT repository hosting.** `packaging/mkrepo.sh` is written and verified
  end to end; distribution is by file for now.
- **Multi-subscription egress registry.** Parked: blocked on subscriptions
  worth trusting rather than on anything technical.
- **A note that warns beats a note that informs, and it should not.** The lease
  note shipped in 2.4.0 said a short lease meant every renewal might move the
  address. The box's own journal said three hundred renewals and no change, and
  nine re-acquisitions in one afternoon that all returned the same address. The
  reader spotted it immediately -- "home internet does not work that way" -- and
  he was right. The rule this leaves behind: **if the gateway can count it, the
  interface must report the count, not the possibility.** Worth auditing the
  rest of the interface against that; this was unlikely to be the only one.
- **Two transparent proxies on one box.** xray intercepts with TPROXY; sing-box
  runs a tun with `auto_route` and its own `final: proxy`. Both capture LAN
  traffic, and which one gets a given packet is not written down anywhere. The
  ICMP hole above is the first visible cost of that ambiguity.
- **ufw is enabled at boot and inactive.** A Debian default, not ours: the
  unit runs, `ufw` itself is off, so it writes nothing today. It is a loaded
  gun rather than a bug — `ufw enable` would insert its own chains and its
  default FORWARD policy would stop the gateway forwarding, with no obvious
  connection to the command that caused it. Either mask the unit or say so
  where an operator would look.
- **Tunnel throughput.** ~9 Mbit/s per flow is a 128 KB window over a 90-120 ms
  RTT, not a provider limit. Untried: AdGuard over QUIC rather than HTTP/2, and
  an exit closer than the United States.
