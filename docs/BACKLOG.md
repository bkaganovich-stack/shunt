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

## 2. DNS that shows whether it works — shipped in 2.5.0

What it found on the way in: the existing status check called connect() on a UDP
socket, which touches no network and cannot fail. It reported 192.0.2.1 and
203.0.113.99 -- documentation addresses nobody answers -- as reachable in 0 ms,
and the gateway's only real resolver as unreachable, because `127.0.0.1#5053`
made the address parser throw. A perfect inversion behind a green tick.

The other thing it found: the obvious probe is the wrong one. Asking the LAN
address on port 53 from the gateway answers "silent", because dnsmasq listens on
5335 and what joins them is a redirect in nat PREROUTING that a locally-sent
packet never passes through. Every device on the network resolves fine. That hop
is checked by counting the packets the redirect has carried instead.

Still worth doing here later: a history, so "it answered a minute ago" is
visible, and per-resolver failure counts over time rather than one probe now.

The original item, for the record:

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

## 3. Notice when the ground moves, and say so — shipped in 2.6.0

Built as a ladder: cable, address, gateway on the wire, path to the internet,
names resolve, tunnel carries. The first unmet rung is the answer and everything
below it is reported as "not checked" rather than as a second problem. Each rung
says whose problem it is, and the egress watchdog now refuses to restart the
tunnel when the break is above it -- which is what it did every two minutes for
hours in September.

What it found on the way in: the old watchdog's "direct path" reading was
fiction in both directions. It pinged the provider's gateway, which answers no
ICMP at all -- so the line read 0% loss while the tunnel's own tun was answering
for it, and would read 100% now that ICMP goes out properly. Presence on the
wire is read from the neighbour table instead, where that gateway shows up
REACHABLE with its MAC.

Still worth doing here later: a history of verdicts, so "this started at 14:02"
is answerable, and letting the operator mute one rung they know about.

The original item, for the record:

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

## 4. Provider profiles — shipped in 2.7.0

Built as an **assumptions audit** rather than as a profile browser, because the
profile was never the point: the gateway depending on assumptions nobody had
written down was. Each check names an assumption, tests it against what the
provider is doing now, and says what to do when it fails. The first one is the
outage itself -- is the gateway's own network excepted from interception? --
and it is verified by deleting the CGNAT line from a copy of the live chain and
watching the check go red with the remedy attached.

The fingerprint is the "named set", keyed on the DHCP server and the resolvers
rather than the address, so a session rebuild is not mistaken for a new company.

One thing this got wrong on the first pass, caught by running it: the cloned WAN
MAC was reported as a broken assumption. Cloning was deliberate. A permanent red
mark for something nobody should act on is the same defect as `ping 1.1.1.1` --
it teaches the reader to ignore the page. It is recorded as a dependency now,
not judged.

The original item, for the record:

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
- **The two address changes are explained, and were not the calls.** The
  subscriber's account had run out and was paid at about the time of the first
  change; the provider rebuilt the session, which is why the new address came
  from a different DHCP server with a different gateway and prefix. Both changes
  fall on 10 September at 13:32 and 13:59 MSK, and both calls fall outside that
  window -- so this closes the address question and leaves the five-minute one
  open. 2.4.2 records the issuing server with every change, so the next billing
  cycle explains itself instead of costing a conversation.
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

## 5. Inbound access, when the box is the edge — shipped in 2.8.0

The forwarding turned out to be the easy half. The half worth building was the
sentence at the top of the page: **this gateway is on CGNAT, and nothing from
the internet reaches it, so no rule below can work.** A form that accepted port
forwards without saying that would have cost somebody an evening and then a
support conversation.

Two things the real `ss` output taught, neither of which the design anticipated.
Of 219 open sockets, 73 are loopback-only and 135 are xray's per-flow UDP
sockets -- some showing foreign addresses in the local column, some bound to the
wildcard on ephemeral ports. Both arrived looking exactly like listeners. A
listener is now defined as a socket bound to an address this machine holds, or
to a wildcard on a port outside the range the kernel hands to clients, read from
the kernel rather than guessed. 219 sockets became 11 services.

Still worth doing here later: UPnP is deliberately absent and should stay that
way, but "this device asked to open a port and was refused" would be worth
showing; and the same page should eventually say whether an open port is
actually answering, in the spirit of item 2.

The original item, for the record:

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

## 6. A way for the box to talk to the person standing next to it

Raised while designing what should happen when the ISP cable is moved onto a
freshly imaged box. The obvious answer -- notice the link, say so in the
interface, offer a button -- was rejected for a good reason: it assumes somebody
is looking at the interface at the moment they plug a cable in, and the whole
point of the scenario is that they are not. They are at the router, which is
frequently nowhere near a monitor. A headless appliance that can only speak
through a web page cannot participate in a physical act.

So the missing piece is not cable detection. It is a channel that reaches a
person whose hands are on the hardware:

- **Bluetooth LE to a phone app.** Works before any network exists, which is
  the moment with the least other options -- a box that has just been flashed,
  or one whose network is the thing that is broken. The most work: a protocol,
  an app, and pairing that a household can do.
- **The web interface on a phone over Wi-Fi.** Cheapest by far, because the
  installer asks for a network during the install and the installed system
  keeps it: the box is already on the household Wi-Fi the first time it boots,
  and a phone is already on it too. Fails in exactly the case BLE covers --
  when the network is what is wrong.
- **A small USB display with a graphical interface of our own.** Bought
  separately, so it costs nothing for anyone who does not want one. Gives
  unambiguous feedback at the machine: what it thinks it is, which port it
  believes is the provider's, whether it has an address. This is the only one
  of the three that answers "what is it doing right now" without a second
  device.

Worth building at least one before automatic behaviour keyed to physical events
is added at all, because such behaviour is only safe when the person doing the
plugging can see what the box concluded. This also anticipates hardware beyond
this one mini-PC: single-board machines with no video output at all make the
question sharper, not softer.

Deliberately parked until then: adopting the ISP cable automatically. The
detection already lands in a sane place -- a box installed over Wi-Fi with no
cable comes up as `loop` with the wireless interface as its LAN link -- so
nothing is broken by waiting.

## 7. Loop topology over Wi-Fi

A gateway plugged into a LAN port of the router hairpins traffic through itself.
The same arrangement should work with no cable at all, with the box joined to
the router's Wi-Fi -- slower and less reliable, and a genuinely nice way to meet
a man-in-the-middle gateway before committing a household's internet to it.

Two things point the same way. `shunt-setup` already chooses exactly this
configuration on a box installed over Wi-Fi with no cable plugged in. And the
objection recorded in the code -- "Wi-Fi can't serve as a TProxy LAN port",
which excludes wireless interfaces in `apply_topology.py` and in the interface
list -- looks right for inline and wrong for loop: loop routes rather than
bridges, and the familiar limitation (a station cannot carry other MACs without
4-address mode) is about bridging.

That is reasoning, not measurement, and this file exists because reasoning has
lost to measurement repeatedly. The test costs nothing and has a natural home:
the second mini-PC, once imaged, comes up in this state on its own. Lift the
exclusion only after traffic has actually gone through it.

## 8. An installer that needs no network

The image carries the two Shunt packages and nothing else. Their dependencies --
fastapi, uvicorn, pydantic, hostapd, dnsmasq-base, avahi and the rest -- come
from deb.debian.org during the install, which is the whole reason the installer
has to configure a network before it can finish. Every question the household is
asked at install time exists to serve that one fact.

Remove the fact and the questions go with it. The dependency closure, minus
whatever the netinst pool already carries, is a few tens of megabytes: staged
into the image as a small local archive with a generated `Packages` file and
installed from `file://`, it would let the installer run with `netcfg/enable`
false, no cable, no Wi-Fi key, no prompt of any kind, on a machine that has
never seen a network. Shunt configures the network on first boot anyway -- that
is what it is for.

The cost is in the build, not the install: resolving that closure needs the
Debian package indices and a resolver honest about alternatives and virtual
packages, and the build host here is a Mac with no apt. Worth doing, and worth
doing only once it can be tested end to end on the second mini-PC.

## Earlier items, unchanged

- **Sources**: the manifest format and registry ship as of 2.2.0, reading only.
  Import — the front door, the recipe format, and the preview a change to a
  household's routing deserves — is next, then egress as data, then the plugin
  contract for third-party clients. See the design note for the ordering.
- **APT repository hosting.** `packaging/mkrepo.sh` is written and verified
  end to end; distribution is by file for now.
- **Multi-subscription egress registry.** Parked: blocked on subscriptions
  worth trusting rather than on anything technical.
- **The interface audit is done, and it found the headline indicator.** The
  dashboard said "Подключено" whenever the service was running and a key was
  configured — a statement about a configuration file, not about the network.
  It stayed green for a day in September while nothing resolved and nothing
  left the house. A dashboard that cannot go red is decoration. It now reports
  the ladder's last measurement, with a fourth state for "not measured" so a
  stale reading is never mistaken for good news. AdGuard's "connected" was the
  same defect one layer down: service active plus a listening socket, both true
  throughout the outage, exactly as the watchdog's own comment warned. The SOCKS
  proxy page now separates "configured" from "listening" for the same reason.
- **A note that warns beats a note that informs, and it should not.** The lease
  note shipped in 2.4.0 said a short lease meant every renewal might move the
  address. The box's own journal said three hundred renewals and no change, and
  nine re-acquisitions in one afternoon that all returned the same address. The
  reader spotted it immediately -- "home internet does not work that way" -- and
  he was right. The rule this leaves behind: **if the gateway can count it, the
  interface must report the count, not the possibility.** Worth auditing the
  rest of the interface against that; this was unlikely to be the only one.
- **Two transparent proxies on one box — written down in 2.9.0.** See
  `docs/DATAPATH.md`. The division turned out to be simple and the consequence
  of not stating it was not: a bare `RETURN` from the interception chain hands
  the packet to the OTHER proxy rather than to the kernel, so "xray declines
  this" never meant "this is not proxied". Measured over a day: sing-box's tun
  took 1124 declined connections and tunnelled 1201 of them, about 324 of those
  being the Google FCM traffic that `iptables.sh` excepts on purpose. That
  exception had been undone the whole time. Every exception now carries the
  bypass mark.

  Left open deliberately: sing-box's `auto_route` is now close to vestigial —
  zero connections in the four minutes after the change, against fifty an hour
  before. Four minutes is not a day, so the tun stays until the `tun0` counter
  has been flat over normal use, at which point the ambiguity can be removed at
  its source instead of covered by marks.
- **ufw is enabled at boot and inactive.** A Debian default, not ours: the
  unit runs, `ufw` itself is off, so it writes nothing today. It is a loaded
  gun rather than a bug — `ufw enable` would insert its own chains and its
  default FORWARD policy would stop the gateway forwarding, with no obvious
  connection to the command that caused it. Either mask the unit or say so
  where an operator would look.
- **Tunnel throughput.** ~9 Mbit/s per flow is a 128 KB window over a 90-120 ms
  RTT, not a provider limit. Untried: AdGuard over QUIC rather than HTTP/2, and
  an exit closer than the United States.
