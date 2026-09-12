# Two transparent proxies, and which one gets a packet

This gateway runs two systems that intercept traffic without the client
knowing, and until 2.9.0 nothing said which one was responsible for what. That
gap was not academic: it produced two defects that each took a day to find, and
a third that quietly undid a fix somebody had already made.

## What each one is

**xray** intercepts in netfilter, in `mangle PREROUTING`, which runs **before
the kernel decides where a packet goes**. TCP and UDP are handed to it by
TPROXY; everything the chain excepts is left alone. This is the main datapath:
about two million packets a day.

**sing-box** runs a `tun` device with `auto_route`, which installs `ip rule`
entries at priority 9000–9010. Those act **after** the routing decision, on
whatever netfilter did not take. It also serves the SOCKS inbound on port 1080
that the interface configures — that part is a deliberate feature and unrelated
to the tun.

The order matters and is the whole point: netfilter first, routing second. A
packet xray takes never reaches sing-box's rules. A packet xray *declines*
lands squarely in them.

## The bug that followed from not writing this down

"xray declines this" was read as "this is not proxied". Those are different
sentences. A bare `RETURN` from `XRAY_PREROUTING` does not send a packet to the
kernel — it sends it to the *other* proxy.

Measured on 2026-09-12, over one day: sing-box's tun accepted **1124
connections that xray had declined** and sent 1201 of them into the tunnel.
The single largest group, about 324 of them, was port 5228 — Google FCM, which
`iptables.sh` excepts a few lines earlier with the comment *"Direct kernel
forwarding + NAT is much more stable"*, written after FCM through xray dropped
Google displays every two minutes. That exception had been silently undone by
the other proxy ever since.

The same ambiguity is what let ICMP fall into a SOCKS outbound that cannot
carry it: 5562 refusals a day, a downstream router that believed it had no
internet, and a `ping` that lied in both directions.

## The rule now

**A decline is a decline.** Every exception in `XRAY_PREROUTING` sets the
bypass mark (`0xff`) before returning. `ip rule` priority 40 sends marked
packets to the `main` table, past both interception paths, so declined traffic
is forwarded by the kernel — which is what every one of those exceptions
already claimed to do.

In `iptables.sh` this is the `decline_dest` helper; ICMP and port 5228 set the
mark the same way. Verified: `ip route get 173.194.221.188` chooses `tun0`,
`ip route get 173.194.221.188 mark 0xff` chooses `enp1s0`.

## What sing-box's tun is for now

Very little. With declines bypassing properly, the only traffic left for it is
forwarded protocols that are neither TCP, UDP nor ICMP — GRE, ESP and the like,
which a household generates approximately never. In the four minutes after the
change it accepted zero connections, against a prior rate near fifty an hour.

It has not been removed, because four minutes is not a day and this box carries
a household's traffic. The evidence to act on is the `tun0` interface counter:
if it stays flat over a day of normal use, `auto_route` can be turned off and
the ambiguity removed at the source rather than papered over with marks. Until
then the marks make the behaviour correct, and this file makes it legible.

## If you add an exception

Use `decline_dest`, or set the mark yourself. A bare `RETURN` will look like it
works — the traffic leaves xray — and will quietly be proxied by sing-box
instead, which is exactly how the FCM exception spent months not working.
