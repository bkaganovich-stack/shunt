# Shunt

Shunt chooses, for every connection, whether it leaves your home network
directly or through a tunnel. Domestic and local destinations go out direct;
blocked and foreign ones take the tunnel. There is nothing to switch on or off.

It runs on a spare always-on mini-PC placed on the network path, so nothing is
installed on any device. Phones, laptops, TVs, consoles, guest hardware and IoT
gear are covered alike — including everything that cannot run a VPN client at
all. Set it up once, and nobody in the household configures anything again.

Built and run in Russia, where both of the obvious settings are wrong. Tunnel
everything and domestic banking and government sites stop working, because they
refuse foreign exit IPs — and everything gets slower. Tunnel nothing and many
foreign services are unreachable. The useful setting is neither on nor off, but
per destination.

Self-hosted. Debian or Ubuntu, managed from one web interface.

## Install

You need Debian or Ubuntu, python3 3.10 or newer, and any small always-on x86
machine with one or two network ports.

Both packages are on the [Releases](https://github.com/bkaganovich-stack/shunt/releases)
page:

```
shasum -a 256 -c SHA256SUMS
sudo apt install ./shunt_2.0.0_all.deb ./shunt-xray_*.deb
```

`apt` resolves the rest from the distribution archive. `sing-box` is not in the
archive and is installed separately from upstream; without it everything works
except the SOCKS proxy features. The geo rule sets are another 92 MB and go
stale, so they download after installation and refresh weekly on a timer.

## After installing

The management interface comes up on port 80, at `http://<box-ip>/`.

The routing services are enabled but deliberately not started. They rewrite
firewall and routing tables, which should not happen unattended during a package
install. Review the layout the setup tool detected, then start them:

```
sudo systemctl start shunt sing-box
```

## Wiring

The setup tool works out which of the two layouts applies.

- **inline** — the box sits between the ISP and the router. Two network ports.
- **loop** — a single port. The box sits inside the router's LAN and the router
  does the final NAT.

## Routing policy

- Geo databases (geoip/geosite) plus your own rules. Your rules win.
- Global profiles: blocked-only, everything-except-domestic, all traffic, or
  direct with the tunnel unused.
- Per-device and per-group policy. A device either follows the global profile or
  carries an explicit override. Devices are discovered from the ARP table.

## Egress and failover

The tunnel provider is pluggable; today that means AdGuard VPN as primary and
FPTN as backup. If the primary goes quiet for about three minutes, Shunt fails
over; if both are down it routes directly and restores your profile once a
tunnel answers again.

## Failing safe

Changing routing on a live network can lock you out of it, so:

- a configuration snapshot is taken before every change;
- if the proxy core fails to start, the change rolls back;
- switching topology or network port rolls back if the router becomes
  unreachable.

## Web interface

Russian or English, switchable at runtime. Mostly you will use the device list
with its per-device policy, the dashboard with live CPU, memory, disk and
throughput graphs, and the DNS page — dnsmasq with a DNS-over-HTTPS upstream,
split-DNS for domestic domains, and DNS-level ad and malware blocking.

Also there: traffic analytics, logs, a live connections table, a SOCKS proxy for
sending one application through the tunnel, a terminal, a scheduler, webhook
notifications, and configuration export/import.

## Reference

Built on xray-core in TPROXY mode, sing-box, dnsmasq and a small
DNS-over-HTTPS proxy. The core is replaceable, which is why it ships as its own
package. Installs to `/opt/shunt` with `shunt-*` systemd units. Rule sets come
from [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat).

```
./packaging/build.sh          # build the packages; needs only dpkg-dev
python3 -m pytest tests/ -q   # 150 tests, redirected to a temp directory
```

Formerly `xray-gateway`, renamed at 2.0.0 because that name promoted one
replaceable component into the name of the whole product.
