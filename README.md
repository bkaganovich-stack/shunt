# Shunt

A transparent split-routing gateway for a home network. Traffic is routed by
destination: domestic sites go out directly, foreign ones through a tunnel.
Nothing has to be installed on the devices behind it, so televisions, consoles
and guest hardware are covered along with the phones and laptops.

Shunt is a box on the wire, not an application: it sits either between the ISP
and the router or inside the router's LAN. It combines xray-core in TPROXY mode,
sing-box, dnsmasq and a DNS-over-HTTPS proxy under one web interface on port 80,
in Russian or English.

The name is the electrical and railway sense of the word: a shunt diverts part
of a flow onto another path. The tunnel is one such path, and which traffic
takes it is the whole point of the product.

## Interface language

Russian is what the markup contains and is the default; English is a dictionary
applied to the DOM at runtime, loaded from `static/locales/en.json` the first
time it is needed. The switcher sits at the bottom of the sidebar and on the
login screen, and the choice is remembered per browser. A phrase with no entry
stays Russian rather than going blank, so a gap in the dictionary degrades
gracefully. To revise a translation, edit `locales/en.json` -- no rebuild of the
page is involved. `tools/i18n_extract.py` regenerates the list of translatable
strings after the interface changes.

## Layouts

**inline** — the gateway sits between the ISP and the router. `WAN_IF` faces the
ISP and is where the gateway MASQUERADEs; `LAN_IF` faces the router.

**loop** — a single network port; the gateway sits inside the router's LAN and
the router performs the final NAT.

`shunt-setup` works out which layout applies and records it in
`/opt/shunt/config/network.conf`.

## Installing

```
shasum -a 256 -c SHA256SUMS
sudo apt install ./shunt_2.0.0_all.deb ./shunt-xray_*.deb
```

Installing the two `.deb` files directly is the supported route. `apt` resolves
their dependencies from the Ubuntu archive the same way it would from a
repository. `packaging/mkrepo.sh` can turn the same files into a signed APT
repository later, if the packages ever need to reach more than one machine.

The Python dependencies come from the Ubuntu archive. `sing-box` is not in the
archive and is installed separately from upstream; the gateway starts without it
but the SOCKS proxy features stay unavailable.

On first install the management interface starts on port 80. The routing
services are enabled but **deliberately not started** — they rewrite firewall
and routing tables, which should not happen unattended during a package
install. Review the detected layout, then:

```
sudo systemctl start shunt sing-box
```

On upgrade, only the services that were already running are restarted.

## Rule sets

`geoip.dat` and `geosite.dat` come from
[runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat).
They are about 92 MB and go stale, so they are downloaded after installation
rather than shipped in the package, and `shunt-geoupdate.timer` refreshes them
weekly.

## Tests

```
python3 -m pytest tests/ -q
```

They redirect every path in the module to a temporary directory, so they can be
run on any machine without touching a real installation.

## Building

```
./packaging/build.sh                          # shunt
./packaging/build.sh --with-core /path/to/xray  # and shunt-xray
```

Needs only `dpkg-dev`, so it builds on the gateway itself. Output goes to
`dist/`. The package version is read from `VERSION` in `src/web/main.py`, so
there is one place to bump.

## Layout on disk

| Path | Owned by | Contents |
|---|---|---|
| `/opt/shunt/web`, `/scripts` | package | application and helper scripts |
| `/opt/shunt/config` | administrator | settings, database, rule sets |
| `/opt/shunt/bin/xray` | `shunt-xray` | the proxy core |
| `/lib/systemd/system` | package | units |
| `/usr/sbin/shunt-setup` | package | network detection |

Removing the package stops the services and withdraws the firewall rules but
leaves `config/` alone. `apt purge` deletes it.
