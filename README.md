# xray-gateway

A transparent split-routing VPN gateway for a home network. Traffic is routed by
destination: domestic sites go out directly, foreign ones through a tunnel. No
client software is needed on the devices behind it — phones, TVs and consoles
included.

It combines xray-core in TPROXY mode, sing-box, dnsmasq and a DNS-over-HTTPS
proxy, and is managed through a web interface on port 80, in Russian or English.

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

`xray-gateway-setup` works out which layout applies and records it in
`/opt/xray-proxy/config/network.conf`.

## Installing

```
sudo apt install ./xray-gateway_1.7.1_all.deb ./xray-gateway-core_*.deb
```

The Python dependencies come from the Ubuntu archive. `sing-box` is not in the
archive and is installed separately from upstream; the gateway starts without it
but the SOCKS proxy features stay unavailable.

On first install the management interface starts on port 80. The routing
services are enabled but **deliberately not started** — they rewrite firewall
and routing tables, which should not happen unattended during a package
install. Review the detected layout, then:

```
sudo systemctl start xray-proxy sing-box
```

On upgrade, only the services that were already running are restarted.

## Rule sets

`geoip.dat` and `geosite.dat` come from
[runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat).
They are about 92 MB and go stale, so they are downloaded after installation
rather than shipped in the package, and `xray-geoupdate.timer` refreshes them
weekly.

## Building

```
./packaging/build.sh                          # xray-gateway
./packaging/build.sh --with-core /path/to/xray  # and xray-gateway-core
```

Needs only `dpkg-dev`, so it builds on the gateway itself. Output goes to
`dist/`. The package version is read from `VERSION` in `src/web/main.py`, so
there is one place to bump.

## Layout on disk

| Path | Owned by | Contents |
|---|---|---|
| `/opt/xray-proxy/web`, `/scripts` | package | application and helper scripts |
| `/opt/xray-proxy/config` | administrator | settings, database, rule sets |
| `/opt/xray-proxy/bin/xray` | `xray-gateway-core` | the proxy core |
| `/lib/systemd/system` | package | units |
| `/usr/sbin/xray-gateway-setup` | package | network detection |

Removing the package stops the services and withdraws the firewall rules but
leaves `config/` alone. `apt purge` deletes it.
