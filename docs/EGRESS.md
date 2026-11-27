# Egresses: what carries the tunnel, and what the package does not install

Shunt's tunnel is not one VPN. It is an ordered list of **egresses**, each of
which looks the same from the inside: a SOCKS address that leads out of the
country. xray's tunnel outbound, the probes, the watchdog and pinned profile
rules all reach whichever egress they need the same way. That uniformity is
deliberate: nothing downstream has to know which client is behind a port.

Until 2.25 there were exactly two egresses, hard-wired: AdGuard VPN first, FPTN
when AdGuard was dead. This file used to describe that pair. The list below is
what there is now.

## The egresses

| id | What it is | SOCKS address | Run by | Client comes from |
|---|---|---|---|---|
| `amnezia` | AmneziaWG 2.0 to the own cascade (Riga → Miami) | `192.168.244.6:1083` | `shunt-egress@amnezia.service` | `shunt-egress-bin` |
| `trusttunnel` | TrustTunnel to the same cascade | `192.168.244.10:1084` | `shunt-egress@trusttunnel.service` | `shunt-egress-bin` |
| `warp` | Cloudflare WARP on the cascade's Miami server | `192.168.244.6:1086` | rides `amnezia`, no unit of its own | the cascade server |
| `adguard` | AdGuard VPN CLI | `127.0.0.1:1081` | `adguardvpn.service` | installed by hand |
| `fptn` | FPTN | `192.168.244.2:1082` | `shunt-fptn-egress.service` | installed by hand |
| `key-<id>` | a Shadowsocks, VLESS, VMess or Trojan key | `127.0.0.1:11001` and up | xray itself | nothing to install |

On this gateway, as of 2026-11-18, the order is
`amnezia → trusttunnel → adguard → warp → fptn`. FPTN is switched off and no
keys are configured. AmneziaWG carries the house. The default for a new
install is still `adguard → amnezia → trusttunnel → fptn → warp`, because a
fresh box has no cascade configuration and AdGuard is the one egress that
needs nothing but an account.

### How the order is used

- The first enabled egress is the **primary** and carries the house whenever
  it answers.
- When the primary misses three checks in a row (about three minutes), the
  first live reserve in the order takes over. A short hiccup moves nothing,
  because a restart of AdGuard looks exactly like a short outage.
- A better reserve that recovers takes over from a worse one, and the primary
  takes the house back as soon as it answers again.
- When no egress answers, the house routes direct and gets its profile back
  once one does. Direct is the last rung, not an error state.
- A profile rule can name an egress: `sony.com → через AmneziaWG`. Such a rule
  rides that egress while it answers and falls back to the house's egress
  when it does not.

The order, a switch for every egress and the failover switch are on
**Выходы → Активный выход**. The egresses themselves are cards on
**Выходы → VPN серверы**: access (account, token or configuration, with
"restore previous"), the settings of that kind, and **Проверить**, which
measures one egress through its own port, so a reserve can be measured while
another carries the house. The last tunnel cannot be switched off.

### Fail closed

Every egress except AdGuard and the keys lives in a network namespace of its
own, and the host sees nothing of it but the SOCKS port on the namespace's veth
address. A VPN client wants the default route and the resolver, and on a
gateway those belong to the whole house. FPTN took both on 2026-09-04 and,
when its tunnel failed, quietly left on the provider's own address. Inside a
namespace that cannot happen: with the tunnel down, a request through the port
fails instead of leaving on the ISP address. This was measured for AmneziaWG
with `awg0` down and for TrustTunnel with Riga unreachable.

The namespaces share `192.168.244.0/28`, one `/30` each (`.0` FPTN, `.4`
AmneziaWG, `.8` TrustTunnel), and `iptables.sh` excepts that whole `/28` from
TPROXY. An exception narrower than that sends one egress's tunnel traffic into
another.

The bridge in each namespace runs as `nobody`, and `nobody` may not start a
connection over the veth at all: it may only answer what the host sent it.
The host's own veth addresses (`.1`, `.5`, `.9`) are inside the `/28`, and the
host accepts connections on every interface but the WAN, so a bridge allowed
to reach the `/28` hands the gateway's own services, sshd among them, to
anyone who can reach its SOCKS port (shown on 2026-11-27 from Riga). The one
exception is AmneziaWG's WARP port falling back to TrustTunnel's,
`192.168.244.10:1086` over TCP (2.33.1).

## The own cascade: AmneziaWG, TrustTunnel and WARP

A pair of servers rented by the household: the entry in Riga, the exit in
Miami. Neither server is configured by Shunt. Shunt only runs the clients and
takes the configurations the cascade server issues.

**Configurations.** They are uploaded on the egress's card on
**Выходы → VPN серверы**, pasted or from a file, and checked first: a config the client would refuse never
replaces a working one. They are stored root-only in
`/opt/shunt/config/egress/<name>/`, with the previous one kept beside it
(`awg.conf.prev`), and the content never comes back to the page, because it
holds a private key or a password. An egress with no configuration is shown
as such and its unit does not start. Hand-set parameters (AmneziaWG's MTU and
I1, TrustTunnel's protocol and anti-DPI) live in `settings.json` and are
applied over the file each time the egress starts, so a re-issued
configuration does not drop them.

**Startup.** `egress-netns.sh` waits up to 75 seconds for a default route and
refuses to start without one. On 2026-10-22, after a power cut, AmneziaWG came
up before the provider's DHCP answered, its first packets left un-NATed, and
conntrack kept that flow alive for nine hours. It then waits up to 60 seconds
for the clock to synchronise and starts anyway after that: the board's CMOS
battery is flat, and with a clock weeks behind TrustTunnel's certificate is
"not yet valid" and WireGuard's handshakes look like replays.

**WARP** exists because on 2026-10-20 Google began placing both the cascade's
Miami address and AdGuard's Atlanta one in Russia, and Gemini refused both,
while a Cloudflare address in Miami stayed American. It is a second port on
AmneziaWG's bridge that leads to a relay on the cascade link. When that road
stops answering, the bridge sends WARP traffic through TrustTunnel's instead,
which reaches the same relay. WARP carries TCP only, so QUIC is refused for
sites pinned to it (2.32.2). It is on only while AmneziaWG is.

**The health monitor** drops any cascade flow that left without NAT. When
AmneziaWG has had no handshake for three minutes while the house reaches the
internet, it drops AmneziaWG's flows, and if three more minutes change
nothing, it restarts the egress, at most once per fifteen minutes.

### shunt-egress-bin

The clients ship as their own package, like xray in `shunt-xray`: they are
per-architecture binaries with their own release cycles, repackaged unmodified
by `packaging/build-egress.sh`. Where each one comes from is in
`packaging/copyright.egress`:

- **amneziawg-go**: built from `amnezia-vpn/amneziawg-go`, tag v3.1.20260828.
- **awg**: built from `amnezia-vpn/amneziawg-tools`, tag v3.1.20260812.
  `awg-quick` is deliberately not used, because it rewrites the host's routes
  and resolver.
- **trusttunnel_client** and **setup_wizard**: the TrustTunnel client 1.1.11
  as released by AdGuard, signature verified against key
  `28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6`.

The package is not on the Releases page. Build it yourself from those
upstream releases: `./packaging/build-egress.sh <dir>`, where `<dir>` holds the
four binaries, already verified.

Installed on the gateway: `shunt-egress-bin 1.1.11+awg3.1.20260812`.

    amneziawg-go        sha256 61b9c86489c314feb43c8bbd919ef6eac29eddf8d2320de696dcfc941a7fe0a9
    awg                 sha256 d3dff54316939fbeda3b148a859e574572db2753d8841ea8c5ce3ce25243a4d4
    trusttunnel_client  sha256 e01411457f65c498063211fa670d55ea710d3a2d35534acd73438bd514df454a
    setup_wizard        sha256 ac781f036cda54d6efd1b133b66b9487e0da3f7d6ae36cd3de233cfe7b9d82c4

## Keys

A Shadowsocks, VLESS, VMess or Trojan key pasted on **Выходы → VPN серверы**
becomes an egress like any other, with a place in the order and a switch.
xray itself is the client, so there is nothing to install: each key gets a
SOCKS port on loopback, from 11001 up, that leads to that key alone. A new key
is added switched on and last in the order. The key never goes back to the
page. Deleting a key moves the profile rules pinned to it to the tunnel and
says so first, and the last way out cannot be deleted.

## AdGuard VPN CLI

Third in the order on this gateway. It runs as its own unprivileged account
and serves SOCKS on `127.0.0.1:1081`. `shunt-agwatch.timer` runs the egress
watchdog every minute. The watchdog's checks are AdGuard's: when AdGuard does
not carry a request, it restarts `adguardvpn.service`, at most three times,
and then stops until AdGuard works again (2.32.12). Before 2.32.12 a dead
AdGuard was restarted three times every half hour for as long as it stayed
dead. It does not touch AdGuard while the service is starting or stopping, or
for two minutes after it came up, and does not count that wait as an attempt
(2.32.13).

Version on the gateway as of 2026-11-18:

    adguardvpn-cli 1.8.3   sha256 8a4e58f6a7231723f5e1ff83b535400329af5e7b7ce653cf955b8ad844eb2f1f

A single statically linked binary at `/usr/local/bin/adguardvpn-cli`, the one
place a package must not write. That is correct here: this is the
administrator's software, not Shunt's. It comes from AdGuard's releases on
GitHub, [AdguardTeam/AdGuardVPNCLI](https://github.com/AdguardTeam/AdGuardVPNCLI/releases),
asset `adguardvpn-cli-<version>-linux-x86_64.tar.gz`. The archive carries the
binary and a detached signature, `adguardvpn-cli.sig`, by AdGuard's key
`28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6` (the fingerprint AdGuard's own
`install.sh` names). Updating by hand:

```
gpg --verify adguardvpn-cli.sig adguardvpn-cli
sudo cp -p /usr/local/bin/adguardvpn-cli /usr/local/bin/adguardvpn-cli.previous
sudo install -m 0755 adguardvpn-cli /usr/local/bin/adguardvpn-cli
sudo systemctl restart adguardvpn
```

The client also has its own `adguardvpn-cli update`. It has not been tried on
this gateway. A first install also needs the account and a login:

```
sudo adduser --system --group --home /var/lib/agvpn \
             --shell /usr/sbin/nologin agvpn
sudo -u agvpn HOME=/var/lib/agvpn /usr/local/bin/adguardvpn-cli login
```

The session lands in `/var/lib/agvpn/.local/share/adguardvpn-cli/`. It is the
account, not the machine: one session cannot be connected from two gateways at
once, which is why `packaging/shunt-clone.sh` masks every automatic caller on
the box it copies onto.

The unit, at `/etc/systemd/system/adguardvpn.service`:

```ini
[Unit]
Description=AdGuard VPN (SOCKS egress on 127.0.0.1:1081 for xray/sing-box proxy)
After=network-online.target shunt.service
Wants=network-online.target

[Service]
Type=simple
User=agvpn
Environment=HOME=/var/lib/agvpn
ExecStartPre=-/usr/local/bin/adguardvpn-cli disconnect
ExecStart=/usr/local/bin/adguardvpn-cli connect --location "Atlanta" --no-fork --boot -y
ExecStop=/usr/local/bin/adguardvpn-cli disconnect
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

The interface writes `--location` into this unit itself when the location is
changed on the page, and keeps `adguard.location` in `settings.json` in step.
The client's own traffic (uid `agvpn`) is excepted from interception
(`XRAY_OUTPUT`) and routed through `main` (`ip rule` priority 50), so it
reaches AdGuard's servers over the WAN and never through a tunnel.

Known on this gateway, none of it Shunt's to fix:

- The copy of the unit still says `After=xray-proxy.service`, a unit that has
  not existed since the rename in September. This is harmless: systemd
  ignores ordering against units it does not have.
- `ExecStop` always exits with status 14. With `--no-fork` there is no
  background client for `disconnect` to talk to, so the stop is really done by
  systemd's SIGTERM.
- 1.8.2 sometimes aborts (SIGABRT, core dumped) on that SIGTERM, after it has
  already shut down cleanly. It happened five times between 2026-11-16 and
  2026-11-18, every time during a restart by the watchdog. It costs nothing:
  the process was stopping anyway. Replaced by 1.8.3 on 2026-11-18; whether
  1.8.3 still does it is not yet known.
- While AdGuard's servers are slow, a start takes longer than the
  watchdog's minute: `location_request` times out after about twenty seconds
  and the client connects only after that. During the 1.8.3 update the
  watchdog took the unconnected client for a dead one and restarted it three
  times in a row, at 16:33:56, 16:34:57 and 16:35:57 UTC. The third start
  connected in two seconds; the house was on AmneziaWG throughout. Since
  2.32.13 the watchdog gives a fresh start two minutes.
- On 2026-11-17/18 AdGuard could not reach its own servers for five hours
  (`location_request failed: Timed out`, health check time-outs) and came back
  on its own. The house did not notice, because AmneziaWG carried it.

## FPTN

Switched off on this gateway. By October its server no longer answered from
Russia (see 2.32.7 in `debian-changelog`). It stays documented because the package still runs it when it is
switched on. When on, it runs inside a network namespace under
`shunt-fptn-egress.service`. Version on the gateway:

    fptn-client-cli 0.4.6   sha256 530aeae7702bc7df73fa2e6cd27a5f5113e4976be6ebc36dc22bf6a4c9c7c339

Installed from a `.deb` that carries four files: `/usr/bin/fptn-client-cli`,
`/etc/fptn-client/client.conf`, its systemd unit, and the directory. The token
is **not** in `client.conf`: `ACCESS_TOKEN` there is empty and the real one
lives in `/etc/fptn-client/token`, mode 600.

Three things the package does on FPTN's behalf:

- **`fptn-client.service` is masked.** The distribution unit puts the tunnel
  on the host, where it rewrites the gateway's own `/etc/resolv.conf`. Shunt
  runs the client inside a namespace instead, so the host's resolver is
  untouched and the SOCKS port is reachable at `192.168.244.2:1082` over a
  veth pair.
- **`shunt-fptn-egress.service` is enabled only when `fptn.enabled` is set in
  `settings.json`.** Until 2.32.7 every upgrade enabled it again, and for three
  weeks the client retried a dead server every ten minutes while the page
  showed FPTN as off.
- **`fptn-resolv-heal.service` runs before the network comes up.** When a
  session is cut rather than stopped, the backup at
  `/etc/resolv.conf.fptn-backup` is left behind and the live file is the
  tunnel's. The unit restores it at boot, before anything tries to resolve a
  name. That is the difference between a gateway that comes back and one that
  cannot look up its own upstream.

## What does not follow the order

**sing-box always uses AdGuard.** Its only tunnel outbound is a SOCKS outbound
to `127.0.0.1:1081`, and it is the final route. Two things go through it: the
SOCKS proxy that the **Proxy** page offers to single applications, and the
little traffic sing-box's `tun0` still takes (see `docs/DATAPATH.md`). Both
ignore the egress order and stop working while AdGuard is down, even when
another egress carries the house.

## Where the hand-installed clients came from

**AdGuard** is settled. The 1.8.2 binary that ran here until 2026-11-18 is
byte for byte the one in AdGuard's `v1.8.2` GitHub release, and its
signature verifies against AdGuard's key, so the source above is where it came
from, whatever installed it. 1.8.3 was taken from the same place.

**FPTN** is still the open part. The cascade clients have their sources in
`packaging/copyright.egress`; the FPTN package has no download URL written
down anywhere on the gateway: no apt source, nothing in the shell history. The
hash above is what is installed, so a rebuild can at least verify that it got
the same bytes. Write the source down here the next time it is updated.
