# The two egress clients, and what the package does not install

Shunt's tunnel outbound is a SOCKS proxy on `127.0.0.1:1081`, and something has
to be listening there. On this gateway that something is **AdGuard VPN CLI**,
with **FPTN** as the backup on `192.168.244.2:1082`. Neither is part of the
Shunt packages, and neither ever will be: they are third-party binaries with
their own licences, their own update cadence and, in FPTN's case, a token that
belongs to one household.

What the package does now carry is everything around them — the units, the
account, the masks and the repair scripts — so that installing the two clients
is the only manual step left. This file is that step.

## Why this file exists at all

Until 2.10.0 the running gateway had ten files that belonged to no package.
`dpkg -V shunt` was clean the whole time, because nothing *packaged* had been
edited; the files simply were not in any package's manifest, so nothing looked
for them. A reinstall produced a gateway that looked identical and was not: no
segmentation offload on the WAN port, no watchdog to withdraw it, no repair for
the resolv.conf FPTN leaves behind, and both conflicting distribution units
unmasked and ready to fight for the radio and the tunnel.

Seven of those ten are now in the package. The remaining three are the two
third-party binaries and the AdGuard unit that names one of them, and they are
here.

## AdGuard VPN CLI

The primary egress. Runs as its own unprivileged account, connects on boot and
serves SOCKS on 127.0.0.1:1081; `shunt-agwatch.timer` restarts it when the
egress ladder measures it as down.

Version on the gateway as of 2026-09-12:

    adguardvpn-cli 1.7.12   sha256 69abfcc6ca2e0c80236f59d06ca565ab59edfca912ceba3eab401c93a890f683

A single statically linked binary at `/usr/local/bin/adguardvpn-cli` — the one
place a package must not write, which is correct here: this is the
administrator's software, not Shunt's. Install it from AdGuard's own
distribution, then:

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
ExecStart=/usr/local/bin/adguardvpn-cli connect --location "United States" --no-fork --boot -y
ExecStop=/usr/local/bin/adguardvpn-cli disconnect
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

`--location` has to match `adguard.location` in `settings.json`; the interface
writes the setting and this unit is what acts on it. The copy on the live
gateway still says `After=xray-proxy.service`, a unit that has not existed
since the rename in September — harmless, because systemd ignores ordering
against units it does not have, and corrected above.

## FPTN

The backup egress, run inside a network namespace by
`shunt-fptn-egress.service`. Version on the gateway:

    fptn-client-cli 0.4.4   sha256 97e3be8ce245ca0a64511747c30bce6c09b95d199269de96398505cdb7004057

Installed from a `.deb` that carries four files: `/usr/bin/fptn-client-cli`,
`/etc/fptn-client/client.conf`, its systemd unit, and the directory. The token
is **not** in `client.conf` — `ACCESS_TOKEN` there is empty and the real one
lives in `/etc/fptn-client/token`, mode 600.

Two things the package does on FPTN's behalf:

- **`fptn-client.service` is masked.** The distribution unit puts the tunnel on
  the host, where it rewrites the gateway's own `/etc/resolv.conf`. Shunt runs
  the client inside a namespace instead, so the host's resolver is untouched
  and the SOCKS port is reachable at `192.168.244.2:1082` over a veth pair.
- **`fptn-resolv-heal.service` runs before the network comes up.** When a
  session is cut rather than stopped, the backup at
  `/etc/resolv.conf.fptn-backup` is left behind and the live file is the
  tunnel's. The unit restores it at boot, before anything tries to resolve a
  name — which is the difference between a gateway that comes back and one that
  cannot look up its own upstream.

## Where these came from

Not recorded, and that is the remaining gap. Neither artefact has a download
URL written down anywhere on the gateway: no apt source for the FPTN package,
no installer trace for AdGuard, nothing in the shell history. The hashes above
are what is actually running, so a rebuild can at least verify that it got the
same bytes — but the place to get them from is currently someone's memory.
Write the source down here the next time either one is updated.
