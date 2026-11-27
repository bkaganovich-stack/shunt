# Remote access to the gateway's own sshd (design, awaiting approval)

Status: **proposal**. Nothing here is implemented yet.

## Why

On 2026-11-27 the owner was away, the house lost direct access, and nobody
could reach the gateway. The Mac was on a foreign network; the WAN is behind
CGNAT, so nothing reaches the gateway from outside; and the one address the
cascade can see, AmneziaWG's `10.8.0.10`, lives inside the `amnezia`
namespace, which answers ping and has no open ports. That last part is
correct and stays that way: the namespaces are fail-closed and must not start
serving the host.

What *was* reachable from anywhere is the owner's own cascade, the Riga entry
(`cascade-lv` in the owner's ssh config) and the Miami exit (`cascade-us`).
They are the natural rendezvous point.

## Shape: one outbound ssh with a reverse forward, from the host

```
 gateway (host namespace)                      rendezvous server (e.g. cascade-lv)
 ┌──────────────────────────────┐              ┌───────────────────────────────┐
 │ shunt-remote-access.service  │  outbound    │ sshd, user shunt-gw           │
 │  ssh -N -R 127.0.0.1:2222:   │ ──────────►  │  listens 127.0.0.1:2222 only  │
 │         127.0.0.1:22         │  (one TCP)   │                               │
 │ sshd :22 ◄── reverse channel │ ◄─────────── │ owner: ssh -J cascade-lv      │
 └──────────────────────────────┘              │        -p 2222 127.0.0.1      │
                                               └───────────────────────────────┘
```

- A new unit, `shunt-remote-access.service`, runs `remote_access.py`, which
  keeps one `ssh -N -R 127.0.0.1:<rport>:127.0.0.1:22` session open to a
  server the owner configures (host, port, user, the server's host key).
- The forwarded port is bound to the **server's loopback only**. The owner
  reaches it with `ProxyJump` through their own account on that server:

  ```
  Host shunt-remote
      HostName 127.0.0.1
      Port 2222
      ProxyJump cascade-lv
      HostKeyAlias shunt-gateway
      User <the owner's account on the gateway>
  ```

- The owner still authenticates to the gateway's sshd with their own key.
  The tunnel adds a road, not a login.

Rejected alternative: a dedicated WireGuard peer in the host namespace. It
would need the cascade server's WireGuard to route a second peer, a second
UDP flow that DPI sees, and it puts a routed interface on the host, which is
exactly what the namespaces exist to avoid. ssh is one TCP flow, and both
ends already have it.

## Which road the ssh takes

The gateway's own TCP is intercepted by xray (`XRAY_OUTPUT`) and follows the
house's profile, so "just run ssh" would ride whatever the profile picks. The
runner chooses the road itself, as a ladder, so it works when direct does not
and when the house's tunnel does not:

1. each **enabled egress in the house's order** (`amnezia`, `trusttunnel`,
   `adguard`, ...), through that egress's SOCKS port with a small Python
   `ProxyCommand` (SOCKS5 CONNECT, no `nc` dependency);
2. **the house's own path** last: no proxy, xray decides, which ends in
   direct when no egress answers.

A setting can pin one road instead (`via: "amnezia"`, `via: "house"`).
The first road that gives a working forward is kept until it breaks; then the
ladder starts again from the top.

**Fail-closed is untouched.** Through an egress the ssh is an ordinary SOCKS
client: one outbound TCP flow from the host to the server, the same as any
probe. Nothing listens in a namespace, no namespace rule changes, and
`egress-netns.sh` and `iptables.sh` are not modified. If the egress's tunnel
is down the connect fails, as it should, and the next rung is tried.

## The health check is end to end

"ssh is running" says nothing about whether the owner can get in. Every 60 s
the runner opens a second channel over the same connection
(`ssh -S <control socket> -W 127.0.0.1:<rport>`): server loopback → back
down the reverse forward → the gateway's own sshd. It passes only when the
gateway's own `SSH-2.0-` banner comes back. Two misses in a row kill the
session and go back to the ladder.

That is why the server-side key carries `permitopen` as well as
`permitlisten`: the probe needs to open exactly that one loopback port, and
nothing else.

## Status line

Written to `/run/shunt-remote-access/status.json`, shown on the page:

| state | text on the page |
|---|---|
| off | Удалённый доступ выключен |
| no config | Не настроен: нужен сервер и ключ сервера |
| connecting | Подключаюсь к <host> через <road>… |
| up | Работает через <road>, проверено <N> с назад |
| failing | Не работает: <reason>, следующая попытка через <N> с |

`<reason>` is specific: host key mismatch, key refused, server unreachable
on every road, port already taken on the server, probe got no banner. The
"up" line is written only by a passed probe, never by a started process.

## Off by default, and what "off" means

- `settings.json`: `remote_access: {enabled: false, host: "", port: 22,
  user: "shunt-gw", remote_port: 2222, via: "auto"}`. The unit is
  installed **disabled** and `ConditionPathExists=` on the key, so even an
  enabled unit with no key does nothing.
- The switch is on a card under **Система** (or wherever the owner prefers).
  On: `systemctl enable --now`; off: `disable --now`. It survives reboots.
  There is deliberately no auto-expiry: the case it exists for is "the owner
  is away and cannot turn it on", so it must be switched on *before* leaving
  and stay on.
- Failure of this unit cannot touch the house: it does not route, does not
  touch iptables or namespaces, and the health monitor ignores it.

## Keys and pinning

- A system account `shunt-ra` (no shell, home `/var/lib/shunt-ra`) runs
  the ssh. Its ed25519 key is generated **on the gateway**, by the page's
  "Создать ключ" button; the private half never leaves the box and never
  goes back to the page. The page shows the public half as a ready
  `authorized_keys` line.
- The server's host key must be pasted on the page (one `known_hosts`
  line, e.g. from `ssh-keyscan` run on the Mac). The ssh runs with
  `StrictHostKeyChecking=yes` and its own `UserKnownHostsFile`; there is
  no trust-on-first-use. A mismatch is a status line, not a reconnect loop.
- The ssh runs with `-F` pointing at a generated config (the system
  `/etc/ssh/ssh_config` is not read), `BatchMode=yes`,
  `IdentitiesOnly=yes`, `ExitOnForwardFailure=yes`,
  `ServerAliveInterval=15`, `ServerAliveCountMax=3`,
  `ConnectTimeout=20`, `PermitLocalCommand=no`, no agent or X11.
- Backoff between failed attempts: 10 s doubling to 10 min, so a dead
  server is not hammered (and fail2ban on the cascade is not provoked).
- Unit hardening: `User=shunt-ra`, `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `MemoryMax=64M`.

No server address, key or token goes into the repository; they live only in
`settings.json` and `/var/lib/shunt-ra/` on the gateway.

## Server side (done once by the owner, documented, not automated)

On the rendezvous server:

```
sudo adduser --disabled-password --gecos "" shunt-gw
# ~shunt-gw/.ssh/authorized_keys, one line:
restrict,port-forwarding,permitlisten="127.0.0.1:2222",permitopen="127.0.0.1:2222",command="/bin/false" ssh-ed25519 AAAA... shunt-ra@gateway
```

and in `sshd_config`, as belt and braces:

```
Match User shunt-gw
    AllowTcpForwarding yes
    GatewayPorts no
    PermitListen 127.0.0.1:2222
    PermitOpen 127.0.0.1:2222
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
    ForceCommand /bin/false
```

(`permitlisten` governs `-R`; `permitopen` alone would not restrict it.
Both need OpenSSH ≥ 7.8.) With `GatewayPorts no`, the port is on the
server's loopback whatever the client asks for.

## Threat notes

- If the rendezvous server is compromised, an attacker reaches the gateway's
  sshd banner, and still needs a key the gateway accepts. Same as being on
  the LAN. The gateway's sshd should stay key-only.
- If the `shunt-ra` key leaks, it can only hold port 2222 on the server's
  loopback and open that same port: no shell, no other forwards.
- An sshd rule that trusts `127.0.0.1` (e.g. a `Match Address 127.0.0.1`
  with weaker auth) would be widened by this. The page will warn if
  `sshd -T` shows password auth enabled.
- It does not help when the gateway itself has no internet at all. It helps
  when any one road (any egress, or direct) still leaves the house.

## What gets built

- `src/scripts/remote_access.py`: the runner (ladder, ssh, probe, backoff,
  status file), with the pure parts (argument building, ladder order, status
  text, settings validation) testable without ssh.
- `src/scripts/socks_connect.py`: the SOCKS5 `ProxyCommand`.
- `systemd/shunt-remote-access.service`, shipped disabled.
- `src/web`: `GET/POST /api/remote-access`, key generation, host-key
  upload, the card and its status line.
- `packaging`: the `shunt-ra` account in `postinst`, `openssh-client` in
  `Depends`, the files in `build.sh` / `verify_package.py`.
- `tests/test_remote_access.py`, a `debian-changelog` entry, and this file
  rewritten from "proposal" to "how it works".
