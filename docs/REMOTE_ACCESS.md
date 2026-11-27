# Remote access to the gateway's own sshd

Since 2.33.0. Off unless switched on under **Система → Настройки →
Удалённый доступ к шлюзу**. Design approved by the owner on 2026-11-27.

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

- `shunt-remote-access.service` runs `scripts/remote_access_runner.py`,
  which keeps one `ssh -N -R 127.0.0.1:<rport>:127.0.0.1:22` session open to a
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
the runner opens a second channel over the same connection's control socket
(`ssh -o ControlMaster=no -W 127.0.0.1:<rport>`): server loopback → back
down the reverse forward → the gateway's own sshd. It passes only when the
banner that comes back is byte for byte the one the gateway's sshd gives on
`127.0.0.1:22`, so another sshd answering on that port does not count. The
probe is not run until the control socket exists, so it can never open a
second connection of its own. A new session has 45 s to pass its first
check; two misses in a row later kill the session and go back to the ladder.

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
  installed **disabled** and has `ConditionPathExists=` on the key, so even an
  enabled unit with no key does nothing. The page refuses to switch it on
  until the server, the gateway's key and the server's host key are all set.
- The switch is on a card under **Система → Настройки**. On: `systemctl
  enable` and a restart; off: `disable --now`. It survives reboots. Saving
  the same values again does not restart it, so a session in use is not cut.
- The package never enables it and never restarts it. An upgrade may be run
  through this very ssh, and restarting the unit would cut it mid-dpkg (the
  same trap as the web terminal). Instead the runner notices that its code
  changed on disk and re-executes itself between sessions.
  There is deliberately no auto-expiry: the case it exists for is "the owner
  is away and cannot turn it on", so it must be switched on *before* leaving
  and stay on.
- Failure of this unit cannot touch the house: it does not route, does not
  touch iptables or namespaces, and the health monitor ignores it.

## Keys and pinning

- The supervisor runs as root, because it reads `settings.json` and the
  egress configuration, both root-only. Every ssh it starts runs as the
  system account `shunt-ra` (no shell, home `/var/lib/shunt-ra`, 0700),
  created by `postinst`. Its ed25519 key is generated **on the gateway**, by the page's
  "Создать ключ" button; the private half never leaves the box and never
  goes back to the page. The page shows the public half as a ready
  `authorized_keys` line.
- The server's host key must be pasted on the page (one `known_hosts`
  line, e.g. from `ssh-keyscan` run on the Mac). It is stored under the
  name `shunt-rendezvous`, which ssh asks for with `HostKeyAlias`, so it
  matches whatever road the ssh takes. The ssh runs with
  `StrictHostKeyChecking=yes` and its own `UserKnownHostsFile`; there is
  no trust-on-first-use. A mismatch on one road moves to the next road (one
  intercepted road should not block an honest one) and ends as a status line.
  A refused key or a refused port stops the walk at once: every road would
  say the same.
- The ssh runs with `-F` pointing at a config generated for each road in
  `/run/shunt-remote-access/ssh/` (the system
  `/etc/ssh/ssh_config` is not read), `BatchMode=yes`,
  `IdentitiesOnly=yes`, `ExitOnForwardFailure=yes`,
  `ServerAliveInterval=15`, `ServerAliveCountMax=3`,
  `ConnectTimeout=20`, `PermitLocalCommand=no`, no agent or X11.
- Backoff between failed attempts: 10 s doubling to 10 min, so a dead
  server is not hammered (and fail2ban on the cascade is not provoked).
- Unit hardening: `NoNewPrivileges`, a capability set of only what
  dropping to `shunt-ra` needs, `ProtectSystem=strict` with only
  `/run/shunt-remote-access` writable, `ProtectHome`, `PrivateTmp`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `MemoryMax=64M`.
  No namespace option: the unit lives in the host namespace and never
  enters an egress's.

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
Both need OpenSSH ≥ 7.8.) To get the server's host key for the page, on the
Mac: `ssh-keyscan -t ed25519 <server>`, and compare its fingerprint with the
one `ssh cascade-lv` already trusts. With `GatewayPorts no`, the port is on the
server's loopback whatever the client asks for.

## Threat notes

- If the rendezvous server is compromised, an attacker reaches the gateway's
  sshd banner, and still needs a key the gateway accepts. Same as being on
  the LAN. The gateway's sshd should stay key-only.
- If the `shunt-ra` key leaks, it can only hold port 2222 on the server's
  loopback and open that same port: no shell, no other forwards.
- An sshd rule that trusts `127.0.0.1` (e.g. a `Match Address 127.0.0.1`
  with weaker auth) would be widened by this. The page warns when
  `sshd -T` shows password or keyboard-interactive login enabled.
- It does not help when the gateway itself has no internet at all. It helps
  when any one road (any egress, or direct) still leaves the house.

## Where it lives

- `src/web/remote_access.py`: the pure part both sides use (settings,
  validation, the generated ssh_config, the order of roads, reading ssh's
  errors, the status line).
- `src/scripts/remote_access_runner.py`: the supervisor (ladder, ssh,
  probe, backoff, status file, re-exec on upgrade).
- `src/scripts/socks_connect.py`: the SOCKS5 `ProxyCommand`, standard
  library only.
- `systemd/shunt-remote-access.service`, shipped disabled.
- `src/web/main.py`: `GET/POST /api/remote-access`,
  `POST /api/remote-access/key`, `POST /api/remote-access/host-key`; the
  card in `index.html`.
- `packaging`: the `shunt-ra` account and `/var/lib/shunt-ra` in
  `postinst`, the unit in `prerm` (stopped and disabled on removal),
  `openssh-client` in `Depends`.
- `tests/test_remote_access.py`.

## Not yet verified on the gateway

Everything above is tested with ssh and the network replaced. It has not run
on the gateway or against a real server: the first switch-on should be done
while at home, with the status line read and one login through
`ssh shunt-remote` made from outside (e.g. the phone's hotspot) before
relying on it.
