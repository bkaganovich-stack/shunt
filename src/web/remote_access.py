"""
Remote access to the gateway's own sshd from outside the house (docs/REMOTE_ACCESS.md).

The gateway is behind CGNAT and its egresses live in fail-closed namespaces,
so nothing can reach it from outside. What can be reached from anywhere is a
server the owner keeps (the cascade's Riga entry, say). The runner,
scripts/remote_access_runner.py, keeps one outbound ssh to that server open
with a reverse forward bound to the server's loopback, and proves it works by
reading the gateway's own sshd banner back through it.

This module is the part both the web application and the runner need, and it
is pure: settings, validation, the generated ssh_config, the order of roads,
the reading of ssh's errors and the status line. Nothing here starts a
process or touches the network.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

# The account the ssh runs as, and where its key and the server's pinned host
# key live. Root-owned config is not readable by it, which is the point.
ACCOUNT = "shunt-ra"
HOME = Path("/var/lib/shunt-ra")
KEY = HOME / "id_ed25519"
KNOWN_HOSTS = HOME / "known_hosts"
RUN_DIR = Path("/run/shunt-remote-access")
STATUS = RUN_DIR / "status.json"
# The ssh's own directory: owned by the account, since ssh creates its
# control socket there. The config is regenerated for every road.
SSH_DIR = RUN_DIR / "ssh"
SSH_CONFIG = SSH_DIR / "ssh_config"
CONTROL = SSH_DIR / "ctl"
UNIT = "shunt-remote-access.service"
SOCKS_HELPER = Path("/opt/shunt/scripts/socks_connect.py")

# Every host key line is stored under this name and ssh_config asks for it with
# HostKeyAlias, so a key pasted from `ssh-keyscan riga.example` still matches
# when the ssh goes through a SOCKS port, or the server's name changes.
HOST_ALIAS = "shunt-rendezvous"

# The house's own path: no proxy, xray decides (and ends in direct when no
# egress answers). Always the last road in the automatic order.
HOUSE = "house"
AUTO = "auto"

DEFAULTS = {
    "enabled": False,
    "host": "",
    "port": 22,
    "user": "shunt-gw",
    "remote_port": 2222,
    "via": AUTO,
}

PROBE_INTERVAL = 60      # s between end-to-end checks while up
PROBE_MISSES = 2         # consecutive failed checks that end a session
BACKOFF_MIN = 10
BACKOFF_MAX = 600

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                      r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_VIA_RE = re.compile(r"^[A-Za-z0-9-]{1,40}$")
_KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
              "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa",
              "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,3}$")


def config(settings: dict) -> dict:
    """The remote_access section with every field present."""
    out = dict(DEFAULTS)
    raw = settings.get("remote_access")
    if isinstance(raw, dict):
        out.update({k: raw[k] for k in DEFAULTS if k in raw})
    return out


_HOST_CHARS_RE = re.compile(r"^[A-Za-z0-9.:-]+$")


def _valid_host(host: str) -> bool:
    # Characters first: ipaddress accepts an IPv6 scope suffix ("fe80::1%x")
    # with anything after the '%', newlines included, and that would reach
    # ssh_config as a directive of its own. No scope, no whitespace, no '%'.
    if not _HOST_CHARS_RE.match(host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOST_RE.match(host))


def validate(data: dict) -> tuple[dict, list[str]]:
    """Clean what the page sent. Returns (clean fields, errors).

    Every value ends up in a generated ssh_config, one option per line, so a
    value that could carry a newline, a space or a '%' token never gets in.
    """
    clean: dict = {}
    errors: list[str] = []
    if "host" in data:
        host = str(data.get("host") or "").strip()
        if host and not _valid_host(host):
            errors.append("Адрес сервера: имя или IP-адрес, без порта и пробелов")
        else:
            clean["host"] = host
    for key, lo, hi, text in (("port", 1, 65535, "Порт SSH сервера"),
                              ("remote_port", 1024, 65535, "Порт на сервере")):
        if key not in data:
            continue
        try:
            v = int(data[key])
        except (TypeError, ValueError):
            v = -1
        if lo <= v <= hi:
            clean[key] = v
        else:
            errors.append(f"{text}: число от {lo} до {hi}")
    if "user" in data:
        user = str(data.get("user") or "").strip()
        if _USER_RE.match(user):
            clean["user"] = user
        else:
            errors.append("Пользователь на сервере: латиница в нижнем регистре, цифры, _ и -")
    if "via" in data:
        via = str(data.get("via") or AUTO).strip()
        if _VIA_RE.match(via):
            clean["via"] = via
        else:
            errors.append("Неизвестный путь")
    if "enabled" in data:
        clean["enabled"] = bool(data["enabled"])
    return clean, errors


def missing(cfg: dict, has_key: bool, has_host_key: bool) -> list[str]:
    """What still has to be set before the switch can be turned on."""
    out = []
    if not cfg.get("host"):
        out.append("адрес сервера")
    if not has_key:
        out.append("ключ шлюза")
    if not has_host_key:
        out.append("ключ сервера")
    return out


def normalize_host_key(text: str) -> str | None:
    """One known_hosts line for the server, filed under HOST_ALIAS, or None.

    Accepts what `ssh-keyscan` prints ("host type base64"), a known_hosts line
    with markers or a hashed name, or a bare "type base64". Comments and other
    lines are ignored; the first usable key wins. The name the owner had is
    dropped on purpose: HostKeyAlias makes it irrelevant.
    """
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        for i, p in enumerate(parts):
            if p in _KEY_TYPES and i + 1 < len(parts) and _B64_RE.match(parts[i + 1]) \
                    and len(parts[i + 1]) >= 60:
                return f"{HOST_ALIAS} {p} {parts[i + 1]}"
    return None


def authorized_keys_line(public_key: str, remote_port: int) -> str:
    """The line the owner puts in ~shunt-gw/.ssh/authorized_keys on the server.

    restrict turns everything off; port-forwarding turns forwarding back on,
    and the two permit* options narrow it to exactly one loopback port:
    permitlisten for the -R (the forward itself), permitopen for the -W the
    health check uses to come back down it. command= makes sure that even a
    session request runs nothing.
    """
    p = int(remote_port)
    return (f'restrict,port-forwarding,permitlisten="127.0.0.1:{p}",'
            f'permitopen="127.0.0.1:{p}",command="/bin/false" {public_key.strip()}')


def ssh_config(cfg: dict, proxy: tuple[str, int] | None,
               key: Path = KEY, known_hosts: Path = KNOWN_HOSTS,
               control: Path = CONTROL, helper: Path = SOCKS_HELPER) -> str:
    """The whole ssh_config for one road. Passed with -F, so neither
    /etc/ssh/ssh_config nor anything in the account's home is read."""
    lines = [
        f"Host {HOST_ALIAS}",
        f"    HostName {cfg['host']}",
        f"    Port {int(cfg['port'])}",
        f"    User {cfg['user']}",
        f"    HostKeyAlias {HOST_ALIAS}",
        f"    IdentityFile {key}",
        "    IdentitiesOnly yes",
        "    IdentityAgent none",
        f"    UserKnownHostsFile {known_hosts}",
        "    GlobalKnownHostsFile /dev/null",
        "    StrictHostKeyChecking yes",
        "    UpdateHostKeys no",
        "    CheckHostIP no",
        "    BatchMode yes",
        "    PasswordAuthentication no",
        "    KbdInteractiveAuthentication no",
        "    PreferredAuthentications publickey",
        "    ExitOnForwardFailure yes",
        "    ServerAliveInterval 15",
        "    ServerAliveCountMax 3",
        "    ConnectTimeout 20",
        "    ForwardAgent no",
        "    ForwardX11 no",
        "    PermitLocalCommand no",
        "    RequestTTY no",
        f"    ControlPath {control}",
        "    LogLevel ERROR",
    ]
    if proxy:
        host, port = proxy
        lines.append(f"    ProxyCommand /usr/bin/python3 -I {helper} {host} {int(port)} %h %p")
    return "\n".join(lines) + "\n"


def master_argv(cfg: dict, config_path: Path = SSH_CONFIG) -> list[str]:
    """The long-lived session: no command, one reverse forward, a control
    socket for the health check to ride."""
    rp = int(cfg["remote_port"])
    return ["ssh", "-F", str(config_path), "-N", "-T", "-M",
            "-R", f"127.0.0.1:{rp}:127.0.0.1:22", HOST_ALIAS]


def probe_argv(cfg: dict, config_path: Path = SSH_CONFIG) -> list[str]:
    """A stdio channel to the server's end of the forward, over the open
    session. What comes out is whatever answers on the gateway's port 22."""
    rp = int(cfg["remote_port"])
    return ["ssh", "-F", str(config_path), "-o", "ControlMaster=no",
            "-W", f"127.0.0.1:{rp}", HOST_ALIAS]


def roads(cfg: dict, egress_candidates: list[str],
          socks_of) -> list[tuple[str, tuple[str, int] | None]]:
    """The roads to try, in order: (name, SOCKS address or None for the house).

    Automatic: every enabled egress in the house's order, then the house's own
    path. A pinned road is that road alone; an egress that is pinned but not
    enabled leaves nothing to try, which the status line says.
    """
    via = cfg.get("via") or AUTO
    if via == HOUSE:
        return [(HOUSE, None)]
    if via != AUTO:
        return [(via, socks_of(via))] if via in egress_candidates else []
    return [(e, socks_of(e)) for e in egress_candidates] + [(HOUSE, None)]


# What ssh says, and what that means for the owner. Checked in order; the
# first match wins. "fatal" reasons are the same on every road, so the ladder
# stops at them instead of walking the rest.
_REASONS = [
    ("hostkey", False, ("host key verification failed",
                        "remote host identification has changed",
                        "no ed25519 host key is known", "host key is known for",
                        "no matching host key")),
    ("auth", True, ("permission denied",)),
    ("forward", True, ("remote port forwarding failed", "forwarding failed for listen port",
                       "cannot listen to port", "administratively prohibited")),
    ("socks", False, ("socks:",)),
    ("unreachable", False, ("connection refused", "timed out", "no route to host",
                            "network is unreachable", "could not resolve",
                            "name or service not known", "connection closed",
                            "connection reset", "kex_exchange_identification",
                            "broken pipe")),
]

REASON_TEXT = {
    "hostkey": "ключ сервера не совпадает с сохранённым",
    "auth": "сервер не принял ключ шлюза",
    "forward": "сервер не дал открыть порт (занят или запрещён)",
    "socks": "выход не пропустил соединение",
    "unreachable": "сервер недоступен",
    "probe": "сквозная проверка не получила ответ sshd шлюза",
    "no_roads": "нет ни одного пути: выбранный выход выключен",
    "no_config": "не настроен",
    "unknown": "ssh завершился",
}


def classify(stderr: str) -> tuple[str, bool]:
    """(reason, fatal) for what ssh printed when it gave up."""
    low = (stderr or "").lower()
    for reason, fatal, needles in _REASONS:
        if any(n in low for n in needles):
            return reason, fatal
    return "unknown", False


def is_fatal(reason: str) -> bool:
    """A reason that would be the same on every road (the key is refused, the
    port is taken): walking the rest of the ladder would only repeat it."""
    return any(r == reason and fatal for r, fatal, _ in _REASONS)


def road_label(name: str, labels: dict | None = None) -> str:
    if name == HOUSE:
        return "путь дома"
    return (labels or {}).get(name, name)


def status_text(st: dict, now: float, labels: dict | None = None) -> str:
    """The one line the page shows. "Работает" only ever comes from a passed
    end-to-end check, never from a process that merely runs."""
    state = st.get("state")
    road = road_label(st.get("road") or "", labels)
    if state == "off":
        return "Удалённый доступ выключен"
    if state == "no_config":
        return "Не настроен: " + ", ".join(st.get("missing") or ["адрес сервера"])
    if state == "connecting":
        return f"Подключаюсь к серверу через {road}…"
    if state == "up":
        ago = max(0, int(now - float(st.get("checked_at") or now)))
        return f"Работает через {road}, проверено {ago} с назад"
    if state == "failing":
        reason = REASON_TEXT.get(st.get("reason") or "unknown", REASON_TEXT["unknown"])
        wait = max(0, int(float(st.get("retry_at") or now) - now))
        tail = f", следующая попытка через {wait} с" if wait else ""
        return f"Не работает: {reason}{tail}"
    return "Состояние неизвестно"


def next_backoff(current: int) -> int:
    return min(BACKOFF_MAX, max(BACKOFF_MIN, current * 2))


def password_auth_on(sshd_t: str) -> bool:
    """Whether `sshd -T` shows password or keyboard-interactive login on.

    The forward arrives at the gateway's sshd from 127.0.0.1. A password a
    stranger could guess is fine on a LAN nobody else is on; it is not once a
    server on the internet holds the other end."""
    for line in (sshd_t or "").splitlines():
        k, _, v = line.strip().partition(" ")
        if k in ("passwordauthentication", "kbdinteractiveauthentication") and v.strip() == "yes":
            return True
    return False
