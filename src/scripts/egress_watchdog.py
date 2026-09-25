#!/usr/bin/env python3
"""
Restart the tunnel when the tunnel is what is broken — and only then.

The shell version this replaces restarted AdGuard every two minutes for hours
during the September outage, while the fault was two layers below it and no
restart could have helped. It had a cooldown but no memory: after each restart
it cleared its own failure counter, so it would do the same thing again forever.

It also logged a "direct path" reading that was never real. It pinged the
provider's gateway, which answers no ICMP at all -- so the line read 0% loss
while the tunnel's own tun device was answering for it, and reads 100% loss now
that ICMP goes out properly. A number that was fiction in both directions, put
in front of whoever had to read the log next.

So this asks the ladder first. If the break is above us -- no cable, no address,
no gateway, no internet -- there is nothing here to restart and saying so is the
whole job. If the tunnel really is the first thing unmet, restart it, but count
the attempts: the fourth one in half an hour is not a fix in progress, it is
proof the diagnosis is wrong, and it escalates instead.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

BASE = Path("/opt/shunt")
sys.path.insert(0, str(BASE / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import diagnose as dg  # noqa: E402

LOG = BASE / "logs" / "agwatch.log"
STATE = Path("/run/shunt-agwatch-state.json")
ATTENTION = BASE / "logs" / "attention.json"
NET_CONF = BASE / "config" / "network.conf"

REMEDY = "restart-adguard"
OWN_KINDS = ("egress", "uplink")
MAX_ATTEMPTS = 3
WINDOW_SEC = 1800

# A tunnel can answer every check and still be useless. On Sep 25 one AdGuard
# endpoint carried 0.1-0.6 Mbit/s for the whole house while the neighbouring
# one carried 12-19; the ladder called it healthy throughout and YouTube on the
# TV barely moved. So the healthy path also measures, cheaply: 2 MB every 15
# minutes (~190 MB a day), and one confirming sample a minute later against a
# different host before anything is said, so one slow CDN node is not blamed on
# the tunnel. The household shares the tunnel with the probe, but a working one
# still leaves it several Mbit/s.
SOCKS = "127.0.0.1:1081"
SPEED_EVERY = 900
SLOW_MBIT = 2.0
SLOW_CONFIRM = 2
SPEED_TARGETS = (
    ("https://speed.cloudflare.com/__down?bytes=2000000", None),
    ("https://proof.ovh.net/files/10Mb.dat", "0-1999999"),
)


def log(msg: str) -> None:
    line = "%s %s" % (time.strftime("%F %T"), msg)
    try:
        with LOG.open("a") as f:
            f.write(line + "\n")
    except OSError:
        pass
    print(line, flush=True)


def load_state() -> dict:
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def save_state(s: dict) -> None:
    try:
        STATE.write_text(json.dumps(s))
    except OSError:
        pass


def attention(kind: str, text: str, detail: str = "") -> None:
    """Same file the health monitor writes, so one concern has one home."""
    try:
        items = json.loads(ATTENTION.read_text()) if ATTENTION.exists() else []
    except (OSError, ValueError):
        items = []
    if not isinstance(items, list):
        items = []
    now = int(time.time())
    for it in items:
        if isinstance(it, dict) and it.get("kind") == kind and not it.get("cleared"):
            it.update(last_seen=now, count=it.get("count", 1) + 1,
                      text=text, detail=detail)
            break
    else:
        items.append({"kind": kind, "text": text, "detail": detail,
                      "first_seen": now, "last_seen": now, "count": 1,
                      "cleared": False})
    try:
        ATTENTION.write_text(json.dumps(items[-20:], ensure_ascii=False))
    except OSError:
        pass


def clear_attention(kind: str) -> None:
    try:
        items = json.loads(ATTENTION.read_text()) if ATTENTION.exists() else []
    except (OSError, ValueError):
        return
    changed = False
    for it in items:
        if isinstance(it, dict) and it.get("kind") == kind and not it.get("cleared"):
            it["cleared"] = True
            it["cleared_at"] = int(time.time())
            changed = True
    if changed:
        try:
            ATTENTION.write_text(json.dumps(items, ensure_ascii=False))
        except OSError:
            pass


def wan_iface() -> str:
    try:
        for ln in NET_CONF.read_text().splitlines():
            if ln.startswith("WAN_IF="):
                return ln.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


def measure_mbit(n: int) -> float:
    """Download ~2 MB through the tunnel; 0.0 when nothing arrived."""
    url, rng = SPEED_TARGETS[n % len(SPEED_TARGETS)]
    cmd = ["curl", "-s", "-o", "/dev/null", "-m", "12",
           "-w", "%{size_download} %{time_total}", "--socks5-hostname", SOCKS]
    if rng:
        cmd += ["-r", rng]
    try:
        r = subprocess.run(cmd + [url], capture_output=True, text=True, timeout=20)
        size, secs = r.stdout.split()
        size, secs = float(size), float(secs)
    except Exception:
        return 0.0
    return size * 8 / secs / 1e6 if secs > 0 else 0.0


def adguard_endpoint() -> str:
    """The server address the client last picked -- what a person would change."""
    try:
        r = subprocess.run(["journalctl", "-u", "adguardvpn", "-n", "400", "--no-pager",
                            "-o", "cat", "-g", "Using endpoint"],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return ""
    for ln in reversed(r.stdout.splitlines()):
        for part in ln.replace(",", " ").split():
            if part.startswith("address="):
                return part.split("=", 1)[1]
    return ""


def check_speed(state: dict) -> None:
    sp = state.setdefault("speed", {})
    now = int(time.time())
    streak = sp.get("slow_streak", 0)
    if not streak and now - sp.get("at", 0) < SPEED_EVERY:
        return
    n = sp.get("n", 0)
    mbit = measure_mbit(n)
    sp.update(at=now, n=n + 1, mbit=round(mbit, 2))
    if mbit >= SLOW_MBIT:
        if streak:
            log("туннель снова быстрый: %.1f Мбит/с" % mbit)
        sp["slow_streak"] = 0
        clear_attention("slow")
        return
    sp["slow_streak"] = streak + 1
    log("туннель медленный: %.2f Мбит/с (замер %d из %d)"
        % (mbit, streak + 1, SLOW_CONFIRM))
    if streak + 1 >= SLOW_CONFIRM:
        ep = adguard_endpoint()
        attention("slow",
                  "Туннель работает, но медленно: %.1f Мбит/с" % mbit,
                  "Сервер AdGuard %s. Разные локации AdGuard идут через разные "
                  "серверы — смените локацию на странице «VPN серверы» и "
                  "замерьте снова." % (ep or "не определён"))


def main() -> int:
    wan = wan_iface()
    if not wan:
        log("WAN-интерфейс не настроен — проверять нечего")
        return 0

    d = dg.ladder(wan)
    state = load_state()

    if d["healthy"]:
        if state.get("remedies", {}).get(REMEDY):
            log("выход снова работает — счётчик попыток сброшен")
        dg.clear_remedy(state, REMEDY)
        # Both of the watchdog's own concerns end here. Clearing only "egress"
        # left a provider outage on the overview for days after it was over.
        for kind in OWN_KINDS:
            clear_attention(kind)
        check_speed(state)
        save_state(state)
        return 0

    allowed, why = dg.remedy_allowed(state, REMEDY, d,
                                     max_attempts=MAX_ATTEMPTS,
                                     window_sec=WINDOW_SEC)
    if not allowed:
        # The two reasons read very differently to a person, and both are more
        # useful than another restart.
        log("НЕ перезапускаю adguardvpn: %s | состояние: %s" % (why, d["summary"]))
        # The diagnosis can move from one side to the other mid-outage; the
        # concern it no longer supports goes, so only the current one shows.
        if d.get("fixable_here"):
            clear_attention("uplink")
            attention("egress",
                      "Туннель не поднимается: %s" % d["summary"],
                      "Автоматические перезапуски прекращены — %s" % why)
        else:
            clear_attention("egress")
            attention("uplink",
                      "Связь нарушена выше туннеля: %s" % d["summary"],
                      "Это не чинится на шлюзе (%s). Перезапуск туннеля "
                      "не поможет и не выполняется." % (d.get("owner") or "—"))
        return 0

    log("перезапускаю adguardvpn — %s | состояние: %s" % (why, d["summary"]))
    dg.record_remedy(state, REMEDY, window_sec=WINDOW_SEC)
    save_state(state)
    subprocess.run(["systemctl", "restart", "adguardvpn"],
                   capture_output=True, timeout=60)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:                       # never let the timer unit fail
        log("сторож упал (не фатально): %s" % e)
        sys.exit(0)
