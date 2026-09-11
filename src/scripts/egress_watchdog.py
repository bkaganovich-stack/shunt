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
MAX_ATTEMPTS = 3
WINDOW_SEC = 1800


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
        save_state(state)
        clear_attention("egress")
        return 0

    allowed, why = dg.remedy_allowed(state, REMEDY, d,
                                     max_attempts=MAX_ATTEMPTS,
                                     window_sec=WINDOW_SEC)
    if not allowed:
        # The two reasons read very differently to a person, and both are more
        # useful than another restart.
        log("НЕ перезапускаю adguardvpn: %s | состояние: %s" % (why, d["summary"]))
        if d.get("fixable_here"):
            attention("egress",
                      "Туннель не поднимается: %s" % d["summary"],
                      "Автоматические перезапуски прекращены — %s" % why)
        else:
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
