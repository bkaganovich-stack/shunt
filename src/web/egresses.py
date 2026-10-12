"""
The egresses Shunt can send tunnelled traffic through, and which one it uses.

Until 2.25 there were exactly two, hard-wired: AdGuard first, FPTN when
AdGuard was dead. The user's own cascade adds two more (AmneziaWG and
TrustTunnel to Riga -> Miami), and which of them should carry the house is
the user's decision, to be revisited as measurements come in. So the order is
data: a list in settings, edited on the page, and the fallback loop walks it.

Every egress looks the same from here: a plain SOCKS address. AdGuard's CLI
listens on loopback; FPTN, AmneziaWG and TrustTunnel each live in a network
namespace behind a bridge on its veth address (fptn-egress.sh,
egress-netns.sh). That uniformity is deliberate -- probes, xray and the
watchdog all speak to "the tunnel" the same way, whichever one it is.

Pure functions only; probing and applying live in main.py.
"""
from __future__ import annotations

from pathlib import Path

EGRESS_DIR = Path("/opt/shunt/config/egress")

CATALOG = {
    "adguard":     {"label": "AdGuard VPN", "host": "127.0.0.1", "port": 1081},
    "amnezia":     {"label": "AmneziaWG (свой каскад)", "host": "192.168.244.6", "port": 1083,
                    "unit": "shunt-egress@amnezia.service"},
    "trusttunnel": {"label": "TrustTunnel (свой каскад)", "host": "192.168.244.10", "port": 1084,
                    "unit": "shunt-egress@trusttunnel.service"},
    "fptn":        {"label": "FPTN", "host": "192.168.244.2", "port": 1082,
                    "unit": "shunt-fptn-egress.service"},
}
# Until the user says otherwise: AdGuard carries the house, the cascade is the
# first reserve (agreed 2026-10-12), FPTN the last.
DEFAULT_ORDER = ["adguard", "amnezia", "trusttunnel", "fptn"]
CASCADE = ("amnezia", "trusttunnel")


def order(settings: dict) -> list[str]:
    """The saved order, made whole: unknown ids dropped, missing ones appended."""
    saved = [e for e in (settings.get("egress_order") or []) if e in CATALOG]
    saved = list(dict.fromkeys(saved))
    return saved + [e for e in DEFAULT_ORDER if e not in saved]


def configured(ident: str, base: Path = EGRESS_DIR) -> bool:
    """A cascade egress exists only once the server has issued it a config."""
    if ident not in CASCADE:
        return True
    try:
        return any((base / ident).iterdir())
    except OSError:
        return False


def enabled(settings: dict, ident: str, is_configured=None) -> bool:
    # Looked up at call time, not bound as a default: a default is captured
    # when the function is defined, and then no test and no caller could
    # substitute the filesystem check.
    is_configured = is_configured or configured
    if ident == "adguard":
        return bool((settings.get("adguard") or {}).get("enabled"))
    if ident == "fptn":
        return bool((settings.get("fptn") or {}).get("enabled"))
    return bool((settings.get("egresses") or {}).get(ident, {}).get("enabled")) \
        and is_configured(ident)


def candidates(settings: dict, is_configured=None) -> list[str]:
    """Enabled egresses, best first. The first one is the primary."""
    return [e for e in order(settings) if enabled(settings, e, is_configured)]


def socks(settings: dict, ident: str) -> tuple[str, int]:
    """Where the egress listens. AdGuard and FPTN keep their own settings."""
    own = settings.get(ident) if ident in ("adguard", "fptn") else None
    c = CATALOG[ident]
    if isinstance(own, dict):
        return own.get("socks_host", c["host"]), int(own.get("socks_port", c["port"]))
    return c["host"], c["port"]


def outbound(settings: dict, ident: str) -> dict:
    host, port = socks(settings, ident)
    return {"protocol": "socks", "tag": "proxy",
            "settings": {"servers": [{"address": host, "port": port}]}}


def active(settings: dict, is_configured=None) -> str | None:
    """
    The egress traffic goes through now: the one the fallback loop chose, if
    it is still enabled, else the primary. None when no egress is enabled --
    the caller then falls back to the legacy key-based servers.
    """
    cands = candidates(settings, is_configured)
    if not cands:
        return None
    chosen = settings.get("egress_active")
    return chosen if chosen in cands else cands[0]


def decide(settings: dict, alive, fails: int, threshold: int = 3,
           is_configured=None) -> tuple[str | None, int, str]:
    """
    One step of the fallback ladder. `alive(ident)` probes an egress.

    Returns (egress to use, new primary-failure count, action), where action is
    one of: "stay", "restore" (back to the primary), "switch" (to a reserve),
    "direct" (no tunnel works; the caller routes direct), "none" (nothing
    enabled).

    The primary always wins when alive. While it is dead, the first live
    reserve in the user's order is used -- re-checked every step, so a better
    reserve that recovers takes over from a worse one. A brief hiccup moves
    nothing: the primary must fail `threshold` steps in a row (~3 min) first,
    because a watchdog restart of AdGuard looks exactly like a short outage.
    """
    cands = candidates(settings, is_configured)
    if not cands:
        return None, 0, "none"
    primary, current = cands[0], active(settings, is_configured)
    if alive(primary):
        return primary, 0, ("stay" if current == primary and not settings.get("fallback_saved_profile")
                            else "restore")
    fails += 1
    if fails < threshold:
        return current, fails, "stay"
    for reserve in cands[1:]:
        if alive(reserve):
            # Leaving a direct fallback is a switch even onto the same egress:
            # the profile the house had has to come back with it.
            stay = reserve == current and not settings.get("fallback_saved_profile")
            return reserve, fails, ("stay" if stay else "switch")
    return current, fails, "direct"


# ── Per-egress parameters, kept apart from the server-issued configuration ──
# A config re-issued by the cascade server must not silently drop what the user
# tuned by hand (MTU, I1), so those live in settings and are applied over the
# file each time the egress starts (egress_config.py), never written into it.
_I1_RE = None


def clean_params(ident: str, data: dict) -> dict:
    """Validate parameters for one egress; raises ValueError in the user's words."""
    import re
    global _I1_RE
    if not isinstance(data, dict):
        raise ValueError("Параметры должны быть объектом")
    if ident == "amnezia":
        out = {}
        mtu = data.get("mtu")
        if mtu not in (None, ""):
            try:
                mtu = int(mtu)
            except (TypeError, ValueError):
                raise ValueError("MTU — целое число") from None
            if not 1280 <= mtu <= 1500:
                raise ValueError("MTU должен быть от 1280 до 1500")
            out["mtu"] = mtu
        i1 = data.get("i1")
        if i1 is not None:
            if not isinstance(i1, dict) or not isinstance(i1.get("enabled"), bool):
                raise ValueError("I1: укажите, включён ли он")
            value = str(i1.get("value") or "").strip()
            _I1_RE = _I1_RE or re.compile(r"^(<(b 0x[0-9a-fA-F]+|r \d{1,4}|rc \d{1,4}|rd \d{1,4}|c|t)>)+$")
            if value and (len(value) > 4000 or not _I1_RE.match(value.replace("> <", "><"))):
                raise ValueError("I1 не похож на сигнатуру AmneziaWG: ожидаются теги вида <b 0x…><r 8>")
            if i1["enabled"] and not value:
                raise ValueError("Чтобы включить I1, задайте его значение")
            out["i1"] = {"enabled": i1["enabled"], "value": value}
        return out
    if ident == "trusttunnel":
        out = {}
        if data.get("protocol") is not None:
            if data["protocol"] not in ("http2", "http3"):
                raise ValueError("Протокол: http2 или http3")
            out["protocol"] = data["protocol"]
        if data.get("anti_dpi") is not None:
            if not isinstance(data["anti_dpi"], bool):
                raise ValueError("anti-DPI: да или нет")
            out["anti_dpi"] = data["anti_dpi"]
        return out
    raise ValueError("У этого выхода нет отдельных параметров")


def params(settings: dict, ident: str) -> dict:
    return dict((settings.get("egresses") or {}).get(ident, {}).get("params") or {})


def pinned_rules(settings: dict, ident: str) -> list[dict]:
    """Profile rules that name this egress, per profile: what switching it off affects."""
    route = "egress:" + ident
    out = []
    sources = [(k, v) for k, v in (settings.get("profile_overrides") or {}).items()] + \
              [(k, (v or {}).get("config") or {}) for k, v in (settings.get("custom_profiles") or {}).items()]
    for pid, cfg in sources:
        n = sum(1 for r in (cfg.get("custom_rules") or []) if r.get("route") == route)
        if n:
            out.append({"profile": pid, "name": cfg.get("name") or pid, "count": n})
    return out
