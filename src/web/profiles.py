"""Pure, version-independent profile settings. No I/O or network access."""
from copy import deepcopy
import ipaddress
import re
import uuid

TUNNEL_LISTS = [
    {"id": ref, "label": ref, "description": description, "source_url": "https://github.com/runetfreedom/russia-v2ray-rules-dat"}
    for ref, description in [
        ("geosite:ru-blocked", "Недоступные из России домены, включая дополнения сообществ"),
        ("geoip:ru-blocked", "Заблокированные IP-адреса и подсети"),
        ("geoip:ru-blocked-community", "IP-список сообщества с защитой общих фронтендов"),
    ]
]
SERVICES = [
    {"id": "openai", "label": "ChatGPT / OpenAI", "description": "Основные домены ChatGPT, API и ресурсов; общие сторонние сервисы не включены", "domains": ["domain:chatgpt.com", "domain:openai.com", "domain:oaistatic.com", "domain:oaiusercontent.com", "domain:oaistatsig.com", "full:cdn.openaimerge.com"], "source_urls": ["https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps"]},
    {"id": "anthropic", "label": "Claude / Anthropic", "description": "Основные домены Claude, ресурсов и API Anthropic", "domains": ["domain:claude.ai", "domain:anthropic.com", "domain:claude.com", "domain:clau.de", "domain:claudemcpclient.com", "domain:claudemcpcontent.com", "domain:claudeusercontent.com", "full:servd-anthropic-website.b-cdn.net"], "source_urls": ["https://platform.claude.com/docs/en/api/overview", "https://github.com/v2fly/domain-list-community/blob/master/data/anthropic"]},
    {"id": "youtube", "label": "YouTube", "description": "Видео, изображения и сайт YouTube; остальные сервисы Google не включены", "domains": ["domain:youtube.com", "domain:youtu.be", "domain:googlevideo.com", "domain:ytimg.com", "domain:youtube-nocookie.com", "full:youtubei.googleapis.com", "full:youtube.googleapis.com", "full:youtubeembeddedplayer.googleapis.com", "full:yt3.ggpht.com"], "source_urls": ["https://github.com/v2fly/domain-list-community/blob/master/data/youtube"]},
    {"id": "telegram", "label": "Telegram", "description": "Домены Telegram; для клиентов, работающих по IP, включите IP-списки", "domains": ["domain:telegram.org", "domain:t.me", "domain:telegram.me"], "source_urls": ["https://github.com/v2fly/domain-list-community/blob/master/data/telegram"]},
]
BUILTINS = {
    "blocked_only": ("Только заблокированное", "Точные исключения и заблокированные ресурсы через туннель, остальное напрямую", "direct"),
    "all_except_ru": ("Всё, кроме России", "Российские ресурсы напрямую, остальное через туннель", "tunnel"),
    "all": ("Всё через туннель", "Туннель по умолчанию", "tunnel"),
    "direct": ("Всё напрямую", "Аварийный профиль: весь трафик напрямую", "direct"),
}
FIELDS = {"name", "default_route", "tunnel_lists", "services", "use_discovered", "apple_vpn", "realtime_direct", "extra_tunnel_domains"}

def ids(settings):
    return tuple(BUILTINS) + tuple(settings.get("custom_profiles", {}))

def _base(settings, ident):
    name, _, default = BUILTINS[ident]
    selective = ident in ("blocked_only", "all_except_ru")
    return {"name": name, "default_route": default, "tunnel_lists": [v["id"] for v in TUNNEL_LISTS] if selective else [], "services": [v["id"] for v in SERVICES] if ident == "blocked_only" else [], "use_discovered": selective, "apple_vpn": selective, "realtime_direct": True, "extra_tunnel_domains": []}

def validate_hostname(value):
    if not isinstance(value, str):
        raise ValueError("Hostname must be text")
    value = value.strip().lower().rstrip(".")
    if len(value) > 253 or "." not in value or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")) or value.endswith((".local", ".localhost", ".internal", ".lan", ".home", ".test", ".invalid")):
        raise ValueError("Укажите публичное имя хоста")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("Укажите имя хоста вместо IP-адреса")

def _validate(config, ident):
    if not isinstance(config, dict) or set(config) - FIELDS:
        raise ValueError("Неизвестные поля настроек профиля")
    c = deepcopy(config)
    if not isinstance(c.get("name"), str) or not c["name"].strip() or len(c["name"]) > 80:
        raise ValueError("Название должно содержать от 1 до 80 символов")
    c["name"] = c["name"].strip()
    if ident in BUILTINS:
        c["name"] = BUILTINS[ident][0]
    if c.get("default_route") not in ("direct", "tunnel"):
        raise ValueError("default_route must be direct or tunnel")
    if ident == "direct" and c["default_route"] != "direct":
        raise ValueError("Аварийный профиль должен направлять трафик напрямую")
    for field, allowed in (("tunnel_lists", {x["id"] for x in TUNNEL_LISTS}), ("services", {x["id"] for x in SERVICES})):
        if not isinstance(c.get(field), list) or any(not isinstance(x, str) or x not in allowed for x in c[field]):
            raise ValueError("Invalid " + field)
        c[field] = list(dict.fromkeys(c[field]))
    for field in ("use_discovered", "apple_vpn", "realtime_direct"):
        if type(c.get(field)) is not bool:
            raise ValueError(field + " must be boolean")
    values = c.get("extra_tunnel_domains")
    if not isinstance(values, list) or len(values) > 100:
        raise ValueError("Допускается не более 100 точных доменных исключений")
    c["extra_tunnel_domains"] = list(dict.fromkeys(validate_hostname(v) for v in values))
    return c

def effective(settings, ident=None):
    ident = ident or settings.get("profile", "all_except_ru")
    if ident in BUILTINS:
        c = _base(settings, ident)
        # Read legacy preferences without writing unrelated profile state. A reset
        # stores explicit factory settings so it does not re-import these values.
        if ident in ("blocked_only", "all_except_ru"):
            c["apple_vpn"] = bool(settings.get("force_aaplimg_vpn", True))
        c["realtime_direct"] = bool(settings.get("realtime_direct", True))
        c.update(deepcopy(settings.get("profile_overrides", {}).get(ident, {})))
    else:
        row = settings.get("custom_profiles", {}).get(ident)
        if row is None:
            raise ValueError("Unknown profile: " + str(ident))
        c = deepcopy(row["config"])
    return _validate(c, ident)

def _raw(settings, ident):
    return deepcopy(settings.get("profile_overrides" if ident in BUILTINS else "custom_profiles", {}).get(ident))

def update(settings, ident, config):
    c = effective(settings, ident)
    if not isinstance(config, dict) or set(config) - FIELDS:
        raise ValueError("Неизвестные поля настроек профиля")
    c.update(config)
    c = _validate(c, ident)
    out = deepcopy(settings)
    if c == effective(settings, ident):
        return out
    out.setdefault("profile_history", {})[ident] = _raw(settings, ident)
    if ident in BUILTINS:
        out.setdefault("profile_overrides", {})[ident] = c
    else:
        out["custom_profiles"][ident]["config"] = c
    return out

def reset(settings, ident):
    current = effective(settings, ident)
    out = deepcopy(settings)
    target = _base(settings, ident) if ident in BUILTINS else settings["custom_profiles"][ident]["original"]
    if current == target:
        return out
    out.setdefault("profile_history", {})[ident] = _raw(settings, ident)
    if ident in BUILTINS:
        out.setdefault("profile_overrides", {})[ident] = _base(settings, ident)
    else:
        out["custom_profiles"][ident]["config"] = deepcopy(out["custom_profiles"][ident]["original"])
    return out

def undo(settings, ident):
    effective(settings, ident)
    if ident not in settings.get("profile_history", {}):
        raise ValueError("Нет изменения профиля для отмены")
    out = deepcopy(settings)
    previous = out["profile_history"].pop(ident)
    dest = out.setdefault("profile_overrides" if ident in BUILTINS else "custom_profiles", {})
    if previous is None:
        dest.pop(ident, None)
    else:
        dest[ident] = previous
    return out

def clone(settings, ident, name):
    c = effective(settings, ident)
    c["name"] = name
    new_id = "custom_" + uuid.uuid4().hex
    c = _validate(c, new_id)
    out = deepcopy(settings)
    out.setdefault("custom_profiles", {})[new_id] = {"config": c, "original": deepcopy(c), "copied_from": settings.get("custom_profiles", {}).get(ident, {}).get("copied_from", ident)}
    return out

def catalog(settings):
    rows = []
    for ident in ids(settings):
        c = effective(settings, ident)
        rows.append({"id": ident, "name": c["name"], "description": BUILTINS[ident][1] if ident in BUILTINS else "Пользовательский профиль", "builtin": ident in BUILTINS, "modified": c != (_base(settings, ident) if ident in BUILTINS else settings["custom_profiles"][ident]["original"]), "can_undo": ident in settings.get("profile_history", {}), "config": c})
    return {"active_profile": settings.get("profile", "all_except_ru"), "profiles": rows, "tunnel_lists": deepcopy(TUNNEL_LISTS), "services": deepcopy(SERVICES)}
