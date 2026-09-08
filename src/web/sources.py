"""
Sources: one description of everything Shunt can be given from outside.

Until now a "subscription" was the only such thing: a URL of domains, fetched on
a schedule, of one of five types. That mechanism works, but it knows nothing
about itself -- nothing states that a geo database replaces the previous one
while a blocklist adds to it, or that importing an egress is a far larger
decision than importing an ad list. This module is that missing description,
plus the interchange format the descriptions travel in.

Two rules hold the design together:

  A source carries data, never code. Every field is a value the gateway reads;
  none is a command it runs. parse_manifest() refuses a manifest with anything
  that looks executable rather than ignoring it, because silently dropping such
  a field would let a publisher believe it had been honoured.

  The registry is the single truth. Cardinality, risk and the consumer that
  applies a type are declared here once, so the interface, the importer and the
  documentation cannot drift apart -- and adding a type is one entry, not a
  search for every place that switches on a string.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, asdict

# Bumped only when a manifest written for an older Shunt would be misread by a
# newer one. Readers reject a version they do not know rather than guessing.
MANIFEST_VERSION = 1


@dataclass(frozen=True)
class SourceType:
    """What one kind of source is, and what accepting it costs."""
    name: str
    payload: str       # list | asset | endpoint | bundle
    consumer: str      # xray | dnsmasq | geo | egress | several
    cardinality: str   # many | one
    risk: str          # low | medium | high
    implemented: bool
    summary: str


# Cardinality is not a presentation detail. "one" means accepting a source of
# this type replaces whatever occupied the slot, which is a different sentence
# to show the operator than "this will be added", and a different thing for the
# importer to do. The geo pair is "one" because xray reads a single
# XRAY_LOCATION_ASSET directory; that is a property of the consumer, not a
# preference.
SOURCE_TYPES: dict[str, SourceType] = {t.name: t for t in (
    SourceType("direct",   "list",     "xray",    "many", "low",    True,
               "Domains and subnets that leave without the tunnel"),
    SourceType("vpn",      "list",     "xray",    "many", "low",    True,
               "Domains forced through the tunnel"),
    SourceType("block",    "list",     "xray",    "many", "low",    True,
               "Domains that are refused outright"),
    SourceType("adblock",  "list",     "dnsmasq", "many", "low",    True,
               "Advertising domains, answered empty by DNS"),
    SourceType("malware",  "list",     "dnsmasq", "many", "low",    True,
               "Known-malicious domains, answered empty by DNS"),
    SourceType("geo",      "asset",    "geo",     "one",  "medium", False,
               "The geoip.dat and geosite.dat pair xray routes by"),
    SourceType("resolver", "endpoint", "dnsmasq", "many", "high",   False,
               "A DNS-over-HTTPS endpoint and the domains sent to it"),
    SourceType("egress",   "endpoint", "egress",  "many", "high",   False,
               "Proxy servers, as vless:// links or a subscription URL"),
    SourceType("probe",    "endpoint", "egress",  "many", "low",    False,
               "How to tell whether one egress is still carrying traffic"),
    SourceType("recipe",   "bundle",   "several", "many", "high",   False,
               "Several sources and a starting profile, as one import"),
)}

# The five types the subscription machinery already applies. Kept as a derived
# value so it cannot fall out of step with the registry.
LIVE_TYPES: tuple[str, ...] = tuple(
    n for n, t in SOURCE_TYPES.items() if t.implemented)

# Fields a source entry may carry. Anything else is refused: an allowlist is
# the only way to be sure a future field name does not smuggle in behaviour.
_SOURCE_FIELDS = {"type", "name", "url", "schedule", "enabled", "note"}

# Refused by name, with an explanation, because these are the fields someone
# would reach for when trying to make a manifest do something rather than say
# something. Any unknown field is refused too; these get a clearer message.
_EXECUTABLE_FIELDS = {
    "exec", "command", "cmd", "run", "script", "hook", "shell",
    "preinst", "postinst", "install", "entrypoint",
}

_SCHEDULES = {"manual", "daily", "weekly"}


def type_table() -> list[dict]:
    """The registry as plain dicts, for the API and the interface."""
    return [asdict(t) for t in SOURCE_TYPES.values()]


def looks_private(url: str) -> bool:
    """
    True when a URL is plausibly a credential rather than a public address.

    A personal subscription link is a secret: the token in it is what
    authenticates you to the provider. Exporting one into a manifest meant for
    sharing would hand that away, so the exporter leaves these out. Being wrong
    in the cautious direction costs the operator one line to re-add by hand;
    being wrong the other way cannot be undone once the file is sent.
    """
    try:
        p = urllib.parse.urlparse(url)
    except ValueError:
        return True
    if p.username or p.password:
        return True
    qs = urllib.parse.parse_qs(p.query)
    if {"token", "key", "secret", "auth", "access", "sid", "uuid"} & {
            k.lower() for k in qs}:
        return True
    # A long opaque path segment is how most providers encode a per-user link.
    for seg in p.path.split("/"):
        if len(seg) >= 24 and seg.replace("-", "").replace("_", "").isalnum():
            return True
    return False


def _err(errors: list[str], msg: str) -> None:
    if len(errors) < 10:
        errors.append(msg)


def _parse_source(obj: object, errors: list[str], where: str) -> dict | None:
    if not isinstance(obj, dict):
        _err(errors, f"{where}: expected an object")
        return None

    bad_exec = _EXECUTABLE_FIELDS & set(obj)
    if bad_exec:
        _err(errors, f"{where}: refused, a source describes data and cannot "
                     f"carry {', '.join(sorted(bad_exec))}")
        return None
    unknown = set(obj) - _SOURCE_FIELDS
    if unknown:
        _err(errors, f"{where}: unknown field(s) {', '.join(sorted(unknown))}")
        return None

    t = obj.get("type")
    if t not in SOURCE_TYPES:
        _err(errors, f"{where}: unknown type {t!r}")
        return None
    if t == "recipe":
        _err(errors, f"{where}: a recipe cannot contain another recipe")
        return None
    st = SOURCE_TYPES[t]
    if not st.implemented:
        _err(errors, f"{where}: type {t!r} is described but not yet applied "
                     f"by this version")
        return None

    url = obj.get("url")
    if not isinstance(url, str) or not url.strip():
        _err(errors, f"{where}: url is required")
        return None
    url = url.strip()
    scheme = urllib.parse.urlparse(url).scheme
    if scheme not in ("http", "https"):
        _err(errors, f"{where}: url must be http or https, got {scheme or 'none'}")
        return None

    name = obj.get("name")
    if name is not None and not isinstance(name, str):
        _err(errors, f"{where}: name must be text")
        return None

    schedule = obj.get("schedule", "weekly")
    if schedule not in _SCHEDULES:
        _err(errors, f"{where}: schedule must be one of "
                     f"{', '.join(sorted(_SCHEDULES))}")
        return None

    enabled = obj.get("enabled", True)
    if not isinstance(enabled, bool):
        _err(errors, f"{where}: enabled must be true or false")
        return None

    return {
        "type": t,
        "name": (name or url)[:64].strip(),
        "url": url,
        "schedule": schedule,
        "enabled": enabled,
    }


def parse_manifest(obj: object) -> tuple[list[dict], list[str]]:
    """
    Validate a manifest and return the sources it asks for.

    Accepts one source, or a recipe carrying several. Returns ([], errors) when
    anything is wrong: a manifest is applied whole or not at all, because a
    recipe that half-applied would leave routing in a state its author never
    described and its reader never saw.
    """
    errors: list[str] = []
    if not isinstance(obj, dict):
        return [], ["manifest must be a JSON object"]

    ver = obj.get("shunt")
    if ver is None:
        return [], ['not a Shunt manifest: no "shunt" version field']
    if not isinstance(ver, int):
        return [], ['"shunt" must be a whole number']
    if ver > MANIFEST_VERSION:
        return [], [f"manifest is version {ver}; this Shunt reads up to "
                    f"{MANIFEST_VERSION}. Upgrade before importing it."]

    if obj.get("type") == "recipe":
        allowed = {"shunt", "type", "name", "note", "sources"}
        unknown = set(obj) - allowed
        if unknown:
            return [], [f"recipe: unknown field(s) {', '.join(sorted(unknown))}"]
        raw = obj.get("sources")
        if not isinstance(raw, list) or not raw:
            return [], ["recipe: sources must be a non-empty list"]
        out = []
        for i, entry in enumerate(raw):
            parsed = _parse_source(entry, errors, f"source {i + 1}")
            if parsed:
                out.append(parsed)
        return ([], errors) if errors else (out, [])

    single = _parse_source({k: v for k, v in obj.items() if k != "shunt"},
                           errors, "source")
    return ([], errors) if errors else ([single], [])


def manifest_from_settings(settings: dict, name: str = "Shunt sources",
                           include_private: bool = False) -> dict:
    """
    Describe the gateway's current sources as a recipe manifest.

    This is the half of the format that can be shipped safely: writing a
    manifest changes nothing on anyone's machine, while reading one changes
    routing for a whole household. Import arrives with the preview it needs.
    """
    sources, omitted = [], []
    for sub in settings.get("subscriptions", []):
        t = sub.get("type")
        if t not in SOURCE_TYPES:
            continue
        url = (sub.get("url") or "").strip()
        if not url:
            continue
        if not include_private and looks_private(url):
            omitted.append(sub.get("name") or url)
            continue
        sources.append({
            "type": t,
            "name": (sub.get("name") or "")[:64],
            "url": url,
            "schedule": sub.get("schedule", "weekly"),
            "enabled": bool(sub.get("enabled", True)),
        })

    manifest: dict = {
        "shunt": MANIFEST_VERSION,
        "type": "recipe",
        "name": name,
        "sources": sources,
    }
    if omitted:
        manifest["note"] = (
            "Left out because their addresses look like personal links: "
            + ", ".join(omitted[:5])
            + ("…" if len(omitted) > 5 else "")
        )
    return manifest
