"""
What is actually inside geosite.dat and geoip.dat, and whether the routing
rules can be satisfied by it.

This exists because of one silent failure. The `blocked_only` profile asked for
`geosite:category-ru-blocked`; upstream renamed that list to `ru-blocked` at
some point, and xray does not ignore a rule it cannot resolve -- it refuses the
whole configuration:

    failed to load geosite: CATEGORY-RU-BLOCKED
      > code not found in geosite.dat: CATEGORY-RU-BLOCKED   (exit 23)

So a profile stopped working entirely, at a moment nobody was watching, because
a file downloaded by a weekly timer changed a name. `apply_config` would have
caught it the hard way -- xray fails to start, the snapshot is restored -- but
the message the household gets is "xray failed to start", which points at the
tunnel rather than at a list.

Checking the names against the file before writing the configuration turns that
into a sentence naming the missing list, and leaves the working configuration
in place. It is the same idea as everywhere else here: ask the thing itself
rather than assume it still looks the way it did.

Both files use the same shape, so one parser reads either:

    message GeoSite   { string country_code = 1; repeated Domain domain = 2; }
    message GeoSiteList { repeated GeoSite entry = 1; }
"""
from __future__ import annotations

import re
from pathlib import Path

# geosite.dat is 70 MB and this runs on every apply. Only the names are read --
# the domain payload of each entry is skipped by its length -- and the result is
# remembered until the file changes underneath us.
_cache: dict[str, tuple[tuple, frozenset]] = {}


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    r = s = 0
    while True:
        b = buf[i]
        i += 1
        r |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            return r, i


def categories(path: str | Path) -> frozenset[str]:
    """Every list name in a .dat file, upper-cased as xray compares them."""
    path = Path(path)
    try:
        st = path.stat()
    except OSError:
        return frozenset()
    key = str(path)
    stamp = (st.st_mtime_ns, st.st_size)
    hit = _cache.get(key)
    if hit and hit[0] == stamp:
        return hit[1]

    try:
        data = path.read_bytes()
    except OSError:
        return frozenset()

    names: set[str] = set()
    i, n = 0, len(data)
    try:
        while i < n:
            tag, i = _varint(data, i)
            if tag >> 3 != 1 or tag & 7 != 2:
                break                      # not a GeoSiteList after all
            length, i = _varint(data, i)
            end = i + length
            # Only the first field of the entry is the name; the rest is the
            # payload and is skipped wholesale by jumping to `end`.
            j = i
            while j < end:
                t, j = _varint(data, j)
                field, wire = t >> 3, t & 7
                if wire == 2:
                    l, j = _varint(data, j)
                    if field == 1:
                        names.add(data[j:j + l].decode("utf-8", "replace").upper())
                        break
                    j += l
                elif wire == 0:
                    _, j = _varint(data, j)
                else:
                    break
            i = end
    except (IndexError, ValueError):
        # A truncated download is not a reason to take the gateway down; an
        # empty answer makes every reference "missing", which the caller
        # reports without touching the running configuration.
        pass

    result = frozenset(names)
    _cache[key] = (stamp, result)
    return result


_REF = re.compile(r"^(geosite|geoip):([^@]+)", re.IGNORECASE)


def referenced(config: dict) -> set[tuple[str, str]]:
    """The (kind, name) pairs a built xray configuration asks the .dat files for."""
    out: set[tuple[str, str]] = set()
    for rule in (config.get("routing", {}) or {}).get("rules", []) or []:
        for field in ("domain", "ip"):
            for value in rule.get(field) or []:
                m = _REF.match(str(value))
                if m:
                    out.add((m.group(1).lower(), m.group(2).upper()))
    return out


def missing(config: dict, geosite_path: str | Path,
            geoip_path: str | Path) -> list[str]:
    """
    What a configuration asks for that the files on disk cannot answer.

    Returned as text ready to show someone, because the useful form of this
    answer is "the list X is gone", not a set of tuples.

    A file that yields nothing at all -- absent, empty, or a truncated download
    -- is reported once, by name. Listing its forty references as forty missing
    lists would be true and useless: the reader would go looking for forty
    renamed categories instead of one missing file.
    """
    paths = {"geosite": Path(geosite_path), "geoip": Path(geoip_path)}
    have = {kind: categories(path) for kind, path in paths.items()}
    refs = referenced(config)

    problems = []
    for kind in ("geosite", "geoip"):
        if not have[kind] and any(k == kind for k, _ in refs):
            problems.append("%s не прочитан (%s)" % (paths[kind].name, paths[kind]))
    gone = sorted("%s:%s" % (kind, name.lower())
                  for kind, name in refs
                  if have[kind] and name not in have[kind])
    return problems + gone
