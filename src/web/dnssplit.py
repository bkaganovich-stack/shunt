"""
Which names the Russian resolvers answer: the names the routing sends direct.

Until 2.31 only .ru (and .local) went to the Russian upstreams; every other
name was resolved through the tunnel, by a resolver abroad. For a Russian
service on another zone that is the wrong question to ask: its CDN sees a
foreign client and hands out a foreign node. Avito's photos (avito.st) came
back as Qrator in Germany and Level3 in the Netherlands instead of MTU and
Beeline in Russia; the routing correctly sent them direct -- Avito is for
Russia and must never ride the tunnel -- and the direct path to a foreign
address froze after ~20 KB on the censor's throttling. Pictures half loaded,
on Avito and on every Russian site served from a non-.ru zone.

So DNS follows the route: a name the routing sends direct is resolved where it
will be fetched from, and a name it tunnels is resolved abroad -- including a
blocked site under .ru, which used to get the Russian resolver's answer too.

"The routing" is the compiled xray rule list itself, read the way xray reads
it: the first rule a name matches decides. Rules that depend on more than the
name (a source device, a port, an address) cannot be answered from a name and
are skipped.

Pure: rules and list contents in, dnsmasq lines out.
"""
from __future__ import annotations

import re

_SAFE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$")
# Conditions other than the name: such a rule cannot decide for a name alone.
_OTHER = ("source", "sourcePort", "port", "ip", "inboundTag", "user", "protocol", "attrs", "sourceIP")


def _ancestors(name: str):
    """The name and every parent zone: a.b.c -> a.b.c, b.c, c."""
    parts = name.split(".")
    for i in range(len(parts)):
        yield ".".join(parts[i:])


class Matcher:
    """xray's domain matching over an ordered rule list, by name only."""

    def __init__(self, rules: list[dict], lists: dict[str, dict]):
        self.rules = []
        for r in rules:
            if any(k in r for k in _OTHER):
                continue
            out = r.get("outboundTag") or ("balancer:" + r["balancerTag"] if r.get("balancerTag") else None)
            if not out:
                continue
            if "domain" not in r:
                if r.get("network"):              # the catch-all decides everything left
                    self.rules.append((None, out, r))
                continue
            self.rules.append((self._compile(r["domain"], lists), out, r))

    @staticmethod
    def _compile(values: list[str], lists: dict[str, dict]) -> dict:
        m = {"full": set(), "domain": set(), "plain": [], "regex": []}
        for v in values:
            v = str(v)
            kind, _, val = v.partition(":") if ":" in v else ("", "", v)
            if kind == "geosite":
                if "@" in val:
                    continue                      # attribute subsets: not read, not guessed
                g = lists.get(val.upper())
                if g:
                    m["full"] |= g["full"]
                    m["domain"] |= g["domain"]
                    m["plain"] += list(g["plain"])
                    m["regex"] += [re.compile(x) for x in g["regex"] if _compiles(x)]
            elif kind == "domain":
                m["domain"].add(val.lower())
            elif kind == "full":
                m["full"].add(val.lower())
            elif kind == "keyword" or kind == "":
                m["plain"].append(val.lower())
            elif kind == "regexp" and _compiles(val):
                m["regex"].append(re.compile(val))
        return m

    @staticmethod
    def _hit(m: dict, name: str) -> bool:
        if name in m["full"] or any(a in m["domain"] for a in _ancestors(name)):
            return True
        return any(k in name for k in m["plain"]) or any(r.search(name) for r in m["regex"])

    def route(self, name: str) -> str | None:
        """The outbound the first matching rule names; None when nothing matches."""
        name = name.lower().rstrip(".")
        for m, out, _ in self.rules:
            if m is None or self._hit(m, name):
                return out
        return None


def _compiles(src: str) -> bool:
    try:
        re.compile(src)
        return True
    except re.error:
        return False


def _names(rule: dict, lists: dict[str, dict]) -> set[str]:
    """The concrete names a rule lists (suffixes and exact names), for candidates."""
    out = set()
    for v in rule.get("domain") or []:
        kind, _, val = str(v).partition(":")
        if kind == "geosite" and "@" not in val:
            g = lists.get(val.upper())
            if g:
                out |= g["domain"] | g["full"]
        elif kind in ("domain", "full"):
            out.add(val.lower())
    return {n.rstrip(".") for n in out if _SAFE.match(n.rstrip("."))}


def split(rules: list[dict], lists: dict[str, dict], base=("ru", "local"),
          skip_reasons=("geosite:private",)) -> tuple[list[str], list[str]]:
    """
    (zones for the Russian resolvers, zones back to the default resolver).

    The first are the names the rules send direct and that, asked of the rule
    list as a whole, really do go direct (a tunnel rule earlier in the list
    wins, as in xray). The second are names under those zones that the rules
    tunnel: dnsmasq picks the longest matching zone, so each one carves its
    subtree back out. Both are reduced to the shortest form that resolves the
    same way.
    """
    matcher = Matcher(rules, lists)
    direct = set(base)
    for r in rules:
        if r.get("outboundTag") == "direct" and "domain" in r and not any(k in r for k in _OTHER) \
                and r.get("_reason") not in skip_reasons:
            for n in _names(r, lists):
                if n not in direct and matcher.route(n) == "direct":
                    direct.add(n)

    def covered(n: str) -> bool:
        return any(a in direct for a in _ancestors(n))

    back = set()
    for r in rules:
        out = r.get("outboundTag") or ("balancer:" + r["balancerTag"] if r.get("balancerTag") else None)
        if out and out != "direct" and "domain" in r and not any(k in r for k in _OTHER):
            for n in _names(r, lists):
                if n not in direct and covered(n) and matcher.route(n) != "direct":
                    back.add(n)

    def nearest(n: str) -> str | None:
        for a in list(_ancestors(n))[1:]:
            if a in direct:
                return "direct"
            if a in back:
                return "back"
        return None

    keep_direct = sorted(n for n in direct if n not in base and nearest(n) != "direct")
    keep_back = sorted(n for n in back if nearest(n) != "back")
    return keep_direct, keep_back


def dnsmasq_lines(direct: list[str], back: list[str], servers: list[str], limit: int = 900) -> list[str]:
    """
    server=/zone/.../ip lines; '#' sends a zone back to the default servers.
    Zones are packed several to a line, but dnsmasq rejects a line much past
    1 KB ("Name or service not known"), so lines are cut by length.
    """
    def packs(zones):
        cur, size = [], 0
        for z in zones:
            if cur and size + len(z) + 1 > limit:
                yield "/".join(cur)
                cur, size = [], 0
            cur.append(z)
            size += len(z) + 1
        if cur:
            yield "/".join(cur)
    lines = []
    for pack in packs(direct):
        lines += ["server=/%s/%s" % (pack, ip) for ip in servers]
    lines += ["server=/%s/#" % pack for pack in packs(back)]
    return lines
