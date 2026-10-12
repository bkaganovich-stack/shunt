#!/usr/bin/env python3
"""
Turn the configuration files the cascade servers issue into what the egress
clients on this gateway are started with. Pure text in, text out; the shell
side (egress-netns.sh) owns namespaces and processes.

Two inputs, both written once by an administrator and kept root-only:

  amnezia/awg.conf          a client config exactly as awg-add.sh issues it
                            for phones and laptops
  trusttunnel/endpoint.toml the endpoint's `--client_config ... -f toml` export

Neither can be used as-is. `awg setconf` rejects the wg-quick keys (Address,
DNS, MTU) that only awg-quick understands, and awg-quick itself is exactly
what must not run here: it rewrites the host's routes and resolv.conf, the
behaviour that forced FPTN into a namespace in the first place. The
TrustTunnel wizard, given the export, produces a TUN client that would take
over the default route; here the client must expose SOCKS on the namespace's
veth address and nothing else.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import sys

# Keys only awg-quick understands. Everything else, including AmneziaWG's
# obfuscation (Jc, Jmin, Jmax, S1-S4, H1-H4 ranges, I1-I5), passes to setconf.
_QUICK_ONLY = ("address", "dns", "mtu", "table", "preup", "postup",
               "predown", "postdown", "saveconfig")


def _resolve4(host: str) -> str:
    try:
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        pass
    for fam, _, _, _, addr in socket.getaddrinfo(host, None, socket.AF_INET):
        return addr[0]
    raise ValueError("cannot resolve %s" % host)


def split_awg(text: str, resolve=_resolve4, params: dict | None = None) -> tuple[str, dict]:
    """
    Split an awg-quick client config into (setconf text, interface facts).

    The facts are what the namespace needs set by hand instead: the tunnel
    address, MTU, DNS server, and the endpoint's address, which must be routed
    via the veth so the tunnel's own packets do not try to enter the tunnel.

    `params` are the user's own settings from the web page (egresses.py), laid
    over the file: an MTU, and I1 switched on with a value or switched off.
    The file is left as the server issued it.
    """
    params = params or {}
    out, facts = [], {"mtu": "1420", "dns": ""}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = line.lower()
        m = re.match(r"([A-Za-z0-9]+)\s*=\s*(.*)", line)
        if m:
            key, value = m.group(1).lower(), m.group(2).strip()
            if section == "[interface]" and key in _QUICK_ONLY:
                if key == "address":
                    v4 = [a.strip() for a in value.split(",") if ":" not in a]
                    facts["address"] = v4[0] if v4 else ""
                elif key == "dns":
                    facts["dns"] = value.split(",")[0].strip()
                elif key == "mtu":
                    facts["mtu"] = value
                continue
            if section == "[peer]" and key == "endpoint":
                host, _, port = value.rpartition(":")
                host = host.strip("[]")
                facts["endpoint_ip"] = resolve(host)
                facts["endpoint_port"] = port
                line = "Endpoint = %s:%s" % (facts["endpoint_ip"], port)
        if section == "[interface]" and m and m.group(1).lower() == "i1" and "i1" in params:
            continue                    # replaced (or dropped) below
        out.append(line)
    if params.get("mtu"):
        facts["mtu"] = str(params["mtu"])
    i1 = params.get("i1")
    if i1 and i1.get("enabled") and i1.get("value"):
        at = next((n for n, l in enumerate(out) if l.lower() == "[peer]"), len(out))
        while at > 0 and not out[at - 1].strip():
            at -= 1
        out.insert(at, "I1 = " + i1["value"])
    if not facts.get("address"):
        raise ValueError("awg.conf has no IPv4 Address")
    if not facts.get("endpoint_ip"):
        raise ValueError("awg.conf has no [Peer] Endpoint")
    return "\n".join(out) + "\n", facts


def tt_client(wizard: str, socks: str, user: str | None = None, password: str | None = None,
              protocol: str = "http3", resolve=_resolve4, anti_dpi: bool | None = None) -> str:
    """
    Rewrite the setup wizard's client config for SOCKS-only use in a namespace.

    egress-netns.sh puts the listener on the namespace's loopback and a bridge
    in front of it, like every other egress: Shunt speaks to all of them as a
    plain SOCKS address. The client refuses a non-loopback listener without
    credentials, so they are written when given and required off loopback.
    The endpoint is pinned to its IPv4 address because the namespace has no
    resolver; the hostname stays, since it is also the TLS name.
    """
    if protocol not in ("http2", "http3"):
        raise ValueError("protocol must be http2 or http3")
    if "[endpoint]" not in wizard:
        raise ValueError("not a TrustTunnel client config: no [endpoint]")
    m = re.search(r'(?m)^addresses\s*=\s*\[\s*"([^"]+)"', wizard)
    if not m:
        raise ValueError("no endpoint address")
    host, _, port = m.group(1).rpartition(":")
    s = wizard
    s = re.sub(r'(?m)^addresses\s*=.*$', 'addresses = ["%s:%s"]' % (resolve(host), port), s)
    s = re.sub(r'(?m)^killswitch_enabled\s*=.*$', "killswitch_enabled = false", s)
    s = re.sub(r'(?m)^has_ipv6\s*=.*$', "has_ipv6 = false", s)
    s = re.sub(r'(?m)^upstream_protocol\s*=.*$', 'upstream_protocol = "%s"' % protocol, s)
    if anti_dpi is not None:
        s = re.sub(r'(?m)^anti_dpi\s*=.*$', "anti_dpi = %s" % ("true" if anti_dpi else "false"), s)
    # Everything from the listener section on is replaced: the wizard writes a
    # TUN listener, and a client holding both would also grab the route.
    s = re.sub(r"(?ms)^\[listener\].*\Z", "", s).rstrip() + "\n"
    loopback = ipaddress.ip_address(socks.rpartition(":")[0].strip("[]")).is_loopback
    if not loopback and not (user and password):
        raise ValueError("a SOCKS listener off loopback needs credentials")
    s += '\n[listener]\n\n[listener.socks]\naddress = "%s"\n' % socks
    if user and password:
        s += 'username = "%s"\npassword = "%s"\n' % (user, password)
    return s


def _params(path: str | None, ident: str) -> dict:
    """The user's parameters for one egress, from settings.json; none if unreadable."""
    if not path:
        return {}
    try:
        import json
        s = json.load(open(path))
        return dict(((s.get("egresses") or {}).get(ident) or {}).get("params") or {})
    except (OSError, ValueError, AttributeError):
        return {}


def main(argv: list[str]) -> int:
    if len(argv) >= 4 and argv[1] == "awg":
        setconf, facts = split_awg(open(argv[2]).read(),
                                   params=_params(argv[4] if len(argv) > 4 else None, "amnezia"))
        with open(argv[3], "w") as f:
            f.write(setconf)
        for k in ("address", "mtu", "dns", "endpoint_ip", "endpoint_port"):
            print("%s=%s" % (k.upper(), facts.get(k, "")))
        return 0
    if len(argv) >= 6 and argv[1] == "tt":
        p = _params(argv[6] if len(argv) > 6 else None, "trusttunnel")
        out = tt_client(open(argv[2]).read(), argv[4], protocol=p.get("protocol") or argv[5],
                        anti_dpi=p.get("anti_dpi"))
        with open(argv[3], "w") as f:
            f.write(out)
        return 0
    print("usage: egress_config.py awg <awg.conf> <setconf-out> [settings.json]\n"
          "       egress_config.py tt <wizard.toml> <out.toml> <socks-addr> <http2|http3> [settings.json]",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
