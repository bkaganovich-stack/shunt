#!/bin/bash
# Egresses through the user's own cascade (Riga entry, Miami exit), each
# isolated in a network namespace the way FPTN is.
#
#   egress-netns.sh <amnezia|trusttunnel> {setup|run|teardown|status}
#
# Why a namespace at all: a VPN client wants the default route and the
# resolver, and on a gateway those belong to the whole house. FPTN took both
# on 2026-09-04 and, when its tunnel failed, silently egressed on the ISP's
# own address. Here each client gets a namespace of its own; the only thing
# visible from the host is a SOCKS port on the namespace's veth address, and
# that port can only reach the internet through the tunnel. No tunnel, no
# egress -- never a quiet leak.
#
# The namespace plumbing below is shared; only the client differs. FPTN keeps
# its own script until these two have proven themselves.
set -u
NAME=${1:-}
ACTION=${2:-}
BIN=/opt/shunt/egress/bin
CFG=/opt/shunt/config/egress/$NAME
RUN=/run/shunt-egress/$NAME
BRIDGE_UID=65534          # nobody
EGRESS_NET=192.168.244.0/28   # every egress's /30; the bridges may talk across it
WAN=$(ip route show default | awk '/default/{print $5; exit}')

# One /30 per egress inside 192.168.244.0/28, which iptables.sh excludes from
# TPROXY as a whole (.0/30 is FPTN's).
case "$NAME" in
    amnezia)     NS=amnezia;     TAG=am; SUB=192.168.244.4/30; HOSTIP=192.168.244.5; NSIP=192.168.244.6;  PORT=1083 ;;
    trusttunnel) NS=trusttunnel; TAG=tt; SUB=192.168.244.8/30; HOSTIP=192.168.244.9; NSIP=192.168.244.10; PORT=1084 ;;
    *) echo "usage: $0 <amnezia|trusttunnel> {setup|run|teardown|status}" >&2; exit 2 ;;
esac
VETH=veg-$TAG; VETH_NS=veg-$TAG-ns
# Cloudflare WARP on the cascade's exit (Miami), via its relay on the link.
WARP_PORT=1086; WARP_RELAY_HOST=10.99.0.2; WARP_RELAY_PORT=40001
TT_NSIP=192.168.244.10    # TrustTunnel's bridge: WARP's second road (run_amnezia)

# The house's way out must exist before the tunnel's first packet does.
# 2026-10-22: after a power cut the egress started a minute before the
# provider's DHCP answered; with no default route in main, AmneziaWG's first
# packets to Riga fell through to sing-box's table and left un-NATed. The
# kernel's conntrack then pinned that flow "no NAT" -- and keepalives every
# 25 s kept it alive, so for 9 hours every packet went to the provider with
# the source 192.168.244.6 and was dropped. TrustTunnel, restarted later,
# was fine. Together with wait_clock under the unit's TimeoutStartSec.
wait_wan() {
    for _ in $(seq 75); do
        WAN=$(ip route show default | awk '/default/{print $5; exit}')
        [ -n "$WAN" ] && return 0
        sleep 1
    done
    echo "no default route after 75 s -- not starting without a way out" >&2
    return 1
}

# ...and the right time. The same night the board's clock came back 35 days
# behind (a flat CMOS battery): TrustTunnel's certificate was "not yet valid"
# and WireGuard's handshake timestamps looked like replays, until NTP -- which
# now goes direct (iptables.sh) and needs only the WAN -- set it right. Not a
# hard condition: past 60 s the egress starts anyway and retries on its own.
wait_clock() {
    for _ in $(seq 60); do
        [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ] && return 0
        sleep 1
    done
    echo "clock not synchronised after 60 s -- starting anyway" >&2
}

setup() {
    teardown >/dev/null 2>&1
    wait_wan || exit 1
    wait_clock
    install -d -m 700 "$RUN"
    ip netns add "$NS"
    ip link add "$VETH" type veth peer name "$VETH_NS"
    ip link set "$VETH_NS" netns "$NS"
    ip addr add "$HOSTIP/30" dev "$VETH" && ip link set "$VETH" up
    ip -n "$NS" addr add "$NSIP/30" dev "$VETH_NS"
    ip -n "$NS" link set "$VETH_NS" up
    ip -n "$NS" link set lo up
    ip -n "$NS" route add default via "$HOSTIP"
    # The other egresses' bridges stay reachable once the tunnel takes the
    # default route (AmneziaWG's WARP port falls back through TrustTunnel's).
    ip -n "$NS" route add "$EGRESS_NET" via "$HOSTIP"
    # No global IPv6 on this box; an enabled stack only produces instant
    # EHOSTUNREACH on AAAA addresses (the trap that held AdGuard for 6.5 h).
    ip netns exec "$NS" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    ip netns exec "$NS" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
    iptables -t nat -A POSTROUTING -s "$SUB" -o "$WAN" -j MASQUERADE
    iptables -I FORWARD 1 -d "$SUB" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -I FORWARD 2 -s "$SUB" -j ACCEPT
    # sing-box's auto_route grabs forwarded traffic too; without this the
    # cascade would ride inside AdGuard and not be a second path at all.
    ip rule add from "$SUB" priority 40 lookup main
    # ...and only main: if main has no way there (no WAN yet, a lease
    # lapsing), refuse rather than fall through to sing-box's tunnel. A
    # packet routed there leaves un-NATed and conntrack keeps the flow so
    # for as long as the tunnel keeps sending -- see wait_wan.
    ip rule add from "$SUB" priority 41 unreachable
    # A flow left over from before (a previous run, a WAN flap) may have been
    # recorded without NAT; it would keep its private source for good.
    command -v conntrack >/dev/null && conntrack -D -s "$NSIP" >/dev/null 2>&1
    # Fail closed in the kernel: whatever runs as BRIDGE_UID may answer the
    # host over the veth but never leave through it.
    ip netns exec "$NS" iptables -A OUTPUT -o "$VETH_NS" -d "$EGRESS_NET" -j ACCEPT
    ip netns exec "$NS" iptables -A OUTPUT -o "$VETH_NS" -m owner --uid-owner $BRIDGE_UID \
        -j REJECT --reject-with icmp-host-unreachable
}

# ── AmneziaWG: userspace amneziawg-go, configured with awg, plus a SOCKS bridge
run_amnezia() {
    local facts pids
    umask 077
    facts=$(python3 /opt/shunt/scripts/egress_config.py awg "$CFG/awg.conf" "$RUN/setconf.conf" \
        /opt/shunt/config/settings.json) || exit 1
    eval "$facts"   # ADDRESS MTU DNS ENDPOINT_IP ENDPOINT_PORT
    ip netns exec "$NS" env WG_PROCESS_FOREGROUND=1 "$BIN/amneziawg-go" awg0 &
    pids=$!
    for _ in $(seq 50); do ip -n "$NS" link show awg0 >/dev/null 2>&1 && break; sleep 0.2; done
    ip netns exec "$NS" "$BIN/awg" setconf awg0 "$RUN/setconf.conf" || exit 1
    rm -f "$RUN/setconf.conf"           # the private key need not outlive setconf
    ip -n "$NS" addr add "$ADDRESS" dev awg0
    ip -n "$NS" link set awg0 mtu "$MTU" up
    ip -n "$NS" route add "$ENDPOINT_IP/32" via "$HOSTIP"
    ip -n "$NS" route replace default dev awg0
    # A second port leads to Cloudflare WARP on the Miami server (warp-relay
    # there, reachable only through this tunnel): the "warp" egress. TCP only
    # -- the WARP client's proxy does not carry UDP; QUIC falls back to TCP.
    #
    # WARP is handed the site's name, not its address: the house's xray passes
    # on the IPv4 address the device dialled, and WARP then leaves through its
    # IPv4 pool -- which Google places in Iran ("IRN", 2026-10-20), refused by
    # Gemini like Russia. Given a name, WARP resolves it itself and leaves over
    # IPv6, which Google places in the USA. So this inbound reads the name from
    # the TLS or HTTP start and sends that on.
    #
    # WARP lives in Miami, so it dies with this tunnel unless there is a
    # second road there (2026-10-22: AWG down 9 hours, Google rules fell back
    # to the house egress and Gemini saw Russia). TrustTunnel's bridge offers
    # the same relay on its own WARP port: the observatory watches the road
    # through AWG, and while it does not answer the balancer takes TT's.
    cat > "$RUN/bridge.json" <<JSON
{"log": {"loglevel": "warning"},
 "dns": {"servers": ["${DNS:-1.1.1.1}"]},
 "inbounds": [{"tag": "socks-in", "listen": "$NSIP", "port": $PORT,
               "protocol": "socks", "settings": {"auth": "noauth", "udp": true}},
              {"tag": "warp-in", "listen": "$NSIP", "port": $WARP_PORT,
               "protocol": "socks", "settings": {"auth": "noauth", "udp": false},
               "sniffing": {"enabled": true, "destOverride": ["http", "tls"], "routeOnly": false}}],
 "outbounds": [{"protocol": "freedom", "tag": "out", "settings": {"domainStrategy": "UseIP"}},
               {"protocol": "socks", "tag": "relay-awg",
                "settings": {"servers": [{"address": "$WARP_RELAY_HOST", "port": $WARP_RELAY_PORT}]}},
               {"protocol": "socks", "tag": "relay-tt",
                "settings": {"servers": [{"address": "$TT_NSIP", "port": $WARP_PORT}]}}],
 "observatory": {"subjectSelector": ["relay-awg"], "probeURL": "https://www.google.com/generate_204",
                 "probeInterval": "15s"},
 "routing": {"balancers": [{"tag": "warp", "selector": ["relay-awg"], "fallbackTag": "relay-tt"}],
             "rules": [{"type": "field", "inboundTag": ["warp-in"], "balancerTag": "warp"}]}}
JSON
    chmod 644 "$RUN/bridge.json"; chmod 711 "$RUN"
    ip netns exec "$NS" setpriv --reuid=$BRIDGE_UID --regid=$BRIDGE_UID --clear-groups \
        /opt/shunt/bin/xray run -config "$RUN/bridge.json" &
    pids="$pids $!"
    # Either half dying is the egress dying: exit and let systemd restart both.
    wait -n $pids
    kill $pids 2>/dev/null
    exit 1
}

# ── TrustTunnel: the client listens on the namespace's loopback; a bridge
# exposes it on the veth like every other egress, as a plain SOCKS address.
run_trusttunnel() {
    local proto pids
    umask 077
    proto=$(cat "$CFG/upstream" 2>/dev/null || echo http3)
    "$BIN/setup_wizard" --mode non-interactive --endpoint_config "$CFG/endpoint.toml" \
        --settings "$RUN/wizard.toml" >/dev/null 2>&1 || exit 1
    python3 /opt/shunt/scripts/egress_config.py tt "$RUN/wizard.toml" "$RUN/client.toml" \
        127.0.0.1:1085 "$proto" /opt/shunt/config/settings.json || exit 1
    rm -f "$RUN/wizard.toml"
    ip netns exec "$NS" "$BIN/trusttunnel_client" --config "$RUN/client.toml" &
    pids=$!
    # Its WARP port is AmneziaWG's second road to the relay in Miami (see
    # run_amnezia): the relay reached through this tunnel. Riga lets TT reach
    # that one private address and no other (allow_private_network_connections
    # plus an nft output rule there, 2026-10-22).
    cat > "$RUN/bridge.json" <<JSON
{"log": {"loglevel": "warning"},
 "inbounds": [{"tag": "socks-in", "listen": "$NSIP", "port": $PORT,
               "protocol": "socks", "settings": {"auth": "noauth", "udp": true}},
              {"tag": "warp-in", "listen": "$NSIP", "port": $WARP_PORT,
               "protocol": "socks", "settings": {"auth": "noauth", "udp": false},
               "sniffing": {"enabled": true, "destOverride": ["http", "tls"], "routeOnly": false}}],
 "outbounds": [{"protocol": "socks", "tag": "out",
                "settings": {"servers": [{"address": "127.0.0.1", "port": 1085}]}},
               {"protocol": "socks", "tag": "warp",
                "settings": {"servers": [{"address": "$WARP_RELAY_HOST", "port": $WARP_RELAY_PORT}]},
                "proxySettings": {"tag": "out"}}],
 "routing": {"rules": [{"type": "field", "inboundTag": ["warp-in"], "outboundTag": "warp"}]}}
JSON
    chmod 644 "$RUN/bridge.json"; chmod 711 "$RUN"
    ip netns exec "$NS" setpriv --reuid=$BRIDGE_UID --regid=$BRIDGE_UID --clear-groups \
        /opt/shunt/bin/xray run -config "$RUN/bridge.json" &
    pids="$pids $!"
    wait -n $pids
    kill $pids 2>/dev/null
    exit 1
}

teardown() {
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null
    sleep 0.5
    ip netns pids "$NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    ip link del "$VETH" 2>/dev/null
    ip rule del from "$SUB" priority 40 lookup main 2>/dev/null
    ip rule del from "$SUB" priority 41 unreachable 2>/dev/null
    iptables -t nat -D POSTROUTING -s "$SUB" -o "$WAN" -j MASQUERADE 2>/dev/null
    iptables -D FORWARD -d "$SUB" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    iptables -D FORWARD -s "$SUB" -j ACCEPT 2>/dev/null
    [ "$NAME" = amnezia ] && rm -f /var/run/amneziawg/awg0.sock
    rm -rf "$RUN"
}

status() {
    echo "  netns:  $(ip netns list 2>/dev/null | grep -cw "$NS")"
    echo "  socks:  $(ip netns exec "$NS" ss -tlnH 2>/dev/null | grep -c "$NSIP:$PORT") on $NSIP:$PORT"
    if [ "$NAME" = amnezia ]; then
        local t
        t=$(ip netns exec "$NS" "$BIN/awg" show awg0 latest-handshakes 2>/dev/null | awk '{print $2; exit}')
        [ -n "$t" ] && [ "$t" != 0 ] && echo "  handshake: $(( $(date +%s) - t ))s ago" || echo "  handshake: none"
    fi
}

case "$ACTION" in
    setup) setup ;;
    run) "run_$NAME" ;;
    teardown) teardown ;;
    status) status ;;
    *) echo "usage: $0 <amnezia|trusttunnel> {setup|run|teardown|status}" >&2; exit 2 ;;
esac
