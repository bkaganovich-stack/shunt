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
WAN=$(ip route show default | awk '/default/{print $5; exit}')

# One /30 per egress inside 192.168.244.0/28, which iptables.sh excludes from
# TPROXY as a whole (.0/30 is FPTN's).
case "$NAME" in
    amnezia)     NS=amnezia;     TAG=am; SUB=192.168.244.4/30; HOSTIP=192.168.244.5; NSIP=192.168.244.6;  PORT=1083 ;;
    trusttunnel) NS=trusttunnel; TAG=tt; SUB=192.168.244.8/30; HOSTIP=192.168.244.9; NSIP=192.168.244.10; PORT=1084 ;;
    *) echo "usage: $0 <amnezia|trusttunnel> {setup|run|teardown|status}" >&2; exit 2 ;;
esac
VETH=veg-$TAG; VETH_NS=veg-$TAG-ns

setup() {
    teardown >/dev/null 2>&1
    install -d -m 700 "$RUN"
    ip netns add "$NS"
    ip link add "$VETH" type veth peer name "$VETH_NS"
    ip link set "$VETH_NS" netns "$NS"
    ip addr add "$HOSTIP/30" dev "$VETH" && ip link set "$VETH" up
    ip -n "$NS" addr add "$NSIP/30" dev "$VETH_NS"
    ip -n "$NS" link set "$VETH_NS" up
    ip -n "$NS" link set lo up
    ip -n "$NS" route add default via "$HOSTIP"
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
    # Fail closed in the kernel: whatever runs as BRIDGE_UID may answer the
    # host over the veth but never leave through it.
    ip netns exec "$NS" iptables -A OUTPUT -o "$VETH_NS" -d "$SUB" -j ACCEPT
    ip netns exec "$NS" iptables -A OUTPUT -o "$VETH_NS" -m owner --uid-owner $BRIDGE_UID \
        -j REJECT --reject-with icmp-host-unreachable
}

# ── AmneziaWG: userspace amneziawg-go, configured with awg, plus a SOCKS bridge
run_amnezia() {
    local facts pids
    umask 077
    facts=$(python3 /opt/shunt/scripts/egress_config.py awg "$CFG/awg.conf" "$RUN/setconf.conf") || exit 1
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
    cat > "$RUN/bridge.json" <<JSON
{"log": {"loglevel": "warning"},
 "dns": {"servers": ["${DNS:-1.1.1.1}"]},
 "inbounds": [{"tag": "socks-in", "listen": "$NSIP", "port": $PORT,
               "protocol": "socks", "settings": {"auth": "noauth", "udp": true}}],
 "outbounds": [{"protocol": "freedom", "tag": "out", "settings": {"domainStrategy": "UseIP"}}]}
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
        127.0.0.1:1085 "$proto" || exit 1
    rm -f "$RUN/wizard.toml"
    ip netns exec "$NS" "$BIN/trusttunnel_client" --config "$RUN/client.toml" &
    pids=$!
    cat > "$RUN/bridge.json" <<JSON
{"log": {"loglevel": "warning"},
 "inbounds": [{"tag": "socks-in", "listen": "$NSIP", "port": $PORT,
               "protocol": "socks", "settings": {"auth": "noauth", "udp": true}}],
 "outbounds": [{"protocol": "socks", "tag": "out",
                "settings": {"servers": [{"address": "127.0.0.1", "port": 1085}]}}]}
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
