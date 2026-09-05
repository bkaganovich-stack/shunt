#!/bin/bash
# FPTN as a second egress, isolated in a netns.
#
# The client rewrites host routing and /etc/resolv.conf and, when its tunnel
# fails to come up, silently egresses DIRECTLY instead of blocking — measured on
# 2026-09-04, where USA-1 left traffic on the ISP's own address. So it runs in a
# namespace, and the SOCKS bridge is bound to the tunnel interface: no tunnel,
# no egress, rather than a silent leak.
set -u
NS=fptn
SUB=192.168.244.0/30
HOSTIP=192.168.244.1
NSIP=192.168.244.2
WAN=$(ip route show default | awk '/default/{print $5; exit}')
TUN=fptn0
SOCKS_PORT=1082
TUN_IP=10.77.0.1          # bind the bridge to this; gone with the tunnel
BRIDGE_UID=65534          # nobody: the bridge needs no privileges
CONF=/opt/shunt/config/fptn-socks.json
SERVER=$(cat /opt/shunt/config/fptn-server 2>/dev/null || echo USA-2)

setup() {
    teardown >/dev/null 2>&1
    ip netns add $NS
    ip link add veth-fptn type veth peer name veth-fptn-ns
    ip link set veth-fptn-ns netns $NS
    ip addr add $HOSTIP/30 dev veth-fptn && ip link set veth-fptn up
    ip netns exec $NS ip addr add $NSIP/30 dev veth-fptn-ns
    ip netns exec $NS ip link set veth-fptn-ns up
    ip netns exec $NS ip link set lo up
    ip netns exec $NS ip route add default via $HOSTIP
    # No global IPv6 exists on this box; leaving it enabled makes the client try
    # AAAA addresses and fail instantly with EHOSTUNREACH (the same trap that
    # kept AdGuard from reconnecting for 6.5 hours on Sep 3).
    ip netns exec $NS sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    ip netns exec $NS sysctl -qw net.ipv6.conf.default.disable_ipv6=1
    iptables -t nat -A POSTROUTING -s $SUB -o "$WAN" -j MASQUERADE
    iptables -I FORWARD 1 -d $SUB -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -I FORWARD 2 -s $SUB -j ACCEPT
    # The TPROXY exclusion for this subnet lives in iptables.sh, which owns the
    # chain: adding it here as well meant teardown deleted a rule this script
    # did not create, and 36 restart cycles silently stripped the primary
    # egress's protection.
    iptables -t nat -I PREROUTING 1 -s $SUB -p udp --dport 53 -j RETURN
    iptables -t nat -I PREROUTING 2 -s $SUB -p tcp --dport 53 -j RETURN
    # sing-box's auto_route rules also grab forwarded traffic; without this the
    # namespace would egress through AdGuard and the "second" egress would not
    # be independent at all.
    ip rule add from $SUB priority 40 lookup main
    # Fail closed at the kernel, not by trusting the app: the bridge runs as
    # BRIDGE_UID and is refused any egress over the veth, so if the tunnel is
    # absent (it starts before the client connects) traffic stops instead of
    # leaking to the ISP address — measured leaking on the first attempt.
    # The bridge answers the host's SOCKS client over the veth, so that traffic
    # must stay allowed — the first version of this rule blocked those replies
    # and the bridge looked dead while the real egress was never the problem.
    ip netns exec $NS iptables -A OUTPUT -o veth-fptn-ns -d $SUB -j ACCEPT
    ip netns exec $NS iptables -A OUTPUT -o veth-fptn-ns -m owner --uid-owner $BRIDGE_UID \
        -j REJECT --reject-with icmp-host-unreachable
    mkdir -p /etc/netns/$NS && echo "nameserver $HOSTIP" > /etc/netns/$NS/resolv.conf
    sed "s|^LISTEN = .*|LISTEN = [(\"$HOSTIP\", 53)]|" /opt/shunt/doh_proxy.py > /opt/shunt/doh_proxy_ns.py
    systemctl reset-failed fptn-ns-dns 2>/dev/null
    systemd-run --unit fptn-ns-dns --collect /usr/bin/python3 /opt/shunt/doh_proxy_ns.py >/dev/null 2>&1
}

bridge() {
    # No binding in the app at all. Both attempts at one failed: SO_BINDTODEVICE
    # needs CAP_NET_RAW the unprivileged bridge lacks, and binding the source
    # address fails because the tunnel's default route is scope-link with no
    # gateway. Fail-closed comes from the kernel instead: the bridge's uid is
    # refused egress on the veth, so it can only leave through the tunnel's
    # default route, and when the tunnel dies that route falls back to the veth
    # and the traffic is rejected rather than leaked.
    cat > "$CONF" <<EOF
{
  "log": {"loglevel": "warning"},
  "dns": {"servers": ["172.20.0.1"]},
  "inbounds": [{
    "tag": "socks-in", "listen": "$NSIP", "port": $SOCKS_PORT,
    "protocol": "socks", "settings": {"auth": "noauth", "udp": true}
  }],
  "outbounds": [{
    "protocol": "freedom", "tag": "out",
    "settings": {"domainStrategy": "UseIP"}
  }]
}
EOF
    ip netns exec $NS setpriv --reuid=$BRIDGE_UID --regid=$BRIDGE_UID --clear-groups \
        /opt/shunt/bin/xray run -config "$CONF" &
    echo $! > /run/fptn-bridge.pid
}

run() {
    bridge
    exec ip netns exec $NS /usr/bin/fptn-client-cli \
        --access-token "$(cat /etc/fptn-client/token)" \
        --out-network-interface veth-fptn-ns \
        --gateway-ip $HOSTIP \
        --tun-interface-name $TUN \
        --tun-interface-ip $TUN_IP \
        --preferred-server "$SERVER" \
        --enable-ad-block false \
        --blacklist-domains ""
}

teardown() {
    [ -f /run/fptn-bridge.pid ] && kill "$(cat /run/fptn-bridge.pid)" 2>/dev/null
    rm -f /run/fptn-bridge.pid
    pkill -9 -f 'fptn-client-cli' 2>/dev/null
    systemctl stop fptn-ns-dns 2>/dev/null; systemctl reset-failed fptn-ns-dns 2>/dev/null
    ip netns del $NS 2>/dev/null
    ip link del veth-fptn 2>/dev/null
    ip rule del from $SUB priority 40 lookup main 2>/dev/null
    iptables -t nat -D POSTROUTING -s $SUB -o "$WAN" -j MASQUERADE 2>/dev/null
    iptables -t nat -D PREROUTING -s $SUB -p udp --dport 53 -j RETURN 2>/dev/null
    iptables -t nat -D PREROUTING -s $SUB -p tcp --dport 53 -j RETURN 2>/dev/null
    iptables -D FORWARD -d $SUB -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    iptables -D FORWARD -s $SUB -j ACCEPT 2>/dev/null
    rm -rf /etc/netns/$NS /opt/shunt/doh_proxy_ns.py
}

status() {
    echo "  netns:    $(ip netns list 2>/dev/null | grep -c $NS)"
    echo "  tun:      $(ip netns exec $NS ip -br addr show $TUN 2>/dev/null | awk '{print $1, $3}' || echo 'нет')"
    echo "  bridge:   $(ip netns exec $NS ss -tln 2>/dev/null | grep -c ":$SOCKS_PORT")"
    echo "  server:   $SERVER"
}

case "${1:-}" in
    setup) setup ;;
    run) run ;;
    teardown) teardown ;;
    status) status ;;
    *) echo "usage: $0 {setup|run|teardown|status}"; exit 1 ;;
esac
