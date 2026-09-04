#!/usr/bin/env bash
# iptables TProxy setup for xray-core transparent proxy
# Called by xray-proxy.service ExecStartPost / ExecStopPost
set -euo pipefail

ACTION="${1:-up}"
TPROXY_PORT=12345
TPROXY_MARK=1
XRAY_MARK=255   # mark on xray's own outbound sockets (set in xray config)

# ── Resolve topology + interfaces ─────────────────────────────────────────────
# Priority 1: network.conf written by install.sh / switch scripts
NET_CONF=/opt/xray-proxy/config/network.conf
if [[ -f "$NET_CONF" ]] && grep -q '^LAN_IF=' "$NET_CONF"; then
    # shellcheck source=/dev/null
    source "$NET_CONF"
fi

# TOPOLOGY=loop   : single NIC, gateway sits inside the router's LAN (hairpin).
#                   The router does the final NAT to the internet.
# TOPOLOGY=inline : gateway sits between ISP and router. LAN_IF faces the router
#                   (forwarded traffic enters here), WAN_IF faces the ISP and is
#                   where the gateway MASQUERADEs everything to the internet.
TOPOLOGY="${TOPOLOGY:-loop}"

# Priority 2: environment variable.  Priority 3: auto-detect from default route.
if [[ -z "${LAN_IF:-}" ]]; then
    LAN_IF=$(ip route show default 2>/dev/null \
             | awk 'NR==1{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); break}}')
fi

[[ -z "${LAN_IF:-}" || "$LAN_IF" == "lo" ]] && \
    { echo "ERROR: cannot resolve LAN interface (set LAN_IF in $NET_CONF)"; exit 1; }

if [[ "$TOPOLOGY" == "inline" ]]; then
    [[ -z "${WAN_IF:-}" ]] && \
        { echo "ERROR: inline topology needs WAN_IF in $NET_CONF"; exit 1; }
    EGRESS_IF="$WAN_IF"   # internet-facing interface to MASQUERADE on
else
    EGRESS_IF="$LAN_IF"   # loop: same NIC carries egress (router NATs upstream)
fi

# Detect gateway IP dynamically so rules work on any device. Only used by the
# legacy LAN_IP-specific DNS-redirect cleanup; the active rules don't need it.
# In inline the LAN may have no IP until its carrier is up, so this is NOT fatal.
LAN_IP=$(ip -4 addr show "$LAN_IF" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1 || true)
[ -n "$LAN_IP" ] || LAN_IP="0.0.0.0"

AGVPN_SOCKS_PORT=${AGVPN_SOCKS_PORT:-1081}

flush_rules() {
    iptables -t mangle -D PREROUTING -j XRAY_PREROUTING 2>/dev/null || true
    iptables -t mangle -D OUTPUT     -j XRAY_OUTPUT     2>/dev/null || true
    iptables -t mangle -F XRAY_PREROUTING 2>/dev/null || true
    iptables -t mangle -F XRAY_OUTPUT     2>/dev/null || true
    iptables -t mangle -X XRAY_PREROUTING 2>/dev/null || true
    iptables -t mangle -X XRAY_OUTPUT     2>/dev/null || true
    iptables -t mangle -D OUTPUT -j XRAY_ACCT 2>/dev/null || true
    iptables -t mangle -D INPUT  -j XRAY_ACCT 2>/dev/null || true
    iptables -t mangle -F XRAY_ACCT 2>/dev/null || true
    iptables -t mangle -X XRAY_ACCT 2>/dev/null || true
    ip rule  del fwmark $TPROXY_MARK table 100 2>/dev/null || true
    ip rule  del to 1.1.1.1/32 priority 50 lookup main 2>/dev/null || true
    ip rule  del to 1.0.0.1/32 priority 50 lookup main 2>/dev/null || true
    ip rule  del uidrange 994-994 priority 50 lookup main 2>/dev/null || true
    ip rule  del fwmark 0xff priority 40 lookup main 2>/dev/null || true
    ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
    # DNS redirect cleanup — both old (LAN_IP-specific) and new (any dst) forms
    iptables -t mangle -D XRAY_PREROUTING -p udp --dport 53 -j RETURN 2>/dev/null || true
    iptables -t mangle -D XRAY_PREROUTING -p tcp --dport 53 -j RETURN 2>/dev/null || true
    iptables -t nat -D PREROUTING -p udp --dport 53 -d "$LAN_IP" -j REDIRECT --to-port 5335 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 53 -d "$LAN_IP" -j REDIRECT --to-port 5335 2>/dev/null || true
    iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5335 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5335 2>/dev/null || true
    # FCM bypass cleanup (try both possible egress interfaces)
    iptables -t nat -D POSTROUTING -o "$LAN_IF" -p tcp --dport 5228 -j MASQUERADE 2>/dev/null || true
    [[ -n "${WAN_IF:-}" ]] && iptables -t nat -D POSTROUTING -o "$WAN_IF" -p tcp --dport 5228 -j MASQUERADE 2>/dev/null || true
    # inline general MASQUERADE + WAN edge-firewall cleanup — UNCONDITIONAL:
    # scan the live ruleset and remove these on WHATEVER interface they sit on, instead of
    # relying on the current WAN_IF. In loop WAN_IF is empty, so a left-over inline rule on
    # the old WAN (e.g. enx) would otherwise persist — that DROP answered ICMP but blocked
    # new TCP:22 and locked out SSH after a rollback (the 2026-06-20 rollback bug).
    for _if in $(iptables -t nat -S POSTROUTING 2>/dev/null | grep -oP '(?<=-o )\S+(?= -j MASQUERADE)' | sort -u || true); do
        iptables -t nat -D POSTROUTING -o "$_if" -j MASQUERADE 2>/dev/null || true
    done
    for _if in $(iptables -S INPUT 2>/dev/null | grep -oP '(?<=-i )\S+(?= -j DROP)' | sort -u || true); do
        iptables -D INPUT -i "$_if" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -i "$_if" -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -i "$_if" -j DROP 2>/dev/null || true
    done
    for _if in $(iptables -S FORWARD 2>/dev/null | grep -oP '(?<=-i )\S+(?= -j DROP)' | sort -u || true); do
        iptables -D FORWARD -i "$_if" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -i "$_if" -j DROP 2>/dev/null || true
    done
}

if [ "$ACTION" = "down" ]; then
    flush_rules
    echo "iptables TProxy rules removed"
    exit 0
fi

# ── UP ──────────────────────────────────────────────────────────────────────

# Kernel requirements
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.conf.all.route_localnet=1
sysctl -qw net.ipv4.conf.$LAN_IF.route_localnet=1

# Clean up any stale rules
flush_rules

# IP rule: packets marked with TPROXY_MARK go to local loopback (table 100)
ip rule  add fwmark $TPROXY_MARK table 100 priority 100
# DoH resolvers reached DIRECT (RU-ISP vantage) so Cloudflare returns Russian
# CDN IPs for .ru services (avito/banks). Via the VPN it returned foreign nodes
# that silently drop RU-ISP clients -> broken avito photos (fixed 2026-07-09).
# xray marks its own outbound sockets with $XRAY_MARK so they can leave the box
# directly. Without a rule sending that mark to the main table they fall through
# to sing-box's auto_route rule 9003 ("from 0.0.0.0 iif lo lookup 2022"), get a
# source address of 172.19.0.1 and re-enter tun0 — a loop that surfaces as a
# storm of "no route to host" on outbound/direct[bypass] and kills all direct
# (i.e. Russian) traffic while the tunnelled path keeps working.
ip rule  add fwmark 0xff priority 40 lookup main 2>/dev/null || true
ip rule  add to 1.1.1.1/32 priority 50 lookup main 2>/dev/null || true
ip rule  add to 1.0.0.1/32 priority 50 lookup main 2>/dev/null || true
ip rule  add uidrange 994-994 priority 50 lookup main 2>/dev/null || true   # AdGuard CLI (agvpn) egress -> direct
ip route add local 0.0.0.0/0 dev lo table 100

# ── PREROUTING: intercept forwarded LAN traffic ────────────────────────────
iptables -t mangle -N XRAY_PREROUTING
iptables -t mangle -A PREROUTING -j XRAY_PREROUTING

# Skip already-marked (xray's own) traffic
# The FPTN second egress lives in a netns on this subnet. Its exclusion belongs
# here, not in fptn-egress.sh: this chain is flushed and rebuilt on every
# xray-proxy restart, so a rule added elsewhere silently disappears and the
# secondary egress starts being TPROXY-ed into the primary one — a second exit
# must never be able to disturb the first.
iptables -t mangle -A XRAY_PREROUTING -s 192.168.244.0/30 -j RETURN
iptables -t mangle -A XRAY_PREROUTING -m mark --mark $XRAY_MARK -j RETURN
# Skip multicast / broadcast
iptables -t mangle -A XRAY_PREROUTING -d 224.0.0.0/4   -j RETURN
iptables -t mangle -A XRAY_PREROUTING -d 240.0.0.0/4   -j RETURN
# Skip private/local destinations (private ranges handled by xray routing)
iptables -t mangle -A XRAY_PREROUTING -d 127.0.0.0/8   -j RETURN
iptables -t mangle -A XRAY_PREROUTING -d 10.0.0.0/8    -j RETURN
iptables -t mangle -A XRAY_PREROUTING -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A XRAY_PREROUTING -d 192.168.0.0/16 -j RETURN
# Skip DHCP
iptables -t mangle -A XRAY_PREROUTING -d 255.255.255.255 -j RETURN
# Skip DNS port 53 — handled separately by nat PREROUTING REDIRECT to dnsmasq.
# This intercepts hardcoded resolvers (8.8.8.8, 8.8.4.4, etc.) before TProxy sees them.
iptables -t mangle -A XRAY_PREROUTING -p udp --dport 53 -j RETURN
iptables -t mangle -A XRAY_PREROUTING -p tcp --dport 53 -j RETURN
# Skip Google FCM (Firebase Cloud Messaging) port 5228 — bypass xray entirely.
# FCM is Google Home's persistent backend connection; routing it through xray caused
# the tunnel to act as a middleman and drop the connection every ~2 minutes, causing
# "Connecting to Home" flashes on Google displays. Direct kernel forwarding + NAT is
# much more stable. MASQUERADE below ensures the reply path is symmetric.
iptables -t mangle -A XRAY_PREROUTING -p tcp --dport 5228 -j RETURN
# TPROXY TCP and UDP to xray
iptables -t mangle -A XRAY_PREROUTING -p tcp -j TPROXY \
    --on-port $TPROXY_PORT --tproxy-mark $TPROXY_MARK
iptables -t mangle -A XRAY_PREROUTING -p udp -j TPROXY \
    --on-port $TPROXY_PORT --tproxy-mark $TPROXY_MARK

# ── OUTPUT: intercept locally-generated traffic (from mini PC itself) ──────
iptables -t mangle -N XRAY_OUTPUT
iptables -t mangle -A OUTPUT -j XRAY_OUTPUT

iptables -t mangle -A XRAY_OUTPUT -m mark --mark $XRAY_MARK -j RETURN
# AdGuard VPN CLI (user agvpn) egress must bypass this tunnel -> DIRECT to reach AdGuard servers (else loop)
iptables -t mangle -A XRAY_OUTPUT -m owner --uid-owner agvpn -j RETURN
iptables -t mangle -A XRAY_OUTPUT -d 224.0.0.0/4   -j RETURN
iptables -t mangle -A XRAY_OUTPUT -d 240.0.0.0/4   -j RETURN
iptables -t mangle -A XRAY_OUTPUT -d 127.0.0.0/8   -j RETURN
iptables -t mangle -A XRAY_OUTPUT -d 10.0.0.0/8    -j RETURN
iptables -t mangle -A XRAY_OUTPUT -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A XRAY_OUTPUT -d 192.168.0.0/16 -j RETURN
# Mark locally-generated traffic → route via loopback → xray
iptables -t mangle -A XRAY_OUTPUT -p tcp -j MARK --set-mark $TPROXY_MARK
iptables -t mangle -A XRAY_OUTPUT -p udp -j MARK --set-mark $TPROXY_MARK


# ── Traffic accounting: bytes entering the tunnel ───────────────────────────
# Counting-only rules (no target), read by the web UI sampler. The VPN/direct
# split cannot be taken from interface counters: proxied and direct traffic
# both leave via the WAN, and tun0 carries only sing-box's own SOCKS inbound.
# xray's "proxy" outbound talks to the AdGuard SOCKS port on loopback, so this
# is the exact payload going through the tunnel, before encryption.
# Xray's own stats API is deliberately NOT used: it leaked file descriptors and
# took the gateway down on Jun-04 (see the note in the config generator).
iptables -t mangle -N XRAY_ACCT
iptables -t mangle -I OUTPUT 1 -j XRAY_ACCT
iptables -t mangle -I INPUT  1 -j XRAY_ACCT
iptables -t mangle -A XRAY_ACCT -o lo -p tcp --dport $AGVPN_SOCKS_PORT -m comment --comment vpn_up
iptables -t mangle -A XRAY_ACCT -i lo -p tcp --sport $AGVPN_SOCKS_PORT -m comment --comment vpn_down


# ── DNS redirect: перехватываем DNS на ЛЮБОЙ адрес → dnsmasq (порт 5335) ───
# Покрывает: $LAN_IP:53 (из DHCP), 8.8.8.8:53, 8.8.4.4:53 и любые хардкод-резолверы.
# DNS-пакеты пропущены через mangle (RETURN выше), поэтому nat PREROUTING их видит.
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5335
iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5335

# ── inline: MASQUERADE all internet-bound traffic on the WAN interface ──────
# In inline topology the gateway is the edge router: traffic it forwards or
# proxies out to the ISP must be source-NATed to the WAN address. In loop mode
# this is skipped — the downstream router performs the final NAT instead.
if [[ "$TOPOLOGY" == "inline" ]]; then
    iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE

    # ── inline WAN edge firewall: default-deny inbound from the internet ──────
    # In inline the WAN port faces the ISP directly, so the admin UI (:80),
    # SSH (:22) and other local services would otherwise be exposed. Allow only
    # replies to traffic we initiated (+ optional ping); drop everything new.
    # Management stays reachable via LAN and the out-of-band Wi-Fi AP, which are
    # different interfaces and untouched by these WAN-scoped rules.
    iptables -A INPUT   -i "$WAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT   -i "$WAN_IF" -p icmp --icmp-type echo-request -j ACCEPT
    iptables -A INPUT   -i "$WAN_IF" -j DROP
    # Forwarded path: let return traffic back to the LAN, block new inbound.
    iptables -A FORWARD -i "$WAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i "$WAN_IF" -j DROP
fi

# ── FCM bypass NAT: MASQUERADE port 5228 forwarded traffic ──────────────────
# Since port 5228 is skipped by TProxy (RETURN above), packets from LAN devices
# to FCM:5228 are forwarded by the kernel. MASQUERADE rewrites the source IP to
# the gateway's own IP so that return traffic comes back through the gateway,
# allowing conntrack to forward replies back to the originating device.
# (Redundant under the inline blanket MASQUERADE above, but harmless and keeps
# loop mode covered.)
iptables -t nat -A POSTROUTING -o "$EGRESS_IF" -p tcp --dport 5228 -j MASQUERADE

echo "iptables TProxy rules installed (topology=$TOPOLOGY, egress=$EGRESS_IF, port=$TPROXY_PORT)"
