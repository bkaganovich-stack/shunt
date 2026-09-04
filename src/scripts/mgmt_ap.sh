#!/usr/bin/env bash
# Out-of-band management Wi-Fi AP for the gateway.
#
# Brings up an isolated, management-only access point on the built-in Wi-Fi
# (Intel 3165 / wlan0). Lets you reach the web UI at http://192.168.99.1 from
# a phone/laptop without depending on the wired topology — a rescue channel
# that survives interface/topology switches.
#
# Isolated by design:
#   * static 192.168.99.1/24 on wlan0 (no overlap with LAN/router subnets)
#   * its own DHCP via a DEDICATED dnsmasq instance (DHCP-only, port=0) so the
#     production DNS dnsmasq is never touched
#   * management-only: AP clients reach the gateway itself, their traffic is
#     NOT forwarded/proxied to the internet (minimal attack surface)
#
# Usage: mgmt_ap.sh up | down | status
set -euo pipefail

# Auto-detect the wireless interface to run the AP on.
# Prefer a NON-iwlwifi radio: the built-in Intel 3165 advertises AP but its
# firmware tears the AP down ~2s after START_AP (won't beacon). An external
# ath9k_htc / rtl* / mt7* dongle is the real AP. Fall back to whatever exists.
AP_IF="${AP_IF:-}"
if [ -z "$AP_IF" ]; then
    fallback=""
    for d in /sys/class/net/*/wireless; do
        [ -e "$d" ] || continue
        ifn=$(basename "$(dirname "$d")")
        drv=$(basename "$(readlink -f "$(dirname "$d")/device/driver" 2>/dev/null)" 2>/dev/null)
        [ -z "$fallback" ] && fallback="$ifn"
        if [ "$drv" != "iwlwifi" ]; then AP_IF="$ifn"; break; fi
    done
    [ -z "$AP_IF" ] && AP_IF="$fallback"
fi
AP_IP=192.168.99.1
AP_CIDR=24
DHCP_START=192.168.99.10
DHCP_END=192.168.99.50
HOSTAPD_CONF=/opt/xray-proxy/config/mgmt-ap-hostapd.conf
DNSMASQ_PID=/run/mgmt-ap-dnsmasq.pid
HOSTAPD_PID=/run/mgmt-ap-hostapd.pid

ACTION="${1:-status}"

ap_down() {
    [ -f "$HOSTAPD_PID" ] && kill "$(cat $HOSTAPD_PID)" 2>/dev/null || true
    [ -f "$DNSMASQ_PID" ] && kill "$(cat $DNSMASQ_PID)" 2>/dev/null || true
    pkill -f "mgmt-ap-hostapd.conf" 2>/dev/null || true
    pkill -f "dnsmasq.*mgmt-ap" 2>/dev/null || true
    rm -f "$HOSTAPD_PID" "$DNSMASQ_PID"
    ip addr flush dev "$AP_IF" 2>/dev/null || true
    ip link set "$AP_IF" down 2>/dev/null || true
    echo "mgmt-AP down"
}

ap_status() {
    if pgrep -f "mgmt-ap-hostapd.conf" >/dev/null 2>&1; then
        echo "running"
        ip -br addr show "$AP_IF" 2>/dev/null || true
    else
        echo "stopped"
    fi
}

ap_up() {
    [ -f "$HOSTAPD_CONF" ] || { echo "ERROR: $HOSTAPD_CONF not found (generate it first)"; exit 1; }
    [ -d "/sys/class/net/$AP_IF" ] || { echo "ERROR: $AP_IF not present (Wi-Fi firmware?)"; exit 1; }

    rfkill unblock wifi 2>/dev/null || true
    # Free the radio from any station-mode manager (EBUSY on AP otherwise)
    pkill -f "wpa_supplicant.*$AP_IF" 2>/dev/null || true
    # Lift the world-domain "00" no-IR ban so the AP may transmit/beacon
    iw reg set "${AP_COUNTRY:-RU}" 2>/dev/null || true
    # Point hostapd at the detected interface (names vary by adapter/MAC)
    sed -i "s/^interface=.*/interface=$AP_IF/" "$HOSTAPD_CONF"
    ap_down 2>/dev/null || true
    sleep 1

    # L3 on the AP interface
    ip addr add "$AP_IP/$AP_CIDR" dev "$AP_IF"
    ip link set "$AP_IF" up

    # Dedicated DHCP-only dnsmasq (port=0 disables DNS → no clash with prod DNS)
    dnsmasq --port=0 \
        --interface="$AP_IF" --bind-interfaces \
        --dhcp-range="$DHCP_START,$DHCP_END,255.255.255.0,12h" \
        --dhcp-option=3,"$AP_IP" \
        --dhcp-authoritative \
        --pid-file="$DNSMASQ_PID" \
        --log-facility=/opt/xray-proxy/logs/mgmt-ap-dnsmasq.log \
        --conf-file=/dev/null \
        --dhcp-leasefile=/run/mgmt-ap.leases \
        --except-interface=lo

    # hostapd (foreground -B = daemonize)
    hostapd -B -P "$HOSTAPD_PID" "$HOSTAPD_CONF"

    echo "mgmt-AP up: SSID see $HOSTAPD_CONF, UI at http://$AP_IP"
}

case "$ACTION" in
    up)     ap_up ;;
    down)   ap_down ;;
    status) ap_status ;;
    *)      echo "usage: $0 up|down|status"; exit 1 ;;
esac
