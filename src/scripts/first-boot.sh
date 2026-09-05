#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Shunt — first boot setup
# Runs once after Ubuntu autoinstall, via shunt-first-boot.service.
# Detects the LAN interface, runs install.sh, then disables itself.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

LOG=/var/log/shunt-first-boot.log
exec > >(tee -a "$LOG") 2>&1

STAMP=/opt/shunt/.installed
SRC=/opt/shunt-src

echo "════════════════════════════════════════════════"
echo " Xray Proxy — first-boot setup  $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "════════════════════════════════════════════════"

# ── Guard: skip if already installed ─────────────────────────────────────────
if [[ -f "$STAMP" ]]; then
    echo "[skip] Already installed (found $STAMP). Exiting."
    systemctl disable shunt-first-boot.service 2>/dev/null || true
    exit 0
fi

# ── Require source tree ───────────────────────────────────────────────────────
if [[ ! -d "$SRC" ]]; then
    echo "[ERROR] Source directory $SRC not found."
    echo "        During autoinstall, the CIDATA USB must contain shunt/"
    echo "        which gets copied to /opt/shunt-src by late-commands."
    exit 1
fi

# ── Wait for network (DHCP can take a few seconds after boot) ────────────────
echo "[+] Waiting for network..."
for i in $(seq 1 30); do
    ip route show default &>/dev/null && break
    sleep 2
done
ip route show default &>/dev/null || { echo "[ERROR] No default route after 60s"; exit 1; }

echo "[+] Network ready"
ip route show default
ip -4 addr show

# ── Run install.sh from source tree ──────────────────────────────────────────
# install.sh auto-detects LAN_IF and ROUTER_IP, then writes them to
# /opt/shunt/config/network.conf for iptables.sh and dnsmasq.
echo "[+] Running install.sh..."
bash "$SRC/install.sh"

# ── Mark as installed ─────────────────────────────────────────────────────────
touch "$STAMP"
echo "[+] Marked as installed: $STAMP"

# ── Self-disable ──────────────────────────────────────────────────────────────
systemctl disable shunt-first-boot.service
echo "[+] shunt-first-boot.service disabled (will not run again)"

echo ""
echo "════════════════════════════════════════════════"
echo " First-boot complete!"
echo " Open http://$(ip -4 addr show | grep -oP '(?<=inet )[\d.]+' | grep -v 127 | head -1)"
echo " Login: admin / admin   (change in Settings)"
echo "════════════════════════════════════════════════"
