#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Xray Proxy Gateway — Installation Script
# Run as root on the mini PC (Ubuntu 26.04+)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
INSTALL_DIR=/opt/xray-proxy
NET_CONF="$INSTALL_DIR/config/network.conf"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step()  { echo -e "\n${YLW}══ $* ══${NC}"; }

[ "$(id -u)" = "0" ] || error "Run as root: sudo bash install.sh"

# ── Detect LAN interface and router IP ────────────────────────────────────────
detect_network() {
    local iface router

    # 1. Interface with default route — the most reliable method
    iface=$(ip route show default 2>/dev/null \
            | awk 'NR==1{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); break}}')

    # 2. Fallback: first physical interface with carrier (link UP)
    if [[ -z "$iface" || "$iface" == "lo" ]]; then
        for p in /sys/class/net/*/carrier; do
            local n; n=$(basename "$(dirname "$p")")
            [[ "$n" == "lo" ]] && continue
            [[ ! -e "/sys/class/net/$n/device" ]] && continue   # skip virtual
            [[ "$(cat "$p" 2>/dev/null)" == "1" ]] && { iface=$n; break; }
        done
    fi

    # 3. Last resort: any physical interface, even without link
    if [[ -z "$iface" || "$iface" == "lo" ]]; then
        for p in /sys/class/net/*/device; do
            local n; n=$(basename "$(dirname "$p")")
            [[ "$n" != "lo" ]] && { iface=$n; break; }
        done
    fi

    [[ -z "$iface" || "$iface" == "lo" ]] && error "Cannot detect LAN interface"

    # Router = default gateway IP
    router=$(ip route show default 2>/dev/null | awk 'NR==1{print $3}')
    [[ -z "$router" ]] && router="192.168.50.1"   # fallback

    LAN_IF="$iface"
    ROUTER_IP="$router"
    info "LAN interface : $LAN_IF"
    info "Router IP     : $ROUTER_IP"

    # Persist so iptables.sh and future scripts can read without re-detecting
    mkdir -p "$INSTALL_DIR/config"
    cat > "$NET_CONF" <<NETEOF
# Auto-detected by install.sh on $(date -u '+%Y-%m-%d %H:%M UTC')
# Edit manually if the values are wrong, then restart xray-proxy.
LAN_IF=$LAN_IF
ROUTER_IP=$ROUTER_IP
NETEOF
    info "Saved to $NET_CONF"
}

detect_network

# ── 1. Stop old services ──────────────────────────────────────────────────────
step "Stopping old services"
systemctl stop sing-box   2>/dev/null || true
systemctl disable sing-box 2>/dev/null || true
systemctl stop portal     2>/dev/null || true
systemctl stop xray-proxy 2>/dev/null || true
systemctl stop xray-web   2>/dev/null || true

# ── 2. System packages ─────────────────────────────────────────────────────────
step "Installing system packages"
apt-get update -qq
apt-get install -y -qq curl python3 python3-pip iptables iproute2 \
    dnsmasq ca-certificates

# ── 3. Python deps ─────────────────────────────────────────────────────────────
step "Installing Python dependencies"
pip3 install -q fastapi uvicorn[standard] python-multipart

# ── 4. Download xray-core ─────────────────────────────────────────────────────
step "Downloading xray-core"
mkdir -p "$INSTALL_DIR/bin"
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  XRAY_ARCH="64"    ;;
    aarch64) XRAY_ARCH="arm64-v8a" ;;
    *)       error "Unsupported arch: $ARCH" ;;
esac

XRAY_API="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
XRAY_TAG=$(curl -sfL "$XRAY_API" | python3 -c "import sys,json;print(json.load(sys.stdin)['tag_name'])")
info "Latest xray-core: $XRAY_TAG"
XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_TAG}/Xray-linux-${XRAY_ARCH}.zip"

TMP=$(mktemp -d); trap "rm -rf $TMP" EXIT
curl -sfL --progress-bar -o "$TMP/xray.zip" "$XRAY_URL"
cd "$TMP" && unzip -q xray.zip
cp xray "$INSTALL_DIR/bin/xray"
chmod +x "$INSTALL_DIR/bin/xray"
"$INSTALL_DIR/bin/xray" version
cd /

# ── 5. Create directory structure ─────────────────────────────────────────────
step "Creating directory structure"
mkdir -p "$INSTALL_DIR"/{bin,config,scripts,web/static,logs}

# ── 6. Copy application files ─────────────────────────────────────────────────
step "Copying application files"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "$SCRIPT_DIR/web/."     "$INSTALL_DIR/web/"
cp -r "$SCRIPT_DIR/scripts/." "$INSTALL_DIR/scripts/"
chmod +x "$INSTALL_DIR/scripts/"*.sh

# ── 7. Generate secret key ────────────────────────────────────────────────────
step "Generating secret key"
if [ ! -f "$INSTALL_DIR/.secret" ]; then
    python3 -c "import secrets; print(secrets.token_hex(32))" > "$INSTALL_DIR/.secret"
    chmod 600 "$INSTALL_DIR/.secret"
    info "New secret key generated"
fi

# ── 8. Download geo files ─────────────────────────────────────────────────────
step "Downloading geo files"
bash "$INSTALL_DIR/scripts/update-geo.sh" || warn "Geo download failed — will retry later"

# ── 9. Generate initial xray config (direct-only until VPN key is set) ────────
step "Generating initial xray config"
python3 - <<'PYEOF'
import json, sys
sys.path.insert(0, '/opt/xray-proxy/web')
from main import build_xray_config, save_settings, DEFAULT_SETTINGS, CFG_DIR, XCFG
import pathlib; pathlib.Path('/opt/xray-proxy/config').mkdir(parents=True, exist_ok=True)
# Write default settings if not present
if not pathlib.Path('/opt/xray-proxy/config/settings.json').exists():
    save_settings(dict(DEFAULT_SETTINGS))
cfg = build_xray_config(DEFAULT_SETTINGS)
XCFG.write_text(json.dumps(cfg, indent=2))
print("xray.json written")
PYEOF

# ── 10. Install dnsmasq config ────────────────────────────────────────────────
step "Configuring dnsmasq"
# Get LAN IP of this machine on the detected interface
LAN_IP=$(ip -4 addr show "$LAN_IF" | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
[[ -z "$LAN_IP" ]] && warn "No IPv4 yet on $LAN_IF — dnsmasq will bind on first-boot"
info "LAN IP: ${LAN_IP:-<pending>}"

cat > /etc/dnsmasq.d/gateway.conf <<DNSEOF
# Listen only on LAN interface
listen-address=${LAN_IP:-127.0.0.1}
bind-interfaces
# Port 5335: avoids conflict with xray TProxy SO_REUSEPORT sockets on *:53
port=5335

# Upstream DNS: router (auto-detected)
server=$ROUTER_IP
no-resolv

# Cache
cache-size=1000
DNSEOF

# Web app now handles /generate_204 and /hotspot-detect.html (no separate portal.py needed)
# Remove old portal.py if present
systemctl stop portal 2>/dev/null || true
systemctl disable portal 2>/dev/null || true
rm -f /etc/systemd/system/portal.service
systemctl daemon-reload 2>/dev/null || true

systemctl enable dnsmasq
systemctl restart dnsmasq

# ── 11. systemd-resolved stub ─────────────────────────────────────────────────
step "Configuring systemd-resolved"
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/no-stub.conf <<EOF
[Resolve]
DNSStubListener=no
DNS=9.9.9.9
EOF
systemctl restart systemd-resolved
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

# ── 12. sysctl ────────────────────────────────────────────────────────────────
step "Enabling IP forwarding"
cat > /etc/sysctl.d/90-xray-proxy.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.route_localnet = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl --system -q

# ── 13. Install systemd services ──────────────────────────────────────────────
step "Installing systemd services"
cp "$SCRIPT_DIR/systemd/xray-proxy.service" /etc/systemd/system/
cp "$SCRIPT_DIR/systemd/xray-web.service"   /etc/systemd/system/
systemctl daemon-reload
systemctl enable xray-proxy xray-web

# ── 14. Weekly geo cron ───────────────────────────────────────────────────────
step "Setting up weekly geo update"
echo "0 3 * * 0 root /opt/xray-proxy/scripts/update-geo.sh && systemctl restart xray-proxy" \
    > /etc/cron.d/xray-geo-update

# ── 15. Start services ────────────────────────────────────────────────────────
step "Starting services"
systemctl start xray-web
sleep 2
systemctl start xray-proxy
sleep 2

# ── 16. Status check ─────────────────────────────────────────────────────────
step "Verifying installation"
echo ""
systemctl is-active xray-web   && info "xray-web   ✓ running" || warn "xray-web   ✗ failed"
systemctl is-active xray-proxy && info "xray-proxy ✓ running" || warn "xray-proxy ✗ check: journalctl -u xray-proxy"
systemctl is-active dnsmasq    && info "dnsmasq    ✓ running" || warn "dnsmasq    ✗ failed"

echo ""
echo -e "${GRN}════════════════════════════════════════${NC}"
echo -e "${GRN} Installation complete!${NC}"
echo -e "${GRN}════════════════════════════════════════${NC}"
echo ""
echo " Web UI:  http://$LAN_IP"
echo " Login:   admin / admin"
echo ""
echo " Next steps:"
echo " 1. Open http://$LAN_IP in browser"
echo " 2. Paste your VPN key"
echo " 3. Choose routing profile"
echo " 4. Change the admin password"
echo ""
