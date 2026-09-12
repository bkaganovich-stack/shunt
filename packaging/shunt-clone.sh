#!/usr/bin/env bash
# Copy one gateway's identity onto another.
#
#   ./packaging/shunt-clone.sh --from bkaganovich@192.168.100.1 --to shunt@192.168.50.42
#
# The target must already be a working Shunt install -- this moves what a fresh
# install cannot know: the household's routing decisions, the AdGuard session,
# the FPTN token, and the handful of files that live on the running gateway and
# in no package.
#
# It deliberately does NOT copy anything that describes the machine rather than
# the household. Interface names are the reason: the live gateway routes between
# enp1s0 and a USB adapter called enx6c1ff7c1784f, and that name is a property
# of one piece of plastic. Copying network.conf onto a box that does not have
# that adapter produces a gateway that believes it has a LAN port it cannot
# find -- which is worse than one that has not been configured at all.
#
# Egress is left STOPPED on the target. One AdGuard session, two machines: the
# live box is carrying a household's internet, and taking its session away is
# not a thing to do as a side effect of copying a file.
#
# Stopped is not enough on its own, which is worth knowing before trusting this:
# egress_watchdog.py runs `systemctl restart adguardvpn` when it thinks egress
# is down, and on the target it would think exactly that. So the automatic
# callers are MASKED, not merely disabled -- the watchdog timer, its service,
# the health monitor's auto-fix, and the FPTN egress unit. A disabled unit is
# one `systemctl start` away from taking the household offline; a masked one
# refuses. The checklist at the end unmasks them in the right order.
set -euo pipefail

SRC="" ; DST="" ; KEY="" ; DRY=0

die() { echo "shunt-clone: $*" >&2; exit 1; }

usage() {
    awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"
    cat <<EOF

  --from USER@HOST   the working gateway to copy from (required)
  --to   USER@HOST   the machine to copy onto (required)
  --identity FILE    ssh private key for both
  --dry-run          list what would be copied, touch nothing
Both ends need passwordless sudo. Nothing is written to this machine's disk:
the files are streamed from one host to the other through a pipe.
EOF
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --from) SRC="$2"; shift 2;;
        --to) DST="$2"; shift 2;;
        --identity) KEY="$2"; shift 2;;
        --dry-run) DRY=1; shift;;
        -h|--help) usage 0;;
        *) echo "shunt-clone: unknown option $1" >&2; usage 1;;
    esac
done
[ -n "$SRC" ] && [ -n "$DST" ] || usage 1

SSHOPTS=(-o ConnectTimeout=10 -o BatchMode=yes)
[ -z "$KEY" ] || SSHOPTS+=(-i "$KEY")
src() { ssh "${SSHOPTS[@]}" "$SRC" "$@"; }
dst() { ssh "${SSHOPTS[@]}" "$DST" "$@"; }

# ── What travels ──────────────────────────────────────────────────────────────
# Split three ways on purpose, because the three have different failure modes:
# software can be reinstalled, identity cannot be regenerated, and settings are
# the only part a person would notice missing.

# Not carried by the shunt package and not on the installer image. Every one of
# these was placed by hand on the live gateway, which is the finding that made
# this script longer than it looked: a fresh install is NOT the gateway.
SOFTWARE=(
    /usr/local/bin/adguardvpn-cli
    /etc/systemd/system/adguardvpn.service
    /etc/systemd/system/shunt-nic-offload.service
    /etc/systemd/system/shunt-offload-watch.service
    /etc/systemd/system/shunt-offload-watch.timer
    /usr/lib/systemd/system/fptn-resolv-heal.service
    /usr/sbin/fptn-resolv-heal
    /usr/bin/fptn-client-cli
    /lib/systemd/system/fptn-client.service
)
# Credentials. These cannot be rebuilt from anything in the repository.
IDENTITY=(
    /etc/fptn-client/client.conf
    /etc/fptn-client/token
    /var/lib/agvpn
)
# The household's decisions: routing profile, custom always-direct list, DNS,
# the web interface's own password, and the management AP's name and key.
SETTINGS=(
    /opt/shunt/config/settings.json
    /opt/shunt/.secret
    /opt/shunt/config/mgmt-ap-hostapd.conf
)
# Named here so that "it was not copied" is a decision on the record rather than
# something discovered later on the new box.
EXCLUDED=(
    "config/network.conf         interface names of the old machine"
    "config/topology-*.json      same, plus a stale target from an older plan"
    "config/netswitch-status.json  a measurement, not a setting"
    "config/xray.json            generated from settings.json"
    "config/inbound.conf         generated from settings.json"
    "config/health-state.json    a measurement"
    "logs/provider*.json         what THIS box saw on the provider's wire"
    "logs/diagnosis.json         same"
    "/etc/machine-id, ssh host keys   identity of the machine, not the household"
)
# AdGuard writes these every minute; they are state, not configuration.
AGEXCL=(--exclude=app.log --exclude=tunnel.log --exclude=vpn.socket
        --exclude=cache_selector.dat)

# ── Preflight ─────────────────────────────────────────────────────────────────
echo "shunt-clone: checking both ends"
src 'sudo -n true' 2>/dev/null || die "no passwordless sudo on $SRC"
dst 'sudo -n true' 2>/dev/null || die "no passwordless sudo on $DST"

SRCVER=$(src 'dpkg-query -W -f="\${Version}" shunt 2>/dev/null' || true)
DSTVER=$(dst 'dpkg-query -W -f="\${Version}" shunt 2>/dev/null' || true)
[ -n "$DSTVER" ] || die "$DST has no shunt package installed -- install it first"
[ "$SRCVER" = "$DSTVER" ] || echo "  note: shunt $SRCVER on the source, $DSTVER on the target"

# The one thing a clone cannot fix, so it is said before anything is copied
# rather than after: the live gateway routes between two wired ports, and the
# target has whatever it has.
echo
echo "  interfaces on the target:"
dst 'ip -br link | awk "\$1!=\"lo\" {printf \"    %-20s %s\n\", \$1, \$2}"'
echo
echo "  the source routes: $(src 'sudo sed -n "s/^WAN_IF=//p;s/^LAN_IF=/  -> /p" /opt/shunt/config/network.conf | tr "\n" " "')"
echo "  (a missing LAN port is a cable to move, not something this script can copy)"
echo

if [ "$DRY" = 1 ]; then
    echo "would copy:"
    printf '  %s\n' "${SOFTWARE[@]}" "${IDENTITY[@]}" "${SETTINGS[@]}"
    echo
    echo "would NOT copy:"
    printf '  %s\n' "${EXCLUDED[@]}"
    exit 0
fi

# ── Copy ──────────────────────────────────────────────────────────────────────
# The agvpn account has to exist before its files land, or tar restores them
# owned by a uid with no name and AdGuard cannot write its own directory.
echo "shunt-clone: preparing the target"
dst 'getent passwd agvpn >/dev/null || sudo adduser --system --group --home /var/lib/agvpn --shell /usr/sbin/nologin agvpn >/dev/null'
# Shunt runs FPTN inside a netns and hostapd under its own unit; both packaged
# units are masked on the live box and must be masked here for the same reason.
dst 'sudo systemctl mask fptn-client.service hostapd.service >/dev/null 2>&1 || true'

# Everything that could bring egress up by itself, stopped and masked BEFORE the
# credentials land. The watchdog is the one that matters: it restarts adguardvpn
# whenever egress looks down, and on a box that is not the gateway yet it always
# will. Masked rather than disabled, because disabled still starts on request.
echo "shunt-clone: masking the paths that would start egress by themselves"
dst 'sudo systemctl disable --now shunt-agwatch.timer shunt-agwatch.service \
        shunt-health.service shunt-fptn-egress.service >/dev/null 2>&1 || true
     sudo systemctl mask shunt-agwatch.timer shunt-agwatch.service \
        shunt-health.service shunt-fptn-egress.service >/dev/null 2>&1 || true'

# Streamed host to host. Nothing touches this machine's disk, which matters
# because two of these files are credentials.
echo "shunt-clone: copying software, identity and settings"
# Leading slashes are stripped here rather than letting tar strip them and warn,
# so that anything on tar's stderr is a real problem and is allowed to be seen.
src "sudo tar -C / -cf - ${AGEXCL[*]} ${SOFTWARE[*]#/} ${IDENTITY[*]#/} ${SETTINGS[*]#/}" \
  | dst 'sudo tar -C / -xpf -'

# ── Verify ────────────────────────────────────────────────────────────────────
# A copy that silently truncated is the failure worth catching, and settings.json
# is the file whose loss would be least visible and most annoying.
echo "shunt-clone: verifying"
A=$(src 'sudo sha256sum /opt/shunt/config/settings.json | cut -d" " -f1')
B=$(dst 'sudo sha256sum /opt/shunt/config/settings.json | cut -d" " -f1')
[ "$A" = "$B" ] || die "settings.json differs after the copy -- target is half-configured"
dst 'sudo test -s /etc/fptn-client/token' || die "FPTN token did not arrive"
dst 'sudo test -s /var/lib/agvpn/.local/share/adguardvpn-cli/adguardvpn-cli.conf' \
    || die "AdGuard session did not arrive"

dst 'sudo systemctl daemon-reload'
# adguardvpn.service arrived with the copy but nothing enabled it: the
# multi-user.target.wants symlink is deliberately not in the file list, so it
# cannot start at boot. It is not masked because its unit file now lives in
# /etc/systemd/system and systemd refuses to mask over a real file there -- the
# masked callers above are what actually holds the line.
dst 'sudo systemctl disable --now adguardvpn.service >/dev/null 2>&1 || true'
dst 'sudo systemctl restart shunt-web.service || true'

# Said as a measurement rather than an assumption, because the whole point of
# the masking above is that it holds.
echo "shunt-clone: egress on the target is $(dst 'systemctl is-active adguardvpn.service 2>/dev/null || true') / $(dst 'systemctl is-enabled adguardvpn.service 2>/dev/null || true')"
[ "$(dst 'systemctl is-active adguardvpn.service 2>/dev/null || true')" = "active" ] \
    && die "adguardvpn came up on the target -- stop it before the live box notices"
true

echo
echo "shunt-clone: done. $DST now holds the household's settings and both credentials."
echo
echo "  Not copied, on purpose:"
printf '    %s\n' "${EXCLUDED[@]}"
echo
echo "  Egress is stopped and disabled on the target. One AdGuard session cannot"
echo "  be connected from two machines, and the one that is connected is carrying"
echo "  the house. At cutover, in this order:"
echo
echo "    1. move the ISP cable and the USB LAN adapter to the new box"
echo "    2. on the OLD box:  sudo systemctl disable --now adguardvpn shunt-fptn-egress"
echo "    3. on the NEW box:  sudo shunt-setup            # names ITS interfaces"
echo "    4. on the NEW box:  sudo systemctl unmask shunt-agwatch.timer \\"
echo "                            shunt-agwatch.service shunt-health.service \\"
echo "                            shunt-fptn-egress.service"
echo "    5. on the NEW box:  sudo systemctl enable --now adguardvpn \\"
echo "                            shunt-fptn-egress shunt-health shunt-agwatch.timer"
echo "    6. open the web interface and check the dashboard measures, not assumes"
