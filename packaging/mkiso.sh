#!/usr/bin/env bash
# Build an unattended Shunt installer image from a Debian netinst ISO.
#
#   ./packaging/mkiso.sh --iso debian-13.6.0-amd64-netinst.iso --ssh-key ~/.ssh/id_ed25519.pub
#
# The result installs Debian, then both Shunt packages, on a machine with no
# keyboard or monitor attached. It ERASES the target machine's internal disk.
#
# Only xorriso is needed to build. The image is repacked with the boot records
# reported by the source ISO, so it stays bootable on both BIOS and UEFI.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ISO="" ; OUT="" ; USERNAME="shunt" ; SSHKEY="" ; PWHASH="" ; PASSWORD=""
DISK="" ; APTMIRROR="deb.debian.org" ; DEBDIR="$ROOT/dist"

die() { echo "mkiso: $*" >&2; exit 1; }

usage() {
    # The header comment, minus the shebang, is the description.
    awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"
    cat <<EOF

  --iso PATH            Debian amd64 netinst ISO to build from (required)
  --out PATH            output image (default dist/shunt-<ver>-amd64-installer.iso)
  --deb-dir DIR         where to find shunt_*.deb and shunt-xray_*.deb (default dist/)
  --user NAME           administrator account (default: shunt)
  --ssh-key FILE        public key for that account
  --password-hash HASH  crypt(3) hash for that account, e.g. from: openssl passwd -6
  --password PASS       plaintext, hashed here (needs openssl/mkpasswd; not on macOS)
  --disk DEVICE         install target, e.g. /dev/sda. Default: first non-removable disk
  --apt-mirror HOST     Debian mirror for the install (default: deb.debian.org)
At least one of --ssh-key, --password-hash, --password is required: an image
that ships a known password is worse than no image.
EOF
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --iso) ISO="$2"; shift 2;;
        --out) OUT="$2"; shift 2;;
        --deb-dir) DEBDIR="$2"; shift 2;;
        --user) USERNAME="$2"; shift 2;;
        --ssh-key) SSHKEY="$2"; shift 2;;
        --password-hash) PWHASH="$2"; shift 2;;
        --password) PASSWORD="$2"; shift 2;;
        --disk) DISK="$2"; shift 2;;
        --apt-mirror) APTMIRROR="$2"; shift 2;;
        -h|--help) usage 0;;
        *) echo "mkiso: unknown option $1" >&2; usage 1;;
    esac
done

command -v xorriso >/dev/null || die "xorriso is not installed"
[ -n "$ISO" ] || { echo "mkiso: --iso is required" >&2; usage 1; }
[ -f "$ISO" ] || die "$ISO does not exist"
# The boot records are replayed by reference to this path, so it has to be one
# that still resolves from wherever xorriso is run.
ISO=$(cd "$(dirname "$ISO")" && pwd)/$(basename "$ISO")

# ── Credentials ───────────────────────────────────────────────────────────────
if [ -n "$PASSWORD" ]; then
    # LibreSSL (macOS) has no -6 and Python dropped crypt in 3.13, so this can
    # legitimately fail on a Mac; --password-hash is the way out.
    if openssl passwd -6 "$PASSWORD" >/dev/null 2>&1; then
        PWHASH=$(openssl passwd -6 "$PASSWORD")
    elif command -v mkpasswd >/dev/null 2>&1; then
        PWHASH=$(mkpasswd -m sha-512 "$PASSWORD")
    elif python3 -c 'import crypt' >/dev/null 2>&1; then
        PWHASH=$(python3 -c 'import crypt,sys; print(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_SHA512)))' "$PASSWORD")
    else
        die "no SHA-512 crypt available here. Hash it on a Linux box with
       openssl passwd -6
     and pass the result to --password-hash."
    fi
fi
[ -n "$SSHKEY" ] || [ -n "$PWHASH" ] || \
    die "one of --ssh-key, --password-hash or --password is required"
[ -z "$SSHKEY" ] || [ -f "$SSHKEY" ] || die "$SSHKEY does not exist"
case "$PWHASH" in
    ''|\$*) ;;
    *) die "--password-hash does not look like a crypt(3) hash (no leading \$)";;
esac

# ── Packages to install ───────────────────────────────────────────────────────
shopt -s nullglob
MAIN=("$DEBDIR"/shunt_*.deb) ; CORE=("$DEBDIR"/shunt-xray_*.deb)
shopt -u nullglob
[ ${#MAIN[@]} -eq 1 ] || die "expected exactly one shunt_*.deb in $DEBDIR, found ${#MAIN[@]}"
[ ${#CORE[@]} -eq 1 ] || die "expected exactly one shunt-xray_*.deb in $DEBDIR, found ${#CORE[@]}"
VER=$(basename "${MAIN[0]}" | sed 's/^shunt_//; s/_all\.deb$//')
[ -n "$OUT" ] || OUT="$ROOT/dist/shunt-${VER}-amd64-installer.iso"
mkdir -p "$(dirname "$OUT")"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
TREE="$STAGE/tree"

echo "mkiso: unpacking $(basename "$ISO")"
xorriso -osirrox on -indev "$ISO" -extract / "$TREE" >/dev/null 2>&1
chmod -R u+w "$TREE"
[ -f "$TREE/install.amd/vmlinuz" ] || die "no install.amd/vmlinuz -- is this a Debian amd64 netinst ISO?"

# ── Payload ───────────────────────────────────────────────────────────────────
# Emptied first, not merged into. The source image is usually a stock netinst,
# but it can equally be an installer this script built earlier -- which already
# carries a /shunt directory with an older pair of .deb files. The preseed
# installs /cdrom/shunt/*.deb, so a merge would ship two versions of the same
# package in one image and let apt pick between them.
rm -rf "$TREE/shunt"
mkdir -p "$TREE/shunt"
cp "${MAIN[0]}" "${CORE[0]}" "$TREE/shunt/"
[ -z "$SSHKEY" ] || cp "$SSHKEY" "$TREE/shunt/authorized_keys"

# Shown at the console login prompt. A gateway is normally headless, but when
# something has gone wrong a monitor gets plugged in, and the first question is
# always what address it ended up on. \4 is the IPv4 address, \n the hostname.
cat > "$TREE/shunt/issue" <<'EOF'
Shunt -- transparent split-routing gateway

  host \n    address \4
  web interface: http://\4/  or  http://\n.local/

EOF

# ── Preseed ───────────────────────────────────────────────────────────────────
# Built from fragments rather than one template because three of the answers
# depend on how the operator chose to authenticate.

if [ -n "$DISK" ]; then
    DISKLINE="d-i partman-auto/disk string $DISK"
else
    # The installer is normally booted from a USB stick, and that stick is a
    # disk like any other as far as partman is concerned. Removable ones are
    # skipped so the image cannot eat the medium it was booted from, and the
    # first fixed disk -- SATA or NVMe, both report removable 0 -- is taken.
    DISKLINE='d-i partman/early_command string \
    D=""; \
    for d in $(list-devices disk); do \
        n=$(basename $(readlink -f $d)); \
        [ "$(cat /sys/block/$n/removable 2>/dev/null)" = 1 ] && continue; \
        D="$d"; break; \
    done; \
    { [ -n "$D" ] && debconf-set partman-auto/disk "$D"; } || true'
fi

SSHFRAG=""
if [ -n "$SSHKEY" ]; then
    SSHFRAG='    mkdir -p /target/home/@USERNAME@/.ssh; \
    cp /cdrom/shunt/authorized_keys /target/home/@USERNAME@/.ssh/authorized_keys; \
    in-target chown -R @USERNAME@:@USERNAME@ /home/@USERNAME@/.ssh; \
    in-target chmod 700 /home/@USERNAME@/.ssh; \
    in-target chmod 600 /home/@USERNAME@/.ssh/authorized_keys; \'
fi

KEYONLYFRAG=""
if [ -z "$PWHASH" ]; then
    # A locked account cannot answer sudo's password prompt, so key-only
    # installs get passwordless sudo -- the key is then the only credential
    # that exists, and without this the box would have no way to become root.
    PWHASH='*'
    KEYONLYFRAG='    printf "@USERNAME@ ALL=(ALL) NOPASSWD:ALL\n" > /target/etc/sudoers.d/shunt-admin; \
    chmod 440 /target/etc/sudoers.d/shunt-admin; \
    printf "PasswordAuthentication no\n" > /target/etc/ssh/sshd_config.d/shunt.conf; \'
fi

cat > "$STAGE/preseed.cfg" <<'PRESEED'
# Unattended install for Shunt. Generated by packaging/mkiso.sh -- edit that,
# not this. Reached from the boot menu as file=/cdrom/preseed.cfg.

### Localisation. Kept to a neutral default; the box has no keyboard.
d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select us

### Network. A wired link is preferred and named explicitly -- `auto` picks the
### first interface with a carrier, and on a box with Wi-Fi that can be the
### wireless one.
###
### But a gateway is usually installed onto a machine whose only Ethernet cable
### is still in the router, doing the job. "No wired link" is the NORMAL case,
### not a failure. When there is none, the wireless interface is selected and
### the question priority is raised to `high` for the rest of the run, which is
### all it takes: the installer then does its own thing -- scans, offers the
### networks it can see or manual entry, asks for the key, works out the
### security type, connects -- and carries on unattended afterwards, because
### every other question is already answered in this file.
###
### Credentials are deliberately NOT preseeded here. An earlier version of this
### took them at build time and wrote them into the image, which put the
### household's Wi-Fi key on a USB stick to save one prompt, and needed argument
### parsing, a key file, length checks and its own substitution path to do it.
### The installer already knows how to ask. Asking is also the only version that
### works for someone building an image for a network they do not know.
###
### The network chosen here is kept by the installed system, so the box is
### reachable the moment it boots and the ISP cable can be moved across later by
### someone who is not standing at a monitor.
# early_command runs before the network drivers are necessarily loaded, so it
# waits only when there is something to wait FOR: a wired interface that exists
# but has not negotiated yet. With no wired interface visible at all it gives up
# at once rather than charging every install twenty seconds for nothing.
d-i preseed/early_command string \
    W=""; \
    for i in $(seq 1 20); do \
        SEEN=""; \
        for n in /sys/class/net/*; do \
            d=$(basename $n); \
            [ "$d" = lo ] && continue; \
            [ -e "$n/wireless" ] && continue; \
            [ -e "$n/phy80211" ] && continue; \
            SEEN=1; \
            [ "$(cat $n/carrier 2>/dev/null)" = 1 ] || continue; \
            W="$d"; break; \
        done; \
        [ -n "$W" ] && break; \
        [ -z "$SEEN" ] && break; \
        sleep 1; \
    done; \
    if [ -z "$W" ]; then \
        for n in /sys/class/net/*; do \
            [ -e "$n/phy80211" ] || continue; \
            W=$(basename $n); \
            debconf-set debconf/priority high; \
            break; \
        done; \
    fi; \
    { [ -n "$W" ] && debconf-set netcfg/choose_interface "$W"; } || true
d-i netcfg/choose_interface select auto
# Give a slow-negotiating port time before anything is decided about it.
d-i netcfg/link_wait_timeout string 30
d-i netcfg/link_detection_timeout string 30
d-i netcfg/dhcp_timeout string 60
d-i netcfg/get_hostname string shunt
d-i netcfg/get_domain string local
d-i netcfg/hostname string shunt
d-i netcfg/domain string local

### Mirror
d-i mirror/country string manual
d-i mirror/http/hostname string @APTMIRROR@
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string

### Clock. UTC, because every log and metric this thing writes is in UTC.
d-i clock-setup/utc boolean true
d-i time/zone string Etc/UTC
d-i clock-setup/ntp boolean true

### Accounts. No root login; the first user has sudo.
d-i passwd/root-login boolean false
d-i passwd/user-fullname string Shunt administrator
d-i passwd/username string @USERNAME@
d-i passwd/user-password-crypted password @PWHASH@

### Partitioning -- THIS ERASES THE DISK.
@DISKLINE@
d-i partman-auto/method string regular
d-i partman-auto/choose_recipe select atomic
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-md/device_remove_md boolean true
d-i partman/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman-efi/non_efi_system boolean true

### Base system. "standard" only: this is an appliance, not a workstation.
d-i base-installer/install-recommends boolean true
d-i apt-setup/non-free-firmware boolean true
tasksel tasksel/first multiselect standard
d-i pkgsel/include string openssh-server sudo avahi-daemon libnss-mdns dnsmasq-base ethtool unattended-upgrades
d-i pkgsel/upgrade select full-upgrade
popularity-contest popularity-contest/participate boolean false

### Boot loader
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string default

### Reboot without waiting for a keypress that nobody is there to give.
d-i finish-install/reboot_in_progress note

### Shunt itself. The packages travel on the image; their dependencies come
### from the mirror, so the machine needs working internet during the install.
### The ceiling runs inside the target, not out here: the installer environment
### is busybox and has no timeout applet, so wrapping in-target from outside
### fails instantly with "not found" and skips the install it was protecting.
### Bounded on purpose. A box being installed headless has nobody watching it,
### so a stalled mirror must not turn into an install that sits at 14% forever:
### apt gets timeouts, the whole step gets a ceiling, and if it still does not
### finish the machine is left booting and reachable with the packages on disk
### and an explanation on the console, rather than never finishing at all.
d-i preseed/late_command string \
    mkdir -p /target/root/shunt-packages; \
    cp /cdrom/shunt/*.deb /target/root/shunt-packages/; \
    cp /cdrom/shunt/issue /target/etc/issue; \
    printf 'Acquire::Retries "3";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n' > /target/etc/apt/apt.conf.d/99shunt-timeouts; \
    @SSHFRAG@
    @KEYONLYFRAG@
    if in-target sh -c 'timeout 1800 apt-get -y install /root/shunt-packages/shunt-xray_*.deb /root/shunt-packages/shunt_*.deb'; then \
        rm -rf /target/root/shunt-packages; \
    else \
        in-target dpkg --configure -a >/dev/null 2>&1 || true; \
        printf 'The Shunt packages did not install: apt failed, or it was still\nrunning after 30 minutes and was stopped.\n\nThey are in /root/shunt-packages. Retry with:\n\n    sudo sh -c "apt-get -y install /root/shunt-packages/*.deb"\n\n(the quotes matter: /root is readable only by root, so the shell that\nexpands *.deb has to be the root one)\n' > /target/etc/shunt-install-failed; \
        cat /target/etc/shunt-install-failed >> /target/etc/issue; \
    fi
PRESEED

# Substituted with | because a crypt(3) hash contains / but never |.
sed -i.bak \
    -e "s|@APTMIRROR@|$APTMIRROR|g" \
    -e "s|@USERNAME@|$USERNAME|g" \
    -e "s|@PWHASH@|$PWHASH|g" \
    "$STAGE/preseed.cfg"
# The three multi-line fragments go in with awk, which does not mind newlines
# in the replacement the way sed does.
for marker in DISKLINE SSHFRAG KEYONLYFRAG; do
    eval "value=\$$marker"
    value="${value//@USERNAME@/$USERNAME}"
    printf '%s' "$value" > "$STAGE/frag"
    awk -v m="@$marker@" -v f="$STAGE/frag" '
        index($0, m) { while ((getline line < f) > 0) print line; close(f); next }
        { print }' "$STAGE/preseed.cfg" > "$STAGE/preseed.new"
    mv "$STAGE/preseed.new" "$STAGE/preseed.cfg"
done
rm -f "$STAGE/preseed.cfg.bak" "$STAGE/frag"
cp "$STAGE/preseed.cfg" "$TREE/preseed.cfg"

# ── Boot menus ────────────────────────────────────────────────────────────────
# Both firmwares get the same three entries, with the unattended one selected
# and a ten second pause. Long enough for someone who booted the wrong machine
# to stop it, short enough that a headless box comes up on its own.
KCMD="auto=true priority=critical file=/cdrom/preseed.cfg"

cat > "$TREE/isolinux/isolinux.cfg" <<'CFG'
# D-I config version 2.0
path 
ui vesamenu.c32
prompt 0
timeout 100
menu hshift 4
menu width 70
menu title Shunt installer (BIOS mode)
include stdmenu.cfg
include shunt.cfg
CFG

cat > "$TREE/isolinux/shunt.cfg" <<CFG
label shunt
    menu label ^Install Shunt  --  ERASES THE INTERNAL DISK
    menu default
    kernel /install.amd/vmlinuz
    append initrd=/install.amd/initrd.gz $KCMD --- quiet

label manual
    menu label ^Manual Debian install  --  nothing erased without asking
    kernel /install.amd/vmlinuz
    append initrd=/install.amd/initrd.gz --- quiet

label rescue
    menu label ^Rescue mode
    kernel /install.amd/vmlinuz
    append initrd=/install.amd/initrd.gz rescue/enable=true --- quiet
CFG

# Deliberately plain: the stock file pulls in a graphical theme, and a missing
# font or background on unfamiliar firmware turns into a blank screen on a
# machine with no keyboard to recover it with.
cat > "$TREE/boot/grub/grub.cfg" <<CFG
set default=0
set timeout=10

menuentry 'Install Shunt  --  ERASES THE INTERNAL DISK' {
    linux  /install.amd/vmlinuz $KCMD --- quiet
    initrd /install.amd/initrd.gz
}

menuentry 'Manual Debian install  --  nothing erased without asking' {
    linux  /install.amd/vmlinuz --- quiet
    initrd /install.amd/initrd.gz
}

menuentry 'Rescue mode' {
    linux  /install.amd/vmlinuz rescue/enable=true --- quiet
    initrd /install.amd/initrd.gz
}
CFG

# md5sum.txt covers files this script has just replaced. Left stale, it makes
# the installer's own "check disc integrity" option report a broken disc, so
# the entries for changed files are refreshed and the rest left alone.
md5of() { if command -v md5sum >/dev/null 2>&1; then md5sum "$1" | cut -d' ' -f1
          else md5 -q "$1"; fi; }
if [ -f "$TREE/md5sum.txt" ]; then
    ( cd "$TREE"
      grep -vE '\./(preseed\.cfg|isolinux/isolinux\.cfg|isolinux/shunt\.cfg|boot/grub/grub\.cfg|shunt/)' \
          md5sum.txt > md5sum.new || true
      for f in preseed.cfg isolinux/isolinux.cfg isolinux/shunt.cfg boot/grub/grub.cfg shunt/*; do
          [ -f "$f" ] && printf '%s  ./%s\n' "$(md5of "$f")" "$f"
      done >> md5sum.new
      mv md5sum.new md5sum.txt )
fi

# ── Deduplicate ───────────────────────────────────────────────────────────────
# Debian's own image stores identical files once and points two directory
# entries at the same extent -- /firmware and /pool/non-free-firmware hold the
# same 164 MB of .deb, and install.amd/vmlinuz is also install.amd/xen/vmlinuz.
# Extracting to a filesystem turns each into two real files, and a plain repack
# would then write both. Hardlinking them back together and telling xorriso to
# honour hardlinks restores the original layout; without this the image comes
# out around 200 MB larger than the one it was built from.
echo "mkiso: deduplicating"
find "$TREE" -type f -size +512k -exec cksum {} + | sort -k1,2 |
awk '{ key = $1 " " $2; path = $0; sub(/^[0-9]+ [0-9]+ /, "", path)
       if (key == prevkey) print prevpath "\t" path
       else { prevkey = key; prevpath = path } }' > "$STAGE/dups"
# cksum is a checksum, not a proof, so every pair is compared byte for byte
# before one file is replaced by a link to the other.
while IFS="$(printf '\t')" read -r a b; do
    [ -f "$a" ] && [ -f "$b" ] || continue
    cmp -s "$a" "$b" && ln -f "$a" "$b"
done < "$STAGE/dups"

# ── Repack ────────────────────────────────────────────────────────────────────
# The boot records are not reconstructed by hand: xorriso is asked how the
# source image was made, and told to do the same again. That keeps the isohybrid
# MBR, the EFI El Torito entry and the APM/GPT layout exactly as Debian built
# them, which is what lets one image boot on both firmwares and from USB.
OPTS=()
while IFS= read -r line; do
    case "$line" in ''|'#'*) continue;; esac
    eval "OPTS+=($line)"
done < <(xorriso -indev "$ISO" -report_el_torito as_mkisofs 2>/dev/null)
[ ${#OPTS[@]} -gt 0 ] || die "xorriso could not read the boot records of $ISO"

echo "mkiso: repacking"
xorriso -hardlinks on -as mkisofs "${OPTS[@]}" -o "$OUT" "$TREE" >/dev/null 2>&1 \
    || die "repack failed"

echo
echo "mkiso: $OUT"
echo "       $(du -h "$OUT" | cut -f1), shunt $VER, administrator '$USERNAME'"
[ -z "$SSHKEY" ] || echo "       ssh key: $(basename "$SSHKEY")"
[ "$PWHASH" != '*' ] || echo "       console password locked; sudo needs no password"
echo "       target disk: ${DISK:-first non-removable disk in the machine}"
echo
echo "  Write it to a USB stick. Identify the device first -- naming the wrong"
echo "  one destroys whatever is on it:"
if [ "$(uname)" = Darwin ]; then
    echo "      diskutil list external              # find the stick, e.g. disk4"
    echo "      diskutil unmountDisk /dev/disk4"
    echo "      sudo dd if=$OUT of=/dev/rdisk4 bs=4m   # the r matters, ~20x faster"
else
    echo "      lsblk                               # find the stick, e.g. sdb"
    echo "      sudo dd if=$OUT of=/dev/sdb bs=4M status=progress oflag=sync"
fi
echo "  It installs unattended after a ten second pause and ERASES that disk."
echo
echo "  A cable is optional. With one plugged into something that hands out"
echo "  DHCP the install is unattended from end to end. With none -- the usual"
echo "  case, because the cable that matters is still in the router -- the"
echo "  installer stops once to ask which Wi-Fi network to join, offering the"
echo "  ones it can see, and carries on by itself afterwards. It keeps that"
echo "  network, so the box is reachable as soon as it boots and the ISP cable"
echo "  can be moved across later by someone who is not at a monitor."
