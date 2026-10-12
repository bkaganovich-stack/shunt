#!/usr/bin/env bash
# Build shunt-egress-bin: the third-party clients for the cascade egresses.
#
#   ./packaging/build-egress.sh <dir>
#
# <dir> holds amneziawg-go, awg, trusttunnel_client and setup_wizard, already
# verified (see debian-changelog for how each was obtained). Kept out of the
# main package for the same reason xray is: they are per-architecture binaries
# with their own release cycles, and repackaged unmodified.
set -euo pipefail
# The build host's umask must not leak into the package: on the gateway it is
# 002, which made every directory group-writable.
umask 022
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=${1:?usage: build-egress.sh <dir-with-binaries>}
OUT="$ROOT/dist"; mkdir -p "$OUT"
STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"' EXIT
for b in amneziawg-go awg trusttunnel_client setup_wizard; do
    [ -x "$SRC/$b" ] || { echo "$SRC/$b missing or not executable" >&2; exit 1; }
done
TT=$("$SRC/trusttunnel_client" --version 2>/dev/null | awk '{print $NF; exit}')
AWG=$("$SRC/awg" --version 2>/dev/null | awk '{print $2; exit}' | sed 's/^v//')
VER="${TT}+awg${AWG}"
ARCH=$(dpkg --print-architecture)
C="$STAGE/pkg"
install -d "$C/DEBIAN" "$C/opt/shunt/egress/bin" "$C/usr/share/doc/shunt-egress-bin"
install -m 755 "$SRC"/amneziawg-go "$SRC"/awg "$SRC"/trusttunnel_client "$SRC"/setup_wizard \
    "$C/opt/shunt/egress/bin/"
install -m 644 "$ROOT/packaging/copyright.egress" "$C/usr/share/doc/shunt-egress-bin/copyright"
printf 'shunt-egress-bin (%s) stable; urgency=medium\n\n  * TrustTunnel client %s (AdGuard release, signature verified),\n    amneziawg-go and amneziawg-tools %s built from upstream tags,\n    repackaged unmodified.\n\n -- Boris Kaganovich <bkaganovich@gmail.com>  %s\n' \
    "$VER" "$TT" "$AWG" "$(LC_ALL=C date -R)" | gzip -9nc > "$C/usr/share/doc/shunt-egress-bin/changelog.gz"
( cd "$C" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' | sort -z | xargs -0 md5sum > DEBIAN/md5sums )
chmod 644 "$C/DEBIAN/md5sums"
cat > "$C/DEBIAN/control" <<CTRL
Package: shunt-egress-bin
Version: $VER
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Boris Kaganovich <bkaganovich@gmail.com>
Installed-Size: $(du -sk "$C" | cut -f1)
Enhances: shunt
Description: Clients for Shunt's own-cascade egresses
 amneziawg-go and awg (AmneziaWG 2.0, userspace) and the TrustTunnel client,
 run by shunt-egress@.service inside isolated network namespaces.
CTRL
dpkg-deb --root-owner-group -b "$C" "$OUT/shunt-egress-bin_${VER}_${ARCH}.deb" >/dev/null
echo "built $OUT/shunt-egress-bin_${VER}_${ARCH}.deb"
