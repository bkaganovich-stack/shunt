#!/usr/bin/env bash
# Build the xray-gateway Debian packages.
#
#   ./packaging/build.sh            build xray-gateway
#   ./packaging/build.sh --with-core /path/to/xray   also build xray-gateway-core
#
# Plain dpkg-deb is used rather than debhelper so that the build needs nothing
# beyond dpkg-dev and runs on the gateway itself.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/dist"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# One source of truth for the version: VERSION in the application itself.
VER=$(sed -n 's/^VERSION *= *"\([^"]*\)".*/\1/p' "$ROOT/src/web/main.py" | head -1)
[ -n "$VER" ] || { echo "cannot read VERSION from src/web/main.py" >&2; exit 1; }
ARCH=$(dpkg --print-architecture)
mkdir -p "$OUT"

# ── xray-gateway ─────────────────────────────────────────────────────────────
P="$STAGE/xray-gateway"
install -d "$P/DEBIAN" "$P/opt/xray-proxy/web/static" "$P/opt/xray-proxy/scripts" \
           "$P/lib/systemd/system" "$P/usr/sbin" "$P/usr/share/doc/xray-gateway"

install -m 644 "$ROOT"/src/web/*.py            "$P/opt/xray-proxy/web/"
cp -r "$ROOT"/src/web/static/.                 "$P/opt/xray-proxy/web/static/"
install -m 644 "$ROOT"/src/doh_proxy.py "$ROOT"/src/doh_proxy_ns.py "$P/opt/xray-proxy/"
for f in "$ROOT"/src/scripts/*; do install -m 755 "$f" "$P/opt/xray-proxy/scripts/"; done
# The FPTN egress script drops privileges and edits a network namespace; it is
# root-only on the live system and stays that way in the package.
chmod 750 "$P/opt/xray-proxy/scripts/fptn-egress.sh"
install -m 644 "$ROOT"/systemd/*.service "$ROOT"/systemd/*.timer "$P/lib/systemd/system/"
install -m 755 "$ROOT/packaging/xray-gateway-setup" "$P/usr/sbin/"
install -m 644 "$ROOT/README.md"            "$P/usr/share/doc/xray-gateway/"
install -m 644 "$ROOT/packaging/copyright"   "$P/usr/share/doc/xray-gateway/copyright"
gzip -9nc "$ROOT/debian-changelog" > "$P/usr/share/doc/xray-gateway/changelog.Debian.gz"
# Strip build-host litter: byte-compiled caches, editor backups, and the
# AppleDouble sidecars macOS leaves behind when files are copied through it.
find "$P/opt" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
find "$P/opt" \( -name '*.bak*' -o -name '._*' -o -name '.DS_Store' \) -delete 2>/dev/null || true

# md5sums lets dpkg --verify and debsums detect files altered after install.
( cd "$P" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' \
  | sort -z | xargs -0 md5sum > DEBIAN/md5sums )
chmod 644 "$P/DEBIAN/md5sums"

SIZE=$(du -sk "$P" | cut -f1)
sed -e "s/@VER@/$VER/" -e "s/@SIZE@/$SIZE/" \
    "$ROOT/packaging/templates/control.main" > "$P/DEBIAN/control"
for s in postinst prerm postrm; do
    install -m 755 "$ROOT/packaging/templates/$s" "$P/DEBIAN/$s"
done
dpkg-deb --root-owner-group -b "$P" "$OUT/xray-gateway_${VER}_all.deb" >/dev/null
echo "built $OUT/xray-gateway_${VER}_all.deb"

# ── xray-gateway-core (optional) ─────────────────────────────────────────────
if [ "${1:-}" = --with-core ]; then
    XRAY="${2:?usage: build.sh --with-core /path/to/xray}"
    [ -x "$XRAY" ] || { echo "$XRAY is not an executable" >&2; exit 1; }
    COREVER=$("$XRAY" version 2>/dev/null | awk 'NR==1{print $2}')
    [ -n "$COREVER" ] || COREVER=0
    C="$STAGE/core"
    install -d "$C/DEBIAN" "$C/opt/xray-proxy/bin"
    install -m 755 "$XRAY" "$C/opt/xray-proxy/bin/xray"
    CSIZE=$(du -sk "$C" | cut -f1)
    sed -e "s/@COREVER@/$COREVER/" -e "s/@ARCH@/$ARCH/" -e "s/@SIZE@/$CSIZE/" \
        "$ROOT/packaging/templates/control.core" > "$C/DEBIAN/control"
    dpkg-deb --root-owner-group -b "$C" "$OUT/xray-gateway-core_${COREVER}_${ARCH}.deb" >/dev/null
    echo "built $OUT/xray-gateway-core_${COREVER}_${ARCH}.deb"
fi
