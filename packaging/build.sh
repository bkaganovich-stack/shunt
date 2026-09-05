#!/usr/bin/env bash
# Build the shunt Debian packages.
#
#   ./packaging/build.sh            build shunt
#   ./packaging/build.sh --with-core /path/to/xray   also build shunt-xray
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

# ── shunt ─────────────────────────────────────────────────────────────
P="$STAGE/shunt"
install -d "$P/DEBIAN" "$P/opt/shunt/web/static" "$P/opt/shunt/scripts" \
           "$P/lib/systemd/system" "$P/usr/sbin" "$P/usr/share/doc/shunt"

install -m 644 "$ROOT"/src/web/*.py            "$P/opt/shunt/web/"
# main.py carries a shebang, so it gets the matching exec bit. The alternative
# -- stripping the shebang -- would alter the file, and keeping the packaged
# copy byte-identical to what is deployed is worth more than one dead line.
chmod 755 "$P/opt/shunt/web/main.py"
cp -r "$ROOT"/src/web/static/.                 "$P/opt/shunt/web/static/"
# These carry a shebang and are meant to be runnable, so they get exec bits.
install -m 755 "$ROOT"/src/doh_proxy.py "$ROOT"/src/doh_proxy_ns.py "$P/opt/shunt/"
for f in "$ROOT"/src/scripts/*; do install -m 755 "$f" "$P/opt/shunt/scripts/"; done
# The FPTN egress script drops privileges and edits a network namespace; it is
# root-only on the live system and stays that way in the package.
chmod 750 "$P/opt/shunt/scripts/fptn-egress.sh"
install -m 644 "$ROOT"/systemd/*.service "$ROOT"/systemd/*.timer "$P/lib/systemd/system/"
install -m 755 "$ROOT/packaging/shunt-setup" "$P/usr/sbin/"
install -d "$P/usr/share/man/man8"
gzip -9nc "$ROOT/packaging/shunt-setup.8" > "$P/usr/share/man/man8/shunt-setup.8.gz"
install -m 644 "$ROOT/README.md"            "$P/usr/share/doc/shunt/"
install -m 644 "$ROOT/packaging/copyright"   "$P/usr/share/doc/shunt/copyright"
# A native package (no Debian revision in the version) names it changelog.gz.
gzip -9nc "$ROOT/debian-changelog" > "$P/usr/share/doc/shunt/changelog.gz"
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
dpkg-deb --root-owner-group -b "$P" "$OUT/shunt_${VER}_all.deb" >/dev/null
echo "built $OUT/shunt_${VER}_all.deb"

# ── shunt-xray (optional) ─────────────────────────────────────────────
if [ "${1:-}" = --with-core ]; then
    XRAY="${2:?usage: build.sh --with-core /path/to/xray}"
    [ -x "$XRAY" ] || { echo "$XRAY is not an executable" >&2; exit 1; }
    COREVER=$("$XRAY" version 2>/dev/null | awk 'NR==1{print $2}')
    [ -n "$COREVER" ] || COREVER=0
    C="$STAGE/core"
    install -d "$C/DEBIAN" "$C/opt/shunt/bin" "$C/usr/share/doc/shunt-xray"
    install -m 755 "$XRAY" "$C/opt/shunt/bin/xray"
    install -m 644 "$ROOT/packaging/copyright.core" \
                   "$C/usr/share/doc/shunt-xray/copyright"
    printf 'shunt-xray (%s) stable; urgency=medium\n\n  * Upstream Xray-core release %s, repackaged unmodified.\n\n -- Boris Kaganovich <bkaganovich@gmail.com>  %s\n' \
        "$COREVER" "$COREVER" "$(LC_ALL=C date -R)" |
        gzip -9nc > "$C/usr/share/doc/shunt-xray/changelog.gz"
    ( cd "$C" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' \
      | sort -z | xargs -0 md5sum > DEBIAN/md5sums )
    chmod 644 "$C/DEBIAN/md5sums"
    CSIZE=$(du -sk "$C" | cut -f1)
    sed -e "s/@COREVER@/$COREVER/" -e "s/@ARCH@/$ARCH/" -e "s/@SIZE@/$CSIZE/" \
        "$ROOT/packaging/templates/control.core" > "$C/DEBIAN/control"
    dpkg-deb --root-owner-group -b "$C" "$OUT/shunt-xray_${COREVER}_${ARCH}.deb" >/dev/null
    echo "built $OUT/shunt-xray_${COREVER}_${ARCH}.deb"
fi
