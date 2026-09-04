#!/usr/bin/env bash
# mkrepo.sh — turn dist/*.deb into a signed APT repository.
#
#   ./packaging/mkrepo.sh <repo-dir> <gpg-key-id>
#
# The result can be served by any static web server, or used locally with a
# file:// source. Needs apt-utils (apt-ftparchive) and gpg.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
REPO="${1:?usage: mkrepo.sh <repo-dir> <gpg-key-id>}"
KEYID="${2:?usage: mkrepo.sh <repo-dir> <gpg-key-id>}"
SUITE=stable
COMPONENT=main
ARCHES="amd64 all"

command -v apt-ftparchive >/dev/null || { echo "install apt-utils" >&2; exit 1; }
command -v gpg            >/dev/null || { echo "install gnupg" >&2; exit 1; }
ls "$ROOT"/dist/*.deb >/dev/null 2>&1 || { echo "no packages in $ROOT/dist — run build.sh" >&2; exit 1; }

mkdir -p "$REPO/pool/$COMPONENT"
cp -f "$ROOT"/dist/*.deb "$REPO/pool/$COMPONENT/"

# Architecture-independent packages are advertised under every architecture the
# repository serves, so an amd64-only client still sees them.
for a in $ARCHES; do
    d="$REPO/dists/$SUITE/$COMPONENT/binary-$a"
    mkdir -p "$d"
    ( cd "$REPO" && apt-ftparchive --arch "$a" packages "pool/$COMPONENT" ) > "$d/Packages"
    gzip -9nkf "$d/Packages"
done

# Release is written once, after every Packages file exists, because it carries
# their checksums -- generating it inside the loop would hash an incomplete set.
( cd "$REPO" && apt-ftparchive \
    -o "APT::FTPArchive::Release::Origin=xray-gateway" \
    -o "APT::FTPArchive::Release::Label=xray-gateway" \
    -o "APT::FTPArchive::Release::Suite=$SUITE" \
    -o "APT::FTPArchive::Release::Codename=$SUITE" \
    -o "APT::FTPArchive::Release::Architectures=$ARCHES" \
    -o "APT::FTPArchive::Release::Components=$COMPONENT" \
    release "dists/$SUITE" ) > "$REPO/dists/$SUITE/Release.tmp"
mv "$REPO/dists/$SUITE/Release.tmp" "$REPO/dists/$SUITE/Release"

# Sign: InRelease (inline) and Release.gpg (detached), so both old and new
# clients can verify.
cd "$REPO/dists/$SUITE"
rm -f InRelease Release.gpg
gpg --batch --yes --default-key "$KEYID" --clearsign -o InRelease   Release
gpg --batch --yes --default-key "$KEYID" -abs        -o Release.gpg Release

# The public key, in the dearmored form apt expects under /etc/apt/keyrings.
gpg --export "$KEYID" > "$REPO/xray-gateway-archive-keyring.gpg"

echo "repository ready at $REPO"
echo
echo "On a client:"
echo "  sudo install -m644 xray-gateway-archive-keyring.gpg /etc/apt/keyrings/"
echo "  echo 'deb [signed-by=/etc/apt/keyrings/xray-gateway-archive-keyring.gpg] \\"
echo "        <base-url> $SUITE $COMPONENT' | sudo tee /etc/apt/sources.list.d/xray-gateway.list"
echo "  sudo apt update && sudo apt install xray-gateway"
