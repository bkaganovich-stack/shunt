#!/usr/bin/env bash
# Update geoip.dat and geosite.dat from runetfreedom/russia-v2ray-rules-dat
set -euo pipefail

GEO_DIR="/opt/shunt/config"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

REPO="https://github.com/runetfreedom/russia-v2ray-rules-dat"
API="https://api.github.com/repos/runetfreedom/russia-v2ray-rules-dat/releases/latest"

# --connect-timeout only bounds the handshake. A connection that opens and then
# delivers nothing hangs forever, which is how this script -- run from the
# postinst and from a weekly timer -- can stall a package installation with no
# way to tell that anything is wrong. --speed-time aborts a transfer that stays
# under --speed-limit, which is the right test here: the files are 92 MB and a
# slow link may legitimately need a long time, but never at 100 bytes a second.
CURL=(curl -sfL --connect-timeout 15 --speed-limit 1024 --speed-time 60
      --retry 3 --retry-delay 5 --max-time 1800)

echo "Fetching latest release info…"
RELEASE_JSON=$("${CURL[@]}" "$API")
TAG=$(echo "$RELEASE_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['tag_name'])")
echo "Latest tag: $TAG"

BASE_URL="$REPO/releases/download/$TAG"

echo "Downloading geoip.dat…"
"${CURL[@]}" -o "$TMP/geoip.dat"   "$BASE_URL/geoip.dat"
echo "Downloading geosite.dat…"
"${CURL[@]}" -o "$TMP/geosite.dat" "$BASE_URL/geosite.dat"

# Verify files are not empty
[ -s "$TMP/geoip.dat" ]   || { echo "ERROR: geoip.dat is empty"; exit 1; }
[ -s "$TMP/geosite.dat" ] || { echo "ERROR: geosite.dat is empty"; exit 1; }

# Atomic replace
cp "$TMP/geoip.dat"   "$GEO_DIR/geoip.dat"
cp "$TMP/geosite.dat" "$GEO_DIR/geosite.dat"

echo "Done: $(du -sh $GEO_DIR/geoip.dat $GEO_DIR/geosite.dat)"
