#!/usr/bin/env bash
# Update geoip.dat and geosite.dat from runetfreedom/russia-v2ray-rules-dat
set -euo pipefail

GEO_DIR="${SHUNT_GEO_DIR:-/opt/shunt/config}"
WEB_DIR="${SHUNT_WEB_DIR:-/opt/shunt/web}"
XRAY_BIN="${SHUNT_XRAY_BIN:-/opt/shunt/bin/xray}"
mkdir -p "$GEO_DIR"
exec 9>"$GEO_DIR/.geo-update.lock"
flock -n 9 || { echo "Geo update already running" >&2; exit 1; }
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

# Verify the configuration against the staged assets before touching live files.
if [ -f "$GEO_DIR/xray.json" ]; then
    PYTHONPATH="$WEB_DIR" python3 - "$GEO_DIR/xray.json" "$TMP" <<'PYCODE'
import json, pathlib, sys
import geosite
cfg = json.loads(pathlib.Path(sys.argv[1]).read_text())
tmp = pathlib.Path(sys.argv[2])
missing = geosite.missing(cfg, tmp/'geosite.dat', tmp/'geoip.dat')
if missing:
    raise SystemExit('Missing routing lists: ' + ', '.join(missing))
PYCODE
    if [ -x "$XRAY_BIN" ]; then
        XRAY_LOCATION_ASSET="$TMP" "$XRAY_BIN" run -test -config "$GEO_DIR/xray.json"
    fi
fi

if cmp -s "$TMP/geoip.dat" "$GEO_DIR/geoip.dat" && cmp -s "$TMP/geosite.dat" "$GEO_DIR/geosite.dat"; then
    echo "UNCHANGED: geo databases already current"
    exit 0
fi

# Stage on the destination filesystem, then rename each complete file.
# The running Xray retains its loaded tables until the caller reloads it.
install -m 644 "$TMP/geoip.dat" "$GEO_DIR/geoip.dat.new"
install -m 644 "$TMP/geosite.dat" "$GEO_DIR/geosite.dat.new"
mv "$GEO_DIR/geoip.dat.new" "$GEO_DIR/geoip.dat"
mv "$GEO_DIR/geosite.dat.new" "$GEO_DIR/geosite.dat"
python3 - "$GEO_DIR/geo-version.json" "$TAG" <<'PYCODE'
import datetime, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
tmp = p.with_suffix('.new')
tmp.write_text(json.dumps({'tag': sys.argv[2], 'updated': datetime.datetime.now(datetime.timezone.utc).isoformat()}))
tmp.replace(p)
PYCODE


echo "Done: $(du -sh $GEO_DIR/geoip.dat $GEO_DIR/geosite.dat)"
