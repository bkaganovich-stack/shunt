#!/usr/bin/env bash
# Install a newer Shunt package from GitHub releases.
#
#   self-update.sh apply [version]   install the latest, or the version given
#   self-update.sh auto              same, but only if the operator turned it on
#
# Never run this from the web process. Installing the package restarts
# shunt-web, so anything running inside it is killed part-way through its own
# upgrade; main.py launches this through systemd-run, which keeps it alive and
# supervised while the thing that started it goes away and comes back.
#
# The gateway carries a household's traffic, so the order matters more than the
# speed: verify before installing, keep the package currently installed so a
# failure can be undone without a network, snapshot, install, then prove the
# result answers. Every stage is written to a status file the interface reads,
# because for most of this there is no interface running to report to.
set -uo pipefail

# This script is part of the package it installs. dpkg replaces files by
# renaming over them, so a running shell keeps reading the inode it opened and
# is not corrupted mid-run -- but that is a property of dpkg's implementation
# rather than a promise, and the failure it would cause is a gateway halfway
# through replacing itself. Running from a copy costs nothing and removes the
# question.
if [ "${SHUNT_SELF_UPDATE_DETACHED:-}" != 1 ]; then
    _copy=$(mktemp /tmp/shunt-self-update.XXXXXX.sh) || exit 1
    cat "$0" > "$_copy" && chmod 700 "$_copy" || exit 1
    export SHUNT_SELF_UPDATE_DETACHED=1
    exec "$_copy" "$@"
fi
trap 'rm -f "$0"' EXIT

BASE=/opt/shunt
STATUS="$BASE/logs/self-update.json"
KEEP="$BASE/logs/rollback"
REPO="bkaganovich-stack/shunt"
API="https://api.github.com/repos/$REPO/releases/latest"

# --speed-limit rather than --connect-timeout: a connection that opens and then
# delivers nothing would satisfy the latter and hang forever.
CURL=(curl -sfL --connect-timeout 15 --speed-limit 1024 --speed-time 60
      --retry 3 --retry-delay 5 --max-time 900)

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Written after every stage: this script routinely outlives the interface that
# started it, so the file is the only way the result is ever seen.
say() {
    local state="$1" msg="$2"
    mkdir -p "$(dirname "$STATUS")"
    python3 - "$STATUS" "$state" "$msg" "${FROM_VER:-}" "${TO_VER:-}" <<'PY'
import json, sys, time, os
path, state, msg, frm, to = sys.argv[1:6]
try:
    old = json.load(open(path))
except Exception:
    old = {}
log = old.get("log", [])
if not log or log[-1].get("msg") != msg:
    log.append({"ts": int(time.time()), "state": state, "msg": msg})
json.dump({"state": state, "message": msg, "from": frm or None, "to": to or None,
           "ts": int(time.time()), "log": log[-20:]},
          open(path + ".tmp", "w"), ensure_ascii=False)
os.replace(path + ".tmp", path)
PY
    echo "[$(now)] $state: $msg"
}

fail() { say failed "$1"; exit 1; }

# Sort two dotted versions and refuse anything that is not strictly newer. An
# attacker who cannot replace the newest release can still point a gateway at
# an older one whose holes are public.
newer_than() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

MODE="${1:-apply}"
WANT="${2:-}"

FROM_VER=$(dpkg-query -W -f='${Version}' shunt 2>/dev/null || echo "")
[ -n "$FROM_VER" ] || fail "shunt is not installed through dpkg; update it by hand"

if [ "$MODE" = auto ]; then
    # The operator has to have asked for this. Absent or unreadable settings
    # count as "no": an unattended install of anything is opt-in only.
    enabled=$(python3 - <<'PY' 2>/dev/null || echo false
import json
try:
    s = json.load(open("/opt/shunt/config/settings.json"))
    print("true" if s.get("updates", {}).get("auto") else "false")
except Exception:
    print("false")
PY
)
    [ "$enabled" = true ] || { echo "automatic updates are off"; exit 0; }
fi

say checking "looking for a newer release"
if [ -z "$WANT" ]; then
    WANT=$("${CURL[@]}" "$API" 2>/dev/null |
           python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))' \
           2>/dev/null) || fail "could not reach the releases API"
fi
[ -n "$WANT" ] || fail "the releases API returned no version"
TO_VER="$WANT"

newer_than "$TO_VER" "$FROM_VER" || {
    say idle "$FROM_VER is current; $TO_VER is not newer"; exit 0; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"; rm -f "$0"' EXIT
DEB="shunt_${TO_VER}_all.deb"
DL="https://github.com/$REPO/releases/download/v${TO_VER}"

say downloading "fetching $DEB"
"${CURL[@]}" -o "$TMP/$DEB" "$DL/$DEB"        || fail "could not download $DEB"
"${CURL[@]}" -o "$TMP/SHA256SUMS" "$DL/SHA256SUMS" || fail "could not download SHA256SUMS"

say verifying "checking the package against SHA256SUMS"
( cd "$TMP" && sha256sum -c --ignore-missing SHA256SUMS >/dev/null 2>&1 ) \
    || fail "checksum mismatch -- refusing to install $DEB"
# The checksum proves the file arrived intact, not that it is Shunt. Ask dpkg
# what it actually is before handing it to apt.
got_pkg=$(dpkg-deb -f "$TMP/$DEB" Package 2>/dev/null)
got_ver=$(dpkg-deb -f "$TMP/$DEB" Version 2>/dev/null)
[ "$got_pkg" = shunt ] || fail "that file is '$got_pkg', not the shunt package"
[ "$got_ver" = "$TO_VER" ] || fail "package says $got_ver, release says $TO_VER"

# Keep the version currently installed, so undoing this needs no network -- the
# case that matters is exactly the one where the gateway came back broken.
mkdir -p "$KEEP"; rm -f "$KEEP"/shunt_*.deb
if "${CURL[@]}" -o "$KEEP/shunt_${FROM_VER}_all.deb" \
        "https://github.com/$REPO/releases/download/v${FROM_VER}/shunt_${FROM_VER}_all.deb"
then ROLLBACK="$KEEP/shunt_${FROM_VER}_all.deb"
else ROLLBACK=""; rm -f "$KEEP/shunt_${FROM_VER}_all.deb"
     say downloading "no published package for $FROM_VER; continuing without a local rollback copy"
fi

# What was running before, so the check afterwards compares like with like. An
# upgrade is judged on what it broke, not on what was already down: the timer
# can fire on a gateway whose interface the operator stopped on purpose, and
# rolling back a sound package because of that would be its own failure.
ROUTING_WAS=$(systemctl is-active shunt.service 2>/dev/null || true)
WEB_WAS=$(systemctl is-active shunt-web.service 2>/dev/null || true)

say installing "installing $TO_VER (this restarts the interface)"
if ! DEBIAN_FRONTEND=noninteractive apt-get -y install "$TMP/$DEB" >"$TMP/apt.log" 2>&1; then
    say failed "apt refused the package: $(tail -3 "$TMP/apt.log" | tr '\n' ' ')"
    exit 1
fi

ok=1
if [ "$WEB_WAS" = active ]; then
    say verifying "waiting for the interface to answer"
    ok=0
    for _ in $(seq 1 30); do
        sleep 2
        systemctl is-active --quiet shunt-web.service || continue
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1/ || true)
        case "$code" in 200|302|401) ok=1; break;; esac
    done
else
    say verifying "the interface was not running before this update; not waiting on it"
fi

routing_now=$(systemctl is-active shunt.service 2>/dev/null || true)
if [ "$ok" = 1 ] && { [ "$ROUTING_WAS" != active ] || [ "$routing_now" = active ]; }; then
    say done "updated $FROM_VER to $TO_VER"
    exit 0
fi

# Something that was working before is not working now.
why="the interface did not answer"
[ "$ok" = 1 ] && why="routing did not come back up"
if [ -n "$ROLLBACK" ]; then
    say rollback "$why -- putting $FROM_VER back"
    if DEBIAN_FRONTEND=noninteractive apt-get -y install --allow-downgrades \
            "$ROLLBACK" >>"$TMP/apt.log" 2>&1; then
        say failed "$TO_VER $why; rolled back to $FROM_VER"
    else
        say failed "$TO_VER $why, and restoring $FROM_VER also failed. Install it by hand: apt-get install --allow-downgrades $ROLLBACK"
    fi
else
    say failed "$TO_VER $why, and no local copy of $FROM_VER to go back to"
fi
exit 1
