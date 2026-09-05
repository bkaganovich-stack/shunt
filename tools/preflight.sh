#!/usr/bin/env bash
# preflight.sh — check that a machine running the pre-2.0 xray-gateway layout is
# ready to be migrated to Shunt. Read-only: it changes nothing.
#
# Run on the gateway as root:  bash preflight.sh
set -uo pipefail

OLD=/opt/xray-proxy
NEW=/opt/shunt
fail=0; warn=0
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fail=$((fail+1)); }
note() { printf '  \033[33mWARN\033[0m  %s\n' "$*"; warn=$((warn+1)); }

echo "── layout ──────────────────────────────────────────────────────────────"
[ -d "$OLD" ] && ok "$OLD present" || bad "$OLD missing — nothing to migrate"
[ -d "$NEW/config" ] && bad "$NEW/config already exists — migration would be skipped" \
                     || ok "$NEW/config absent, migration will run"
# A rename is instant; a copy across filesystems is not, and the switch window
# is sized on the assumption that it is a rename.
if [ -d "$OLD" ]; then
    a=$(stat -c %d "$OLD" 2>/dev/null); b=$(stat -c %d /opt 2>/dev/null)
    [ "$a" = "$b" ] && ok "/opt is one filesystem — the data move is a rename" \
                    || note "$OLD is on another filesystem — the move will copy, not rename"
fi

echo "── the config that will be carried over ────────────────────────────────"
NC="$OLD/config/network.conf"
if [ -f "$NC" ]; then
    ok "network.conf present"
    # shellcheck source=/dev/null
    . "$NC"
    for v in LAN_IF WAN_IF; do
        n=$(eval "echo \${$v:-}")
        [ -z "$n" ] && continue
        if [ -e "/sys/class/net/$n" ]; then ok "$v=$n exists"
        else bad "$v=$n does not exist — iptables.sh up will abort and strip the NAT"; fi
    done
    [ "${TOPOLOGY:-}" = inline ] && [ -z "${WAN_IF:-}" ] && \
        bad "TOPOLOGY=inline without WAN_IF — iptables.sh up will abort"
    ok "topology=${TOPOLOGY:-loop}"
else
    bad "$NC missing — the new units would come up with no interface names"
fi
for f in xray.json settings.json; do
    [ -s "$OLD/config/$f" ] && ok "config/$f present" || bad "config/$f missing or empty"
done

echo "── the core ────────────────────────────────────────────────────────────"
if [ -x "$OLD/bin/xray" ]; then
    ok "old core present ($("$OLD/bin/xray" version 2>/dev/null | awk 'NR==1{print $2}')) — carried over if shunt-xray is absent"
else
    note "no core in $OLD/bin — install shunt-xray in the same transaction"
fi

echo "── dependencies ────────────────────────────────────────────────────────"
uv=$(python3 -c 'import importlib.metadata as m;print(m.version("uvicorn"))' 2>/dev/null || echo 0)
if [ "$(printf '%s\n0.23.1\n' "$uv" | sort -V | head -1)" = 0.23.1 ]; then
    ok "uvicorn $uv (>= 0.23.1)"
else
    bad "uvicorn $uv is older than 0.23.1 — shunt-web would crash-loop"
fi
python3 -c 'import multipart' 2>/dev/null && ok "python-multipart present" \
    || bad "python-multipart missing — file upload would fail"
for c in iptables ip curl; do
    command -v $c >/dev/null && ok "$c present" || bad "$c missing"
done

echo "── room and reachability ───────────────────────────────────────────────"
avail=$(df -Pk /opt | awk 'NR==2{print $4}')
[ "$avail" -gt 524288 ] && ok "$((avail/1024)) MB free on /opt" \
                        || note "only $((avail/1024)) MB free on /opt"
mgmt=$(ip -4 -o addr show 2>/dev/null | awk '$2!="lo"{split($4,a,"/"); print $2"="a[1]}' | tr '\n' ' ')
ok "addresses: $mgmt"
n=$(ip -4 -o addr show 2>/dev/null | grep -vc ' lo ')
[ "$n" -ge 2 ] && ok "more than one address to reach this box on" \
               || note "only one address — no out-of-band way in if the LAN link drops"

echo "── running services that the switch will restore ───────────────────────"
for u in xray-proxy xray-web xray-dohproxy xray-health xray-agwatch.timer \
         xray-mgmt-ap fptn-egress; do
    systemctl is-active --quiet "$u" 2>/dev/null && echo "    will resume: $u"
done

echo
if [ "$fail" -gt 0 ]; then
    echo "NOT READY: $fail blocking problem(s), $warn warning(s)."
    exit 1
fi
echo "READY${warn:+ with $warn warning(s)}."
