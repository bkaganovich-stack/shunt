#!/usr/bin/env bash
# Timer entry point: reload only when staged, validated tables have changed.
set -euo pipefail
result=$(/opt/shunt/scripts/update-geo.sh)
printf '%s\n' "$result"
case "$result" in *UNCHANGED:*) exit 0;; esac
if systemctl is-active --quiet shunt.service; then
    systemctl restart shunt.service
fi
