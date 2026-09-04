#!/bin/bash
# AdGuard egress watchdog.
#  (a) PROACTIVE: the client's memory creeps up (2.8 GB cgroup peak + 924 MB swap over
#      6.5 days, Aug 2026). Restart it GRACEFULLY well before MemoryMax kills it — an
#      OOM kill has historically cost the saved login (AdGuardVPNCLI issue #68), while a
#      clean stop writes the config properly.
#  (b) REACTIVE: the SOCKS listener can stay UP while the tunnel is dead (sing-box then
#      logs `socks5: request rejected, code=5`) and Restart=always never fires because
#      the process hangs in its own "Waiting recovery" loop instead of exiting.
SOCKS=127.0.0.1:1081
STATE=/run/xray-agwatch.fail
STAMP=/run/xray-agwatch.last
LOG=/opt/xray-proxy/logs/agwatch.log
MAX_FAIL=2
COOLDOWN=90   # a restart costs ~10 s, so do not suppress a needed second attempt
MEM_LIMIT_MB=600

log(){ echo "$(date '+%F %T') $*" >>"$LOG"; }
cooled(){ now=$(date +%s); last=$(cat "$STAMP" 2>/dev/null || echo 0); [ $(( now - last )) -ge "$COOLDOWN" ]; }
mark(){ date +%s >"$STAMP"; }

# NOTE (2026-08-18): the memory-based restart was REMOVED. MemoryCurrent counts socket
# buffers, not just anon RSS (anon was only 7 MB while the counter read 767 MB), and the
# 766-768 MB readings were the process being throttled at the MemoryHigh=768M ceiling I
# had set — so the "leak" restarts were self-inflicted outages. Limits are gone too.
# Only the reactive egress probe remains; a real leak would show up as a dead egress.
# (b) egress probe
probe(){
  c=$(curl -s -o /dev/null -m 8 -w '%{http_code}' --socks5 "$SOCKS" http://cp.cloudflare.com/generate_204 2>/dev/null)
  [ "$c" = "204" ] && return 0
  c=$(curl -s -o /dev/null -m 8 -w '%{http_code}' --socks5 "$SOCKS" https://api.ipify.org 2>/dev/null)
  [ "$c" = "200" ] && return 0
  return 1
}
if probe; then
  [ -f "$STATE" ] && { log "egress OK again (after $(cat "$STATE") fail(s))"; rm -f "$STATE"; }
  exit 0
fi
n=$(( $(cat "$STATE" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$STATE"
# Sample the DIRECT path too (not through the tunnel), so the next incident settles
# whether the WAN blipped first (ISP fault) or only the tunnel died (AdGuard fault).
# xray-health flags "inline WAN unhealthy" ~14 s before every egress failure, but that
# check reads WAN byte counters, which also go quiet when the tunnel dies — so on its
# own it cannot tell cause from consequence.
isp=$(ip route | awk '/default/{print $3; exit}')
pl=$(ping -c 3 -W 1 -i 0.3 "$isp" 2>/dev/null | grep -oE '[0-9]+% packet loss' | head -1)
ru=$(curl -s -o /dev/null -m 5 -w '%{http_code}' http://ya.ru/ 2>/dev/null)
log "egress probe FAILED ($n/$MAX_FAIL) | direct: ISP-gw loss=${pl:-n/a} ya.ru=${ru:-000}"
[ "$n" -lt "$MAX_FAIL" ] && exit 0
cooled || { log "restart suppressed (cooldown)"; exit 0; }
mark; log "RESTARTING adguardvpn — egress dead while service looked active"
systemctl restart adguardvpn; rm -f "$STATE"
