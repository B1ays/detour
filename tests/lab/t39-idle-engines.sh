#!/bin/sh
# Engines of exits no policy uses are not started (core.mark_idle): a policy switched off takes its engine exits'
# processes down, without "exit down" messages; "Start for 10 minutes" (exit_wake) runs one for a check and it stops
# again by itself; an exit a used one connects through (via) runs; WireGuard exits are never touched. Needs
# t10/t30's engine exits sbx (sing-box, sbtun) and xrx (Xray, xtun) under the policy px.
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
running() { ps w | grep -v grep | grep -c "engines/$1.json"; }
st() { ubus call detour status | jsonfilter -e "@.exits[@.name='$1'].$2"; }
apply() { uci commit detour; /etc/init.d/detour reload >/dev/null 2>&1; sleep 3; }
cleanup() {
	uci -q delete detour.px.enabled; uci -q delete detour.xr.via; rm -f /tmp/detour/warm.json
	apply
}
[ -n "$(uci -q get detour.sbx)" ] && [ -n "$(uci -q get detour.xrx)" ] && [ -n "$(uci -q get detour.px)" ] || { echo "needs the engine exits sbx, xrx and the policy px"; echo "RESULT: FAIL"; exit 1; }
cleanup
waitfor 1 "running sb" 20 && waitfor 1 "running xr" 20 && ok "px on: both engines run" || bad "engines: sb $(running sb), xr $(running xr)"

echo "== the policy off: its engine exits stop"
n0=$(logread | grep -c 'notify: \|stopped answering')
uci set detour.px.enabled=0; apply
waitfor 0 "running sb" 20 && waitfor 0 "running xr" 20 && ok "both engines stopped" || bad "still running: sb $(running sb), xr $(running xr)"
[ "$(st sbx idle)" = true ] && [ "$(st xrx idle)" = true ] && [ "$(st sbx healthy)" = false ] && ok "status: idle, not healthy" || bad "status sbx: $(st sbx idle)/$(st sbx healthy)"
[ "$(st warp idle)" = false ] && ip link show wgx1 >/dev/null 2>&1 && ok "WireGuard exit untouched" || bad "warp: idle $(st warp idle)"
ubus call detour exits_info | jsonfilter -e "@.exits[@.name='sbx'].idle" | grep -q true && ok "exits_info says so (LuCI)" || bad "exits_info"
sleep 15
[ "$(logread | grep -c 'notify: \|stopped answering')" = "$n0" ] && ok "no message about the stopped exits" || bad "messages: $(logread | grep 'notify: \|stopped answering' | tail -2)"
detour check >/dev/null 2>&1 && ok "detour check: no errors" || bad "check: $(detour check 2>&1 | head -2)"

echo "== started for a check"
R=$(ubus call detour exit_wake '{"name":"sbx"}')
U=$(echo "$R" | jsonfilter -e '@.until'); NOW=$(date +%s)
[ "$(echo "$R" | jsonfilter -e '@.ok')" = true ] && [ $((U - NOW)) -gt 590 ] && [ $((U - NOW)) -le 600 ] && ok "for 10 minutes" || bad "wake: $R"
waitfor 1 "running sb" 20 && ok "its engine runs" || bad "sb not started"
[ "$(running xr)" = 0 ] && ok "the other stays stopped" || bad "xr started too"
waitfor true "st sbx healthy" 30 && [ "$(st sbx warm)" = "$U" ] && ok "probed, healthy, warm until $U" || bad "sbx: healthy $(st sbx healthy) warm $(st sbx warm)"
[ "$(ubus -t 20 call detour exit_check '{"name":"sbx"}' | jsonfilter -e '@.ok')" = true ] && ok "Check works" || bad "check failed"
r=$(ubus call detour exit_wake '{"name":"warp"}'); echo "$r" | grep -q 'not an exit on an engine' && ok "a WireGuard exit: nothing to start" || bad "warp wake: $r"
echo "-- its time over: stopped again"
echo "{\"sbx\": $(( $(date +%s) + 2 ))}" > /tmp/detour/warm.json
waitfor 0 "running sb" 20 && [ "$(st sbx idle)" = true ] && ok "stopped, idle again" || bad "sb $(running sb), idle $(st sbx idle)"

echo "== an exit another one connects through runs"
uci set detour.xr.via=sbx; uci set detour.px.enabled=1; uci set detour.px.exit=xrx; apply
waitfor 1 "running xr" 20 && waitfor 1 "running sb" 20 && ok "xrx in use and sbx (its via) run" || bad "sb $(running sb), xr $(running xr)"
[ "$(st sbx idle)" = false ] && ok "sbx not idle" || bad "sbx idle"
uci -q delete detour.px.exit; uci add_list detour.px.exit=sbx; uci add_list detour.px.exit=xrx; uci -q delete detour.xr.via

echo "== the policy on again: both run, healthy"
cleanup
waitfor true "st sbx healthy" 40 && waitfor true "st xrx healthy" 40 && ok "both healthy" || bad "sbx $(st sbx healthy), xrx $(st xrx healthy)"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
