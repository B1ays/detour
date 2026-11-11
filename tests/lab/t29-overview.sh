#!/bin/sh
# Stage 5: the Overview - the outside address (directly as dtnotify, through each policy's exit; "Check" keeps
# what it learnt), the counters for the speed graph (the provider's line under the default route, every exit),
# the VPN switch (main.enabled: off takes the rules down - everything directly - and on brings them back).
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
st() { ubus call detour status | jsonfilter -e "$1"; }
waitfor() { i=0; while [ $i -lt ${3:-60} ]; do [ -n "$(eval "$2")" ] && return 0; sleep 2; i=$((i+2)); done; return 1; }

echo "== outside address"
waitfor x "st '@.extip.direct.ip'" 90 && ok "directly: $(st '@.extip.direct.ip') ($(st '@.extip.direct.loc'))" || bad "no direct address: $(st '@.extip')"
act=$(st "@.policies[@.name='vpn'].active")
waitfor x "st \"@.extip.exits.$act.ip\"" 90 && ok "through $act (the exit of vpn): $(st "@.extip.exits.$act.ip")" || bad "no address through $act: $(st '@.extip')"
ubus call detour exit_check '{"name":"alt"}' >/dev/null
[ -n "$(st '@.extip.exits.alt.ip')" ] && ok "Check keeps the address of alt" || bad "exit_check did not keep it"

echo "== counters for the speed graph"
R=$(ubus call detour rates)
dev=$(echo "$R" | jsonfilter -e '@.wan.dev')
l3=$(ip -4 route show default | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
[ -n "$dev" ] && ok "the provider's line: $dev (default route on $l3)" || bad "no wan: $R"
[ -n "$(echo "$R" | jsonfilter -e '@.exits.warp[0]')" ] && [ -n "$(echo "$R" | jsonfilter -e '@.exits.sbx[0]')" ] && ok "exit counters (warp, sbx)" || bad "exits: $R"
t1=$(echo "$R" | jsonfilter -e '@.t'); w1=$(echo "$R" | jsonfilter -e '@.wan.rx')
ping -c3 -i 0.3 1.1.1.1 >/dev/null 2>&1; sleep 1
R2=$(ubus call detour rates)
[ "$(echo "$R2" | jsonfilter -e '@.t')" -gt "$t1" ] && [ "$(echo "$R2" | jsonfilter -e '@.wan.rx')" -ge "$w1" ] && ok "they grow, the time goes on" || bad "t/rx: $t1 $w1 -> $R2"

echo "== VPN switch"
uci set detour.main.enabled=0; uci commit detour; reload_config
i=0; while nft list tables | grep -q detour && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
[ -z "$(nft list tables | grep detour)" ] && ok "off: no rules after ${i} s (everything directly)" || bad "off: the table is still there after 30 s"
uci set detour.main.enabled=1; uci commit detour; reload_config
waitfor x "nft list tables | grep detour" 30 && ok "on: the rules are back" || bad "on: no table"
waitfor x "st '@.policies[0].name'" 30 && ok "on: the daemon answers" || bad "on: no daemon"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
