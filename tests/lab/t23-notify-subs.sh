#!/bin/sh
# Stage 1 of the panel work: a subscription's traffic and end date from its headers (subscription-userinfo,
# profile-update-interval), which server the automatic group uses and each server's own check (sing-box control
# API on 127.0.0.1 behind a secret), notifications in Russian about a
# list / a subscription that failed, a subscription running out, the provider's line going away and coming back.
# Needs the stubs: sub_stub.py 8768, tg_stub.py 8766.
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
S=http://10.0.2.2:8768
T=http://10.0.2.2:8766
nlog() { wget -qO- $T/log | grep -c "$1"; }
b64() { ucode -e 'print(b64enc(ARGV[0]))' "$1"; }
PW=$(cat /etc/enodia-lab/ss.pw)
lab tests/lab/restart-sb.sh >/dev/null
cleanup() {
	for s in usub usub_sub usub_sub_eng l_bad; do uci -q delete detour.$s; done
	uci -q delete network.usub_sub; for z in vpn detour; do uci -q del_list firewall.$z.network=usub_sub; done
	uci -q delete detour.notify
	uci commit; rm -f /etc/detour/engines/usub_sub.* /tmp/detour/subs/usub.* /tmp/detour/lists/l_bad.*
	curl -s --data-binary '' $S/set/userinfo >/dev/null
	ubus call detour reload >/dev/null
}
cleanup
uci -q batch <<'U'
set detour.notify=notify
set detour.notify.enabled=1
set detour.notify.tg_token=123456:LABTOKEN_not_a_real_token_xxxxxxxxxxx
set detour.notify.tg_chat=4242
set detour.notify.tg_api=http://10.0.2.2:8766
set detour.notify.throttle=5
commit detour
U
# a fresh daemon: what it already told today (once a day, once per failure) is in its memory
/etc/init.d/detour restart; sleep 5
waitfor true "ubus call detour status >/dev/null 2>&1 && echo true" 20

echo "== subscription: traffic and end date from the headers"
DEAD="ss://$(b64 "2022-blake3-aes-128-gcm:$PW")@10.199.1.2:9999#dead"
GOOD="ss://$(b64 "2022-blake3-aes-128-gcm:$PW")@10.199.1.2:8443#good"
printf '%s\n%s\n' "$DEAD" "$GOOD" > /tmp/l.txt; curl -s --data-binary @/tmp/l.txt $S/set/links >/dev/null
EXP=$(( $(date +%s) + 2 * 86400 ))
curl -s --data-binary "upload=1073741824; download=96636764160; total=107374182400; expire=$EXP" $S/set/userinfo >/dev/null
uci -q batch <<U
set detour.usub=subscription
set detour.usub.label=Лаб-подписка
set detour.usub.url=$S/sub/TOKEN-U/b64
set detour.usub.allow_private=1
commit detour
U
n_exp=$(nlog 'заканчивается'); n_tr=$(nlog 'израсходовано')
R=$(detour sub-update usub)
echo "$R" | grep -q '"servers": 2' || bad "update: $R"
st() { jsonfilter -i /tmp/detour/subs/usub.status -e "@.info.$1"; }
[ "$(st total)" = 107374182400 ] && [ "$(st download)" = 96636764160 ] && [ "$(st expire)" = $EXP ] && [ "$(st update_hours)" = 12 ] \
	&& ok "status: total, used, end date, provider's interval 12 h" || bad "info: $(cat /tmp/detour/subs/usub.status)"
[ "$(ubus call detour exits_info | jsonfilter -e "@.exits[@.name='usub_sub'].sub_info.total")" = 107374182400 ] && ok "exits_info carries it to LuCI" || bad "exits_info: no sub_info"
[ "$(ubus call detour exits_info | jsonfilter -e "@.exits[@.name='usub_sub'].sub_interval")" = 12 ] && ok "no own interval: the provider's 12 h is used" || bad "interval"
waitfor $((n_exp+1)) "nlog 'заканчивается'" 30 && ok "notification: the subscription ends soon" || bad "no 'ends' message"
waitfor $((n_tr+1)) "nlog 'израсходовано'" 10 && ok "notification: 90% of the traffic used" || bad "no traffic message: $(wget -qO- $T/log | tail -2)"
wget -qO- $T/log | grep 'заканчивается' | tail -1 | grep -q '«Лаб-подписка»' && ok "with the name people gave" || bad "label"
sleep 3; n2=$(nlog 'заканчивается'); sleep 12
[ "$(nlog 'заканчивается')" = "$n2" ] && ok "said once a day, not every check" || bad "repeated"

echo "== a failed update keeps what the provider said, and is told once"
curl -s --data-binary '' $S/set/userinfo >/dev/null
n_f=$(nlog 'не обновилась')
uci set detour.usub.url=$S/nothing-here; uci commit detour
detour sub-update usub >/dev/null
[ "$(st total)" = 107374182400 ] && ok "traffic info kept after a failure" || bad "info lost: $(cat /tmp/detour/subs/usub.status)"
waitfor $((n_f+1)) "nlog 'не обновилась'" 30 && ok "notification: the subscription failed" || bad "no failure message"
wget -qO- $T/log | grep 'не обновилась' | tail -1 | grep -q 'провайдер не ответил' && ok "the reason in words" || bad "reason: $(wget -qO- $T/log | grep 'не обновилась' | tail -1)"
detour sub-update usub >/dev/null; sleep 12
[ "$(nlog 'не обновилась')" = $((n_f+1)) ] && ok "a second failure in a row is not repeated" || bad "repeated failure message"
uci set detour.usub.url=$S/sub/TOKEN-U/b64; uci commit detour
detour sub-update usub >/dev/null
[ -z "$(st total)" ] && ok "the provider stopped sending it: cleared" || bad "stale info"

echo "== the automatic group: which server now, each server checked on its own"
reload_config
waitfor true "ubus call detour status | jsonfilter -e '@.exits[@.name=\"usub_sub\"].healthy'" 120 || bad "usub not healthy"
[ "$(ls -l /tmp/detour/engines/usub_sub_eng.api | cut -c1-10)" = '-rw-------' ] && ok "control API secret: a file, mode 600" || bad "api file: $(ls -l /tmp/detour/engines/usub_sub_eng.api)"
SEC=$(sed -n 's/.*Bearer //p' /tmp/detour/engines/usub_sub_eng.api | cut -c1-32)
P=$(sed -n 's/.*127.0.0.1:\([0-9]*\).*/\1/p' /tmp/detour/engines/usub_sub_eng.api)
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$P/proxies)" = 401 ] && ok "API refuses without the secret" || bad "API open without secret"
ps w | grep -v grep | grep -q "$SEC" && bad "secret on a command line" || ok "secret not on a command line"
netstat -ltn 2>/dev/null | grep ":$P " | grep -q '127.0.0.1' && ok "API listens on 127.0.0.1 only" || bad "listen: $(netstat -ltn | grep ":$P ")"
waitfor 1 "ubus call detour sub_state '{\"name\":\"usub_sub\"}' | jsonfilter -e '@.now'" 60 && ok "now: server 2 (the working one)" || bad "sub_state: $(ubus call detour sub_state '{"name":"usub_sub"}')"
R=$(ubus -t 20 call detour sub_check '{"name":"usub_sub","index":1}')
[ "$(echo "$R" | jsonfilter -e '@.ok')" = true ] && ok "check of server 2: $(echo "$R" | jsonfilter -e '@.ms') ms" || bad "check good: $R"
R=$(ubus -t 20 call detour sub_check '{"name":"usub_sub","index":0}')
[ "$(echo "$R" | jsonfilter -e '@.ok')" = false ] && ok "check of the dead server 1: no answer" || bad "check dead: $R"
[ "$(ubus call detour sub_state '{"name":"usub_sub"}' | jsonfilter -e '@.now')" = 1 ] && ok "a check does not switch the group" || bad "switched"
R=$(ubus call detour sub_state '{"name":"nosuch"}'); echo "$R" | grep -q error && ok "unknown exit refused" || bad "unknown: $R"

echo "== a list that fails to update"
n_l=$(nlog 'Список «Плохой список» не обновился')
uci -q batch <<U
set detour.l_bad=list
set detour.l_bad.label='Плохой список'
set detour.l_bad.policy=vpn
set detour.l_bad.url=$S/no-such-list.txt
commit detour
U
/usr/libexec/detour/lists-update l_bad >/dev/null 2>&1
waitfor $((n_l+1)) "nlog 'Список «Плохой список» не обновился'" 30 && ok "notification: the list failed, with its name" || bad "no list message: $(cat /tmp/detour/lists/l_bad.status)"
wget -qO- $T/log | grep 'Плохой список' | tail -1 | grep -q 'не удалось скачать с 10.0.2.2:8768' && ok "the reason: the host, not the whole address" || bad "reason: $(wget -qO- $T/log | grep 'Плохой список' | tail -1)"

echo "== the provider's line goes away and comes back"
DEF=$(ip -4 route show default table main | head -1)
n_w=$(nlog 'Пропал интернет'); n_b=$(nlog 'Интернет у провайдера вернулся'); n_d=$(nlog 'перестал отвечать')
ip route del $DEF
waitfor $((n_w+1)) "nlog 'Пропал интернет'" 40 && ok "notification: the line is gone" || bad "no WAN down message"
ip route add $DEF
waitfor $((n_b+1)) "nlog 'Интернет у провайдера вернулся'" 40 && ok "notification: the line is back" || bad "no WAN back message"
[ "$(nlog 'перестал отвечать')" = "$n_d" ] && ok "no exit messages meanwhile" || bad "exit messages during the outage"
[ -n "$(ip -4 route show default table main)" ] || { ip route add $DEF; bad "default route not restored"; }

echo "== messages are Russian"
wget -qO- $T/log | tail -5 | grep -qE 'is working again|not responding|now goes through' && bad "an English message" || ok "no English texts"

cleanup
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
