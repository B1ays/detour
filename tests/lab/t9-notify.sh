#!/bin/sh
# notifications against the lab stub of the Bot API on 10.0.2.2:8766 (no real Telegram):
# test message, exit down/switch events, API failure -> queue -> later delivery, token not in argv.
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
S=http://10.0.2.2:8766
nlog() { wget -qO- $S/log | grep -c "$1"; }
# at least one more (a message left in the queue by an earlier run may arrive too)
waitge() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" -ge "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
uci -q batch <<'U'
set detour.notify=notify
set detour.notify.enabled=1
set detour.notify.tg_token=123456:LABTOKEN_not_a_real_token_xxxxxxxxxxx
set detour.notify.tg_chat=4242
set detour.notify.tg_api=http://10.0.2.2:8766
set detour.notify.throttle=5
commit detour
U
ubus call detour reload >/dev/null
n0=$(nlog 'Проверочное сообщение')
ubus call detour notify_test >/dev/null
waitge $((n0+1)) "nlog 'Проверочное сообщение'" 15 && ok "test message delivered" || bad "test message not delivered"
logread | grep 'notify: sent via' | tail -1 | grep -qv 'via direct' && ok "sent through a working exit ($(logread | grep 'notify: sent via' | tail -1 | sed 's/.*via //'))" || bad "path: $(logread | grep 'notify: sent via' | tail -1)"
wget -qO- $S/log | tail -1 | grep -q '"chat_id": "4242"' && ok "chat id and JSON body" || bad "body: $(wget -qO- $S/log | tail -1)"
ls -l /tmp/detour/notify/curl.cfg | grep -q "^-rw------- .* dtnotify " && ok "token file mode 600, owned by dtnotify" || bad "mode: $(ls -l /tmp/detour/notify/curl.cfg)"
# after a line outage (another test) exit messages are held back for 3 min
waitfor false "ubus call detour status | jsonfilter -e '@.notify_quiet'" 200 || bad "notifications still quiet"
echo "== exit down -> 'перестал отвечать' + switch"
d0=$(nlog 'перестал отвечать'); s0=$(nlog 'переключилась')
ifdown wgx1
waitge $((d0+1)) "nlog 'перестал отвечать'" 40 && ok "exit down message" || bad "no exit down message"
waitge $((s0+1)) "nlog 'переключилась'" 45 && ok "switch message" || bad "no switch message"
ifup wgx1; sleep 8
echo "== API failing (blocked) -> queued, delivered later with its time"
wget -qO- "$S/fail?n=25" >/dev/null
q0=$(nlog 'Проверочное сообщение'); ubus call detour notify_test >/dev/null; sleep 5
[ "$(ubus call detour status | jsonfilter -e '@.notify_queued')" -ge 1 ] && ok "queued while the API fails" || bad "not queued"
waitfor 0 "ubus call detour status | jsonfilter -e '@.notify_queued'" 60 && ok "queue drained after the API came back" || bad "queue stuck"
[ "$(nlog 'Проверочное сообщение')" -gt "$q0" ] && ok "delivered" || bad "not delivered"
echo "== all exits down and the API address is on a VPN list: the direct attempt must still deliver"
# lab: a TEST-NET address stands for api.telegram.org; router-originated traffic to it is DNATed to the stub
nft -f - <<'N'
table ip labdnat
delete table ip labdnat
table ip labdnat {
	chain out {
		type nat hook output priority dstnat;
		ip daddr 198.51.100.7 tcp dport 80 dnat to 10.0.2.2:8766
	}
}
N
uci set detour.sb.enabled=0; uci set detour.xr.enabled=0
uci add_list detour.vpn.dst=198.51.100.0/24; uci set detour.notify.tg_api=http://198.51.100.7; uci commit detour
reload_config; sleep 6
ifdown wgx1; ifdown wgx2; sleep 8
n0=$(nlog 'Проверочное сообщение'); ubus call detour notify_test >/dev/null
waitge $((n0+1)) "nlog 'Проверочное сообщение'" 40 && ok "delivered with every exit down (address on a VPN list)" || bad "not delivered: queue=$(ubus call detour status | jsonfilter -e '@.notify_queued')"
logread | grep 'notify: sent via' | tail -1 | grep -q 'via direct' && ok "path: direct" || bad "path: $(logread | grep 'notify: sent via' | tail -1)"
ifup wgx1; ifup wgx2
nft delete table ip labdnat
uci set detour.sb.enabled=1; uci set detour.xr.enabled=1
uci del_list detour.vpn.dst=198.51.100.0/24; uci set detour.notify.tg_api=http://10.0.2.2:8766; uci commit detour
reload_config; sleep 6
echo "== disabled -> nothing sent"
uci set detour.notify.enabled=0; uci commit detour; ubus call detour reload >/dev/null
r=$(ubus call detour notify_test | jsonfilter -e '@.queued'); [ "$r" = false ] && ok "test refused when disabled" || bad "test: $r"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
