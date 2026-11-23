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
set detour.notify.lang=ru
commit detour
U
ubus call detour reload >/dev/null
n0=$(nlog 'Проверочное сообщение')
ubus call detour notify_test >/dev/null
waitge $((n0+1)) "nlog 'Проверочное сообщение'" 15 && ok "test message delivered" || bad "test message not delivered"
logread | grep 'notify: sent via' | tail -1 | grep -qv 'via direct' && ok "sent through a working exit ($(logread | grep 'notify: sent via' | tail -1 | sed 's/.*via //'))" || bad "path: $(logread | grep 'notify: sent via' | tail -1)"
wget -qO- $S/log | tail -1 | grep -q '"chat_id": "4242"' && ok "chat id and JSON body" || bad "body: $(wget -qO- $S/log | tail -1)"
ls -l /tmp/detour/notify/telegram.cfg | grep -q "^-rw------- .* dtnotify " && ok "token file mode 600, owned by dtnotify" || bad "mode: $(ls -l /tmp/detour/notify/telegram.cfg)"
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
echo "== the language of the messages"
uci set detour.notify.lang=en; uci commit detour
n0=$(nlog 'Test message: notifications work'); ubus call detour notify_test >/dev/null
waitge $((n0+1)) "nlog 'Test message: notifications work'" 15 && ok "lang=en: in English" || bad "no English test message: $(wget -qO- $S/log | tail -1)"
uci -q delete detour.notify.lang; uci commit detour
L=$(uci -q get luci.main.lang)
uci set luci.main.lang=en; uci commit luci
[ "$(ucode -e 'import { lang } from "detour.i18n"; print(lang())')" = en ] && ok "no lang: as LuCI (en)" || bad "as LuCI en"
uci set luci.main.lang=ru; uci commit luci
[ "$(ucode -e 'import { lang } from "detour.i18n"; print(lang())')" = ru ] && ok "no lang: as LuCI (ru)" || bad "as LuCI ru"
uci set detour.notify.lang=de; uci commit detour
[ "$(ucode -e 'import { lang } from "detour.i18n"; print(lang())')" = en ] && ok "a language without a dictionary: English" || bad "unknown language"
uci set detour.notify.lang=ru
[ -n "$L" ] && uci set luci.main.lang="$L" || uci -q delete luci.main.lang
uci commit luci; uci commit detour
echo "== ntfy"
NT=detour-lab-t9topic; NK=tk_labntfytoken0123456789abcdef
uci -q batch <<U
set detour.notify.telegram=0
set detour.notify.ntfy=1
set detour.notify.ntfy_url=$S/
set detour.notify.ntfy_topic=$NT
set detour.notify.ntfy_token=$NK
commit detour
U
ubus call detour reload >/dev/null
ntl() { wget -qO- $S/log | grep '"ntfy": true' | grep -c "$1"; }
n0=$(ntl 'Проверочное сообщение')
# a watcher of the command lines while the message goes (the stub answers ntfy after 1 s)
(e=$(($(date +%s) + 8)); while [ "$(date +%s)" -lt $e ]; do P=$(ps w); echo "$P" | grep -q '[c]url' && echo curl >> /tmp/t9seen; echo "$P" | grep -F -e "$NK" -e "$NT" | grep -v grep; done) > /tmp/t9ps &
ubus call detour notify_test >/dev/null
waitge $((n0+1)) "ntl 'Проверочное сообщение'" 15 && ok "ntfy: test message delivered" || bad "ntfy: not delivered (queue $(ubus call detour status | jsonfilter -e '@.notify_queued'))"
L=$(wget -qO- $S/log | grep '"ntfy": true' | tail -1)
echo "$L" | grep -q "\"topic\": \"$NT\"" && echo "$L" | grep -q '"title": "' && ! echo "$L" | grep -q '"message": "[^"]*: Проверочное' && ok "topic in the body, the router's name as the title" || bad "body: $L"
echo "$L" | grep -q "\"auth\": \"Bearer\", \"auth_len\": ${#NK}" && ok "the token as a Bearer header" || bad "auth: $L"
logread | grep 'notify: sent via' | tail -1 | grep -q '(ntfy)' && ok "logged as ntfy" || bad "log: $(logread | grep 'notify: sent via' | tail -1)"
wait; [ -s /tmp/t9seen ] && [ ! -s /tmp/t9ps ] && ok "neither token nor topic on curl's command line" || bad "argv: curl seen $(wc -l < /tmp/t9seen 2>/dev/null) times, $(head -c 300 /tmp/t9ps)"; rm -f /tmp/t9ps /tmp/t9seen
grep -q "$NK" /tmp/detour/notify/ntfy.cfg && grep -q "$NT" /tmp/detour/notify/ntfy.json && [ -z "$(ls -l /tmp/detour/notify/ntfy.cfg /tmp/detour/notify/ntfy.json | grep -v '^-rw------- .* dtnotify ')" ] && ok "token and topic files mode 600, owned by dtnotify" || bad "files: $(ls -l /tmp/detour/notify/)"
[ -z "$(ucode -e 'import { redact } from "detour.core"; print(redact(ARGV[0]))' "option ntfy_topic '$NT'" | grep -F "$NT")" ] && ok "the topic is masked in the log" || bad "topic not masked"
echo "-- refused (403): dropped, not retried"
uci set detour.notify.ntfy_topic=denied; uci commit detour; ubus call detour reload >/dev/null
ubus call detour notify_test >/dev/null
waitfor 0 "ubus call detour status | jsonfilter -e '@.notify_queued'" 20 && logread | tail -20 | grep -q 'rejected by the API (HTTP 403)' && ok "403: dropped" || bad "403: queue $(ubus call detour status | jsonfilter -e '@.notify_queued'), $(logread | grep 'notify:' | tail -1)"
echo "-- no topic: not configured"
uci -q delete detour.notify.ntfy_topic; uci commit detour; ubus call detour reload >/dev/null
r=$(ubus call detour notify_test | jsonfilter -e '@.queued'); [ "$r" = false ] && ok "ntfy without a topic: refused" || bad "test: $r"
echo "== both channels: each message to each; a refusal of one holds nothing of the other"
uci set detour.notify.telegram=1; uci set detour.notify.ntfy_topic=$NT; uci commit detour; ubus call detour reload >/dev/null
tgl() { wget -qO- $S/log | grep -v '"ntfy": true' | grep -c 'Проверочное'; }
a=$(tgl); b=$(ntl 'Проверочное')
ubus call detour notify_test >/dev/null
waitge $((a+1)) tgl 15 && waitge $((b+1)) "ntl 'Проверочное'" 15 && ok "one test message: in Telegram and in ntfy" || bad "both: telegram $a->$(tgl), ntfy $b->$(ntl 'Проверочное')"
uci set detour.notify.ntfy_topic=denied; uci commit detour; ubus call detour reload >/dev/null
a=$(tgl); ubus call detour notify_test >/dev/null
waitge $((a+1)) tgl 15 && waitfor 0 "ubus call detour status | jsonfilter -e '@.notify_queued'" 20 && ok "ntfy refuses (403), Telegram still delivers, nothing stuck" || bad "telegram $a->$(tgl), queue $(ubus call detour status | jsonfilter -e '@.notify_queued')"
echo "-- an older queue (one file) is sent on"
uci set detour.notify.ntfy=0; uci commit detour; ubus call detour reload >/dev/null
a=$(tgl); echo '[{"t":'$(date +%s)',"text":"Проверочное из старой очереди"}]' > /tmp/detour/outbox.json
waitge $((a+1)) tgl 20 && [ ! -e /tmp/detour/outbox.json ] && ok "the old queue delivered and gone" || bad "old queue: $(ls /tmp/detour/outbox*)"
for o in telegram ntfy ntfy_topic ntfy_url ntfy_token; do uci -q delete detour.notify.$o; done; uci commit detour
ubus call detour reload >/dev/null
n0=$(tgl); ubus call detour notify_test >/dev/null
waitge $((n0+1)) tgl 15 && ok "back to Telegram" || bad "telegram after ntfy"
echo "== disabled -> nothing sent"
uci set detour.notify.enabled=0; uci commit detour; ubus call detour reload >/dev/null
r=$(ubus call detour notify_test | jsonfilter -e '@.queued'); [ "$r" = false ] && ok "test refused when disabled" || bad "test: $r"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
