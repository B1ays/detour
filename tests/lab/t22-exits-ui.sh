#!/bin/sh
# LuCI "Exits" backend: exits_info (what each exit is, no secrets), exit_check (a real request through the exit),
# a subscription's servers by name and choosing one (pick) / automatic, the proxy exit's configuration
# (get / set / another server from a link), removing an exit with everything it owns, refusing to remove an exit
# another one rides, subscriptions updated by their own interval (sub-update --due).
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
info() { ubus call detour exits_info; }
xi() { info | jsonfilter -e "@.exits[@.name='$1'].$2"; }
S=http://10.0.2.2:8768
b64() { ucode -e 'print(b64enc(ARGV[0]))' "$1"; }
PW=$(cat /etc/enodia-lab/ss.pw)
lab tests/lab/restart-sb.sh >/dev/null
cleanup() {
	for s in tsub tsub_sub tsub_sub_eng tmpx tmpx_eng tmpy tmpy_eng; do uci -q delete detour.$s; done
	for s in tsub_sub tmpx tmpy; do uci -q delete network.$s; for z in vpn detour; do uci -q del_list firewall.$z.network=$s; done; done
	uci commit; rm -f /etc/detour/engines/tsub_sub.* /etc/detour/engines/tmpx.json /etc/detour/engines/tmpy.json /tmp/detour/subs/tsub.*
	ubus call detour reload >/dev/null
}
cleanup

echo "== exits_info"
[ "$(xi sbx kind)" = singbox ] && [ "$(xi sbx proto)" = 'Shadowsocks' ] && ok "sbx: sing-box, Shadowsocks ($(xi sbx server):$(xi sbx port))" || bad "sbx: $(info | jsonfilter -e "@.exits[@.name='sbx']")"
[ "$(xi xrx kind)" = xray ] && [ "$(xi xrx proto)" = 'Shadowsocks' ] && ok "xrx: Xray, $(xi xrx proto)" || bad "xrx: $(xi xrx kind) '$(xi xrx proto)'"
[ "$(xi warp kind)" = wireguard ] && [ -n "$(xi warp server)" ] && ok "warp: WireGuard to $(xi warp server):$(xi warp port)" || bad "warp: $(info | jsonfilter -e "@.exits[@.name='warp']")"
info | grep -qiE "$PW|private_key|password" && bad "a secret in exits_info" || ok "no secrets in exits_info"
[ "$(xi sbx healthy)" = true ] && ok "state merged in (healthy)" || bad "healthy '$(xi sbx healthy)'"

echo "== exit_check: a real request through the exit"
R=$(ubus -t 30 call detour exit_check '{"name":"sbx"}')
[ "$(echo "$R" | jsonfilter -e @.ok)" = true ] && [ -n "$(echo "$R" | jsonfilter -e @.ip)" ] && ok "sbx answers ($(echo "$R" | jsonfilter -e @.ms) ms, $(echo "$R" | jsonfilter -e @.ip))" || bad "check: $R"
ifdown wgx2; sleep 2
R=$(ubus -t 30 call detour exit_check '{"name":"alt"}')
[ "$(echo "$R" | jsonfilter -e @.ok)" = false ] && ok "a down exit: no answer reported" || bad "down check: $R"
ifup wgx2

echo "== subscription servers by name, choosing one"
DEAD="ss://$(b64 "2022-blake3-aes-128-gcm:$PW")@10.199.1.2:9999#Dead%20one"
GOOD="ss://$(b64 "2022-blake3-aes-128-gcm:$PW")@10.199.1.2:8443#Good%20one"
printf '%s\n%s\n' "$DEAD" "$GOOD" > /tmp/l.txt; curl -s --data-binary @/tmp/l.txt $S/set/links >/dev/null
uci -q batch <<U
set detour.tsub=subscription
set detour.tsub.url=$S/sub/T22/b64
set detour.tsub.allow_private=1
set detour.tsub.label=Provider
commit detour
U
detour sub-update tsub >/dev/null
names=$(info | jsonfilter -e "@.exits[@.name='tsub_sub'].servers[*].name" | tr '\n' '|')
[ "$names" = 'Dead one|Good one|' ] && ok "servers listed by their names ($names)" || bad "names: $names"
[ "$(xi tsub_sub kind)" = subscription ] && [ "$(xi tsub_sub subscription)" = tsub ] && ok "kind subscription" || bad "kind $(xi tsub_sub kind)"
KEY=$(info | jsonfilter -e "@.exits[@.name='tsub_sub'].servers[1].key")
R=$(ubus -t 30 call detour exit_pick "{\"name\":\"tsub_sub\",\"key\":\"$KEY\"}")
[ "$(uci -q get detour.tsub_sub_eng.pick)" = "$KEY" ] && ok "picked: $KEY" || bad "pick: $R"
waitfor 8443 "jsonfilter -i /tmp/detour/engines/tsub_sub_eng.json -e '@.outbounds[0].server_port'" 20 && \
	[ -z "$(jsonfilter -i /tmp/detour/engines/tsub_sub_eng.json -e '@.outbounds[@.type=\"urltest\"].tag')" ] && ok "engine runs only the picked server" || bad "engine: $(jsonfilter -i /tmp/detour/engines/tsub_sub_eng.json -e '@.outbounds[*].type')"
R=$(ubus -t 30 call detour exit_pick '{"name":"tsub_sub","key":"nope|1.2.3.4:1"}')
echo "$R" | grep -q 'no such server' && ok "an unknown server refused" || bad "unknown pick: $R"
ubus -t 30 call detour exit_pick '{"name":"tsub_sub","key":""}' >/dev/null
waitfor urltest "jsonfilter -i /tmp/detour/engines/tsub_sub_eng.json -e '@.outbounds[@.type=\"urltest\"].type'" 20 && [ -z "$(uci -q get detour.tsub_sub_eng.pick)" ] && ok "back to automatic (urltest)" || bad "auto"

echo "== the configuration of a proxy exit"
detour engine-add tmpx "ss://$(b64 "2022-blake3-aes-128-gcm:$PW")@10.199.1.2:8443#tmp" >/dev/null
C=$(ubus call detour exit_config_get '{"name":"tmpx"}' | jsonfilter -e @.config)
echo "$C" | jsonfilter -e @.server_port | grep -qx 8443 && ok "config read" || bad "get: $C"
NEW=$(echo "$C" | sed 's/"server_port": 8443/"server_port": 8444/')
R=$(ubus -t 30 call detour exit_config_set "$(ucode -e 'print(sprintf("%J", { name: "tmpx", config: ARGV[0] }))' "$NEW")")
[ "$(jsonfilter -i /etc/detour/engines/tmpx.json -e @.server_port)" = 8444 ] && ok "config written" || bad "set: $R"
R=$(ubus -t 30 call detour exit_config_set '{"name":"tmpx","config":"{not json"}')
echo "$R" | grep -q 'not valid JSON' && [ "$(jsonfilter -i /etc/detour/engines/tmpx.json -e @.server_port)" = 8444 ] && ok "bad JSON refused, file kept" || bad "bad json: $R"
R=$(ubus -t 30 call detour exit_set_link "{\"name\":\"tmpx\",\"link\":\"trojan://pw@10.199.1.2:443?sni=x.example#t\"}")
[ "$(jsonfilter -i /etc/detour/engines/tmpx.json -e @.type)" = trojan ] && [ "$(xi tmpx proto)" = 'Trojan · TLS · TCP' ] && ok "another server from a link (Trojan · TLS · TCP)" || bad "link: $R / $(xi tmpx proto)"

echo "== removing"
detour engine-add tmpy "ss://$(b64 "2022-blake3-aes-128-gcm:$PW")@10.199.1.2:8443#y" tmpx >/dev/null
R=$(ubus -t 30 call detour exit_remove '{"name":"tmpx"}')
echo "$R" | grep -q 'other exits connect through it' && [ "$(uci -q get detour.tmpx)" = exit ] && ok "refused: tmpy rides tmpx" || bad "ride: $R"
uci set detour.tmpp=policy; uci set detour.tmpp.id=40; uci add_list detour.tmpp.exit=tmpy; uci add_list detour.tmpp.exit=alt; uci commit detour
R=$(ubus -t 30 call detour exit_remove '{"name":"tmpy"}')
[ -z "$(uci -q get detour.tmpy)" ] && [ -z "$(uci -q get detour.tmpy_eng)" ] && [ -z "$(uci -q get network.tmpy)" ] && [ ! -e /etc/detour/engines/tmpy.json ] && ok "exit, engine, interface and file gone" || bad "leftovers: $(uci -q show detour | grep tmpy) $(uci -q get network.tmpy) $(ls /etc/detour/engines/tmpy.json 2>&1)"
uci show firewall | grep -q "'tmpy'" && bad "still in a firewall zone" || ok "out of the firewall zone"
[ "$(uci -q get detour.tmpp.exit)" = alt ] && ok "removed from the policy, the other exit kept" || bad "policy exits: $(uci -q get detour.tmpp.exit)"
uci delete detour.tmpp; uci commit detour
ubus -t 30 call detour exit_remove '{"name":"tmpx"}' >/dev/null
ubus -t 30 call detour exit_remove '{"name":"tsub_sub"}' >/dev/null
[ -z "$(uci -q get detour.tsub)" ] && [ -z "$(uci -q get detour.tsub_sub)" ] && [ ! -e /etc/detour/engines/tsub_sub.json ] && [ ! -e /etc/detour/engines/tsub_sub.names.json ] && ok "a subscription removed with its exit" || bad "sub leftovers"

echo "== subscriptions by their own interval"
uci -q batch <<U
set detour.tsub=subscription
set detour.tsub.url=$S/sub/T22/b64
set detour.tsub.allow_private=1
set detour.tsub.interval=6
commit detour
U
detour sub-update tsub >/dev/null; t1=$(jsonfilter -i /tmp/detour/subs/tsub.status -e @.ts)
sleep 2; detour sub-update --due >/dev/null
[ "$(jsonfilter -i /tmp/detour/subs/tsub.status -e @.ts)" = "$t1" ] && ok "not due yet: not downloaded again" || bad "updated although not due"
ucode -e 'import * as fs from "fs"; let s = json(fs.readfile("/tmp/detour/subs/tsub.status")); s.ts -= 7 * 3600; fs.writefile("/tmp/detour/subs/tsub.status", sprintf("%J", s));'
detour sub-update --due >/dev/null
[ "$(jsonfilter -i /tmp/detour/subs/tsub.status -e @.ts)" -gt "$t1" ] && ok "due after 6 h: downloaded" || bad "not updated when due"
grep -q '^29 \* \* \* \* /usr/libexec/detour/sub-update' /etc/crontabs/root && ok "hourly cron" || bad "cron: $(grep sub-update /etc/crontabs/root)"
cleanup
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
