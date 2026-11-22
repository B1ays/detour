#!/bin/sh
# One server, two engines: a link both sing-box and Xray run is added on the engine chosen (by default on
# sing-box, as before); an XHTTP link (Xray only) becomes an Xray exit; what an engine cannot run is told, not
# written; a subscription on sing-box leaves XHTTP servers out, saying why, on Xray it runs them (a balancer over
# the servers, its choice and a check of one server for LuCI); another server for an exit from a link keeps the
# exit's engine when it can and moves it when it must. Everything comes up healthy against a real Xray server
# (VLESS over XHTTP and over WebSocket) in netns ex2.
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
healthy() { waitfor true "ubus call detour status | jsonfilter -e '@.exits[@.name=\"$1\"].healthy'" ${2:-60}; }
etype() { uci -q get detour.$1_eng.type; }
T=/tmp/t30; rm -rf $T; mkdir -p $T
U=$(cat /proc/sys/kernel/random/uuid)
D=/etc/enodia-lab; umask 077

ip netns list | grep -q '^ex2 ' || lab tests/lab/l2-exit.sh 2 >/dev/null 2>&1
cleanup() {
	for n in tx1 tx2 tx3 tx4 tx5 txs_sub; do [ "$(uci -q get detour.$n)" = exit ] && detour exit-remove $n >/dev/null 2>&1; done
	uci -q delete detour.txs; uci commit detour
	kill $(cat $T/xs.pid 2>/dev/null) 2>/dev/null
	for p in $(pgrep -f xray-t30.json); do kill $p; done
}
cleanup
# the server: VLESS over XHTTP on 8444 and over WebSocket on 8445, no TLS (a private address: Xray allows it); IPv4
# only: the lab's upstream DNS may be a Detour router, its AAAA 100:: is a reserved address Xray's freedom refuses
cat > $D/xray-t30.json <<J
{ "log": { "loglevel": "warning" },
  "inbounds": [
    { "listen": "10.199.2.2", "port": 8444, "protocol": "vless", "settings": { "clients": [ { "id": "$U" } ], "decryption": "none" },
      "streamSettings": { "network": "xhttp", "xhttpSettings": { "path": "/xh", "mode": "auto" } } },
    { "listen": "10.199.2.2", "port": 8445, "protocol": "vless", "settings": { "clients": [ { "id": "$U" } ], "decryption": "none" },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/ws" } } } ],
  "outbounds": [ { "protocol": "freedom", "settings": { "domainStrategy": "UseIPv4" } } ] }
J
(ip netns exec ex2 xray run -c $D/xray-t30.json > $T/xs.log 2>&1 & echo $! > $T/xs.pid)
sleep 2
XH="vless://$U@10.199.2.2:8444?encryption=none&security=none&type=xhttp&path=%2Fxh&mode=auto#t30-xhttp"
WS="vless://$U@10.199.2.2:8445?encryption=none&security=none&type=ws&path=%2Fws#t30-ws"
H2="vless://$U@10.199.2.2:8446?encryption=none&security=tls&sni=x.example&type=h2&path=%2Fh#t30-h2"
put() { printf '%s\n' "$@" > $T/in; }

echo "== what each engine runs"
put "$XH"; R=$(detour exit-parse $T/in)
[ "$(echo "$R" | jsonfilter -e '@.candidates[0].kind')" = xray ] && [ "$(echo "$R" | jsonfilter -e '@.candidates[0].engines[*]' | tr '\n' ' ')" = "xray " ] \
	&& ok "an XHTTP link: Xray only" || bad "xhttp: $R"
put "$WS"; R=$(detour exit-parse $T/in)
[ "$(echo "$R" | jsonfilter -e '@.candidates[0].kind')" = singbox ] && [ "$(echo "$R" | jsonfilter -e '@.candidates[0].engines[*]' | tr '\n' ' ')" = "singbox xray " ] \
	&& ok "a WebSocket link: both, sing-box by default" || bad "ws: $R"
put "$H2"; R=$(detour exit-parse $T/in)
[ "$(echo "$R" | jsonfilter -e '@.candidates[0].engines[*]' | tr '\n' ' ')" = "singbox " ] && ok "an HTTP/2 link: sing-box only (Xray 26 dropped it)" || bad "h2: $R"
echo "$R" | grep -q "$U" && bad "the parse answer shows the UUID" || ok "no secret in the parse answer"
echo '{"protocol":"vless","settings":{"vnext":[{"address":"10.199.2.2","port":8445,"users":[{"id":"'$U'","encryption":"none"}]}]},"streamSettings":{"network":"ws","wsSettings":{"path":"/ws"}}}' > $T/in
R=$(detour exit-parse $T/in)
[ "$(echo "$R" | jsonfilter -e '@.candidates[0].kind')" = xray ] && [ "$(echo "$R" | jsonfilter -e '@.candidates[0].engines[*]' | tr '\n' ' ')" = "xray singbox " ] \
	&& ok "an Xray JSON: Xray by default, sing-box possible" || bad "xray json: $R"

echo "== added on the engine chosen, healthy against the real server"
put "$XH"; R=$(detour exit-add $T/in - tx1)
[ "$(etype tx1)" = xray ] && ok "XHTTP link -> Xray exit" || bad "tx1: $R"
jsonfilter -i /tmp/detour/engines/tx1_eng.json -e '@.outbounds[0].streamSettings.network' | grep -qx xhttp && ok "Xray config has the xhttp transport" || bad "tx1 config"
healthy tx1 && ok "tx1 (VLESS XHTTP on Xray) healthy" || bad "tx1 not healthy ($(cat /tmp/detour/engines.err))"
put "$WS"; R=$(detour exit-add $T/in - tx2)
[ "$(etype tx2)" = singbox ] && ok "WebSocket link, no choice -> sing-box (as before)" || bad "tx2: $R"
put "$WS"; R=$(detour exit-add $T/in - tx3 - - xray)
[ "$(etype tx3)" = xray ] && ok "WebSocket link, Xray chosen -> Xray" || bad "tx3: $R"
healthy tx2 && ok "tx2 (WS on sing-box) healthy" || bad "tx2 not healthy"
healthy tx3 && ok "tx3 (WS on Xray) healthy" || bad "tx3 not healthy"
put "$XH"; R=$(detour exit-add $T/in - tx4 - - singbox)
[ "$(etype tx4)" = xray ] && ok "sing-box asked for XHTTP -> still Xray (the only one that can)" || bad "tx4: $R"
grep -q '"_x"' /etc/detour/engines/tx2.json /tmp/detour/engines/tx2_eng.json && bad "Xray-only fields in a sing-box config" || ok "no Xray-only fields in the sing-box config"
ls -l /etc/detour/engines/tx1.json | grep -q '^-rw-------' && ok "outbound file mode 600" || bad "mode"
ls /tmp/detour/engines/.test-* 2>/dev/null && bad "the engine test left a file" || ok "the engine test left nothing"

echo "== an engine that refuses is told, nothing is written"
put "vless://$U@10.199.2.2:8444?encryption=mlkem768x25519plus.native.0rtt.AAAA&security=none&type=xhttp&path=%2Fxh#bad"
R=$(detour exit-add $T/in - tx5); echo "$R" | grep -q 'Xray refused the configuration' && [ -z "$(uci -q get detour.tx5)" ] \
	&& ok "a configuration Xray refuses: told, no exit" || bad "tx5: $R"

echo "== another server from a link: the exit keeps its engine when it can"
R=$(detour exit-set-link tx3 "$WS")
[ "$(etype tx3)" = xray ] && ok "Xray exit + WS link -> stays on Xray" || bad "tx3 set-link: $R"
R=$(detour exit-set-link tx2 "$XH")
[ "$(etype tx2)" = xray ] && ok "sing-box exit + XHTTP link -> moves to Xray" || bad "tx2 set-link: $R"
healthy tx2 && ok "tx2 healthy on Xray" || bad "tx2 not healthy after the move"

echo "== a subscription leaves XHTTP servers out, saying why"
R=$(ucode -L /usr/share/ucode -e 'import * as s from "detour.subs"; const r = s.parse_body(ARGV[0]); print(length(r.outbounds), " ", join("|", r.skipped));' -- "$(printf '%s\n%s' "$WS" "$XH")")
case "$R" in "1 t30-xhttp: sing-box has no XHTTP transport, needs Xray") ok "subscription: 1 server, XHTTP skipped with the reason";; *) bad "subs: $R";; esac
HY="hysteria2://pw@10.199.2.2:8447?sni=x.example#t30-hy2"
R=$(ucode -L /usr/share/ucode -e 'import * as s from "detour.subs"; const r = s.parse_body(ARGV[0], "xray"); print(length(r.outbounds), " ", join(",", map(r.outbounds, (o) => o.protocol + "/" + o.streamSettings.network)), " ", join("|", r.skipped));' -- "$(printf '%s\n%s\n%s' "$WS" "$XH" "$HY")")
case "$R" in "2 vless/ws,vless/xhttp t30-hy2: Xray runs here only VLESS, VMess, Trojan and Shadowsocks") ok "subscription on Xray: WS and XHTTP in Xray form, Hysteria2 skipped with the reason";; *) bad "subs xray: $R";; esac

echo "== a subscription on Xray: one exit, a balancer over its servers, healthy; back to sing-box"
SS=http://10.0.2.2:8768
printf '%s\n%s\n' "$WS" "$XH" > $T/l.txt; curl -s --data-binary @$T/l.txt $SS/set/links >/dev/null
uci -q batch <<U
set detour.txs=subscription
set detour.txs.url=$SS/sub/T30/b64
set detour.txs.allow_private=1
set detour.txs.engine=xray
commit detour
U
R=$(detour sub-update txs)
echo "$R" | grep -q '"servers": 2' && [ "$(etype txs_sub)" = xray ] && ok "subscription on Xray: 2 servers, an Xray engine" || bad "txs: $R"
reload_config; sleep 5
X=/tmp/detour/engines/txs_sub_eng.json
[ "$(jsonfilter -i $X -e '@.routing.balancers[0].strategy.type')" = leastPing ] && [ "$(jsonfilter -i $X -e '@.routing.rules[0].balancerTag')" = out ] \
	&& ok "balancer leastPing, the tunnel's traffic goes to it" || bad "balancer: $(jsonfilter -i $X -e '@.routing')"
[ "$(jsonfilter -i $X -e '@.outbounds[*].streamSettings.sockopt.mark' | sort -u | wc -l)" = 1 ] && [ "$(jsonfilter -i $X -e '@.outbounds[1].streamSettings.sockopt.mark')" != "" ] \
	&& ok "every server carries the underlay mark" || bad "marks"
xray run -test -c $X >/dev/null 2>&1 && ok "Xray accepts it" || bad "xray -test: $(xray run -test -c $X 2>&1 | tail -1)"
healthy txs_sub 90 && ok "txs (Xray balancer) healthy" || bad "txs not healthy"
R=$(ubus call detour sub_state '{"name":"txs_sub"}'); echo "$R" | grep -q '"now": [01]' && ok "the group says which server it uses" || bad "sub_state: $R"
R=$(ubus call detour sub_check '{"name":"txs_sub","index":1}'); echo "$R" | grep -q '"ok": true' && ok "one server checked through the check inbound" || bad "sub_check: $R"
# the usual speed address (the internet, as the checks above): the lab's Xray server does not reach the PC's private address
R=$(ubus -t 30 call detour sub_speed '{"name":"txs_sub","index":0}'); echo "$R" | grep -q '"ok": true' && ok "speed of one server of the Xray group: $(echo "$R" | jsonfilter -e '@.mbps') Mbit/s" || bad "xray server speed: $R"
ps w | grep -v grep | grep 'xray run' | grep -q -- "-c $X" && ok "Xray runs it" || bad "no xray process"
uci -q delete detour.txs.engine; uci commit detour
R=$(detour sub-update txs)
echo "$R" | grep -q '"servers": 1' && [ "$(etype txs_sub)" = singbox ] && ok "back on sing-box: 1 server, XHTTP skipped" || bad "txs back: $R"
grep -q streamSettings /etc/detour/engines/txs_sub.json && bad "an Xray form left in a sing-box file" || ok "the file is in sing-box form again"
healthy txs_sub 90 && ok "txs healthy on sing-box" || bad "txs not healthy on sing-box"

echo "== cleanup"
cleanup
[ -z "$(uci -q get detour.tx1)$(uci -q get detour.tx2)$(uci -q get detour.tx3)" ] && ok "test exits removed" || bad "left"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
