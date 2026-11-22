#!/bin/sh
# Subscriptions against the lab stub (10.0.2.2:8768): base64 links (a dead server + the lab server) -> one exit
# with a urltest group that finds the working one; sing-box JSON format; UA/x-hwid sent; URL never on a command
# line; private URL refused without allow_private; failed download keeps the servers; works over a "via" exit.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
S=http://10.0.2.2:8768
txb() { cat /sys/class/net/$1/statistics/tx_bytes 2>/dev/null || echo 0; }
b64() { ucode -e 'print(b64enc(ARGV[0]))' "$1"; }
PW=$(cat /etc/enodia-lab/ss.pw)
lab tests/lab/restart-sb.sh >/dev/null   # with DNS in the netns (urltest probes resolve names)
cleanup() {
	for s in prov prov_sub prov_sub_eng prov2 prov2_sub prov2_sub_eng ps; do uci -q delete detour.$s; done
	uci -q delete network.prov_sub; uci -q delete network.prov2_sub; uci -q del_list firewall.vpn.network=prov_sub; uci -q del_list firewall.vpn.network=prov2_sub
	uci commit; rm -f /etc/detour/engines/prov*.json; rm -rf /tmp/detour/subs
}
cleanup
DEAD="ss://$(b64 "2022-blake3-aes-128-gcm:$PW")@10.199.1.2:9999#dead"
GOOD="ss://$(b64 "2022-blake3-aes-128-gcm:$PW")@10.199.1.2:8443#good"
printf '%s\n%s\nnot-a-link\n' "$DEAD" "$GOOD" > /tmp/l.txt; curl -s --data-binary @/tmp/l.txt $S/set/links >/dev/null

echo "== base64 subscription"
uci -q batch <<U
set detour.prov=subscription
set detour.prov.url=$S/sub/SECRET-TOKEN-123/b64
set detour.prov.hwid=lab-hwid-1
set detour.prov.allow_private=1
commit detour
U
R=$(detour sub-update prov)
echo "$R" | grep -q '"servers": 2' && ok "2 servers parsed (junk line skipped)" || bad "update: $R"
[ "$(uci -q get detour.prov_sub)" = exit ] && [ "$(uci -q get detour.prov_sub_eng.type)" = singbox ] && ok "exit + engine created" || bad "exit/engine"
wget -qO- $S/log | grep -q '"ua": "v2rayNG/1.10.0", "hwid": "lab-hwid-1"' && ok "User-Agent and x-hwid sent" || bad "headers: $(wget -qO- $S/log)"
reload_config; sleep 10
[ "$(jsonfilter -i /tmp/detour/engines/prov_sub_eng.json -e '@.outbounds[2].type')" = urltest ] && ok "urltest group over 2 servers" || bad "no urltest"
sing-box check -c /tmp/detour/engines/prov_sub_eng.json && ok "sing-box accepts it" || bad "sing-box check"
waitfor true "ubus call detour status | jsonfilter -e '@.exits[@.name=\"prov_sub\"].healthy'" 120 && ok "exit prov healthy (urltest found the working server)" || bad "prov not healthy"
# speed: the subscription as a whole and one server of it (the group's check inbound, user sN), from the lab's PC
BIG=$(wget -qO- http://10.0.2.2:8765/feed/ | grep -o 'xray-core-[^"]*\.apk' | head -n1)   # ~12 MB, on the lab's PC
uci set detour.main.speed_url=http://10.0.2.2:8765/feed/$BIG; uci commit detour
R=$(ubus -t 30 call detour exit_speed '{"name":"prov_sub"}'); echo "$R" | grep -q '"ok": true' && ok "speed of the subscription: $(echo "$R" | jsonfilter -e '@.mbps') Mbit/s" || bad "subscription speed: $R"
jsonfilter -i /tmp/detour/engines/prov_sub_eng.json -e '@.inbounds[@.tag="check"].type' | grep -qx socks && ok "sing-box group has its check inbound" || bad "no check inbound in the sing-box config"
R=$(ubus -t 30 call detour sub_speed '{"name":"prov_sub","index":1}'); echo "$R" | grep -q '"ok": true' && ok "speed of server 2 (good): $(echo "$R" | jsonfilter -e '@.mbps') Mbit/s" || bad "server speed: $R"
R=$(ubus -t 30 call detour sub_speed '{"name":"prov_sub","index":0}'); echo "$R" | grep -q '"ok": false' && ok "server 1 (dead): no speed, said so" || bad "dead server speed: $R"
uci -q delete detour.main.speed_url; uci commit detour
uci set detour.ps=policy; uci set detour.ps.id=8; uci add_list detour.ps.exit=prov_sub; uci add_list detour.ps.dst=9.9.9.0/24; uci commit detour; reload_config; sleep 5
conntrack -D -d 9.9.9.9 >/dev/null 2>&1
t0=$(txb provtun); r=$(cl "curl -s -m 10 -o /dev/null -w '%{http_code}' https://9.9.9.9/"); t1=$(txb provtun)
[ "$r" != 000 ] && [ $((t1 - t0)) -gt 0 ] && ok "policy traffic through the subscription exit (http $r)" || bad "traffic: http=$r tx+$((t1 - t0))"
grep -rq 'SECRET-TOKEN-123' /tmp/detour/subs 2>/dev/null && bad "URL left in /tmp" || ok "subscription URL not left in files"
logread | grep -q 'SECRET-TOKEN-123' && bad "URL in the log" || ok "subscription URL not in the log"

echo "== provider down: previous servers kept"
uci set detour.prov.url=$S/nothing-here; uci commit detour
detour sub-update prov >/dev/null
[ "$(jsonfilter -i /tmp/detour/subs/prov.status -e '@.ok')" = false ] && [ "$(jsonfilter -i /etc/detour/engines/prov_sub.json -e '@[1].server_port')" = 8443 ] && ok "error reported, servers unchanged" || bad "after failure"

echo "== sing-box JSON format"
printf '{"outbounds":[{"type":"shadowsocks","tag":"x","server":"10.199.1.2","server_port":8443,"method":"2022-blake3-aes-128-gcm","password":"%s"},{"type":"direct","tag":"direct"},{"type":"selector","tag":"sel","outbounds":["x"]}]}' "$PW" > /tmp/j.json
curl -s --data-binary @/tmp/j.json $S/set/json >/dev/null
uci set detour.prov2=subscription; uci set detour.prov2.url=$S/sub/T2/json; uci set detour.prov2.allow_private=1; uci set detour.prov2.user_agent=sing-box; uci commit detour
R=$(detour sub-update prov2); echo "$R" | grep -q '"servers": 1' && ok "1 proxy outbound taken from a sing-box config (direct/selector dropped)" || bad "json: $R"

echo "== redirects: followed by Detour itself, hop by hop"
uci set detour.prov2.url=$S/redir/sub/T2/json; uci commit detour
R=$(detour sub-update prov2); echo "$R" | grep -q '"servers": 1' && ok "a redirect is followed" || bad "redirect: $R"
uci set detour.prov2.url=$S/redir/redir/redir/redir/redir/redir/sub/T2/json; uci commit detour
R=$(detour sub-update prov2); echo "$R" | grep -q 'download failed' && ok "more than 5 redirects: refused" || bad "redirect loop: $R"
uci set detour.prov2.url=$S/sub/T2/json; uci set detour.prov2.allow_private=1; uci commit detour

echo "== a private URL is refused unless allowed"
uci delete detour.prov2.allow_private; uci commit detour
R=$(detour sub-update prov2); echo "$R" | grep -q 'private network' && ok "refused" || bad "private: $R"

echo "== subscription over another exit (via)"
uci set detour.prov.url=$S/sub/SECRET-TOKEN-123/b64; uci set detour.prov.via=alt; uci commit detour
detour sub-update prov >/dev/null
[ "$(uci -q get detour.prov_sub_eng.via)" = alt ] && ok "engine via alt" || bad "via"
reload_config; sleep 8
[ "$(jsonfilter -i /tmp/detour/engines/prov_sub_eng.json -e '@.outbounds[1].bind_interface')" = wgx2 ] && ok "servers dialled through wgx2" || bad "bind_interface"

cleanup; reload_config
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
