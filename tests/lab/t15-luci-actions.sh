#!/bin/sh
# Stage 4 "everything without SSH": the LuCI actions through the same path the pages use
# (LuCI login session -> /ubus JSON-RPC -> detourd deferred methods). Password: /tmp/lab-pw.
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
PW=$(cat /tmp/lab-pw)
rm -f /tmp/cj
curl -s -o /dev/null -c /tmp/cj --data-urlencode luci_username=root --data-urlencode "luci_password=$PW" http://127.0.0.1/cgi-bin/luci/
SID=$(awk '/sysauth/{print $7}' /tmp/cj | head -n1)
[ -n "$SID" ] && ok "LuCI session" || { bad "login"; exit 1; }
rpc() { curl -s -m 90 http://127.0.0.1/ubus -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"$SID\",\"detour\",\"$1\",${2:-{\}}]}"; }
D=/etc/enodia-lab

echo "== exit from a link"
PW2=$(cat $D/ss.pw)
L="ss://$(ucode -e 'print(b64enc(ARGV[0]))' "2022-blake3-aes-128-gcm:$PW2")@10.199.1.2:8443#lab-link"
uci -q delete detour.lnk1; uci -q delete detour.lnk1_eng; uci -q delete network.lnk1; uci commit
r=$(rpc engine_add "{\"name\":\"lnk1\",\"link\":\"$L\"}")
echo "$r" | grep -q '"exit_id"' && ok "engine_add: $(echo "$r" | jsonfilter -e '@.result[1].type')/$(echo "$r" | jsonfilter -e '@.result[1].server')" || bad "engine_add: $r"
reload_config
waitfor true "ubus call detour status | jsonfilter -e '@.exits[@.name=\"lnk1\"].healthy'" 40 && ok "exit lnk1 healthy" || bad "lnk1 not healthy"
r=$(rpc engine_add "{\"name\":\"lnk1\",\"link\":\"$L\"}"); echo "$r" | grep -q 'already used' && ok "duplicate name refused" || bad "dup: $r"
r=$(rpc engine_add "{\"name\":\"lnk2\",\"link\":\"$L\",\"via\":\"alt\"}")
[ "$(uci -q get detour.lnk2_eng.via)" = alt ] && ok "engine_add with via=alt (chain)" || bad "via: $r"
r=$(rpc engine_add "{\"name\":\"lnk3\",\"link\":\"$L\",\"via\":\"nosuch\"}"); echo "$r" | grep -q 'is not an exit' && ok "unknown via refused" || bad "via nosuch: $r"
r=$(rpc engine_add '{"name":"bad","link":"http://x"}'); echo "$r" | grep -q 'unsupported scheme' && ok "bad link refused" || bad "bad link: $r"

echo "== lists update"
uci -q delete detour.tl_ui; uci set detour.tl_ui=list; uci set detour.tl_ui.policy=vpn; uci add_list detour.tl_ui.url=http://10.0.2.2:8765/tests/stub/lists/cidr.txt; uci commit detour
r=$(rpc lists_update '{"name":"tl_ui"}'); echo "$r" | grep -q '"code":0' && ok "lists_update" || bad "lists_update: $r"
ubus call detour status | jsonfilter -e '@.lists[@.name="tl_ui"].count' | grep -qx 22 && ok "status shows 22 entries" || bad "status lists"

echo "== WARP (lab stub via main.warp_*)"
SPUB=$(cat $D/ex3.pub)
wget -qO- "http://10.0.2.2:8767/setpeer?key=$(echo "$SPUB" | sed 's/+/%2B/g; s/\//%2F/g; s/=/%3D/g')&ep=10.199.3.2&v4=10.200.3.1" >/dev/null
uci set detour.main.warp_api=http://10.0.2.2:8767/v0a2158; uci set detour.main.warp_peer="$SPUB"; uci set detour.main.warp_port=51820; uci commit detour
detour warp-unregister warpui >/dev/null 2>&1
r=$(rpc warp_register '{"name":"warpui"}'); echo "$r" | grep -q '"exit_id"' && ok "warp_register" || bad "warp_register: $r"
r=$(rpc warp_unregister '{"name":"warpui"}'); echo "$r" | grep -q '"deregistered":true' && ok "warp_unregister" || bad "warp_unregister: $r"
r=$(rpc warp_register '{"name":"warpaw","awg":true}'); [ "$(uci -q get network.warpaw.proto)" = amneziawg ] && ok "warp_register with AmneziaWG masking" || bad "awg: $r"
rpc warp_unregister '{"name":"warpaw"}' >/dev/null

echo "== import (file as LuCI uploads it)"
[ -s /tmp/stock.tgz ] || lab tests/lab/t13-import.sh >/dev/null 2>&1
cp /tmp/stock.tgz /tmp/detour-import.tgz
r=$(rpc import_check); echo "$r" | grep -q 'st_main: wg' && echo "$r" | grep -q '"note"' && ok "import_check (dry run)" || bad "import_check: $(echo "$r" | head -c 300)"
[ -z "$(uci -q get detour.st_main)" ] && ok "nothing written by the check" || bad "check wrote config"

echo "== actions need the write ACL: a read-only session is refused"
ubus call session create '{"timeout":60}' > /tmp/s.json; RO=$(jsonfilter -i /tmp/s.json -e '@.ubus_rpc_session')
ubus call session grant "{\"ubus_rpc_session\":\"$RO\",\"scope\":\"access-group\",\"objects\":[[\"luci-app-detour\",\"read\"]]}"
r=$(curl -s http://127.0.0.1/ubus -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"$RO\",\"detour\",\"engine_add\",{\"name\":\"x\",\"link\":\"$L\"}]}")
echo "$r" | grep -q 'Access denied' && ok "read-only session cannot add exits" || bad "ro: $r"

echo "== cleanup"
for s in lnk1 lnk1_eng lnk2 lnk2_eng tl_ui; do uci -q delete detour.$s; done; uci -q delete network.lnk1; uci -q delete network.lnk2; uci -q del_list firewall.vpn.network=lnk2
uci -q del_list firewall.vpn.network=lnk1; uci -q delete detour.main.warp_api; uci -q delete detour.main.warp_peer; uci -q delete detour.main.warp_port
uci commit; rm -f /etc/detour/engines/lnk1.json /etc/detour/engines/lnk2.json /tmp/detour-import.tgz; /etc/init.d/network reload; reload_config
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
