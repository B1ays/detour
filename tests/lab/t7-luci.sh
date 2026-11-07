#!/bin/sh
# LuCI path without a browser: form login -> session; menu has the Detour pages; ACL lets the views
# read status/uci and pin/unpin; views and translations are served. Password: /tmp/lab-pw (lab only).
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
PW=$(cat /tmp/lab-pw)
rm -f /tmp/cj
curl -s -o /dev/null -c /tmp/cj --data-urlencode luci_username=root --data-urlencode "luci_password=$PW" http://127.0.0.1/cgi-bin/luci/
SID=$(awk '/sysauth/{print $7}' /tmp/cj | head -n1)
[ -n "$SID" ] && ok "LuCI login" || { bad "login"; exit 1; }
rpc() { curl -s http://127.0.0.1/ubus -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"$SID\",\"$1\",\"$2\",${3:-{\}}]}"; }
M=$(curl -s -b /tmp/cj "http://127.0.0.1/cgi-bin/luci/admin/menu")
for p in overview policies exits settings; do echo "$M" | grep -q "\"$p\"" && ok "menu: $p" || bad "menu: $p"; done
for v in overview policies exits settings; do
	c=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/luci-static/resources/view/detour/$v.js); [ "$c" = 200 ] && ok "view $v.js served" || bad "view $v.js $c"; done
rpc detour status | grep -q '"policies"' && ok "rpc detour.status" || bad "rpc status: $(rpc detour status | head -c 120)"
rpc uci get '{"config":"detour"}' | grep -q '"warp"' && ok "rpc uci get detour" || bad "uci get"
r=$(rpc detour pin '{"policy":"vpn","exit":"alt"}'); echo "$r" | grep -q '"pinned":"alt"' && ok "rpc pin" || bad "pin: $r"
sleep 4; ubus call detour status | jsonfilter -e '@.policies[0].active' | grep -q alt && ok "pin applied" || bad "pin not applied"
r=$(rpc detour unpin '{"policy":"vpn"}'); echo "$r" | grep -q '"policy":"vpn"' && ok "rpc unpin" || bad "unpin: $r"
r=$(rpc file exec '{"command":"/bin/id"}'); echo "$r" | grep -q 'uid=0' && echo "  note: admin session can exec (expected for root)" 
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
