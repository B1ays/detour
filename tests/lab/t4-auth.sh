#!/bin/sh
# A-8: 2FA on -> session.login over HTTP /ubus closed; rpcd reinstall reopens it -> daemon closes again;
# 2FA off -> stock ACL back. LuCI login itself is not affected (checked in the browser separately).
P=bb4ea47fcffb44ec9bb3d3673c9b4ed2
F=/usr/share/rpcd/acl.d/unauthenticated.json
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
rpc_login() { curl -s http://127.0.0.1/ubus -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["00000000000000000000000000000000","session","login",{"username":"root","password":"x"}]}' | grep -c 'Access denied'; }
open_() { ubus call detour status | jsonfilter -e '@.auth.http_login_open'; }
echo "== baseline (2FA off): stock ACL"
[ "$(open_)" = true ] && ok "login over /ubus allowed (stock)" || bad "baseline: $(open_)"
echo "== 2FA on"
uci set luci_plugins.global.enabled=1; uci set luci_plugins.global.auth_login_enabled=1
uci set luci_plugins.$P.enabled=1; uci set luci_plugins.$P.key_root=JBSWY3DPEHPK3PXP; uci set luci_plugins.$P.type_root=totp
uci commit luci_plugins; ubus call detour reload >/dev/null
waitfor false open_ 10 && ok "closed by the daemon" || bad "still open"
[ "$(rpc_login)" = 1 ] && ok "HTTP session.login -> Access denied" || bad "HTTP login not denied"
echo "== rpcd reinstall brings the stock file back"
apk fix -r rpcd >/dev/null 2>&1
grep -q '"login"' $F && ok "stock file is back after reinstall" || echo "  note: reinstall kept our file"
waitfor false open_ 75 && ok "re-closed by the periodic guard" || bad "not re-closed"
echo "== 2FA off -> stock restored"
uci set luci_plugins.$P.enabled=0; uci set luci_plugins.global.auth_login_enabled=0; uci -q delete luci_plugins.$P.key_root; uci commit luci_plugins
ubus call detour reload >/dev/null
waitfor true open_ 10 && ok "restored" || bad "not restored"
grep -q '"login"' $F && ok "file grants login again" || bad "file"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
