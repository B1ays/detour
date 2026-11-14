#!/bin/sh
# Stage 3, the core: the "Block" target (a policy with action block: addresses and lists refused at once, its
# domains and domain lists answer "no such name"); a policy that goes directly while all its exits are down
# (on_down direct) and comes back to its exit, next to one that stays blocked (the default); "Check a site":
# where an address goes and why (the winning rule and the ones that lost), does it open directly / through an exit.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
pst() { ubus call detour status | jsonfilter -e "@.policies[@.name='$1'].$2"; }
txb() { cat /sys/class/net/$1/statistics/tx_bytes 2>/dev/null || echo 0; }
lab tests/lab/restart-sb.sh >/dev/null
cleanup() {
	for s in zblock zopen zclosed zdirect zl_dom zl_ip; do uci -q delete detour.$s; done
	uci -q delete detour.main.alert_hold
	uci commit detour; ubus call detour reload >/dev/null
	rm -f /tmp/t26-*.list
	nft delete table inet t26 2>/dev/null
	ifup wgx2 2>/dev/null
}
cleanup
printf 'example.net\n' > /tmp/t26-dom.list
printf '9.9.8.0/24\n' > /tmp/t26-ip.list
uci -q batch <<'U'
set detour.main.alert_hold=2
set detour.zblock=policy
set detour.zblock.id=9
set detour.zblock.label='Заблокировать'
set detour.zblock.action=block
add_list detour.zblock.dst=9.9.9.9
add_list detour.zblock.domain=example.org
set detour.zl_dom=list
set detour.zl_dom.policy=zblock
set detour.zl_dom.file=/tmp/t26-dom.list
set detour.zl_dom.kind=domain
set detour.zl_dom.min_lines=1
set detour.zl_ip=list
set detour.zl_ip.policy=zblock
set detour.zl_ip.file=/tmp/t26-ip.list
set detour.zl_ip.kind=cidr
set detour.zl_ip.min_lines=1
set detour.zopen=policy
set detour.zopen.id=10
set detour.zopen.label='Открытая'
add_list detour.zopen.exit=alt
add_list detour.zopen.dst=8.8.4.4
set detour.zopen.on_down=direct
set detour.zclosed=policy
set detour.zclosed.id=11
add_list detour.zclosed.exit=alt
add_list detour.zclosed.dst=8.8.8.8
add_list detour.zclosed.dst=8.8.4.4
set detour.zdirect=policy
set detour.zdirect.id=12
set detour.zdirect.action=direct
add_list detour.zdirect.dst=4.4.4.4
commit detour
U
R=$(ubus call detour reload); echo "$R" | grep -q '"ok": true' || bad "reload: $R"
/usr/libexec/detour/lists-update zl_dom zl_ip >/dev/null 2>&1
sleep 2

echo "== Block"
nft list chain inet detour blockrej | grep -q 'reject with tcp reset' && ok "blockrej chain" || bad "no blockrej"
nft list map inet detour pol2exit | grep -q '0x00000900 : jump blockrej' && ok "the block policy -> blockrej" || bad "pol2exit: $(nft list map inet detour pol2exit)"
t0=$(date +%s); r=$(cl "curl -s -m 10 -o /dev/null -w '%{http_code}' https://9.9.9.9/"); t1=$(date +%s)
[ "$r" = 000 ] && [ $((t1 - t0)) -le 3 ] && ok "a blocked address is refused at once ($((t1 - t0)) s)" || bad "9.9.9.9: http=$r in $((t1 - t0)) s"
r=$(cl "curl -s -m 10 -o /dev/null -w '%{http_code}' https://9.9.8.8/"); [ "$r" = 000 ] && ok "an address list into Block: refused" || bad "9.9.8.8: $r"
cl "nslookup example.org 192.168.1.1" | grep -qiE "NXDOMAIN|can't find|No answer" && ok "a blocked domain: no such name" || bad "example.org resolves: $(cl "nslookup example.org 192.168.1.1" | tail -3)"
cl "nslookup example.net 192.168.1.1" | grep -qiE "NXDOMAIN|can't find|No answer" && ok "a domain list into Block: no such name" || bad "example.net resolves"
grep -rq 'address=/example.net/$' /tmp/dnsmasq*.d/detour-list-zl_dom.conf && ok "list file: address=/…/ (no set)" || bad "list conf: $(cat /tmp/dnsmasq*.d/detour-list-zl_dom.conf | head -2)"
[ "$(ubus call detour status | jsonfilter -e '@.blocked')" -gt 0 ] && ok "status counts what was refused ($(ubus call detour status | jsonfilter -e '@.blocked'))" || bad "blocked counter"
[ "$(pst zblock block)" = true ] && ok "status: block" || bad "status block"
ubus call detour status | jsonfilter -e '@.errors' | grep -q zblock && bad "errors about the block policy" || ok "no 'no exit' error for Block"

echo "== all exits down: directly (on_down direct) vs blocked (default)"
waitfor true "ubus call detour status | jsonfilter -e '@.exits[@.name=\"alt\"].healthy'" 30 || bad "alt not healthy at start"
t=$(txb wgx2); r=$(cl "curl -s -m 8 -o /dev/null -w '%{http_code}' https://8.8.4.4/"); [ "$r" != 000 ] && [ $(($(txb wgx2) - t)) -gt 0 ] && ok "zopen via alt while it works" || bad "zopen via alt: $r"
ifdown wgx2
waitfor true "pst zopen direct" 30 && ok "alt down: zopen goes directly" || bad "zopen not direct: $(ubus call detour status | jsonfilter -e "@.policies[@.name='zopen']")"
r=$(cl "curl -s -m 8 -o /dev/null -w '%{http_code}' https://8.8.4.4/"); [ "$r" != 000 ] && ok "zopen traffic goes directly ($r)" || bad "zopen direct: $r"
ctn() { conntrack -L -m 0xa00/0xffff00 2>/dev/null | grep -c .; }
[ "$(ctn)" -gt 0 ] && ok "its direct flows are pinned (ct mark: the policy, no exit)" || bad "no pinned direct flow"
r=$(cl "curl -s -m 6 -o /dev/null -w '%{http_code}' https://8.8.8.8/"); [ "$r" = 000 ] && ok "zclosed stays blocked" || bad "zclosed leaked: $r"
nft list map inet detour pol2exit | grep -q '0x00000a00 : jump podirect' && ok "pol2exit: zopen -> podirect (direct, flows pinned)" || bad "map: $(nft list map inet detour pol2exit)"
logread | grep -q 'policy zopen: no working exit - goes directly' && ok "event logged" || bad "no event"
ifup wgx2
waitfor false "pst zopen direct" 60 && ok "alt back: zopen through its exit again" || bad "zopen still direct"
[ "$(ctn)" = 0 ] && ok "the flows it opened directly were dropped" || bad "direct flows left: $(ctn)"
sleep 2; t=$(txb wgx2); r=$(cl "curl -s -m 8 -o /dev/null -w '%{http_code}' https://8.8.4.4/"); [ $(($(txb wgx2) - t)) -gt 0 ] && ok "zopen traffic through alt again" || bad "zopen not via alt: $r"
ubus call detour reload >/dev/null
[ "$(pst zopen direct)" = false ] && ok "a reload keeps it on the exit (alt works)" || bad "after reload"

echo "== where an address goes, and why"
ex() { ubus call detour site_explain "{\"target\":\"$1\"}"; }
R=$(ex 9.9.9.9); [ "$(echo "$R" | jsonfilter -e '@.goes.to')" = block ] && ok "9.9.9.9 -> Block" || bad "9.9.9.9: $R"
R=$(ex https://8.8.4.4/x); [ "$(echo "$R" | jsonfilter -e '@.goes.to')" = exit ] && [ "$(echo "$R" | jsonfilter -e '@.goes.policy')" = zopen ] \
	&& [ "$(echo "$R" | jsonfilter -e '@.goes.exit.name')" = alt ] && [ "$(echo "$R" | jsonfilter -e '@.matches[1].policy')" = zclosed ] \
	&& ok "8.8.4.4 -> zopen via alt; zclosed also matched and lost" || bad "8.8.4.4: $R"
R=$(ex 4.4.4.4); [ "$(echo "$R" | jsonfilter -e '@.matches[0].policy')" = zdirect ] && [ "$(echo "$R" | jsonfilter -e '@.goes.to')" = direct ] && [ "$(echo "$R" | jsonfilter -e '@.goes.policy')" = zdirect ] && ok "4.4.4.4 -> directly, by the direct policy" || bad "4.4.4.4: $R"
R=$(ex 192.168.1.10); [ "$(echo "$R" | jsonfilter -e '@.matches[0].why')" = local ] && ok "a LAN address: local" || bad "local: $R"
R=$(ex example.net); [ "$(echo "$R" | jsonfilter -e '@.goes.to')" = block ] && [ "$(echo "$R" | jsonfilter -e '@.matches[0].lists[0].list')" = zl_dom ] && ok "example.net -> Block, by the list zl_dom" || bad "example.net: $R"
R=$(ex 9.9.8.7); [ "$(echo "$R" | jsonfilter -e '@.matches[0].why')" = address_list ] && [ "$(echo "$R" | jsonfilter -e '@.matches[0].lists[0].list')" = zl_ip ] && ok "9.9.8.7 -> by the address list zl_ip" || bad "9.9.8.7: $R"
R=$(ex 1.1.1.1); [ "$(echo "$R" | jsonfilter -e '@.goes.policy')" = vpn ] && ok "1.1.1.1 -> vpn" || bad "1.1.1.1: $R"
R=$(ex 'bad target!'); echo "$R" | grep -q error && ok "a bad target refused" || bad "bad: $R"

echo "== does it open: directly and through an exit"
sc() { ubus -t 40 call detour site_check "{\"target\":\"$1\",\"exit\":\"sbx\"}"; }
R=$(sc https://1.0.0.1/); [ "$(echo "$R" | jsonfilter -e '@.verdict')" = direct_ok ] && ok "1.0.0.1 opens directly ($(echo "$R" | jsonfilter -e '@.direct.ms') ms)" || bad "direct_ok: $R"
# the provider "cuts" 1.1.1.1: only the direct check (user dtnotify) is dropped
nft -f - <<N
table inet t26 {
	chain out { type filter hook output priority 0; meta skuid dtnotify ip daddr 1.1.1.1 drop; }
}
N
R=$(sc https://1.1.1.1/); [ "$(echo "$R" | jsonfilter -e '@.verdict')" = need_vpn ] && [ "$(echo "$R" | jsonfilter -e '@.direct.st')" = silent ] \
	&& ok "1.1.1.1: silent directly, opens through sbx: need_vpn" || bad "need_vpn: $R"
nft delete table inet t26

cleanup
[ -z "$(nft list map inet detour pol2exit | grep -E '0x00000(9|a|b)00')" ] && ok "cleanup: the test policies are gone" || bad "left in pol2exit"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
