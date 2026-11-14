#!/bin/sh
# "Directly" is a kind of policy (action direct), next to the VPN ones and "Block": what it covers leaves the
# classification unmarked, so it goes through the provider and the policies below it never take it; placed below
# a VPN policy it no longer wins. Needs t2-routing's exits and its "vpn" policy (1.1.1.0/24 through warp = exit 1).
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
excnt() { ip netns exec ex$1 nft list chain ip exnat cnt 2>/dev/null | sed -n 's/.*packets \([0-9]*\).*/\1/p' | head -n1; }
leak() { nft list chain inet labwatch post 2>/dev/null | sed -n 's/.*packets \([0-9]*\).*/\1/p' | head -n1; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
inset() { nft get element inet detour $1 "{ $2 }" >/dev/null 2>&1 && echo yes || echo no; }
reload() { R=$(ubus call detour reload); echo "$R" | grep -q '"ok": true' || bad "reload: $R"; conntrack -F >/dev/null 2>&1; sleep 1; }
# 1.1.1.1 from the client: through exit 1 (1), through the WAN (the leak counter of 1.1.1.0/24) (1)
meas() { a=$(excnt 1); l=$(leak); cl "curl -s -m 6 -o /dev/null https://$1/" >/dev/null; echo "$(( $(excnt 1) - a > 0 ? 1 : 0 )) $(( $(leak) - l > 0 ? 1 : 0 ))"; }
# up to 3 tries (the first packets after a rules reload may still be in the WireGuard handshake): want <ip> <expected>
mwant() { M1=; for i in 1 2 3; do m=$(meas $1); [ -n "$M1" ] || M1=$m; [ "$m" = "$2" ] && return 0; done; return 1; }
cleanup() {
	for s in tdir; do uci -q delete detour.$s; done
	uci -q delete detour.main.dns_policy; uci set detour.main.dns=off
	uci commit detour; ubus call detour reload >/dev/null
	nft delete table inet labwatch 2>/dev/null
}
cleanup
[ "$(uci -q get detour.vpn.id)" = 1 ] && [ -n "$(uci -q get detour.warp)" ] || { echo "needs t2-routing's config"; echo "RESULT: FAIL"; exit 1; }
# the lab exit behind warp (a namespace that counts what it carries) is gone after a reboot: as t2 makes it
if ! ip netns list | grep -q '^ex1'; then
	lab tests/lab/l2-exit.sh 1 >/dev/null 2>&1; uci set network.wgx1.fwmark='0x10000000'; uci commit network
	ifdown wgx1; ifup wgx1
fi
i=0; until [ "$(ubus call detour status | jsonfilter -e "@.exits[@.name='warp'].healthy")" = true ] || [ $i -ge 40 ]; do sleep 1; i=$((i + 1)); done
[ "$(ubus call detour status | jsonfilter -e "@.policies[@.name='vpn'].active")" = warp ] || bad "the vpn policy is not on warp: $(ubus call detour status | jsonfilter -e "@.policies[@.name='vpn']")"
nft -f - <<'N'
table inet labwatch
delete table inet labwatch
table inet labwatch {
	chain post {
		type filter hook postrouting priority 0;
		oifname "eth1" ip saddr 192.168.1.145 ip daddr { 1.1.1.0/24 } counter
	}
}
N
MAC=$(ip neigh show 192.168.1.145 | awk '{ for (i = 1; i < NF; i++) if ($i == "lladdr") print $(i + 1) }' | head -n1)
DID=1; while uci show detour | grep -q "\.id='$DID'$"; do DID=$((DID + 1)); done
echo "client $MAC, direct policy id $DID"

echo "== a direct policy above the VPN one: its address goes through the provider"
uci -q batch <<U
set detour.tdir=policy
set detour.tdir.id=$DID
set detour.tdir.action=direct
set detour.tdir.label='Напрямую'
add_list detour.tdir.dst=1.1.1.1
commit detour
U
uci reorder detour.tdir=0; uci commit detour
reload
mwant 1.1.1.1 "0 1" && ok "1.1.1.1: the WAN, not exit 1" || bad "1.1.1.1 above: $M1 (exit1 wan)"
mwant 1.1.1.2 "1 0" && ok "1.1.1.2 (only in the VPN policy): exit 1" || bad "1.1.1.2: $M1"
[ "$(ubus call detour status | jsonfilter -e "@.policies[@.name='tdir'].action")" = direct ] && ok "status: action direct" || bad "status"
R=$(ubus call detour site_explain '{"target":"1.1.1.1"}')
[ "$(echo "$R" | jsonfilter -e '@.goes.to')" = direct ] && [ "$(echo "$R" | jsonfilter -e '@.goes.policy')" = tdir ] \
	&& [ "$(echo "$R" | jsonfilter -e '@.matches[1].policy')" = vpn ] && ok "check a site: directly by tdir, the VPN policy lost" || bad "explain: $R"

echo "== below the VPN policy: the VPN policy takes it first"
uci reorder detour.tdir=99; uci commit detour
reload
mwant 1.1.1.1 "1 0" && ok "1.1.1.1: exit 1" || bad "1.1.1.1 below: $M1"
R=$(ubus call detour site_explain '{"target":"1.1.1.1"}'); [ "$(echo "$R" | jsonfilter -e '@.goes.to')" = exit ] && ok "check a site: through the VPN policy" || bad "explain below: $R"

echo "== a device in the direct policy: all its traffic directly, its IPv6 not refused"
uci -q delete detour.tdir.dst; uci add_list detour.tdir.device="$MAC"; uci commit detour
uci reorder detour.tdir=0; uci commit detour
reload
mwant 1.1.1.1 "0 1" && ok "the client's 1.1.1.1: the WAN" || bad "device: $M1"
nft list chain inet detour v6block | grep -q "dev_p$DID return" && ok "v6block: the device returns before the VPN rules" || bad "v6block: $(nft list chain inet detour v6block | grep "p$DID")"

echo "== a site: the policy's domain set, no AAAA suppression"
uci -q delete detour.tdir.device; uci add_list detour.tdir.domain=example.com; uci commit detour
reload
grep -q "nftset=/example.com/4#inet#detour#dom4_p$DID$" /tmp/dnsmasq.*.d/detour.conf && ok "dnsmasq: IPv4 set only" || bad "conf: $(grep example.com /tmp/dnsmasq.*.d/detour.conf)"
grep -q "address=/example.com/" /tmp/dnsmasq.*.d/detour.conf && bad "AAAA suppressed for a direct site" || ok "AAAA left alone"
A=$(cl "nslookup example.com 192.168.1.1" | awk '/^Address: [0-9.]+$/{print $2}' | head -n1)
[ -n "$A" ] && [ "$(inset dom4_p$DID $A)" = yes ] && ok "example.com ($A) in dom4_p$DID" || bad "dom4_p$DID: '$A'"

echo "== not a policy for the router's DNS, no 'no valid exit'"
uci set detour.main.dns=tunnel; uci set detour.main.dns_policy=tdir; uci commit detour
detour check 2>&1 | grep -q "dns_policy \"tdir\" is not a valid policy" && ok "dns_policy refuses a direct policy" || bad "dns_policy: $(detour check 2>&1 | head -3)"
detour check 2>&1 | grep -q "policy tdir: no valid exit" && bad "a direct policy reported without exits" || ok "no exit is not an error for it"

echo "== cleanup"
cleanup
[ -z "$(uci -q get detour.tdir)" ] && ! nft list table inet detour | grep -q "_p$DID " && ok "removed, its sets gone" || bad "left"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
