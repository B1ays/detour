#!/bin/sh
# Stage 2/3 acceptance against the INSTALLED package (no hand-made rules):
# policy -> exit, domain via dnsmasq nftset, failover/fail-back, pin (A-11), all-down fail-closed,
# fw4 reload survival, reload in place keeps domain sets, router's own traffic, underlay exemption.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
excnt() { ip netns exec ex$1 nft list chain ip exnat cnt 2>/dev/null | sed -n 's/.*packets \([0-9]*\).*/\1/p' | head -n1; }
leak() { nft list chain inet labwatch post 2>/dev/null | sed -n 's/.*packets \([0-9]*\).*/\1/p' | head -n1; }
probe() { cl "curl -s -m 6 -o /dev/null -w '%{http_code}' ${1:-https://1.1.1.1/cdn-cgi/trace}"; }
act() { ubus call detour status | jsonfilter -e '@.policies[@.name="vpn"].active'; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
expect() { if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1: got '$2' want '$3'"; fi; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
# measure: run probe, report "http exitA+ exitB+ leak+"
meas() { a1=$(excnt 1); a2=$(excnt 2); l0=$(leak); r=$(probe "$1"); echo "$r $(( $(excnt 1) - a1 > 0 ? 1 : 0 )) $(( $(excnt 2) - a2 > 0 ? 1 : 0 )) $(( $(leak) - l0 ))"; }

echo "== setup: lab exits, detour config"
for N in 1 2; do lab tests/lab/l2-exit.sh $N >/dev/null 2>&1; uci set network.wgx$N.fwmark='0x10000000'; done
uci commit network; ifdown wgx1; ifdown wgx2; ifup wgx1; ifup wgx2; sleep 5
uci -q batch <<'U'
delete detour.warp
delete detour.alt
delete detour.vpn
set detour.warp=exit
set detour.warp.id=1
set detour.warp.iface=wgx1
set detour.warp.probe=10.200.1.2
set detour.alt=exit
set detour.alt.id=2
set detour.alt.iface=wgx2
set detour.alt.probe=10.200.2.2
set detour.vpn=policy
set detour.vpn.id=1
add_list detour.vpn.exit=warp
add_list detour.vpn.exit=alt
add_list detour.vpn.dst=1.1.1.0/24
add_list detour.vpn.dst=10.199.1.2
add_list detour.vpn.domain=ifconfig.me
commit detour
U
reload_config; sleep 6
nft -f - <<'N'
table inet labwatch
delete table inet labwatch
table inet labwatch {
	set ifme { type ipv4_addr; }
	chain post {
		type filter hook postrouting priority 0;
		oifname "eth1" ip saddr 192.168.1.145 ip daddr { 1.1.1.0/24 } counter
		oifname "eth1" ip saddr 192.168.1.145 ip daddr @ifme counter
	}
}
N
expect "config clean" "$(detour check | tail -1 | grep -o "[0-9]* errors")" "0 errors"
expect "active exit" "$(act)" "warp"
conntrack -F >/dev/null 2>&1

echo "== A. policy subnet -> warp (exit1), nothing via WAN"
expect "1.1.1.1 via exit1" "$(meas)" "200 1 0 0"

echo "== B. domain via dnsmasq nftset; AAAA suppressed"
A=$(cl "nslookup ifconfig.me 192.168.1.1" | awk '/^Address: [0-9.]+$/{print $2}' | head -n1)
nft add element inet labwatch ifme "{ $A }" 2>/dev/null
expect "dom4_p1 has $A" "$(nft list set inet detour dom4_p1 | grep -c "$A")" "1"
expect "AAAA suppressed" "$(cl "nslookup -type=AAAA ifconfig.me 192.168.1.1" | grep -c 'Address: [0-9a-f]*:[0-9a-f:]*[1-9a-f]')" "0"
r=$(meas https://ifconfig.me/ip); expect "ifconfig.me via exit1" "$r" "200 1 0 0"

echo "== C. failover: ifdown wgx1"
t=$(date +%s); ifdown wgx1
waitfor alt act 15 && ok "switched to alt in $(( $(date +%s) - t )) s" || bad "no failover ($(act))"
expect "1.1.1.1 via exit2" "$(meas)" "200 0 1 0"

echo "== C2. server dead, tunnel interface still up (probe path, no hotplug)"
ifup wgx1; waitfor warp act 20 || true; sleep 2
t=$(date +%s); ip -n ex1 link set wgex down
waitfor alt act 20 && ok "probe-path failover to alt in $(( $(date +%s) - t )) s (wgx1 still up: $(cat /sys/class/net/wgx1/operstate))" || bad "no probe-path failover ($(act))"
expect "1.1.1.1 via exit2, no leak" "$(meas)" "200 0 1 0"
ip -n ex1 link set wgex up; ip -n ex1 addr replace 10.200.1.2/30 dev wgex; ip -n ex1 route replace 192.168.1.0/24 dev wgex
waitfor warp act 25 && ok "server back -> warp" || bad "no return ($(act))"
ifdown wgx1; waitfor alt act 15 || true

echo "== D. fail-back: ifup wgx1"
t=$(date +%s); ifup wgx1
waitfor warp act 20 && ok "back to warp in $(( $(date +%s) - t )) s" || bad "no fail-back ($(act))"
expect "1.1.1.1 via exit1" "$(meas)" "200 1 0 0"

echo "== E. pin (A-11): manual choice holds while warp is healthy"
detour pin vpn alt >/dev/null; sleep 5
expect "pinned stays on alt" "$(act)" "alt"
expect "1.1.1.1 via exit2" "$(meas)" "200 0 1 0"
ifdown wgx2; waitfor warp act 15 && ok "pinned exit down -> auto (warp)" || bad "pinned down: $(act)"
ifup wgx2; waitfor alt act 20 && ok "pinned exit back -> alt again" || bad "no return to pin: $(act)"
detour unpin vpn >/dev/null; waitfor warp act 10 && ok "unpinned -> warp" || bad "unpin: $(act)"

echo "== F. all exits down: fail-closed"
ifdown wgx1; ifdown wgx2; sleep 6
r=$(meas); expect "blocked, no leak" "${r%% *} ${r##* }" "000 0"
ifup wgx1; ifup wgx2; waitfor warp act 25 || true; sleep 2
r=$(meas); [ "$r" = "200 1 0 0" ] || { echo "  .. first try: $r act=$(act); retry in 3 s"; ubus call detour status | jsonfilter -e '@.events[*]' | tail -6; sleep 3; r=$(meas); }
expect "recovered" "$r" "200 1 0 0"

echo "== G. fw4 reload does not touch our table"
fw4 reload >/dev/null 2>&1; sleep 1
expect "after fw4 reload" "$(meas)" "200 1 0 0"

echo "== H. reload in place keeps dnsmasq-filled sets"
n0=$(nft list set inet detour dom4_p1 | grep -c expires)
uci add_list detour.vpn.dst=9.9.9.9; uci commit detour; reload_config; sleep 4
expect "dom4_p1 kept ($n0 entries)" "$(nft list set inet detour dom4_p1 | grep -c expires)" "$n0"
expect "new dst applied" "$(nft list set inet detour dst4_p1 | grep -c 9.9.9.9)" "1"
uci del_list detour.vpn.dst=9.9.9.9; uci commit detour; reload_config; sleep 3

echo "== I. router's own traffic follows the policy"
a1=$(excnt 1); c=$(curl -s -m 6 -o /dev/null -w '%{http_code}' https://1.1.1.1/cdn-cgi/trace)
expect "router -> 1.1.1.1 via exit1" "$c $(( $(excnt 1) - a1 > 0 ? 1 : 0 ))" "200 1"

echo "== J. underlay: WG endpoint 10.199.1.2 is in the policy list, tunnel still up"
expect "wg fwmark" "$(wg show wgx1 fwmark)" "0x10000000"
hs=$(wg show wgx1 latest-handshakes | awk '{print $2}'); expect "handshake recent" "$(( $(date +%s) - hs < 180 ? 1 : 0 ))" "1"

echo "== L. LAN DNS interception (client asks 8.8.8.8 directly) and DoT block"
nft flush set inet detour dom4_p1; killall -HUP dnsmasq; sleep 1
cl "nslookup ifconfig.me 8.8.8.8" >/dev/null
expect "dom4_p1 filled via redirected query" "$(nft list set inet detour dom4_p1 | grep -c expires)" "1"
dot() { nft list chain inet detour dotblock | grep -o 'packets [0-9]*' | awk '{print $2+0}' | head -n1; }
d0=$(dot)
cl "timeout 6 curl -s -m 4 telnet://9.9.9.9:853 </dev/null"; d1=$(dot)
expect "DoT :853 rejected" "$(( d1 > d0 ? 1 : 0 ))" "1"

echo "== M. /etc/init.d/detour-fw restart: no leak window"
l0=$(leak); ( i=0; while [ $i -lt 12 ]; do cl "curl -s -m 2 -o /dev/null https://1.1.1.1/cdn-cgi/trace"; i=$((i+1)); done ) &
for i in 1 2 3; do /etc/init.d/detour-fw restart; /etc/init.d/detour-fw reload; done; wait
expect "leaks during restart" "$(( $(leak) - l0 ))" "0"
expect "still routed" "$(meas)" "200 1 0 0"

echo "== N. removed exit/policy: chains and sets are cleaned up"
uci -q batch <<'U'
set detour.tmpx=exit
set detour.tmpx.id=7
set detour.tmpx.iface=wgx2
set detour.tmpp=policy
set detour.tmpp.id=9
add_list detour.tmpp.exit=tmpx
add_list detour.tmpp.dst=203.0.113.0/24
commit detour
U
reload_config; sleep 4
expect "created" "$(nft list table inet detour | grep -cE 'chain (exit7|ks7)|set (dst4_p9|dom4_p9)')" "4"
uci delete detour.tmpx; uci delete detour.tmpp; uci commit detour; reload_config; sleep 4
waitfor 0 "nft list table inet detour | grep -cE 'chain (exit7|ks7)|set (dst4_p9|dom4_p9)'" 20 && ok "removed" || bad "chains/sets of the removed exit/policy still there"
waitfor 0 "ip rule show | grep -c '^11007:'" 20 && ok "rule 11007 removed" || bad "rule 11007 still there"
expect "no config/nft errors" "$(ubus call detour status | jsonfilter -e '@.errors[*]' | wc -l)" "0"

echo "== K. kill-switch counters"
expect "ks1 drops" "$(nft list chain inet detour ks1 | sed -n 's/.*packets \([0-9]*\).*/\1/p')" "0"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
