#!/bin/sh
# Review, stage 1: the decision for a flow is cached in its ct mark (a flow no policy takes is classified once),
# local and private IPv6 is never refused and established flows skip the IPv6 checks, IPv6 networks of address
# lists are refused for a tunnel policy, a policy may refuse all IPv6, main.fw_mask moves the fwmark bits (the
# traffic still goes through the exit), a warning when pbr uses the same bits.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
T='inet detour'
PV=$(uci -q get detour.vpn.id)
NX=$(uci show detour | grep -c '=exit$')
errs() { ubus call detour status | jsonfilter -e '@.errors[*]'; }
cleanup() {
	uci -q delete detour.l33; uci -q delete detour.vpn.ipv6_block; uci -q delete detour.main.fw_mask; uci commit detour
	rm -f /tmp/t33.txt; [ -f /tmp/t33-own-pbr ] || rm -f /etc/config/pbr
	ubus call detour reload >/dev/null; sleep 3
}
[ -f /etc/config/pbr ] && touch /tmp/t33-own-pbr || rm -f /tmp/t33-own-pbr
cleanup

echo "== a flow is classified once; IPv6 checks only for new flows, never for local addresses"
nft list chain $T prerouting | grep -q 'decided: directly' && ok "prerouting returns early for a flow decided directly" || bad "no cached direct decision in prerouting"
# the rules of a chain, in order (the lines after its hook line)
rule() { nft list chain $T "$1" | sed -n '/policy accept;/,$p' | sed -n "$(( $2 + 1 ))p"; }
rule v6block 1 | grep -q 'ct state established,related return' && ok "v6block: established flows first" || bad "v6block 1st: $(rule v6block 1)"
rule v6block 2 | grep -q 'ip6 daddr @bypass6 return' && ok "v6block: local IPv6 never refused" || bad "v6block 2nd: $(rule v6block 2)"
s=$(nft list set $T bypass6); for n in 'fc00::/7' 'fe80::/10' 'ff00::/8'; do echo "$s" | grep -q "$n" || bad "bypass6 has no $n"; done; ok "bypass6: ULA, link-local, multicast"
nft list chain $T dotblock | grep -q 'ct state established,related return' && ok "dotblock: established flows first" || bad "dotblock"

echo "== IPv6 networks in an address list"
printf '2001:db8:33::/48\n203.0.113.33\n::ffff:1.2.3.4\nfd00::/8\n2001:DB8:34::1   # a host\n' > /tmp/t33.txt
uci -q batch <<'U'
set detour.l33=list
set detour.l33.policy=vpn
set detour.l33.file=/tmp/t33.txt
set detour.l33.min_lines=1
commit detour
U
ubus call detour reload >/dev/null; sleep 3; detour lists-update l33 >/dev/null 2>&1
s6=$(nft list set $T lst6_p$PV); s4=$(nft list set $T lst4_p$PV)
echo "$s6" | grep -q '2001:db8:33::/48' && echo "$s6" | grep -q '2001:db8:34::1' && ok "IPv6 networks in lst6_p$PV" || bad "lst6: $s6"
echo "$s6" | grep -qE 'fd00|ffff' && bad "a private or mapped address in lst6" || ok "private and IPv4-mapped lines left out"
echo "$s4" | grep -q '203.0.113.33' && ok "the IPv4 line in lst4_p$PV" || bad "lst4: $s4"
[ "$(jsonfilter -i /tmp/detour/lists/l33.status -e @.kind)" = cidr ] && ok "a mostly-IPv6 list is detected as addresses" || bad "kind: $(cat /tmp/detour/lists/l33.status)"
nft list chain $T v6block | grep -qE "ip6 daddr @lst6_p$PV counter( packets [0-9]+ bytes [0-9]+)? reject" && ok "IPv6 of the list is refused (not sent past the tunnel)" || bad "no lst6 reject"

echo "== a policy refusing all IPv6"
uci set detour.vpn.ipv6_block=1; uci commit detour; ubus call detour reload >/dev/null; sleep 3
nft list chain $T v6block | grep -q '"vpn: no IPv6"' && ok "a reject-all rule at the policy's place" || bad "no reject-all rule"
uci delete detour.vpn.ipv6_block; uci commit detour; ubus call detour reload >/dev/null; sleep 3
nft list chain $T v6block | grep -q '"vpn: no IPv6"' && bad "the rule stayed" || ok "gone when switched off"

echo "== the fwmark bits moved (main.fw_mask 0x0ffff000)"
EX=$(uci -q get detour."$(ubus call detour status | jsonfilter -e '@.policies[@.name="vpn"].active')".id)
uci set detour.main.fw_mask=0x0ffff000; uci commit detour; ubus call detour reload >/dev/null; sleep 5
expect_rules=$(ip rule show | grep 'lookup detour_' | grep -c '/0xff00000 ')
[ "$expect_rules" = "$NX" ] && ok "every exit rule with the moved mask" || bad "rules: $(ip rule show | grep detour_)"
conntrack -D -d 1.1.1.1 >/dev/null 2>&1
# the emulated router applies a reload of all rules in a few seconds: a few tries
for i in 1 2 3 4; do r=$(cl "curl -s -m 10 -o /dev/null -w '%{http_code}' https://1.1.1.1/cdn-cgi/trace"); [ "$r" = 200 ] && break; sleep 3; done
m=$(conntrack -L -p tcp -s $CL -d 1.1.1.1 2>/dev/null | sed -n 's/.*mark=\([0-9]*\).*/\1/p' | head -1)
[ "$r" != 000 ] && [ "$m" = $(( ((EX << 8) | PV) << 12 )) ] && ok "policy traffic through the exit with the moved marks (http $r, mark $m)" || bad "moved marks: http=$r mark=$m want $(( ((EX << 8) | PV) << 12 ))"
[ -z "$(errs)" ] && ok "no config errors" || bad "errors: $(errs)"
uci delete detour.main.fw_mask; uci commit detour; ubus call detour reload >/dev/null; sleep 5
[ "$(ip rule show | grep 'lookup detour_' | grep -c '/0xff0000 ')" = "$NX" ] && ok "back to the default bits" || bad "rules after: $(ip rule show | grep detour_)"

echo "== a warning when pbr uses the same bits"
if [ -f /tmp/t33-own-pbr ]; then echo "  skip: this router has pbr"; else
	printf "config pbr 'config'\n\toption enabled '1'\n" > /etc/config/pbr
	ubus call detour reload >/dev/null; sleep 3
	errs | grep -q 'also used by pbr' && ok "the overlap is reported" || bad "no warning: $(errs)"
	rm -f /etc/config/pbr; ubus call detour reload >/dev/null; sleep 3
	[ -z "$(errs)" ] && ok "and gone without pbr" || bad "errors stayed: $(errs)"
fi

cleanup
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
