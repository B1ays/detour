#!/bin/sh
# What must not open a way around the tunnels:
#  - a policy left without an exit keeps its rules and blocks its traffic (it used to vanish: traffic went directly);
#  - a value nft cannot read (address, dom_timeout) is reported and left out, the rules still load;
#  - main.enabled = 0 really switches everything off (no table, no rules, no daemon) and 1 brings it back.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
D=203.0.113.24
cleanup() {
	uci -q delete detour.tnx; uci -q delete detour.main.dom_timeout; uci set detour.main.enabled=1; uci commit detour
	/etc/init.d/detour reload >/dev/null 2>&1; sleep 4
}
cleanup

echo "== a policy without an exit"
uci -q batch <<U
set detour.tnx=policy
set detour.tnx.id=24
add_list detour.tnx.dst=$D
commit detour
U
ubus call detour reload >/dev/null; sleep 2
detour check 2>&1 | grep -q 'policy tnx: no valid exit' && ok "reported" || bad "not reported: $(detour check 2>&1 | head -3)"
nft list map inet detour pol2exit | grep -Eq '0x0*1800 : drop' && ok "pol2exit: the policy's mark -> drop" || bad "no drop element: $(nft list map inet detour pol2exit | grep -i 1800)"
nft list set inet detour dst4_p24 | grep -q "$D" && ok "its addresses stay in its set" || bad "dst4_p24 is empty"
[ "$(ubus call detour status | jsonfilter -e '@.policies[@.name="tnx"].active')" = "" ] && ok "status: no active exit" || bad "status shows an active exit"
conntrack -D -s $CL -d $D >/dev/null 2>&1
cl "nc -w 2 $D 80 </dev/null"; sleep 1
[ -z "$(conntrack -L -s $CL -d $D 2>/dev/null)" ] && ok "the client's packet is dropped (no flow)" || bad "a flow exists: $(conntrack -L -s $CL -d $D 2>/dev/null | head -1)"

echo "== values nft cannot read"
uci add_list detour.tnx.dst=999.1.1.1 >/dev/null; uci add_list detour.tnx.dst=10.0.0.0/40 >/dev/null; uci add_list detour.tnx.dst=:::: >/dev/null
uci set detour.main.dom_timeout=6x; uci commit detour
[ "$(ubus call detour reload | jsonfilter -e '@.ok')" = true ] && ok "the rules still load" || bad "reload failed: $(ubus call detour reload)"
for w in 'bad address "999.1.1.1"' 'bad address "10.0.0.0/40"' 'bad address "::::"' 'bad dom_timeout "6x"'; do
	detour check 2>&1 | grep -q "$w" && ok "reported: $w" || bad "not reported: $w"
done
nft list set inet detour dom4_p24 | grep -q 'timeout 6h' && ok "dom_timeout falls back to 6h" || bad "dom4_p24: $(nft list set inet detour dom4_p24 | grep timeout)"
[ -s /etc/detour/ruleset.good ] && ok "the last working rules are kept for a boot with a broken config" || bad "no /etc/detour/ruleset.good"

echo "== switched off"
uci set detour.main.enabled=0; uci commit detour; /etc/init.d/detour reload >/dev/null 2>&1; sleep 5
nft list table inet detour >/dev/null 2>&1 && bad "the table is still there" || ok "no table"
ip rule show | grep -q '^110' && bad "ip rules are still there" || ok "no ip rules"
pgrep -f /usr/sbin/detourd >/dev/null && bad "the daemon still runs" || ok "no daemon"
ls /tmp/dnsmasq.*.d/detour.conf >/dev/null 2>&1 && bad "dnsmasq still has detour.conf" || ok "dnsmasq has no detour.conf"
cl "nslookup example.org 192.168.1.1" | grep -q 'Address: [0-9]' && ok "client DNS works" || bad "client DNS"
echo "== switched on again"
uci set detour.main.enabled=1; uci commit detour; /etc/init.d/detour reload >/dev/null 2>&1; sleep 6
nft list table inet detour >/dev/null 2>&1 && ok "the table is back" || bad "no table"
pgrep -f /usr/sbin/detourd >/dev/null && ok "the daemon runs" || bad "no daemon"
ubus call detour status >/dev/null 2>&1 && ok "ubus object" || bad "no ubus object"
cleanup
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
