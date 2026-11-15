#!/bin/sh
# Review, stage 2: devices of a policy by their address (src) and whole networks of the router (network), the
# direct flows of a source newly under a policy reset; a missing network reported; status says whether dnsproxy
# is there (LuCI offers encrypted DNS only with it).
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
T='inet detour'
D=208.67.222.222   # in no lab policy
EX=$(uci -q get detour.warp.id)
mark() { conntrack -L -p icmp -s $CL -d $D 2>/dev/null | sed -n 's/.*mark=\([0-9]*\).*/\1/p' | head -1; }
errs() { ubus call detour status | jsonfilter -e '@.errors[*]'; }
cleanup() { for s in tsrc tnet tbad; do uci -q delete detour.$s; done; uci commit detour; ubus call detour reload >/dev/null; sleep 3; conntrack -D -d $D >/dev/null 2>&1; }
cleanup

echo "== a device by its address"
cl "nohup ping -c 80 -i 0.5 $D >/dev/null 2>&1 </dev/null &"
waitfor $((0xff << 8)) "mark" 10 && ok "before: a direct flow from $CL (decided directly)" || bad "before: mark '$(mark)'"
uci -q batch <<U
set detour.tsrc=policy
set detour.tsrc.id=34
add_list detour.tsrc.exit=warp
add_list detour.tsrc.src=$CL
commit detour
U
ubus call detour reload >/dev/null
logread | tail -20 | grep -q 'new under a policy: .* 1 sources' && ok "its direct flows reset (logged)" || bad "no reset of the source: $(logread | grep 'new under a policy' | tail -1)"
waitfor $(( (EX << 16) | (34 << 8) )) "mark" 15 && ok "its traffic goes through the policy ($(mark))" || bad "mark after: '$(mark)' want $(( (EX << 16) | (34 << 8) ))"
nft list set $T src4_p34 | grep -q "$CL" && ok "src4_p34 holds the address" || bad "src4_p34"
nft list chain $T classify | grep -q "iifname @lan_ifs ip saddr @src4_p34" && ok "only traffic from a home network is matched by source" || bad "src rule"
uci delete detour.tsrc; uci commit detour; ubus call detour reload >/dev/null; sleep 3; conntrack -D -d $D >/dev/null 2>&1

echo "== a whole network"
uci -q batch <<'U'
set detour.tnet=policy
set detour.tnet.id=35
add_list detour.tnet.exit=warp
add_list detour.tnet.network=lan
commit detour
U
ubus call detour reload >/dev/null; sleep 3
logread | tail -20 | grep -q 'new under a policy: .* 1 networks' && ok "the direct flows of the network reset (logged)" || bad "no reset of the network: $(logread | grep 'new under a policy' | tail -1)"
LD=$(ubus call network.interface.lan status | jsonfilter -e '@.l3_device')
nft list set $T ifs_p35 | grep -q "\"$LD\"" && ok "the network lan is its device $LD" || bad "ifs_p35: $(nft list set $T ifs_p35)"
cl "nohup ping -c 20 -i 0.5 $D >/dev/null 2>&1 </dev/null &"
waitfor $(( (EX << 16) | (35 << 8) )) "mark" 15 && ok "traffic of the network goes through the policy ($(mark))" || bad "network mark: '$(mark)'"
nft list chain $T v6block | grep -qE "iifname @ifs_p35 meta nfproto ipv6 counter( packets [0-9]+ bytes [0-9]+)? reject" && ok "its IPv6 is refused (not sent past the tunnel)" || bad "no IPv6 reject for the network"
uci delete detour.tnet; uci commit detour

echo "== a network the router does not have"
uci -q batch <<'U'
set detour.tbad=policy
set detour.tbad.id=36
add_list detour.tbad.exit=warp
add_list detour.tbad.network=nosuch
commit detour
U
ubus call detour reload >/dev/null; sleep 3
errs | grep -q 'policy tbad: network "nosuch" has no device now' && ok "reported" || bad "errors: $(errs)"

echo "== dnsproxy in the status"
[ "$(ubus call detour status | jsonfilter -e '@.dnsproxy')" = "$([ -x /usr/bin/dnsproxy ] && echo true || echo false)" ] && ok "status.dnsproxy matches the system" || bad "status.dnsproxy"

cleanup
[ -z "$(errs)" ] && ok "no config errors after cleanup" || bad "errors: $(errs)"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
