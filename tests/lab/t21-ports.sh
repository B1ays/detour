#!/bin/sh
# Policy by destination port: "tcp/9101", "udp/9102", "9103-9104" (both protocols). Flows from the client to
# those ports carry the policy's mark (any address), other ports stay direct; a bad entry is a config error;
# an IPv6 rule rejects v6 to those ports (no v6 tunnelling yet).
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
D=203.0.113.10
# the client sends one SYN / one datagram; the conntrack entry keeps the mark the classify chain gave it
mark() { conntrack -L -p $1 -s $CL --dport $2 2>/dev/null | sed -n 's/.*mark=\([0-9]*\).*/\1/p' | head -1; }
send() { conntrack -D -p $1 --dport $2 >/dev/null 2>&1
	if [ $1 = tcp ]; then cl "nc -w 2 $D $2 </dev/null"; else cl "echo x | nc -u -w 1 $D $2"; fi; sleep 1; }
WID=$(uci -q get detour.warp.id)
WANT=$(( (WID << 16) | (21 << 8) ))
DIRECT=$(( 0xff << 8 ))   # "decided: directly" (no policy matched)
cleanup() { uci -q delete detour.tport; uci commit detour; ubus call detour reload >/dev/null; }
cleanup
uci -q batch <<'U'
set detour.tport=policy
set detour.tport.id=21
add_list detour.tport.exit=warp
add_list detour.tport.port=tcp/9101
add_list detour.tport.port=udp/9102
add_list detour.tport.port=9103-9104
commit detour
U
ubus call detour reload >/dev/null; sleep 2
nft list chain inet detour classify | grep -q 'tcp dport { 9101, 9103-9104 }' && ok "classify rule tcp { 9101, 9103-9104 }" || bad "tcp rule: $(nft list chain inet detour classify | grep dport)"
nft list chain inet detour classify | grep -q 'udp dport { 9102-9104 }' && ok "classify rule udp { 9102-9104 } (nft merges 9102 and 9103-9104)" || bad "udp rule"
nft list chain inet detour v6block | grep -q 'tcp dport { 9101, 9103-9104 }' && ok "IPv6 to those ports rejected" || bad "v6 rule"
send tcp 9101; [ "$(mark tcp 9101)" = $WANT ] && ok "tcp/9101 -> the policy ($WANT)" || bad "tcp/9101 mark '$(mark tcp 9101)'"
send udp 9102; [ "$(mark udp 9102)" = $WANT ] && ok "udp/9102 -> the policy" || bad "udp/9102 mark '$(mark udp 9102)'"
send udp 9104; [ "$(mark udp 9104)" = $WANT ] && ok "udp/9104 (range, both protocols) -> the policy" || bad "udp/9104 mark '$(mark udp 9104)'"
send udp 9101; [ "$(mark udp 9101)" = $DIRECT ] && ok "udp/9101 stays direct (tcp only)" || bad "udp/9101 mark '$(mark udp 9101)'"
send tcp 9105; [ "$(mark tcp 9105)" = $DIRECT ] && ok "tcp/9105 stays direct" || bad "tcp/9105 mark '$(mark tcp 9105)'"
echo "== a bad entry"
uci add_list detour.tport.port=70000; uci commit detour
detour check 2>&1 | grep -q 'policy tport: bad port "70000"' && ok "reported" || bad "not reported: $(detour check 2>&1 | head -3)"
cleanup
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
