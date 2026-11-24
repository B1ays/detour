#!/bin/sh
# The local SOCKS5 proxy (config socks 'socks', socks.uc): on the home network's address only, its login, its
# traffic by the policies (a policy address or site through its exit, the rest through the WAN) or all through one
# policy, kill-switch included; no IPv6; the password never on a command line or in the log. Needs t2-routing's
# exits and its "vpn" policy (1.1.1.0/24 through warp = exit 1, then alt = exit 2).
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
excnt() { ip netns exec ex$1 nft list chain ip exnat cnt 2>/dev/null | sed -n 's/.*packets \([0-9]*\).*/\1/p' | head -n1; }
# the proxy's own packets out of the WAN to a destination
leak() { nft list chain inet labwatch post 2>/dev/null | grep "$1" | sed -n 's/.*packets \([0-9]*\).*/\1/p' | head -n1; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
inset() { nft get element inet detour $1 "{ $2 }" >/dev/null 2>&1 && echo yes || echo no; }
reload() { R=$(ubus call detour reload); echo "$R" | grep -q '"ok": true' || bad "reload: $R"; conntrack -F >/dev/null 2>&1; sleep 3; }
PU=labuser; PW='t38-proxy-pw_9f3c'
PX="socks5h://$PU:$PW@192.168.1.1:1080"
# through the proxy from the client: <url> -> "<exit 1> <exit 2> <WAN>" (1 = packets seen)
meas() {
	a=$(excnt 1); b=$(excnt 2); w=$(leak "$2")
	cl "curl -s -m 8 -o /dev/null -x '$PX' $1" >/dev/null
	echo "$(( $(excnt 1) - a > 0 ? 1 : 0 )) $(( $(excnt 2) - b > 0 ? 1 : 0 )) $(( $(leak "$2") - w > 0 ? 1 : 0 ))"
}
mwant() { M1=; for i in 1 2 3; do m=$(meas $1 $2); [ -n "$M1" ] || M1=$m; [ "$m" = "$3" ] && return 0; sleep 2; done; return 1; }
listening() { netstat -ltn 2>/dev/null | awk '{print $4}' | grep -c ":1080$"; }
cleanup() {
	uci -q delete detour.socks; uci -q del_list detour.vpn.domain=example.com
	uci commit detour; ubus call detour reload >/dev/null; /etc/init.d/detour reload >/dev/null 2>&1
	ifup wgx1 2>/dev/null; ifup wgx2 2>/dev/null
	nft delete table inet labwatch 2>/dev/null
}
cleanup
[ "$(uci -q get detour.vpn.id)" = 1 ] && [ -n "$(uci -q get detour.warp)" ] || { echo "needs t2-routing's config"; echo "RESULT: FAIL"; exit 1; }
if ! ip netns list | grep -q '^ex1'; then
	lab tests/lab/l2-exit.sh 1 >/dev/null 2>&1; uci set network.wgx1.fwmark='0x10000000'; uci commit network
	ifdown wgx1; ifup wgx1
fi
i=0; until [ "$(ubus call detour status | jsonfilter -e "@.policies[@.name='vpn'].active")" = warp ] || [ $i -ge 40 ]; do sleep 1; i=$((i + 1)); done
SU=$(grep '^dtsocks:' /etc/passwd | cut -d: -f3)
# an address no policy covers (the lab's lists and other tests' policies take many): the first one in no set
insome() { for s in $(nft -j list sets inet detour | jsonfilter -e '@.nftables[*].set.name'); do nft get element inet detour $s "{ $1 }" >/dev/null 2>&1 && return 0; done; return 1; }
FREE=; for a in 9.9.9.9 94.140.14.14 208.67.222.222 8.8.4.4 149.112.112.112; do insome $a || { FREE=$a; break; }; done
[ -n "$FREE" ] && echo "an address of no policy: $FREE" || { echo "no free address"; echo "RESULT: FAIL"; exit 1; }
[ -n "$SU" ] && ok "system user dtsocks ($SU)" || bad "no dtsocks user"
nft -f - <<N
table inet labwatch
delete table inet labwatch
table inet labwatch {
	chain post {
		type filter hook postrouting priority 0;
		oifname "eth1" meta skuid $SU ip daddr 1.1.1.1 counter comment "d1111"
		oifname "eth1" meta skuid $SU ip daddr $FREE counter comment "d8888"
	}
}
N

echo "== on, by the policies, with a login"
uci -q batch <<U
set detour.socks=socks
set detour.socks.enabled=1
set detour.socks.port=1080
set detour.socks.username=$PU
set detour.socks.password=$PW
commit detour
U
/etc/init.d/detour reload >/dev/null 2>&1; reload
waitfor 1 listening 15 && ok "listening on :1080" || bad "not listening: $(netstat -ltn | grep 1080)"
L=$(netstat -ltn 2>/dev/null | awk '{print $4}' | grep ':1080$' | tr '\n' ' ')
[ "$L" = "192.168.1.1:1080 " ] && ok "only the home network's address ($L)" || bad "listens on: $L"
[ "$(ps w | grep -v grep | grep -c 'run -c /tmp/detour/socks.json')" = 1 ] && ps | grep -v grep | grep 'socks.json' | grep -q dtsocks && ok "one process, as dtsocks" || bad "process: $(ps w | grep socks.json | grep -v grep)"
ls -l /tmp/detour/socks.json | grep -q '^-rw------- .* dtsocks ' && ok "its config mode 600, dtsocks's" || bad "config: $(ls -l /tmp/detour/socks.json)"
[ "$(ubus call detour status | jsonfilter -e '@.socks.addrs[0]')" = 192.168.1.1 ] && ! ubus call detour status | grep -q "$PW" && ok "status: the address, no password" || bad "status: $(ubus call detour status | jsonfilter -e '@.socks')"
mwant https://1.1.1.1/ d1111 "1 0 0" && ok "1.1.1.1 (the vpn policy): exit 1" || bad "1.1.1.1: $M1 (exit1 exit2 wan)"
mwant https://$FREE/ d8888 "0 0 1" && ok "$FREE (no policy): the WAN" || bad "$FREE: $M1"
c=$(cl "curl -s -m 8 -o /dev/null -w '%{http_code}' -x socks5h://192.168.1.1:1080 https://1.1.1.1/"; echo " $?")
case "$c" in 200*) bad "no login: let through ($c)";; *) ok "no login: refused ($c)";; esac
c=$(cl "curl -s -m 8 -o /dev/null -w '%{http_code}' -x socks5h://$PU:wrongpw_t38@192.168.1.1:1080 https://1.1.1.1/"; echo " $?")
case "$c" in 200*) bad "a wrong password: let through";; *) ok "a wrong password: refused";; esac
sleep 1; logread | grep -q 'wrongpw_t38' && bad "the password tried is in the system log" || ok "the password tried is not in the system log"

echo "== a site of a policy: resolved by the router, its set filled, through the exit"
uci add_list detour.vpn.domain=example.com; uci commit detour; reload; sleep 3
a=$(excnt 1); cl "curl -s -m 10 -o /dev/null -x '$PX' https://example.com/" >/dev/null
A=$(nslookup example.com 127.0.0.1 2>/dev/null | awk '/^Address: [0-9.]+$/{print $2}' | head -n1)
[ -n "$A" ] && [ "$(inset dom4_p1 $A)" = yes ] && [ $(( $(excnt 1) - a )) -gt 0 ] && ok "example.com ($A): in dom4_p1, through exit 1" || bad "example.com: '$A' in set $(inset dom4_p1 $A), exit1 +$(( $(excnt 1) - a ))"
uci del_list detour.vpn.domain=example.com; uci commit detour

echo "== IPv6: refused, never past the router"
n0=$(nft list chain inet detour output | grep 'socks: no IPv6' | sed -n 's/.*packets \([0-9]*\).*/\1/p')
c=$(cl "curl -s -m 6 -o /dev/null -w '%{http_code}' -x '$PX' 'http://[2606:4700:4700::1111]/'"; echo " $?")
n1=$(nft list chain inet detour output | grep 'socks: no IPv6' | sed -n 's/.*packets \([0-9]*\).*/\1/p')
case "$c" in 200*|301*) bad "IPv6 went through ($c)";; *) [ -n "$n1" ] && ok "IPv6 refused ($c; rule counter $n0 -> $n1)" || bad "no IPv6 rule";; esac

echo "== all through the vpn policy"
uci set detour.socks.policy=vpn; uci commit detour; reload
mwant https://$FREE/ d8888 "1 0 0" && ok "$FREE: exit 1 now" || bad "$FREE through vpn: $M1"
echo "-- its first exit down: the next one"
ifdown wgx1
i=0; until [ "$(ubus call detour status | jsonfilter -e "@.policies[@.name='vpn'].active")" = alt ] || [ $i -ge 40 ]; do sleep 1; i=$((i + 1)); done
conntrack -F >/dev/null 2>&1
mwant https://$FREE/ d8888 "0 1 0" && ok "$FREE: exit 2 (failover)" || bad "after warp down: $M1"
echo "-- every exit down: nothing through the WAN"
ifdown wgx2; sleep 8; conntrack -F >/dev/null 2>&1
w=$(leak d8888); c=$(cl "curl -s -m 6 -o /dev/null -w '%{http_code}' -x '$PX' https://$FREE/"; echo " $?")
[ "$(leak d8888)" = "$w" ] && ok "no packet out of the WAN ($c)" || bad "leaked: $w -> $(leak d8888)"
ifup wgx1; ifup wgx2
i=0; until [ "$(ubus call detour status | jsonfilter -e "@.policies[@.name='vpn'].active")" = warp ] || [ $i -ge 60 ]; do sleep 1; i=$((i + 1)); done

echo "== the password: not on a command line, not in the log"
ps w | grep -v grep | grep -qF "$PW" && bad "on a command line" || ok "no command line has it"
logread | grep -qF "$PW" && bad "in the system log" || ok "not in the system log"
grep -qF "$PW" /etc/config/detour && grep -qF "$PW" /tmp/detour/socks.json && ok "in UCI and the config (mode 600) only" || bad "where it should be"

echo "== checks: a bad port, a login without a password, a block policy"
uci set detour.socks.port=5354; uci commit detour
detour check 2>&1 | grep -q 'socks: port "5354" cannot be used' && ok "port 5354 refused" || bad "port: $(detour check 2>&1 | head -3)"
uci set detour.socks.port=1080; uci -q delete detour.socks.password; uci commit detour
detour check 2>&1 | grep -q 'socks: a login needs a password' && ok "a login without a password refused" || bad "login: $(detour check 2>&1 | head -3)"
uci set detour.socks.password=$PW; uci set detour.socks.policy=nosuch; uci commit detour
detour check 2>&1 | grep -q 'socks: policy "nosuch"' && ok "an unknown policy refused" || bad "policy: $(detour check 2>&1 | head -3)"

echo "== off: nothing listens, no rules"
uci set detour.socks.enabled=0; uci -q delete detour.socks.policy; uci commit detour
/etc/init.d/detour reload >/dev/null 2>&1; reload
waitfor 0 listening 15 && ok "nothing on :1080" || bad "still listening"
nft list chain inet detour output | grep -q "skuid $SU" && bad "rules left" || ok "no rules for dtsocks"
[ ! -e /tmp/detour/socks.json ] && ok "no config" || bad "config left"

cleanup
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
