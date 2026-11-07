#!/bin/sh
# after a reboot: table created before dnsmasq, domain set restored from disk, daemon + rules up,
# no dnsmasq nftset errors, policy traffic works once the exits are back.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
expect() { if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1: got '$2' want '$3'"; fi; }
case "$1" in
before)
	cl "nslookup ifconfig.me 192.168.1.1" >/dev/null
	nft list set inet detour dom4_p1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ expires' | cut -d' ' -f1 > /root/dom-before
	echo "dom4_p1 before: $(cat /root/dom-before | tr '\n' ' ')"
	;;
after)
	expect "saved file exists" "$([ -s /etc/detour/dom.save ] && echo y)" "y"
	for a in $(cat /root/dom-before); do expect "restored $a" "$(nft list set inet detour dom4_p1 | grep -c "$a")" "1"; done
	t_fw=$(logread | grep -m1 -n 'detour' | cut -d: -f1)
	expect "no dnsmasq nftset errors" "$(logread | grep -ci 'nftset.*\(error\|fail\)')" "0"
	expect "daemon" "$(pgrep -f /usr/sbin/detourd >/dev/null && echo up)" "up"
	expect "ip rules" "$(ip rule show | grep -c '^1100[12]:')" "2"
	expect "table 1001 unreachable" "$(ip route show table 1001 | grep -c unreachable)" "1"
	for N in 1 2; do lab tests/lab/l2-exit.sh $N >/dev/null 2>&1; done; ifup wgx1; ifup wgx2; sleep 8
	expect "policy traffic" "$(cl "curl -s -m 8 -o /dev/null -w '%{http_code}' https://1.1.1.1/cdn-cgi/trace")" "200"
	echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
	;;
esac
