#!/bin/sh
# A-14: big lists. Sources are served by the PC (tests/stub/lists). CIDR list -> lst4_p1 and traffic
# via the policy's exit; mixed-format domain list -> dnsmasq -> dom4_p1; "direct" list; a failing or
# too short source keeps the previous data; boot restore from the flash snapshot; 30k CIDR timing.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
B=http://10.0.2.2:8765/tests/stub/lists
st() { jsonfilter -i /tmp/detour/lists/$1.status -e "@.$2" 2>/dev/null; }
inset() { nft get element inet detour $1 "{ $2 }" >/dev/null 2>&1 && echo yes || echo no; }
txb() { cat /sys/class/net/$1/statistics/tx_bytes 2>/dev/null || echo 0; }
cleanup() { for s in tl_cidr tl_dom tl_dir tl_short tl_big; do uci -q delete detour.$s; done; uci commit detour; rm -f /etc/detour/lists/big.txt; }
cleanup
uci -q batch <<U
set detour.tl_cidr=list
set detour.tl_cidr.policy=vpn
add_list detour.tl_cidr.url=$B/cidr.txt
set detour.tl_dom=list
set detour.tl_dom.policy=vpn
add_list detour.tl_dom.url=$B/domains.txt
set detour.tl_dir=list
set detour.tl_dir.policy=direct
add_list detour.tl_dir.url=$B/direct.txt
commit detour
U
reload_config
waitfor true "st tl_cidr ok" 30 && waitfor true "st tl_dom ok" 30 && ok "lists downloaded on config change (daemon --missing)" || bad "status: $(cat /tmp/detour/lists/*.status)"
[ "$(st tl_cidr kind)" = cidr ] && [ "$(st tl_dom kind)" = domain ] && ok "kinds detected (cidr / domain)" || bad "kinds $(st tl_cidr kind)/$(st tl_dom kind)"
[ "$(st tl_cidr count)" = 22 ] && ok "cidr normalised: 22 entries (junk, 127/8 and bad octets dropped)" || bad "cidr count $(st tl_cidr count): $(cat /tmp/detour/lists/tl_cidr.data | tr '\n' ' ')"
D=/tmp/detour/lists/tl_dom.data
for d in ifconfig.io icanhazip.com example.com wikipedia.org a.example.net b.example.net plain-domain.org wild.example.org host9.example.info; do
	grep -qx "$d" $D || bad "domain $d missing"
done
grep -qxE 'localhost|bad_dom' $D && bad "junk domains kept" || ok "domains from hosts/adblock/dnsmasq/plain/wildcard, junk dropped ($(wc -l < $D))"
waitfor yes "inset lst4_p1 198.51.100.7" 30 && [ "$(inset lst4_p1 8.8.8.8)" = yes ] && ok "lst4_p1 filled" || bad "lst4_p1"
waitfor yes "inset lst4_direct 203.0.113.9" 30 && ok "lst4_direct filled" || bad "lst4_direct"
waitfor 0 "ls /tmp/dnsmasq.*.d/detour-list-tl_dom.conf >/dev/null 2>&1; echo \$?" 30 && ok "dnsmasq file for the domain list" || bad "no dnsmasq file"
waitfor ok "cl 'nslookup example.org 192.168.1.1' | grep -q '^Address: [0-9]' && echo ok" 30 || true
echo "== traffic"
conntrack -D -d 8.8.8.8 >/dev/null 2>&1
t0=$(txb wgx1); r=$(cl "curl -s -m 8 -o /dev/null -w '%{http_code}' https://8.8.8.8/"); t1=$(txb wgx1)
[ "$r" != 000 ] && [ $((t1 - t0)) -gt 0 ] && ok "8.8.8.8 (from the list) via the vpn policy's exit" || bad "via list: http=$r tx+$((t1 - t0))"
for i in 1 2 3 4 5; do A=$(cl "nslookup ifconfig.io 192.168.1.1" | awk '/^Address: [0-9.]+$/{print $2}' | head -n1); [ -n "$A" ] && break; sleep 2; done
[ -n "$A" ] && [ "$(inset dom4_p1 $A)" = yes ] && ok "ifconfig.io ($A) in dom4_p1 via the list" || { bad "dom4_p1 for ifconfig.io ($A)"; cl "nslookup ifconfig.io 192.168.1.1" | tail -5; nft list set inet detour dom4_p1 | head -5; cat /tmp/dnsmasq.*.d/detour-list-tl_dom.conf | head -2 | cut -c1-120; }
[ "$(cl "nslookup -type=AAAA ifconfig.io 192.168.1.1" | grep -c 'Address: [0-9a-f]*:[0-9a-f:]*[1-9a-f]')" = 0 ] && ok "AAAA suppressed for list domains" || bad "AAAA"
echo "== a failing source keeps the previous data"
uci set detour.tl_cidr.url=$B/missing.txt; uci commit detour
detour lists-update tl_cidr
[ "$(st tl_cidr ok)" = false ] && [ "$(inset lst4_p1 8.8.8.8)" = yes ] && ok "404: status error, set unchanged ($(st tl_cidr message))" || bad "after 404: ok=$(st tl_cidr ok) 8.8.8.8=$(inset lst4_p1 8.8.8.8)"
uci set detour.tl_cidr.url=$B/short.txt; uci commit detour
detour lists-update tl_cidr
[ "$(st tl_cidr ok)" = false ] && [ "$(inset lst4_p1 8.8.8.8)" = yes ] && [ "$(inset lst4_p1 8.8.4.4)" = no ] && ok "2 lines < min 10: rejected, previous data kept" || bad "short: $(st tl_cidr message)"
uci set detour.tl_cidr.url=$B/cidr.txt; uci commit detour; detour lists-update tl_cidr
echo "== boot: restored from the flash snapshot without downloads"
[ -s /etc/detour/lists/tl_cidr.snap ] && ok "snapshot on flash" || bad "no snapshot"
/etc/init.d/detour stop; rm -rf /tmp/detour/lists; nft delete table inet detour
/usr/sbin/detour fw-start
[ "$(inset lst4_p1 8.8.8.8)" = yes ] && [ "$(inset lst4_direct 203.0.113.9)" = yes ] && ok "sets back from snapshots" || bad "restore"
grep -q 'restored from snapshot' /tmp/detour/lists/tl_cidr.status && ok "status: restored from snapshot" || bad "status: $(cat /tmp/detour/lists/tl_cidr.status)"
/etc/init.d/detour start; sleep 4
echo "== 30000 CIDR (local file)"
awk 'BEGIN { for (a = 11; a < 70; a++) for (b = 0; b < 255; b++) for (c = 0; c < 2; c++) { if (n++ >= 30000) exit; print a "." b "." c*128 ".0/25" } }' > /etc/detour/lists/big.txt
uci set detour.tl_big=list; uci set detour.tl_big.policy=px; uci set detour.tl_big.file=/etc/detour/lists/big.txt; uci commit detour
t=$(date +%s); detour lists-update tl_big; t=$(( $(date +%s) - t ))
[ "$(st tl_big count)" = 30000 ] && ok "30000 entries loaded in ${t} s (TCG emulation)" || bad "big: $(cat /tmp/detour/lists/tl_big.status)"
echo "  memory: $(free | awk '/Mem:/{print $3}') KiB used"
echo "== removing lists cleans up"
cleanup; reload_config; sleep 3; detour lists-update
[ ! -e /etc/detour/lists/tl_cidr.snap ] && ! ls /tmp/dnsmasq.*.d/detour-list-*.conf >/dev/null 2>&1 && ok "snapshots and dnsmasq files removed" || bad "leftovers"
[ "$(inset lst4_p1 8.8.8.8)" = no ] && ok "lst4_p1 emptied" || bad "lst4_p1 still filled"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
