#!/bin/sh
# A-5 from the package: router DNS via policy "vpn"; all its exits down -> dnsproxy (DoH/DoT/DoQ) direct.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
q() { cl "nslookup -timeout=3 $1 192.168.1.1 2>&1" | awk '/^Address: [0-9.]+$/{a=$2} END{print a?"ok":"FAIL"}'; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
expect() { if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1: got '$2' want '$3'"; fi; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
dmode() { ubus call detour status | jsonfilter -e '@.dns'; }
excnt() { ip netns exec ex$1 nft list chain ip exnat cnt 2>/dev/null | sed -n 's/.*packets \([0-9]*\).*/\1/p' | head -n1; }
skuid() { nft list chain inet detour output | grep skuid | sed -n 's/.*skuid \([0-9]*\).*/\1/p'; }
# the whole command line of the running dnsproxy (ps w cuts long ones)
dpargs() { for p in $(pidof dnsproxy); do tr '\0' ' ' < /proc/$p/cmdline; echo; done; }

apk info -e dnsproxy >/dev/null || apk add -q dnsproxy
/etc/init.d/dnsproxy disable 2>/dev/null; /etc/init.d/dnsproxy stop 2>/dev/null
echo "== enable dns=tunnel"
uci set detour.main.dns=tunnel; uci set detour.main.dns_policy=vpn; uci commit detour; reload_config
# wait for the apply (a previous one may still be restarting dnsmasq in the slow emulation), not a fixed time
waitfor tunnel dmode 30 || true
waitfor /tmp/detour/dns.servers "uci -q get dhcp.@dnsmasq[0].serversfile" 15 || true
expect "dnsmasq serversfile" "$(uci -q get dhcp.@dnsmasq[0].serversfile)" "/tmp/detour/dns.servers"
expect "noresolv" "$(uci -q get dhcp.@dnsmasq[0].noresolv)" "1"
expect "servers file" "$(cat /tmp/detour/dns.servers | tr '\n' ' ')" "server=1.1.1.1 server=1.0.0.1 "
waitfor dnsproxy "ps w | grep '[d]nsproxy -l 127.0.0.1' | awk '{print \$2}' | head -n1" 15 && ok "dnsproxy runs as user dnsproxy" || bad "dnsproxy user: $(ps w | grep '[d]nsproxy -l')"
expect "skuid exemption rule for dnsproxy" "$(skuid | grep -cx "$(id -u dnsproxy)")" "1"
expect "mode" "$(dmode)" "tunnel"
a=$(excnt 1); r=$(q example.net); expect "client DNS via tunnel" "$r $(( $(excnt 1) - a > 0 ? 1 : 0 ))" "ok 1"

echo "== all exits down -> fallback"
ifdown wgx1; ifdown wgx2
waitfor fallback dmode 15 && ok "mode fallback" || bad "mode $(dmode)"
expect "servers file" "$(cat /tmp/detour/dns.servers)" "server=127.0.0.1#5354"
expect "client DNS via dnsproxy" "$(q example.com)" "ok"
expect "policy traffic still blocked" "$(cl "curl -s -m 5 -o /dev/null -w '%{http_code}' https://1.1.1.1/cdn-cgi/trace")" "000"

echo "== exits back -> tunnel"
ifup wgx1; ifup wgx2
waitfor tunnel dmode 25 && ok "mode tunnel" || bad "mode $(dmode)"
expect "client DNS" "$(q example.org)" "ok"

echo "== engines' own server names resolve around the tunnels (BE7000: st_main needed itself to find its server)"
# two throw-away engines with server NAMES: one chained to exit alt (wgx2), one direct
printf '{"type":"shadowsocks","server":"chained.example","server_port":1,"method":"none","password":"x"}' > /tmp/te1.json
printf '{"type":"shadowsocks","server":"direct.example","server_port":1,"method":"none","password":"x"}' > /tmp/te2.json
uci -q batch <<'U'
set detour.te1=engine
set detour.te1.type=singbox
set detour.te1.enabled=0
set detour.te1.outbound=/tmp/te1.json
set detour.te1.via=alt
set detour.te2=engine
set detour.te2.type=singbox
set detour.te2.enabled=0
set detour.te2.outbound=/tmp/te2.json
commit detour
U
ubus call detour reload >/dev/null; sleep 2
C=$(cat /tmp/dnsmasq.*.d/detour.conf)
echo "$C" | grep -q 'chained.example' && bad "a disabled engine got DNS lines" || ok "disabled engines: no lines"
uci set detour.te1.enabled=1; uci set detour.te2.enabled=1; uci commit detour
# enabled engines with junk outbounds would fail to start: only the DNS side is looked at, then removed
ubus call detour reload >/dev/null; sleep 2
C=$(cat /tmp/dnsmasq.*.d/detour.conf)
echo "$C" | grep -q '^server=/chained.example/1.1.1.1@wgx2$' && ok "chained engine: asked through its carrying exit" || bad "chained: $(echo "$C" | grep chained)"
W=$(sed -n 's/^nameserver \([0-9.]*\)$/\1/p' /tmp/resolv.conf.d/resolv.conf.auto | head -1)
echo "$C" | grep -q "^server=/direct.example/$W$" && ok "direct engine: asked the provider DNS ($W)" || bad "direct: $(echo "$C" | grep direct.example)"
for s in te1 te2; do uci delete detour.$s; done; uci commit detour; rm -f /tmp/te1.json /tmp/te2.json; ubus call detour reload >/dev/null

echo "== dnsproxy missing: the fallback uses the provider DNS, not nothing"
apk del -q dnsproxy >/dev/null 2>&1
ifdown wgx1; ifdown wgx2
waitfor fallback dmode 25 && ok "mode fallback" || bad "mode $(dmode)"
grep -q "^server=$W$" /tmp/detour/dns.servers && ok "servers file: provider DNS" || bad "servers: $(cat /tmp/detour/dns.servers)"
expect "client DNS without dnsproxy" "$(q example.org)" "ok"
# through the tunnel works on dnsmasq alone: no config error for a missing dnsproxy (only encrypted needs it)
ubus call detour reload >/dev/null; ubus call detour status | jsonfilter -e "@.errors[*]" | grep -q "dnsproxy is not installed" && bad "an error for the tunnel mode without dnsproxy" || ok "no error: the tunnel mode needs no dnsproxy"
[ "$(ubus call detour status | jsonfilter -e '@.dnsproxy')" = false ] && ok "status: no dnsproxy" || bad "status.dnsproxy"
ifup wgx1; ifup wgx2; apk add -q dnsproxy; /etc/init.d/dnsproxy disable 2>/dev/null; /etc/init.d/dnsproxy stop 2>/dev/null
waitfor tunnel dmode 25 && ok "back to tunnel" || bad "mode $(dmode)"

echo "== dns=encrypted: the router always asks dnsproxy (DoH/DoT/DoQ), directly, whatever the exits do"
uci set detour.main.dns=encrypted; uci commit detour; reload_config; sleep 6
waitfor encrypted dmode 20 && ok "mode encrypted" || bad "mode $(dmode)"
grep -qx "server=127.0.0.1#$(uci -q get detour.main.dns_fallback_port || echo 5354)" /tmp/detour/dns.servers && ok "servers file: dnsproxy" || bad "servers: $(cat /tmp/detour/dns.servers)"
waitfor 1 "ps w | grep -c '[d]nsproxy -l 127.0.0.1'" 15 && ok "dnsproxy running" || bad "no dnsproxy"
[ -n "$(skuid)" ] && ok "dnsproxy exempt from the policies (skuid $(skuid))" || bad "no skuid rule"
expect "client DNS" "$(q example.org)" "ok"
ifdown wgx1; ifdown wgx2; sleep 8
expect "still encrypted with every exit down" "$(dmode)" "encrypted"
waitfor ok "q example.net" 20 && ok "client DNS with every exit down" || bad "client DNS with every exit down"
ifup wgx1; ifup wgx2

echo "== a known provider: its addresses and its own bootstrap, the protocol chosen"
uci set detour.main.dns_provider=quad9; uci set detour.main.dns_proto=tls; uci commit detour
R=$(detour dns-upstreams)
[ "$(echo "$R" | sed -n 1p)" = "tls://dns.quad9.net" ] && [ "$(echo "$R" | sed -n 2p)" = "9.9.9.9:53 149.112.112.112:53" ] \
	&& ok "quad9 + tls -> tls://dns.quad9.net, bootstrap its own servers" || bad "dns-upstreams: $R"
reload_config
waitfor 1 "dpargs | grep -c -- '-u tls://dns.quad9.net -b 9.9.9.9:53 -b 149.112.112.112:53'" 20 && ok "dnsproxy restarted with it" || bad "dnsproxy: $(dpargs)"
# a live answer through it: DoH (853, DoT/DoQ, is cut on some networks), dnsmasq's cache dropped first
uci set detour.main.dns_proto=https; uci commit detour; reload_config
waitfor 1 "dpargs | grep -c -- '-u https://dns.quad9.net/dns-query '" 20 && ok "DoH chosen: dnsproxy restarted with it" || bad "dnsproxy (DoH): $(dpargs)"
killall -HUP dnsmasq; sleep 1
waitfor ok "q example.com" 25 && ok "client DNS through Quad9 DoH" || bad "client DNS through Quad9 DoH"
uci set detour.main.dns_proto=quic; uci commit detour
[ "$(detour dns-upstreams | sed -n 1p)" = "https://dns.quad9.net/dns-query" ] && ok "a protocol it lacks (DoQ): its first, DoH" || bad "quic on quad9: $(detour dns-upstreams | sed -n 1p)"
ubus call detour reload >/dev/null; sleep 2
ubus call detour status | jsonfilter -e "@.errors[*]" | grep -q "Quad9 has no quic" && ok "and the status says so" || bad "no error for the missing protocol"
B0=$(uci -q delete detour.main.dns_provider; detour dns-upstreams)
uci set detour.main.dns_provider=nosuch; uci commit detour
[ "$(detour dns-upstreams)" = "$B0" ] && ok "an unknown provider: the addresses given (or the defaults), as without one" || bad "unknown provider: $(detour dns-upstreams) vs $B0"
# every provider and protocol of the table answers (a dnsproxy of its own on a spare port, the lab's internet)
DP=$(command -v dnsproxy)
# DoT and DoQ (port 853) are cut by some networks (the lab's own line, Russian ISPs): checked only where 853 gets out
open853=0; curl -sv -m 5 -o /dev/null telnet://9.9.9.9:853 2>&1 | grep -q '^\* Connected' && open853=1
for pp in $(ucode -L /usr/share/ucode -e 'import * as d from "detour.dnsprov"; for (let p in d.list()) for (let k in p.protos) print(p.id, ":", k, " ");'); do
	case "$pp" in *:tls|*:quic) [ $open853 = 1 ] || { echo "  skip $pp: port 853 does not get out of this network"; continue; } ;; esac
	R=$(ucode -L /usr/share/ucode -e 'import * as d from "detour.dnsprov"; const a = split(ARGV[0], ":"); const r = d.resolve(a[0], a[1]); print(join(" ", map(r.upstreams, (u) => "-u " + u)), " ", join(" ", map(r.bootstrap, (b) => "-b " + b)));' -- "$pp")
	$DP -l 127.0.0.1 -p 5399 $R >/tmp/t3-dp.log 2>&1 & P=$!
	# the emulated lab is slow at TLS/QUIC handshakes: up to 30 s, the first answer counts
	a=0; i=0; while [ $i -lt 15 ] && [ "$a" = 0 ]; do sleep 2; a=$(nslookup -port=5399 example.com 127.0.0.1 2>/dev/null | grep -A1 '^Name' | grep -c Address); i=$((i+1)); done
	kill $P 2>/dev/null; wait $P 2>/dev/null
	[ "$a" -gt 0 ] && ok "$pp answers" || bad "$pp: no answer ($(grep -iE 'error|fail' /tmp/t3-dp.log | tail -n 1 | cut -c1-200))"
done
rm -f /tmp/t3-dp.log
uci -q delete detour.main.dns_provider; uci -q delete detour.main.dns_proto; uci commit detour

echo "== dns=off restores dnsmasq"
uci set detour.main.dns=off; uci commit detour; reload_config; sleep 6
waitfor "" "uci -q get dhcp.@dnsmasq[0].serversfile" 20 && ok "serversfile removed" || bad "serversfile still set"
waitfor 0 "ps w | grep -c '[d]nsproxy -l 127.0.0.1'" 15 && ok "dnsproxy instance gone" || bad "dnsproxy still running"
waitfor ok "q example.org" 20 && ok "client DNS (ISP upstream again)" || bad "client DNS after dns=off"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
