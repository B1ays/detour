#!/bin/sh
# A VPN server on the router (AmneziaWG, or WireGuard: the same to Detour - it goes by the interface a flow came
# in on): its clients' traffic is classified only when the server's device is a home network (main.lan_dev).
# The client: netns awgc on br-lan, a WireGuard tunnel to the router's server "awgsrv" (10.77.0.1), everything
# through it. Policy "vpn" (1.1.1.0/24, domain ifconfig.me -> warp/alt); what an exit carried is counted in exN.
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
D=/etc/enodia-lab; mkdir -p $D; umask 077
NS=awgc; V=vawgc; VP=vawgcp
# the forward counters of the exits' netns (packets that came out of the exit tunnels); Detour's own probes add a
# packet now and then, an HTTPS request is 10+: through = more than 5, directly = at most 2
THRU=5; QUIET=2
cnt() { s=0; for n in 1 2; do c=$(ip netns exec ex$n nft list chain ip exnat cnt 2>/dev/null | sed -n 's/.*counter packets \([0-9]*\).*/\1/p'); s=$((s + ${c:-0})); done; echo $s; }
in_ns() { ip netns exec $NS "$@"; }
LAN0=$(uci -q get detour.main.lan_dev)
cleanup() {
	ip netns del $NS 2>/dev/null; ip link del $V 2>/dev/null
	uci -q delete network.awgsrv; uci -q delete network.awgsrv_c
	uci -q del_list firewall.@zone[0].network=awgsrv
	if [ -n "$LAN0" ]; then uci set detour.main.lan_dev="$LAN0"; else uci -q delete detour.main.lan_dev; fi
	uci commit network; uci commit firewall; uci commit detour
	/etc/init.d/network reload; fw4 -q reload; /etc/init.d/detour reload
}
cleanup >/dev/null 2>&1
sleep 3
lsmod | grep -q '^veth' || apk add -q kmod-veth >/dev/null 2>&1
[ -f $D/awgs.key ] || { wg genkey > $D/awgs.key; wg pubkey < $D/awgs.key > $D/awgs.pub; wg genkey > $D/awgc.key; wg pubkey < $D/awgc.key > $D/awgc.pub; }

echo "== the server on the router, in the home zone"
uci -q batch <<U
set network.awgsrv=interface
set network.awgsrv.proto=wireguard
set network.awgsrv.private_key=$(cat $D/awgs.key)
set network.awgsrv.listen_port=51900
add_list network.awgsrv.addresses=10.77.0.1/24
set network.awgsrv_c=wireguard_awgsrv
set network.awgsrv_c.public_key=$(cat $D/awgc.pub)
add_list network.awgsrv_c.allowed_ips=10.77.0.2/32
set network.awgsrv_c.route_allowed_ips=1
add_list firewall.@zone[0].network=awgsrv
commit network
commit firewall
U
/etc/init.d/network reload; fw4 -q reload; sleep 4
ip -br a show awgsrv | grep -q 10.77.0.1 && ok "server awgsrv up (10.77.0.1)" || bad "awgsrv: $(ip -br a show awgsrv 2>&1)"

echo "== the client: netns on br-lan, all its traffic through the tunnel, the router as its DNS"
ip netns add $NS
mkdir -p /etc/netns/$NS; echo "nameserver 10.77.0.1" > /etc/netns/$NS/resolv.conf
ip link add $V type veth peer name $VP; ip link set $VP netns $NS
ip link set $V master br-lan; ip link set $V up
ip -n $NS link set lo up; ip -n $NS addr add 192.168.1.250/24 dev $VP; ip -n $NS link set $VP up
ip -n $NS link add wgc type wireguard
in_ns wg set wgc private-key $D/awgc.key peer "$(cat $D/awgs.pub)" endpoint 192.168.1.1:51900 allowed-ips 0.0.0.0/0 persistent-keepalive 5
ip -n $NS addr add 10.77.0.2/32 dev wgc; ip -n $NS link set wgc up
ip -n $NS route add default dev wgc
sleep 2
in_ns ping -c1 -W3 10.77.0.1 >/dev/null && ok "client reaches the server through the tunnel" || bad "no tunnel"
[ "$(in_ns curl -s -m 10 -o /dev/null -w '%{http_code}' https://www.gstatic.com/generate_204)" = 204 ] && ok "client has the internet through the server" || bad "client: no internet"

echo "== main.lan_dev without the server: its clients are not classified"
c0=$(cnt); in_ns curl -s -m 10 -o /dev/null https://1.1.1.1/cdn-cgi/trace; c1=$(cnt)
[ $((c1 - c0)) -le $QUIET ] && ok "1.1.1.1 (policy vpn) went directly, not through an exit (+$((c1 - c0)))" || bad "already through an exit (+$((c1 - c0)))"

echo "== main.lan_dev with the server: its clients go by the policies"
uci set detour.main.lan_dev="br-lan awgsrv"; uci commit detour; /etc/init.d/detour reload; sleep 5
# an option of words: both devices (it was read as one bad name, which left no home network at all)
L=$(nft list set inet detour lan_ifs | tr -d '\n\t')
echo "$L" | grep -q '"br-lan"' && echo "$L" | grep -q '"awgsrv"' && ok "lan_dev 'br-lan awgsrv': both in lan_ifs" || bad "lan_ifs: $L"
c0=$(cnt); r=$(in_ns curl -s -m 10 https://1.1.1.1/cdn-cgi/trace | sed -n 's/^ip=//p'); c1=$(cnt)
[ $((c1 - c0)) -gt $THRU ] && [ -n "$r" ] && ok "1.1.1.1 through an exit (+$((c1 - c0)) packets, seen as $r)" || bad "1.1.1.1: +$((c1 - c0)), ip=$r"
killall -HUP dnsmasq; sleep 1   # an answer from the cache would not fill the policy's set
in_ns nslookup ifconfig.me 10.77.0.1 >/dev/null 2>&1 && ok "the router's DNS answers the client" || bad "no DNS on 10.77.0.1"
c0=$(cnt); r=$(in_ns curl -s -m 10 -o /dev/null -w '%{http_code}' https://ifconfig.me/); c1=$(cnt)
[ $((c1 - c0)) -gt $THRU ] && ok "domain ifconfig.me through an exit (http $r, +$((c1 - c0)))" || bad "ifconfig.me: http $r, +$((c1 - c0))"
c0=$(cnt); in_ns curl -s -m 10 -o /dev/null https://www.gstatic.com/generate_204; c1=$(cnt)
[ $((c1 - c0)) -le $QUIET ] && ok "what no policy takes stays direct" || bad "unrelated traffic through an exit (+$((c1 - c0)))"
# the same as a list
uci -q delete detour.main.lan_dev; uci add_list detour.main.lan_dev=br-lan; uci add_list detour.main.lan_dev=awgsrv; uci commit detour
/etc/init.d/detour reload; sleep 5
L=$(nft list set inet detour lan_ifs | tr -d '\n\t')
echo "$L" | grep -q '"br-lan"' && echo "$L" | grep -q '"awgsrv"' && ok "lan_dev as a list: both in lan_ifs" || bad "lan_ifs (list): $L"
# a client asking another resolver: port 53 is taken to the router's dnsmasq, so domain policies still see it
# (dnsmasq fills a set from an upstream answer, not from its cache: the cache is dropped first)
rc() { nft list chain inet detour dnsredir | sed -n 's/.*dport 53 counter packets \([0-9]*\).*/\1/p'; }
nft flush set inet detour dom4_p1 2>/dev/null; killall -HUP dnsmasq; sleep 1
k0=$(rc); in_ns nslookup ifconfig.me 8.8.8.8 >/dev/null 2>&1; k1=$(rc)
[ $((k1 - k0)) -gt 0 ] && ok "a query to 8.8.8.8 was redirected to the router (+$((k1 - k0)))" || bad "DNS to 8.8.8.8 not redirected"
nft list set inet detour dom4_p1 2>/dev/null | grep -q elements && ok "and it filled the policy's set" || bad "the set stayed empty"

echo "== cleanup"
cleanup >/dev/null 2>&1
[ -z "$(uci -q get network.awgsrv)" ] && ! ip netns list | grep -q "^$NS" && ok "server, client and lan_dev put back" || bad "left"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
