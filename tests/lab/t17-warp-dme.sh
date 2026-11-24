#!/bin/sh
# WARP pool. Lab "anycast": servers ex3 (10.199.3.2) and ex4 (10.199.4.2) share ONE private key, like WARP's
# endpoints. Each answers the point URLs (198.51.100.80: /cdn-cgi/trace and /meta, DNATed inside the netns to a
# local uhttpd; the address is on its lo too, for the pings) with its own point: ex3 -> DME (RU), ex4 -> ARN (SE).
# The WARP exit starts on ex3 (DME). The scanner tunnel uses the exit's key next to the live one.
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
D=/etc/enodia-lab
colo_srv() { # $1 netns index, $2 colo, $3 country
	mkdir -p /tmp/tr$1/cdn-cgi; printf 'fl=1\nh=1.1.1.1\nwarp=on\ncolo=%s\n' "$2" > /tmp/tr$1/cdn-cgi/trace
	printf '{"hostname":"speed.cloudflare.com","colo":{"iata":"%s","cca2":"%s","city":"lab"}}' "$2" "$3" > /tmp/tr$1/meta
}
for N in 3 4; do lab tests/lab/l2-exit.sh $N >/dev/null 2>&1; ifdown wgx$N 2>/dev/null; done
ip netns exec ex4 wg set wgex private-key $D/ex3.key            # same key = anycast
colo_srv 3 DME RU; colo_srv 4 ARN SE
for N in 3 4; do
	ip netns exec ex$N uhttpd -p 10.200.$N.2:8080 -h /tmp/tr$N 2>/dev/null
	ip -n ex$N addr add 198.51.100.80/32 dev lo 2>/dev/null
	ip netns exec ex$N nft -f - <<E
table ip trace
delete table ip trace
table ip trace {
	chain pre {
		type nat hook prerouting priority dstnat;
		ip daddr 198.51.100.80 tcp dport 80 dnat to 10.200.$N.2:8080
	}
}
E
	ip -n ex$N route replace 10.200.3.1/32 dev wgex
done

echo "== register a WARP exit on ex3"
uci set detour.main.warp_check=0; uci commit detour   # the daemon stays out until its own step
inpool() { detour warp-pool wd | jsonfilter -e '@.entries[*].endpoint' | grep -qx "$1"; }
SPUB=$(cat $D/ex3.pub)
wget -qO- "http://10.0.2.2:8767/setpeer?key=$(echo "$SPUB" | sed 's/+/%2B/g; s/\//%2F/g; s/=/%3D/g')&ep=10.199.3.2&v4=10.200.3.1" >/dev/null
detour warp-unregister wd >/dev/null 2>&1
detour warp-register wd api=http://10.0.2.2:8767/v0a2158 peer=$SPUB port=51820 >/dev/null || bad "register"
CPUB=$(jsonfilter -i /etc/detour/warp/wd.json -e '@.pub')
for N in 3 4; do ip netns exec ex$N wg set wgex peer "$CPUB" allowed-ips 0.0.0.0/0; done
uci set network.wd.nohostroute=1; uci commit network; ifup wd; sleep 4
# the host route the first start put via WAN (right for a real WARP server) is not taken back by netifd of 25.12
# when nohostroute is set afterwards: it would send the lab server's traffic to WAN
for N in 3 4; do ip route del 10.199.$N.2 dev eth1 2>/dev/null; done
uci set detour.main.warp_trace=http://198.51.100.80/cdn-cgi/trace
uci set detour.main.warp_meta=http://198.51.100.80/meta
uci set detour.main.warp_ping=198.51.100.80
uci set detour.wd.warp_pool_min=1   # the lab has one other address: do not scan on every check
uci set detour.main.warp_hosts=10.199.4.2; uci set detour.main.warp_ports=51820
uci commit detour; reload_config; sleep 3
[ "$(curl -s -m 5 --interface wd http://198.51.100.80/cdn-cgi/trace | sed -n 's/^colo=//p')" = DME ] && ok "tunnel lands on DME (ex3)" || bad "start colo"

echo "== empty pool, DME: the scanner finds ex4, the live tunnel moves there"
R=$(detour warp-pick wd)
echo "$R" | grep -q '"moved": true' && echo "$R" | grep -q '"colo": "ARN"' && ok "moved to ARN after a scan of $(echo "$R" | jsonfilter -e '@.scanned')" || bad "pick: $R"
[ "$(uci -q get network.@wireguard_wd[0].endpoint_host)" = 10.199.4.2 ] && ok "endpoint saved in UCI" || bad "uci endpoint"
wg show wd endpoints | grep -q 10.199.4.2:51820 && ok "tunnel uses it" || bad "wg endpoint"
ip link show dwswd >/dev/null 2>&1 && bad "scanner tunnel left" || ok "scanner tunnel removed"
nft list set inet detour exit_devs | grep -q dwswd && bad "scanner left in exit_devs" || ok "exit_devs clean"
ip rule | grep -q 'lookup 31999' && bad "scanner rule left" || ok "scanner rule removed"
P=$(detour warp-pool wd)
[ "$(echo "$P" | jsonfilter -e '@.entries[@.endpoint="10.199.4.2:51820"].colo')" = ARN ] && ok "in the pool: ARN" || bad "pool: $P"
[ "$(echo "$P" | jsonfilter -e '@.entries[@.endpoint="10.199.4.2:51820"].country')" = SE ] && ok "with its country SE" || bad "country"
inpool 10.199.3.2:51820 && bad "DME address kept in the pool" || ok "DME address not in the pool"
grep -q '^10.199.4.2	51820	ARN	SE' /etc/detour/warp/wd.pool && ok "snapshot on flash" || bad "flash pool: $(cat /etc/detour/warp/wd.pool) / $(cat /tmp/detour/warp-wd.pool.json)"
[ "$(ubus call detour status | jsonfilter -e '@.exits[@.name="wd"].colo')" = ARN ] && ok "status shows colo ARN" || bad "status colo"
R=$(detour warp-pick wd); echo "$R" | grep -q '"moved": false' && echo "$R" | grep -q '"colo": "ARN"' && ok "already fine: no move" || bad "second pick: $R"

back_to_ex3() {   # the live tunnel on ex3 (DME), ex4 forgets the client (else its answers roam the tunnel back)
	ip netns exec ex4 wg set wgex peer "$CPUB" remove; ip netns exec ex4 wg set wgex peer "$CPUB" allowed-ips 0.0.0.0/0
	SP=$(jsonfilter -i /etc/detour/warp/wd.json -e '@.peer')
	wg set wd peer "$SP" remove; wg set wd peer "$SP" endpoint 10.199.3.2:51820 allowed-ips 0.0.0.0/0 persistent-keepalive 25
	uci set network.@wireguard_wd[0].endpoint_host=10.199.3.2; uci commit network; sleep 2
}
echo "== failover from the pool: no scan needed"
back_to_ex3
[ "$(curl -s -m 5 --interface wd http://198.51.100.80/cdn-cgi/trace | sed -n 's/^colo=//p')" = DME ] && ok "back on DME" || bad "not on DME"
R=$(detour warp-pick wd)
echo "$R" | grep -q '"moved": true' && [ "$(echo "$R" | jsonfilter -e '@.scanned')" = 0 ] && ok "moved back to ARN from the pool, no scan" || bad "failover: $R"

echo "== country filter: SE excluded - nothing passes, the working tunnel stays"
uci add_list detour.wd.warp_exclude_country=SE; uci commit detour
R=$(detour warp-pick wd)
echo "$R" | grep -q 'no endpoint outside the filters' && [ "$(echo "$R" | jsonfilter -e '@.colo')" = ARN ] && ok "kept ARN as the last resort" || bad "country filter: $R"
[ "$(curl -s -m 5 --interface wd http://198.51.100.80/cdn-cgi/trace | sed -n 's/^warp=//p')" = on ] && ok "tunnel still works" || bad "tunnel broken"
uci -q delete detour.wd.warp_exclude_country; uci commit detour

echo "== everything lands on DME: keep a working tunnel rather than none"
detour warp-pick wd >/dev/null   # refills the pool (ARN again)
colo_srv 4 DME RU
R=$(detour warp-pick wd --force)
echo "$R" | grep -q 'no endpoint outside the filters' && [ "$(echo "$R" | jsonfilter -e '@.colo')" = DME ] && ok "kept DME as the last resort" || bad "all DME: $R"
[ "$(curl -s -m 5 --interface wd http://198.51.100.80/cdn-cgi/trace | sed -n 's/^warp=//p')" = on ] && ok "tunnel still works" || bad "tunnel broken"
inpool 10.199.4.2:51820 && bad "address now on DME still in the pool" || ok "address that drifted to DME left the pool"

echo "== use / drop by hand"
colo_srv 4 ARN SE
R=$(detour warp-pick wd use=10.199.4.2:51820)
echo "$R" | grep -q '"moved": true' && ok "use=: moved to 10.199.4.2" || bad "use: $R"
inpool 10.199.4.2:51820 && ok "used address in the pool" || bad "use: not in the pool"
detour warp-pick wd drop=10.199.4.2:51820 >/dev/null
inpool 10.199.4.2:51820 && bad "drop: still there" || ok "drop=: out of the pool"

echo "== the daemon does it by itself (and LuCI's scan)"
detour warp-pick wd use=10.199.4.2:51820 >/dev/null   # back into the pool
back_to_ex3
T0=$(date +%s)   # only an event of this step counts (the list keeps those of earlier runs)
moved() { ubus call detour status | jsonfilter -e '@.events[*]' | awk -v t=$T0 '$1 >= t && /WARP wd moved/' | tail -n1; }
uci set detour.main.warp_check=20; uci commit detour; ubus call detour reload >/dev/null
waitfor yes '[ -n "$(moved)" ] && echo yes' 200 && ok "daemon moved it ($(moved))" || bad "daemon did not move"
r=$(ubus call detour warp_scan '{"name":"wd"}'); echo "$r" | grep -q '"queued": true' && ok "warp_scan queued" || bad "warp_scan: $r"
waitfor yes "ubus call detour status | jsonfilter -e '@.events[*]' | awk -v t=$T0 '\$1 >= t && /WARP wd: pool scan/' | grep -q . && echo yes" 90 && ok "LuCI scan ran" || bad "no scan event"
r=$(ubus call detour warp_pool '{"name":"wd"}'); echo "$r" | grep -q '"xcolo"' && ok "warp_pool answers" || bad "warp_pool: $r"
r=$(ubus call detour warp_use '{"name":"wd","endpoint":"bad"}'); echo "$r" | grep -q 'not an address' && ok "warp_use checks the address" || bad "warp_use: $r"

echo "== WireGuard <-> AmneziaWG"
if [ -x /usr/bin/awg ]; then
	R=$(detour warp-proto wd awg dns)
	[ "$(uci -q get network.wd.proto)" = amneziawg ] && [ "$(uci show network | grep -c '=amneziawg_wd$')" = 1 ] && [ "$(uci show network | grep -c '=wireguard_wd$')" = 0 ] && ok "to AmneziaWG: proto and peer section" || bad "to awg: $R"
	[ "$(uci -q get network.@amneziawg_wd[0].endpoint_host)" != "" ] && ok "peer options moved along" || bad "peer options lost"
	[ "$(uci -q get network.wd.awg_jc)" = 4 ] && uci -q get network.wd.awg_i1 | grep -q '^<' && ok "stock masking + I1" || bad "masking"
	R=$(detour warp-proto wd wg)
	[ "$(uci -q get network.wd.proto)" = wireguard ] && [ -z "$(uci -q get network.wd.awg_jc)" ] && [ "$(uci show network | grep -c '=wireguard_wd$')" = 1 ] && ok "back to WireGuard, masking removed" || bad "to wg: $R"
else
	R=$(detour warp-proto wd awg); echo "$R" | grep -q 'not installed' && ok "AmneziaWG missing: refused" || bad "awg missing: $R"
fi
R=$(detour warp-proto wd awg xyz); echo "$R" | grep -q 'quic, dns or stun' && ok "unknown I1 profile refused" || bad "mask check: $R"

echo "== cleanup"
detour warp-unregister wd >/dev/null
[ -f /etc/detour/warp/wd.pool ] && bad "pool file left" || ok "pool removed with the exit"
for k in warp_trace warp_meta warp_ping warp_hosts warp_ports; do uci -q delete detour.main.$k; done; uci set detour.main.warp_check=0; uci commit detour   # lab: its "WARP" exits are not real
for N in 3 4; do ip netns exec ex$N nft delete table ip trace 2>/dev/null; ip -n ex$N addr del 198.51.100.80/32 dev lo 2>/dev/null; done
for p in $(pgrep -f 'uhttpd -p 10.200'); do kill $p; done
reload_config
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
