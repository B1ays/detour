#!/bin/sh
# WARP away from DME. Lab "anycast": servers ex3 (10.199.3.2) and ex4 (10.199.4.2) share ONE private key,
# like WARP's endpoints. Each answers the trace URL (198.51.100.80, DNATed inside the netns to a local
# uhttpd) with its own colo: ex3 -> DME, ex4 -> ARN. The WARP exit starts on ex3 (DME).
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
D=/etc/enodia-lab
colo_srv() { # $1 netns index, $2 colo
	mkdir -p /tmp/tr$1/cdn-cgi; printf 'fl=1\nh=1.1.1.1\nwarp=on\ncolo=%s\n' "$2" > /tmp/tr$1/cdn-cgi/trace
}
for N in 3 4; do lab tests/lab/l2-exit.sh $N >/dev/null 2>&1; ifdown wgx$N 2>/dev/null; done
ip netns exec ex4 wg set wgex private-key $D/ex3.key            # same key = anycast
colo_srv 3 DME; colo_srv 4 ARN
for N in 3 4; do
	ip netns exec ex$N uhttpd -p 10.200.$N.2:8080 -h /tmp/tr$N 2>/dev/null
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
SPUB=$(cat $D/ex3.pub)
wget -qO- "http://10.0.2.2:8767/setpeer?key=$(echo "$SPUB" | sed 's/+/%2B/g; s/\//%2F/g; s/=/%3D/g')&ep=10.199.3.2&v4=10.200.3.1" >/dev/null
detour warp-unregister wd >/dev/null 2>&1
detour warp-register wd api=http://10.0.2.2:8767/v0a2158 peer=$SPUB port=51820 >/dev/null || bad "register"
CPUB=$(jsonfilter -i /etc/detour/warp/wd.json -e '@.pub')
for N in 3 4; do ip netns exec ex$N wg set wgex peer "$CPUB" allowed-ips 0.0.0.0/0; done
uci set network.wd.nohostroute=1; uci commit network; ifup wd; sleep 4
uci set detour.main.warp_trace=http://198.51.100.80/cdn-cgi/trace
uci set detour.main.warp_hosts=10.199.4.2; uci set detour.main.warp_ports=51820; uci set detour.main.warp_check=3600
uci commit detour; reload_config; sleep 3
[ "$(curl -s -m 5 --interface wd http://198.51.100.80/cdn-cgi/trace | sed -n 's/^colo=//p')" = DME ] && ok "tunnel lands on DME (ex3)" || bad "start colo"

echo "== pick: away from DME"
R=$(detour warp-pick wd)
echo "$R" | grep -q '"moved": true' && echo "$R" | grep -q '"colo": "ARN"' && ok "moved to ARN: $(echo "$R" | jsonfilter -e '@.endpoint') after $(echo "$R" | jsonfilter -e '@.tried') tries" || bad "pick: $R"
[ "$(uci -q get network.@wireguard_wd[0].endpoint_host)" = 10.199.4.2 ] && ok "endpoint saved in UCI" || bad "uci endpoint"
wg show wd endpoints | grep -q 10.199.4.2:51820 && ok "tunnel uses it" || bad "wg endpoint"
grep -q '^10.199.4.2	51820	ARN' /etc/detour/warp/wd.pool && ok "added to the pool" || bad "pool"
[ "$(ubus call detour status | jsonfilter -e '@.exits[@.name="wd"].colo')" = ARN ] && ok "status shows colo ARN" || bad "status colo"
R=$(detour warp-pick wd); echo "$R" | grep -q '"moved": false' && echo "$R" | grep -q '"colo": "ARN"' && ok "already fine: no move" || bad "second pick: $R"

echo "== everything lands on DME: keep a working tunnel rather than none"
colo_srv 4 DME
R=$(detour warp-pick wd --force)
echo "$R" | grep -q 'no endpoint outside DME' && [ "$(echo "$R" | jsonfilter -e '@.colo')" = DME ] && ok "kept DME as the last resort" || bad "all DME: $R"
[ "$(curl -s -m 5 --interface wd http://198.51.100.80/cdn-cgi/trace | sed -n 's/^warp=//p')" = on ] && ok "tunnel still works" || bad "tunnel broken"

echo "== the daemon does it by itself"
colo_srv 4 ARN
# ex4 forgets where the client is: otherwise its answers roam the tunnel back to it (a lab artefact - a real
# anycast endpoint does not reach out to a client that went elsewhere)
ip netns exec ex4 wg set wgex peer "$CPUB" remove; ip netns exec ex4 wg set wgex peer "$CPUB" allowed-ips 0.0.0.0/0
wg set wd peer "$(jsonfilter -i /etc/detour/warp/wd.json -e '@.peer')" endpoint 10.199.3.2:51820
uci set network.@wireguard_wd[0].endpoint_host=10.199.3.2; uci commit network
T0=$(date +%s)   # only an event of this step counts (the list keeps those of earlier runs)
moved() { ubus call detour status | jsonfilter -e '@.events[*]' | awk -v t=$T0 '$1 >= t && /WARP wd moved/' | tail -n1; }
uci set detour.main.warp_check=20; uci commit detour; ubus call detour reload >/dev/null
waitfor yes '[ -n "$(moved)" ] && echo yes' 200 && ok "daemon moved it ($(moved))" || bad "daemon did not move"

echo "== cleanup"
detour warp-unregister wd >/dev/null
for k in warp_trace warp_hosts warp_ports; do uci -q delete detour.main.$k; done; uci set detour.main.warp_check=0; uci commit detour   # lab: its "WARP" exits are not real
for N in 3 4; do ip netns exec ex$N nft delete table ip trace 2>/dev/null; done
for p in $(pgrep -f 'uhttpd -p 10.200'); do kill $p; done
reload_config
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
