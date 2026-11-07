#!/bin/sh
# WARP registration against the lab stub of the Cloudflare API (10.0.2.2:8767, no real account):
# the stub answers with the key/endpoint of the lab WireGuard server ex3, so the generated netifd
# interface really comes up and carries a policy. Then deregistration removes everything.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
S=http://10.0.2.2:8767
D=/etc/enodia-lab

# lab "WARP server": netns ex3 (wgex 10.200.3.2, endpoint 10.199.3.2:51820); its netifd client wgx3 is not used
lab tests/lab/l2-exit.sh 3 >/dev/null 2>&1
ifdown wgx3 2>/dev/null
SPUB=$(cat $D/ex3.pub)
wget -qO- "$S/setpeer?key=$(echo "$SPUB" | sed 's/+/%2B/g; s/\//%2F/g; s/=/%3D/g')&ep=10.199.3.2&v4=10.200.3.1" >/dev/null

echo "== register"
detour warp-unregister warp1 >/dev/null 2>&1
R=$(detour warp-register warp1 api=$S/v0a2158 peer=$SPUB port=51820)
echo "$R" | grep -q '"exit_id"' && ok "registered: $(echo "$R" | tr -d '\n\t ')" || bad "register: $R"
wget -qO- $S/log | tail -1 | grep -q '"ok": true' && ok "stub saw the expected client headers/body" || bad "stub: $(wget -qO- $S/log | tail -1)"
[ "$(uci -q get network.warp1.proto)" = wireguard ] && ok "netifd interface warp1" || bad "no interface"
[ "$(uci -q get network.warp1.fwmark)" = 0x10000000 ] && ok "underlay mark on warp1" || bad "fwmark"
ls -l /etc/detour/warp/warp1.json | grep -q '^-rw-------' && ok "registration saved, mode 600" || bad "reg file"
ps w | grep -v grep | grep -q "$(jsonfilter -i /etc/detour/warp/warp1.json -e '@.token')" && bad "token visible in ps" || ok "token not on any command line"
# lab only: the "WARP server" sits next to the router (vex3), not behind WAN - no netifd host route via WAN
uci set network.warp1.nohostroute=1; uci commit network; ifup warp1; sleep 3
# the lab server learns the new client key (a real WARP server knows it from the registration)
CPUB=$(jsonfilter -i /etc/detour/warp/warp1.json -e '@.pub')
ip netns exec ex3 wg set wgex peer "$(cat $D/rt3.pub)" remove 2>/dev/null
ip netns exec ex3 wg set wgex peer "$CPUB" allowed-ips 0.0.0.0/0
ip -n ex3 route replace 10.200.3.1/32 dev wgex
uci -q delete detour.pw; uci set detour.pw=policy; uci set detour.pw.id=5; uci add_list detour.pw.exit=warp1; uci add_list detour.pw.dst=9.9.9.0/24; uci commit detour
reload_config
waitfor true "ubus call detour status | jsonfilter -e '@.exits[@.name=\"warp1\"].healthy'" 40 && ok "warp1 exit healthy (handshake + probe)" || bad "warp1 not healthy: $(wg show warp1 2>&1 | head -5)"
conntrack -D -d 9.9.9.9 >/dev/null 2>&1
t0=$(cat /sys/class/net/warp1/statistics/tx_bytes 2>/dev/null || echo 0)
for i in 1 2 3; do r=$(cl "curl -s -m 8 -o /dev/null -w '%{http_code}' https://9.9.9.9/"); [ "$r" != 000 ] && break; sleep 3; done
t1=$(cat /sys/class/net/warp1/statistics/tx_bytes 2>/dev/null || echo 0)
[ "$r" != 000 ] && [ $((t1 - t0)) -gt 0 ] && ok "policy traffic via warp1 (http $r)" || { bad "via warp1: http=$r tx+$((t1 - t0))"; ip rule | grep 1100; ip route show table 1005; ubus call detour status | jsonfilter -e "@.policies[@.name=\"pw\"]"; wg show warp1 | grep -E "endpoint|handshake|transfer"; ip netns exec ex3 wg show wgex | grep -B1 -A4 "0.0.0.0"; }

echo "== wrong server key is refused"
wget -qO- "$S/setpeer?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D" >/dev/null
R2=$(detour warp-register warp2 api=$S/v0a2158 port=51820)
echo "$R2" | grep -q "not WARP" && ok "refused (key is not WARP's)" || bad "accepted foreign key: $R2"
[ -z "$(uci -q get network.warp2)" ] && ok "nothing written for warp2" || bad "warp2 left in config"

echo "== unregister"
uci -q delete detour.pw; uci commit detour
R3=$(detour warp-unregister warp1)
echo "$R3" | grep -q '"deregistered": true' && ok "deregistered at the API (Bearer token)" || bad "unregister: $R3"
[ -z "$(uci -q get network.warp1)$(uci -q get detour.warp1)" ] && ok "interface and exit removed" || bad "leftovers"
[ ! -f /etc/detour/warp/warp1.json ] && ok "registration file removed" || bad "reg file left"
reload_config
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
