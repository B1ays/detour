#!/bin/sh
# Stage 5 (lab part): sing-box and Xray engines as exits, built from an outbound JSON only.
# Server: shadowsocks (sing-box) in netns ex1 at 10.199.1.2:8443 - that address is ALSO in policy
# "vpn", so the engines' own traffic must carry the underlay mark to work at all.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
expect() { if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1: got '$2' want '$3'"; fi; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
act() { ubus call detour status | jsonfilter -e '@.policies[@.name="px"].active'; }
txb() { cat /sys/class/net/$1/statistics/tx_bytes 2>/dev/null || echo 0; }
probe() { cl "curl -s -m 8 -o /dev/null -w '%{http_code}' https://1.0.0.1/cdn-cgi/trace"; }
D=/etc/enodia-lab; PW=$(cat $D/ss.pw)

lab tests/lab/restart-sb.sh >/dev/null   # with DNS in the netns (urltest probes resolve names)
sleep 2
mkdir -p /etc/detour/engines; umask 077
cat > /etc/detour/engines/sb.json <<EOF
{ "type": "shadowsocks", "server": "10.199.1.2", "server_port": 8443, "method": "2022-blake3-aes-128-gcm", "password": "$PW" }
EOF
cat > /etc/detour/engines/xr.json <<EOF
{ "protocol": "shadowsocks", "settings": { "servers": [ { "address": "10.199.1.2", "port": 8443, "method": "2022-blake3-aes-128-gcm", "password": "$PW" } ] } }
EOF
# the research prototype may still run its own engines on these devices
kill $(pgrep -f sb-client.json) $(pgrep -f xray-client.json) 2>/dev/null
uci -q batch <<'U'
set detour.sb=engine
set detour.sb.type=singbox
set detour.sb.device=sbtun
set detour.sb.outbound=/etc/detour/engines/sb.json
set detour.xr=engine
set detour.xr.type=xray
set detour.xr.device=xtun
set detour.xr.outbound=/etc/detour/engines/xr.json
set detour.sbx=exit
set detour.sbx.id=3
set detour.sbx.iface=sbtun
set detour.sbx.probe=https://1.1.1.1/cdn-cgi/trace
set detour.xrx=exit
set detour.xrx.id=4
set detour.xrx.iface=xtun
set detour.xrx.probe=https://1.1.1.1/cdn-cgi/trace
delete detour.px
set detour.px=policy
set detour.px.id=2
add_list detour.px.exit=sbx
add_list detour.px.exit=xrx
add_list detour.px.dst=1.0.0.0/24
commit detour
U
reload_config; sleep 12
echo "== engines started by procd"
ubus call service list '{"name":"detour"}' | grep -q '"engine_sb"' && ok "instance engine_sb" || bad "no engine_sb ($(cat /tmp/detour/engines.err))"
ubus call service list '{"name":"detour"}' | grep -q '"engine_xr"' && ok "instance engine_xr" || bad "no engine_xr"
expect "sing-box underlay mark" "$(jsonfilter -i /tmp/detour/engines/sb.json -e '@.outbounds[0].routing_mark')" "268435456"
expect "xray underlay mark" "$(jsonfilter -i /tmp/detour/engines/xr.json -e '@.outbounds[0].streamSettings.sockopt.mark')" "268435456"
ls -l /tmp/detour/engines/sb.json | grep -q '^-rw-------' && ok "generated config mode 600" || bad "mode"
waitfor true "ubus call detour status | jsonfilter -e '@.exits[@.name=\"sbx\"].healthy'" 30 && ok "sbx healthy" || bad "sbx not healthy"
waitfor true "ubus call detour status | jsonfilter -e '@.exits[@.name=\"xrx\"].healthy'" 30 && ok "xrx healthy (xtun brought up by the daemon)" || bad "xrx not healthy"
echo "== traffic of policy px through sing-box"
waitfor sbx act 20 || true
conntrack -D -d 1.0.0.1 >/dev/null 2>&1
t0=$(txb sbtun); r=$(probe); expect "via sbtun" "$r $(( $(txb sbtun) - t0 > 0 ? 1 : 0 ))" "200 1"
echo "== tun address flushed (netifd restart on the BE7000) -> the daemon puts it back"
ip -4 addr flush dev sbtun
waitfor 1 "ip -4 -o addr show dev sbtun | grep -c 'inet 172.19.'" 15 && ok "sbtun address restored" || bad "sbtun has no address"
waitfor true "ubus call detour status | jsonfilter -e '@.exits[@.name=\"sbx\"].healthy'" 20 && ok "sbx healthy again" || bad "sbx not healthy"
echo "== sing-box disabled -> failover to Xray"
uci set detour.sb.enabled=0; uci commit detour; reload_config
waitfor xrx act 30 && ok "switched to xrx" || bad "no failover ($(act))"
conntrack -D -d 1.0.0.1 >/dev/null 2>&1
t0=$(txb xtun); r=$(probe); expect "via xtun" "$r $(( $(txb xtun) - t0 > 0 ? 1 : 0 ))" "200 1"
echo "== both engines off: fail-closed"
uci set detour.xr.enabled=0; uci commit detour; reload_config; sleep 10
expect "blocked" "$(probe)" "000"
echo "== cleanup"
uci set detour.sb.enabled=1; uci set detour.xr.enabled=1; uci commit detour; reload_config
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
