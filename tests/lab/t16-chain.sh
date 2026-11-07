#!/bin/sh
# Stage 5 chain: proxy engines whose own connections leave through another exit ("VLESS over WARP";
# here: shadowsocks over the WG exit "alt"/wgx2). Chain down -> fail-closed. Plus WARP with AmneziaWG
# masking: generated UCI (I1 = QUIC Initial) - the tunnel itself needs kmod-amneziawg (hardware).
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
txb() { cat /sys/class/net/$1/statistics/tx_bytes 2>/dev/null || echo 0; }
hl() { ubus call detour status | jsonfilter -e "@.exits[@.name=\"$1\"].healthy"; }
probe() { cl "curl -s -m 8 -o /dev/null -w '%{http_code}' https://1.0.0.1/cdn-cgi/trace"; }
lab tests/lab/restart-sb.sh >/dev/null   # with DNS in the netns (urltest probes resolve names)
for N in 1 2; do lab tests/lab/l2-exit.sh $N >/dev/null 2>&1; done; ifup wgx1; ifup wgx2; sleep 5

echo "== engines sb and xr go through exit alt (wgx2)"
uci set detour.sb.via=alt; uci set detour.xr.via=alt; uci set detour.sb.enabled=1; uci set detour.xr.enabled=1; uci commit detour
reload_config; sleep 10
[ "$(jsonfilter -i /tmp/detour/engines/sb.json -e '@.outbounds[0].bind_interface')" = wgx2 ] && ok "sing-box bind_interface wgx2" || bad "sing-box via"
[ "$(jsonfilter -i /tmp/detour/engines/xr.json -e '@.outbounds[0].streamSettings.sockopt.interface')" = wgx2 ] && ok "xray sockopt.interface wgx2" || bad "xray via"
sing-box check -c /tmp/detour/engines/sb.json && ok "sing-box accepts the config" || bad "sing-box check"
waitfor true "hl sbx" 40 && ok "sbx healthy through the chain" || bad "sbx not healthy"
waitfor true "hl xrx" 40 && ok "xrx healthy through the chain" || bad "xrx not healthy"
conntrack -D -d 1.0.0.1 >/dev/null 2>&1
a=$(txb wgx2); s=$(txb sbtun); r=$(probe)
[ "$r" = 200 ] && [ $(( $(txb sbtun) - s )) -gt 0 ] && [ $(( $(txb wgx2) - a )) -gt 0 ] && ok "1.0.0.1 -> sbtun -> sing-box -> wgx2 (http $r)" || bad "chain traffic: http=$r sbtun+$(( $(txb sbtun) - s )) wgx2+$(( $(txb wgx2) - a ))"
echo "== the carrying exit goes down -> the chained exits fail, the policy is blocked (no direct leak)"
ifdown wgx2
waitfor false "hl sbx" 30 && waitfor false "hl xrx" 30 && ok "sbx and xrx down with wgx2" || bad "still healthy: sbx=$(hl sbx) xrx=$(hl xrx)"
conntrack -D -d 1.0.0.1 >/dev/null 2>&1
[ "$(probe)" = 000 ] && ok "policy px blocked" || bad "px not blocked"
ifup wgx2
waitfor true "hl sbx" 40 && ok "chain back" || bad "chain not back"
uci delete detour.sb.via; uci delete detour.xr.via; uci commit detour; reload_config; sleep 5

echo "== WARP with AmneziaWG masking (lab stub; config only)"
SPUB=$(cat /etc/enodia-lab/ex3.pub)
wget -qO- "http://10.0.2.2:8767/setpeer?key=$(echo "$SPUB" | sed 's/+/%2B/g; s/\//%2F/g; s/=/%3D/g')&ep=10.199.3.2&v4=10.200.3.1" >/dev/null
detour warp-unregister warpa >/dev/null 2>&1
R=$(detour warp-register warpa api=http://10.0.2.2:8767/v0a2158 peer=$SPUB awg=1)
echo "$R" | grep -q exit_id && ok "registered" || bad "register: $R"
[ "$(uci -q get network.warpa.proto)" = amneziawg ] && ok "proto amneziawg" || bad "proto"
[ "$(uci show network | grep -c '=amneziawg_warpa$')" = 1 ] && ok "peer section amneziawg_warpa" || bad "peer section"
[ "$(uci -q get network.warpa.awg_jc)" = 4 ] && ok "junk packets Jc 4" || bad "jc"
uci -q get network.warpa.awg_i1 > /tmp/warpa.i1 && grep -q '^<b 0xc' /tmp/warpa.i1 && ok "I1 is a QUIC long header (decoded on the PC)" || bad "i1: $(cat /tmp/warpa.i1 | cut -c1-40)"
detour warp-unregister warpa >/dev/null
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
