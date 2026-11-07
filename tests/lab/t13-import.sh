#!/bin/sh
# Stage 7: import a stock Detour backup. A synthetic archive in the stock format is built here:
# main exit = AWG/WG config to the lab server ex3, extra exit s2 = Xray (shadowsocks to ex1),
# rules (.vpn-dst, domains, groups), devices by IP + DHCP reservations, Telegram settings.
# Dry run must report; --apply must produce working exits and policies.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
txb() { cat /sys/class/net/$1/statistics/tx_bytes 2>/dev/null || echo 0; }
D=/etc/enodia-lab; S=/tmp/stock-state
cleanup() {
	for s in $(uci show detour | sed -n "s/^detour\.\(st_[a-z0-9_]*\)=.*/\1/p"); do uci delete detour.$s; done
	for s in $(uci show network | sed -n "s/^network\.\(st_[a-z0-9_]*\)=.*/\1/p"); do uci delete network.$s; done
	for s in $(uci show network | sed -n "s/^network\.\(@wireguard_st_[a-z0-9_]*\[0\]\)=.*/\1/p"); do uci delete network.$s; done
	uci -q del_list firewall.vpn.network=st_main; uci -q del_list firewall.vpn.network=st_s2
	for s in $(uci show dhcp | grep -E "mac='(52:54:00:aa:00:01|52:54:00:aa:00:02)'" | cut -d. -f2); do uci delete dhcp.$s; done
	uci -q delete detour.direct.device; uci -q delete detour.direct.domain; uci -q delete detour.direct.dst
	uci -q delete detour.notify
	uci commit; rm -f /etc/detour/engines/st_*.json
}
cleanup

echo "== build a stock-format backup"
rm -rf $S; mkdir -p $S/configs $S/xray-configs $S/groups
CPRIV=$(wg genkey); CPUB=$(echo "$CPRIV" | wg pubkey)
cat > $S/configs/home.conf <<EOF
[Interface]
PrivateKey = $CPRIV
Address = 10.200.3.1/32
MTU = 1280
Jc = 0
Jmin = 0
Jmax = 0
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = $(cat $D/ex3.pub)
AllowedIPs = 0.0.0.0/0
Endpoint = 10.199.3.2:51820
PersistentKeepalive = 25
EOF
echo awg > $S/.transport; echo home > $S/.active
PW=$(cat $D/ss.pw)
cat > $S/xray-configs/lab.json <<EOF
{ "outbounds": [ { "protocol": "shadowsocks", "tag": "proxy", "settings": { "servers": [ { "address": "10.199.1.2", "port": 8443, "method": "2022-blake3-aes-128-gcm", "password": "$PW" } ] } },
  { "protocol": "freedom", "tag": "direct" } ] }
EOF
printf '2\t%s\txray\tlab\tmain\ton\n' "$(ucode -e 'print(b64enc("Лаб s2"))')" > $S/.slots
printf '9.9.9.0/24\n' > $S/.vpn-dst
printf '203.0.113.0/24\n' > $S/.bypass-dst
printf 'ipset=/ifconfig.co/detour_list\nipset=/example.org/detour_bypass\n' > $S/.detour-custom.conf
printf 'g1\t1\tvpn\t2\tlabgroup\ng2\t1\tvpn\t0\tdevgroup\tdev1\n' > $S/groups/groups.tsv
printf '8.8.4.0/24\n' > $S/groups/g1.list
printf '192.168.1.201\n' > $S/.fullvpn-ips
printf '192.168.1.202\n192.168.1.250\n' > $S/.bypass-ips
printf '52:54:00:aa:00:01\t192.168.1.201\n52:54:00:aa:00:02\t192.168.1.202\n' > $S/.dhcp-static
printf '52:54:00:aa:00:01\ttv\n' > $S/.dev-names
printf 'TG_TOKEN="123456:IMPORTED_lab_token_xxxxxxxxxxxxxxxxxxxx"\nTG_CHAT="777"\n' > $S/notify-tg.conf
echo 'hash' > $S/.panel-pass; echo 'x y z' > $S/.totp
tar -czf /tmp/stock.tgz -C $S .

echo "== dry run"
OUT=$(detour import /tmp/stock.tgz)
echo "$OUT" | grep -q 'st_main: wg from configs/home.conf' && ok "main exit recognised as plain WireGuard (all AWG masking off)" || bad "main: $OUT"
echo "$OUT" | grep -q 'st_s2: xray from xray-configs/lab.json' && ok "extra exit s2 (xray)" || bad "s2"
echo "$OUT" | grep -q 'st_p_vpn via main: 1 addresses, 1 domains, 1 devices' && ok "main policy: dst + domain + device" || bad "vpn policy: $(echo "$OUT" | grep st_p_vpn)"
echo "$OUT" | grep -q 'st_p_s2 via s2 -> main: 1 addresses' && ok "slot policy with fallback to main" || bad "s2 policy: $(echo "$OUT" | grep 'st_p_s2 via')"
echo "$OUT" | grep -q '"direct": "1 addresses, 1 devices, 1 domains"' && ok "always-direct items" || bad "direct: $(echo "$OUT" | grep direct)"
echo "$OUT" | grep -q '192.168.1.250: device past VPN: no DHCP reservation' && ok "device without reservation reported" || bad "missing-MAC report"
echo "$OUT" | grep -q 'group devgroup' && ok "device-bound group reported" || bad "src group report"
echo "$OUT" | grep -q '.totp: 2FA secret' && ok "2FA secret deliberately not carried over" || bad "totp report"
echo "$OUT" | grep -q 'dry run' && [ -z "$(uci -q get detour.st_main)" ] && ok "dry run changed nothing" || bad "dry run wrote config"

echo "== apply"
detour import /tmp/stock.tgz --apply > /tmp/import.out
grep -q 'exit st_main' /tmp/import.out && ok "applied" || bad "apply: $(cat /tmp/import.out)"
[ "$(uci -q get network.st_main.proto)" = wireguard ] && ok "netifd st_main" || bad "network st_main"
[ "$(uci -q get detour.st_s2_eng.type)" = xray ] && ok "engine for s2" || bad "engine"
uci -q get detour.direct.device | grep -q 52:54:00:aa:00:02 && ok "bypass device -> direct by MAC" || bad "direct device"
[ "$(uci -q get detour.notify.tg_chat)" = 777 ] && ok "Telegram settings" || bad "notify"
uci show dhcp | grep -q "52:54:00:aa:00:01" && ok "DHCP reservations" || bad "dhcp hosts"
# lab: the server learns the imported client key; endpoint is next to the router
ip netns exec ex3 wg set wgex peer "$CPUB" allowed-ips 0.0.0.0/0
uci set network.st_main.nohostroute=1; uci commit network
/etc/init.d/network reload; fw4 -q reload; reload_config
waitfor true "ubus call detour status | jsonfilter -e '@.exits[@.name=\"st_main\"].healthy'" 45 && ok "st_main healthy" || bad "st_main not healthy"
waitfor true "ubus call detour status | jsonfilter -e '@.exits[@.name=\"st_s2\"].healthy'" 45 && ok "st_s2 healthy (xray)" || bad "st_s2 not healthy"
conntrack -D -d 9.9.9.9 >/dev/null 2>&1; conntrack -D -d 8.8.4.4 >/dev/null 2>&1
t0=$(txb st_main); r=$(cl "curl -s -m 8 -o /dev/null -w '%{http_code}' https://9.9.9.9/"); t1=$(txb st_main)
[ "$r" != 000 ] && [ $((t1 - t0)) -gt 0 ] && ok "9.9.9.9 via imported main exit" || bad "main: http=$r tx+$((t1 - t0))"
DEV=$(uci -q get detour.st_s2.device)
t0=$(txb $DEV); r=$(cl "curl -s -m 8 -o /dev/null -w '%{http_code}' https://8.8.4.4/"); t1=$(txb $DEV)
[ "$r" != 000 ] && [ $((t1 - t0)) -gt 0 ] && ok "8.8.4.4 via imported s2 ($DEV)" || bad "s2: http=$r tx+$((t1 - t0))"
nft list set inet detour direct_dev | grep -q 52:54:00:aa:00:02 && ok "direct_dev set" || bad "direct_dev"
cl "nslookup example.org 192.168.1.1" >/dev/null
nft list set inet detour dom_direct4 | grep -q expires && ok "direct domain filled dom_direct4" || bad "dom_direct4 empty"

echo "== importing the same archive again changes nothing (no duplicated peers)"
detour import /tmp/stock.tgz --apply >/dev/null
[ "$(uci show network | grep -c '=wireguard_st_main$')" = 1 ] && ok "exactly one peer section" || bad "peers: $(uci show network | grep -c '=wireguard_st_main$')"
[ "$(detour check | tail -1 | grep -o '[0-9]* errors')" = "0 errors" ] && ok "config still clean" || bad "$(detour check)"
reload_config; sleep 3
[ "$(wg show st_main peers | wc -l)" = 1 ] && ok "one peer in the kernel" || bad "kernel peers: $(wg show st_main peers | wc -l)"

echo "== archive with an unsafe path is refused"
wget -qO /tmp/evil.tgz http://10.0.2.2:8765/tests/stub/evil.tgz
detour import /tmp/evil.tgz >/dev/null 2>&1 && bad "unsafe archive accepted" || ok "unsafe archive refused"

[ "$1" = keep ] || { cleanup; /etc/init.d/network reload; reload_config; }
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
