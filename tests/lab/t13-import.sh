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
	uci commit; rm -f /etc/detour/engines/st_*.json /etc/detour/lists/st_*
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
# lists registry (lists-lib.sh): id type enabled format count ts label value; file/text in blob/<id>
L=http://10.0.2.2:8765/tests/stub/lists
mkdir -p $S/lists/tunnel-cidr/blob $S/lists/tunnel-domains $S/lists/bypass-ip $S/lists/adblock
printf 's1\turl\t1\tcidr\t22\t0\topencck\t%s/cidr.txt\ns2\ttext\t1\tcidr\t1\t0\tmy own\t\ns3\turl\t0\tcidr\t0\t0\toff\thttp://off.example/x\n' "$L" > $S/lists/tunnel-cidr/sources.tsv
printf '100.64.200.0/24\n' > $S/lists/tunnel-cidr/blob/s2
printf 's1\turl\t1\tauto\t0\t0\tdoms\t%s/domains.txt\n' "$L" > $S/lists/tunnel-domains/sources.tsv
printf 's1\turl\t1\tcidr\t0\t0\tdirect\t%s/direct.txt\n' "$L" > $S/lists/bypass-ip/sources.tsv
printf 's1\turl\t1\tauto\t0\t0\tads\thttp://ads.example/x\n' > $S/lists/adblock/sources.tsv
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
echo "$OUT" | grep -q 'st_l_tunnel_cidr -> vpn: .*cidr.txt + local entries (from lists/tunnel-cidr)' && ok "list registry: URL + text source" || bad "cidr list: $(echo "$OUT" | grep l_tunnel)"
echo "$OUT" | grep -q 'st_l_tunnel_domains -> vpn' && echo "$OUT" | grep -q 'st_l_bypass_ip -> direct' && ok "domain and bypass lists" || bad "other lists"
echo "$OUT" | grep -q 'source off: switched off' && ok "disabled source reported" || bad "disabled source"
echo "$OUT" | grep -q 'lists/adblock: blocking' && ok "adblock reported as not carried over" || bad "adblock"
# legacy config without a registry: iplist.conf sites -> opencck URL with &site=
S2=/tmp/stock-state2; rm -rf $S2; mkdir -p $S2/configs; cp $S/configs/home.conf $S2/configs/; echo awg > $S2/.transport; echo home > $S2/.active
printf 'IPLIST_SITES="steampowered.com discord.com"\nIPLIST_CUSTOM_MODE=merge\n' > $S2/iplist.conf; printf '100.64.201.0/24\n' > $S2/iplist.custom
detour import $S2 | grep -q 'data=cidr4&site=steampowered.com&site=discord.com + local entries (from iplist.conf)' && ok "legacy iplist.conf (sites + merged custom list)" || bad "legacy: $(detour import $S2 | grep l_tunnel)"

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
PID=$(uci -q get detour.st_p_vpn.id)
waitfor yes "nft get element inet detour lst4_p$PID '{ 8.8.8.8 }' >/dev/null 2>&1 && echo yes" 40 && ok "imported list loaded into lst4_p$PID" || bad "list not loaded: $(cat /tmp/detour/lists/st_l_tunnel_cidr.status 2>&1)"
nft get element inet detour lst4_p$PID '{ 100.64.200.1 }' >/dev/null 2>&1 && ok "text source (blob) included" || bad "blob entries missing"
waitfor yes "nft get element inet detour lst4_direct '{ 203.0.113.9 }' >/dev/null 2>&1 && echo yes" 30 && ok "bypass list -> lst4_direct" || bad "bypass list"
waitfor yes "cl 'nslookup example.org 192.168.1.1' >/dev/null; nft list set inet detour dom_direct4 | grep -q expires && echo yes" 30 && ok "direct domain filled dom_direct4" || bad "dom_direct4 empty"

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
