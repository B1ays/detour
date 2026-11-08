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
	uci -q delete detour.st_smyprov; for s in $(uci show detour | sed -n "s/^detour\.\(st_[a-z0-9_]*\)=.*/\1/p"); do uci delete detour.$s; done
	for s in $(uci show network | sed -n "s/^network\.\(st_[a-z0-9_]*\)=.*/\1/p"); do uci delete network.$s; done
	for s in $(uci show network | sed -n "s/^network\.\(@wireguard_st_[a-z0-9_]*\[0\]\)=.*/\1/p"); do uci delete network.$s; done
	uci -q del_list firewall.vpn.network=st_main; uci -q del_list firewall.vpn.network=st_s2
	for s in $(uci show dhcp | grep -E "mac='(52:54:00:aa:00:01|52:54:00:aa:00:02)'" | cut -d. -f2); do uci delete dhcp.$s; done
	uci -q delete detour.direct.device; uci -q delete detour.direct.domain; uci -q delete detour.direct.dst
	uci -q delete detour.notify
	uci -q delete detour.main.dns_fallback; uci -q delete detour.main.dns_bootstrap; uci -q set detour.main.dns=off
	uci commit; rm -f /etc/detour/engines/st_*.json /etc/detour/lists/st_*
}
cleanup
lab tests/lab/restart-sb.sh >/dev/null   # the shadowsocks server the imported xray exit dials (gone after a lab reboot)

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
printf 'myprov	http://10.0.2.2:8768/sub/IMPORTED/b64	My provider
' > $S/.subs
printf 'myprov	happ	Happ/2.0	1	abc-123	gen
' > $S/.sub-client
# lists registry (lists-lib.sh): id type enabled format count ts label value; file/text in blob/<id>
L=http://10.0.2.2:8765/tests/stub/lists
mkdir -p $S/lists/tunnel-cidr/blob $S/lists/tunnel-domains $S/lists/bypass-ip $S/lists/adblock
printf 's1\turl\t1\tcidr\t22\t0\topencck\t%s/cidr.txt\ns2\ttext\t1\tcidr\t1\t0\tmy own\t\ns3\turl\t0\tcidr\t0\t0\toff\thttp://off.example/x\n' "$L" > $S/lists/tunnel-cidr/sources.tsv
printf '100.64.200.0/24\n' > $S/lists/tunnel-cidr/blob/s2
printf 's1\turl\t1\tauto\t0\t0\tdoms\t%s/domains.txt\n' "$L" > $S/lists/tunnel-domains/sources.tsv
printf 's1\turl\t1\tcidr\t0\t0\tdirect\t%s/direct.txt\n' "$L" > $S/lists/bypass-ip/sources.tsv
printf 's1\turl\t1\tauto\t0\t0\tads\thttp://ads.example/x\n' > $S/lists/adblock/sources.tsv
# encrypted DNS (doh-lib.sh): resolver from the catalogue, "encrypt always"
echo quad9 > $S/.doh-resolver; echo on > $S/.doh-on
# port rules (port-lib.sh: src proto ports where)
printf 'any\tudp\t443\tvpn\nany\tboth\t6000-6100,7000\ts2\nany\ttcp\tall\tvpn\n192.168.1.201\ttcp\t22\tvpn\nany\tudp\t53\tblock\n' > $S/.port-rules
# geo categories (geo.sh registry: key action count ts slot)
mkdir -p $S/geo
printf 'rfgs-ru-blocked	vpn	73515	0	0
v2fly-youtube	vpn	177	0	2
rfip-telegram	direct	8	0	0
rfgs-x	block	1	0	0
weird-key	vpn	1	0	0
' > $S/geo/actions.tsv
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
echo "$OUT" | grep -q 'st_smyprov: My provider (the address is kept secret)' && ok "subscription in the plan, address hidden" || bad "subs: $(echo "$OUT" | grep -A2 subscriptions)"
echo "$OUT" | grep -q 'dry run' && [ -z "$(uci -q get detour.st_main)" ] && ok "dry run changed nothing" || bad "dry run wrote config"
echo "$OUT" | grep -q 'st_l_tunnel_cidr -> vpn: .*cidr.txt + local entries (from lists/tunnel-cidr)' && ok "list registry: URL + text source" || bad "cidr list: $(echo "$OUT" | grep l_tunnel)"
echo "$OUT" | grep -q 'st_l_tunnel_domains -> vpn' && echo "$OUT" | grep -q 'st_l_bypass_ip -> direct' && ok "domain and bypass lists" || bad "other lists"
echo "$OUT" | grep -q 'source off: switched off' && ok "disabled source reported" || bad "disabled source"
echo "$OUT" | grep -q 'lists/adblock: blocking' && ok "adblock reported as not carried over" || bad "adblock"
echo "$OUT" | grep -q '"dns": "quad9 (https://dns.quad9.net/dns-query tls://dns.quad9.net), encrypt always"' && ok "encrypted DNS: resolver + encrypt always" || bad "dns: $(echo "$OUT" | grep '"dns"')"
echo "$OUT" | grep -q 'st_p_vpn via main: .*ports udp/443 tcp/1-65535' && ok "port rules -> main policy" || bad "vpn ports: $(echo "$OUT" | grep 'st_p_vpn via')"
echo "$OUT" | grep -q 'st_p_s2 via s2 -> main: .*ports 6000-6100 7000' && ok "port rules -> slot policy (both protocols)" || bad "s2 ports: $(echo "$OUT" | grep 'st_p_s2 via')"
echo "$OUT" | grep -q 'port rule 192.168.1.201 tcp/22 -> vpn: per-device' && echo "$OUT" | grep -q 'port rule any udp/53 -> block: .*port rules are not part' && ok "per-device and block port rules reported" || bad "port reports"
echo "$OUT" | grep -q 'st_g_rfgs_ru_blocked -> vpn: https://cdn.jsdelivr.net/gh/runetfreedom/russia-blocked-geosite@release/ru-blocked.txt' && ok "geo: runetfreedom geosite -> main policy" || bad "geo rfgs: $(echo "$OUT" | grep g_rfgs)"
echo "$OUT" | grep -q 'st_g_v2fly_youtube -> s2: v2fly:youtube' && ok "geo: v2fly category on slot 2 -> its policy" || bad "geo v2fly: $(echo "$OUT" | grep g_v2fly)"
echo "$OUT" | grep -q 'st_g_rfip_telegram -> direct: .*russia-blocked-geoip@release/text/telegram.txt' && ok "geo: geoip CIDR -> direct" || bad "geo rfip: $(echo "$OUT" | grep g_rfip)"
echo "$OUT" | grep -q 'geo category rfgs-x: action' && echo "$OUT" | grep -q 'geo category weird-key: unknown source' && ok "geo: unsupported action / unknown key reported" || bad "geo reports"
# xray main exit whose connection rides slot 2 (sockif.sh, .xray-sockif)
S3=/tmp/stock-state3; rm -rf $S3; mkdir -p $S3/configs $S3/xray-configs; cp $S/configs/home.conf $S3/configs/; cp $S/xray-configs/lab.json $S3/xray-configs/
echo xray > $S3/.transport; echo lab > $S3/.xray-active
printf '2	%s	awg	home	main	on
' "$(ucode -e 'print(b64enc("home"))')" > $S3/.slots; printf 'lab	s2
' > $S3/.xray-sockif
detour import $S3 | grep -q 'st_main: xray from xray-configs/lab.json (connects through st_s2)' && ok "xray exit through another exit (.xray-sockif)" || bad "sockif: $(detour import $S3 | grep st_main)"
# a list registry whose sources are all off: the stock default (opencck) must not come back
mkdir -p $S3/lists/tunnel-cidr; printf 's1	url	0	cidr	0	0	opencck	http://x.example/y
' > $S3/lists/tunnel-cidr/sources.tsv
detour import $S3 | grep -q 'l_tunnel_cidr' && bad "default list added although stock switched it off" || ok "all-off registry: no default list"
# legacy config without a registry: iplist.conf sites -> opencck URL with &site=
S2=/tmp/stock-state2; rm -rf $S2; mkdir -p $S2/configs; cp $S/configs/home.conf $S2/configs/; echo awg > $S2/.transport; echo home > $S2/.active
printf 'IPLIST_SITES="steampowered.com discord.com"\nIPLIST_CUSTOM_MODE=merge\n' > $S2/iplist.conf; printf '100.64.201.0/24\n' > $S2/iplist.custom
detour import $S2 | grep -q 'data=cidr4&site=steampowered.com&site=discord.com + local entries (from iplist.conf)' && ok "legacy iplist.conf (sites + merged custom list)" || bad "legacy: $(detour import $S2 | grep l_tunnel)"

echo "== apply"
detour import /tmp/stock.tgz --apply > /tmp/import.out
grep -q 'exit st_main' /tmp/import.out && ok "applied" || bad "apply: $(cat /tmp/import.out)"
[ "$(uci -q get detour.main.dns)" = encrypted ] && [ "$(uci -q get detour.main.dns_fallback)" = 'https://dns.quad9.net/dns-query tls://dns.quad9.net' ] && [ "$(uci -q get detour.main.dns_bootstrap)" = 9.9.9.9:53 ] && ok "router DNS: encrypted, quad9" || bad "dns: $(uci -q show detour.main | grep dns)"
[ "$(uci -q get detour.st_p_vpn.port)" = 'udp/443 tcp/1-65535' ] && ok "policy ports written" || bad "ports: $(uci -q get detour.st_p_vpn.port)"
[ -z "$(uci -q get detour.st_main.warp)" ] && ok "a plain WireGuard exit is not marked WARP" || bad "st_main marked warp"
[ "$(uci -q get detour.st_g_rfip_telegram.min_lines)" = 4 ] && [ "$(uci -q get detour.st_g_rfgs_ru_blocked.min_lines)" = 10 ] && ok "geo lists: failure threshold from the stock size (8 -> 4, 73515 -> 10)" || bad "min_lines: $(uci -q get detour.st_g_rfip_telegram.min_lines) $(uci -q get detour.st_g_rfgs_ru_blocked.min_lines)"
[ "$(uci -q get detour.st_smyprov.user_agent)" = Happ/2.0 ] && [ "$(uci -q get detour.st_smyprov.hwid)" = abc-123 ] && ok "subscription with its client UA and hwid" || bad "sub fields"
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

echo "== a WARP config is marked WARP (the daemon then watches its Cloudflare point)"
S4=/tmp/stock-state4; rm -rf $S4; mkdir -p $S4/configs; echo awg > $S4/.transport; echo cf > $S4/.active
printf '[Interface]\nPrivateKey = %s\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nEndpoint = 162.159.192.1:2408\nAllowedIPs = 0.0.0.0/0\n' "$(wg genkey)" > $S4/configs/cf.conf
detour import $S4 --apply prefix=w4_ >/dev/null
[ "$(uci -q get detour.w4_main.warp)" = 1 ] && ok "WARP exit marked (warp=1)" || bad "w4_main warp='$(uci -q get detour.w4_main.warp)'"
R=$(detour warp-unregister w4_main); echo "$R" | grep -q '"name": "w4_main"' && [ -z "$(uci -q get detour.w4_main)" ] && ok "a WARP exit without a registration file can be removed" || bad "unregister: $R"
for s in $(uci show detour | sed -n "s/^detour\.\(w4_[a-z0-9_]*\)=.*/\1/p"); do uci -q delete detour.$s; done; for z in vpn detour; do uci -q del_list firewall.$z.network=w4_main; done; uci commit; ubus call detour reload >/dev/null
echo "== archive with an unsafe path is refused"
wget -qO /tmp/evil.tgz http://10.0.2.2:8765/tests/stub/evil.tgz
detour import /tmp/evil.tgz >/dev/null 2>&1 && bad "unsafe archive accepted" || ok "unsafe archive refused"

[ "$1" = keep ] || { cleanup; /etc/init.d/network reload; reload_config; }
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
