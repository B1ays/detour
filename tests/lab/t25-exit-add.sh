#!/bin/sh
# Stage 2 of the panel work: an exit from any link / key / file (share links one or many, base64 lists,
# wireguard://, a WireGuard / AmneziaWG .conf, an Amnezia vpn:// key, sing-box and Xray JSON, a Clash YAML), what
# was found told without secrets, the chosen ones added; export as a link / .conf with a QR code and back; a speed
# test; why an exit does not work (server reachable, down, blocked by the provider, UDP); connecting a proxy exit
# through another one, with no circles. Needs ucode-mod-zlib and qrencode (installed here if missing).
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
b64() { ucode -e 'print(b64enc(ARGV[0]))' "$1"; }
PW=$(cat /etc/enodia-lab/ss.pw)
T=/tmp/t25; rm -rf $T; mkdir -p $T
apk info -e ucode-mod-zlib >/dev/null || apk add -q ucode-mod-zlib
apk info -e qrencode >/dev/null || apk add -q qrencode
lab tests/lab/restart-sb.sh >/dev/null
cleanup() {
	for n in tadd tadd1 tadd2 tadd3 twg tok tdown tblk; do [ "$(uci -q get detour.$n)" = exit ] && detour exit-remove $n >/dev/null 2>&1; done
	nft delete table inet t25 2>/dev/null
	uci -q delete detour.main.speed_url; uci commit detour
}
cleanup
parse() { printf '%s' "$1" > $T/in; detour exit-parse $T/in; }
cnt() { parse "$1" | jsonfilter -e '@.candidates[*]' | wc -l; }
SS="ss://$(b64 "2022-blake3-aes-128-gcm:$PW")@10.199.1.2:8443#lab-ss"
VL='vless://11111111-2222-3333-4444-555555555555@vl.example.org:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdEFg&sid=ab12&type=tcp&flow=xtls-rprx-vision#VL%20test'
TU='tuic://11111111-2222-3333-4444-555555555555:secret@tu.example.org:443?sni=tu.example.org&congestion_control=bbr#TUIC'
K1=$(wg genkey); P1=$(echo "$K1" | wg pubkey); K2=$(wg genkey); P2=$(echo "$K2" | wg pubkey)

echo "== what is inside: links, base64, wireguard://, configs, JSON, YAML, vpn://"
[ "$(parse "$SS" | jsonfilter -e '@.candidates[0].proto')" = Shadowsocks ] && ok "ss link: Shadowsocks" || bad "ss: $(parse "$SS")"
R=$(parse "$VL"); [ "$(echo "$R" | jsonfilter -e '@.candidates[0].proto')" = 'VLESS · Reality · TCP · Vision' ] && [ "$(echo "$R" | jsonfilter -e '@.candidates[0].label')" = 'VL test' ] \
	&& ok "vless link: VLESS · Reality · TCP · Vision, its name" || bad "vless: $R"
[ "$(parse "$TU" | jsonfilter -e '@.candidates[0].proto')" = TUIC ] && ok "tuic link (new)" || bad "tuic: $(parse "$TU")"
[ "$(cnt "$(printf '%s\n%s\n%s\nnot-a-link\n' "$SS" "$VL" "$TU")")" = 4 ] && ok "three links + a bad line: 4 entries (one with its error)" || bad "multi: $(parse "$(printf '%s\n%s\nx\n' "$SS" "$VL")")"
[ "$(cnt "$(b64 "$(printf '%s\n%s\n' "$SS" "$VL")")")" = 2 ] && ok "a base64 list (as a subscription answers)" || bad "base64 list"
R=$(parse "wireguard://$(echo "$K1" | sed 's/+/%2B/g;s#/#%2F#g;s/=/%3D/g')@203.0.113.5:51820?publickey=$(echo "$P2" | sed 's/+/%2B/g;s#/#%2F#g;s/=/%3D/g')&address=10.7.0.2/32&mtu=1280#wglink")
[ "$(echo "$R" | jsonfilter -e '@.candidates[0].kind')" = wg ] && [ "$(echo "$R" | jsonfilter -e '@.candidates[0].server')" = 203.0.113.5 ] && ok "wireguard:// link" || bad "wg link: $R"
CONF=$(printf '[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\nMTU = 1280\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.6:51820\n' "$K1" "$P2")
[ "$(parse "$CONF" | jsonfilter -e '@.candidates[0].kind')" = wg ] && ok "WireGuard .conf" || bad "conf: $(parse "$CONF")"
AWG=$(printf '[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n\n[Peer]\nPublicKey = %s\nEndpoint = 203.0.113.7:51820\n' "$K1" "$P2")
[ "$(parse "$AWG" | jsonfilter -e '@.candidates[0].proto')" = 'AmneziaWG · masking' ] && ok "AmneziaWG .conf: masking recognised" || bad "awg: $(parse "$AWG")"
VPN=$(ucode -e '
	import * as z from "zlib";
	const s = sprintf("%J", { description: "Amnezia lab", containers: [ { container: "amnezia-awg", awg: { last_config: sprintf("%J", { config: ARGV[0] }) } } ] });
	const n = length(s);
	const raw = chr((n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255) + z.deflate(s);
	print("vpn://" + replace(replace(replace(b64enc(raw), "+", "-"), "/", "_"), /=+$/, ""));' "$AWG")
R=$(parse "$VPN"); [ "$(echo "$R" | jsonfilter -e '@.candidates[0].kind')" = awg ] && [ "$(echo "$R" | jsonfilter -e '@.candidates[0].label')" = 'Amnezia lab' ] \
	&& ok "Amnezia vpn:// key (zlib): AmneziaWG, its name" || bad "vpn://: $R"
SB=$(printf '{"outbounds":[{"type":"shadowsocks","tag":"one","server":"10.199.1.2","server_port":8443,"method":"2022-blake3-aes-128-gcm","password":"%s"},{"type":"direct","tag":"direct"},{"type":"vless","tag":"two","server":"x.example.org","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555"}]}' "$PW")
[ "$(cnt "$SB")" = 2 ] && ok "sing-box config: 2 proxies, direct left out" || bad "sing-box json: $(parse "$SB")"
XR='{"outbounds":[{"protocol":"vless","tag":"x1","settings":{"vnext":[{"address":"xr.example.org","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality"}},{"protocol":"freedom","tag":"direct"}]}'
R=$(parse "$XR"); [ "$(echo "$R" | jsonfilter -e '@.candidates[0].kind')" = xray ] && [ "$(echo "$R" | jsonfilter -e '@.candidates[0].proto')" = 'VLESS · Reality · TCP · Vision' ] && ok "Xray config: an Xray exit" || bad "xray: $R"
cat > $T/clash.yaml <<Y
port: 7890
mode: rule
proxies:
  - name: "SS one"
    type: ss
    server: 10.199.1.2
    port: 8443
    cipher: 2022-blake3-aes-128-gcm
    password: "$PW"
  - {name: vmess-ws, type: vmess, server: vm.example.org, port: 443, uuid: 11111111-2222-3333-4444-555555555555, alterId: 0, cipher: auto, tls: true, servername: vm.example.org, network: ws, ws-opts: {path: /ray, headers: {Host: vm.example.org}}}
  - name: tro
    type: trojan
    server: tr.example.org
    port: 443
    password: pass
    network: grpc
    grpc-opts:
      grpc-service-name: svc
  - name: wg-clash
    type: wireguard
    server: 203.0.113.8
    port: 51820
    ip: 10.9.0.2
    private-key: $K1
    public-key: $P2
    amnezia-wg-option:
      jc: 3
      jmin: 30
      jmax: 60
  - name: snell-one
    type: snell
    server: s.example.org
    port: 1
proxy-groups:
  - name: auto
    type: url-test
Y
R=$(detour exit-parse $T/clash.yaml)
[ "$(echo "$R" | jsonfilter -e '@.candidates[*]' | wc -l)" = 5 ] && [ "$(echo "$R" | jsonfilter -e '@.candidates[1].proto')" = 'VMess · TLS · WebSocket' ] \
	&& [ "$(echo "$R" | jsonfilter -e '@.candidates[2].proto')" = 'Trojan · TLS · gRPC' ] && [ "$(echo "$R" | jsonfilter -e '@.candidates[3].kind')" = awg ] \
	&& [ -n "$(echo "$R" | jsonfilter -e '@.candidates[4].error')" ] && ok "Clash YAML: ss, vmess+ws (flow map), trojan+grpc, AmneziaWG, unsupported snell told" || bad "clash: $R"
ALL=$(parse "$SS"; parse "$CONF"; parse "$VPN"; detour exit-parse $T/clash.yaml)
echo "$ALL" | grep -qE "$PW|$K1|11111111-2222|secret" && bad "a secret in what parse tells" || ok "no keys, passwords or UUIDs in what is told"

echo "== adding: a Shadowsocks exit that works, a WireGuard exit (netifd), several at once"
printf '%s' "$SS" > $T/in
R=$(detour exit-add $T/in - tadd); echo "$R" | grep -q '"name": "tadd"' && ok "added from a link" || bad "add: $R"
[ "$(uci -q get detour.tadd_eng.type)" = singbox ] && [ "$(uci -q get network.tadd.proto)" = none ] && ok "engine + interface + exit" || bad "uci"
# no reload_config here: adding must start the engine by itself
waitfor true "ubus call detour status | jsonfilter -e '@.exits[@.name=\"tadd\"].healthy'" 60 && ok "the new exit works" || bad "tadd not healthy"
printf '%s' "$CONF" > $T/in
R=$(detour exit-add $T/in - twg); [ "$(uci -q get network.twg.proto)" = wireguard ] && [ "$(uci -q get network.twg.fwmark)" = 0x10000000 ] \
	&& [ "$(uci show network | grep -c "=wireguard_twg")" = 1 ] && [ -n "$(uci -q get detour.twg.id)" ] && ok "WireGuard exit: interface, peer, underlay mark, exit" || bad "wg add: $R"
uci show firewall | grep -q "network=.*'twg'" && ok "in the tunnels' firewall zone" || bad "zone"
printf '%s\n%s\n' "$VL" "$TU" > $T/in
R=$(detour exit-add $T/in 0,1 tadd); [ "$(uci -q get detour.tadd1)" = exit ] && [ "$(uci -q get detour.tadd2)" = exit ] && [ "$(uci -q get detour.tadd1.label)" = 'VL test' ] \
	&& ok "two at once: tadd1, tadd2, names from the links" || bad "multi add: $R"
printf '%s' "$SS" > $T/in; R=$(detour exit-add $T/in - tadd); echo "$R" | grep -q 'already used' && ok "a used name is refused" || bad "dup: $R"
ls /tmp/detour/in-* 2>/dev/null | grep -q . && bad "an input file left behind" || ok "no input files left"

echo "== through ubus (LuCI): the text goes to the CLI in a file, not on the command line"
R=$(ubus call detour exit_parse "$(printf '{"text":"%s"}' "$SS")"); [ "$(echo "$R" | jsonfilter -e '@.candidates[0].server')" = 10.199.1.2 ] && ok "exit_parse" || bad "exit_parse: $R"
ubus call detour exit_config_get '{"name":"tadd"}' | jsonfilter -e '@.config' > $T/cfg.json
R=$(ubus -t 30 call detour exit_config_set "$(ucode -e 'print(sprintf("%J", { name: "tadd", config: ARGV[0] }))' "$(cat $T/cfg.json)")")
[ "$(echo "$R" | jsonfilter -e '@.code')" = 0 ] && ok "exit_config_set with the secret through a file" || bad "config_set: $R"
ls /tmp/detour/in-* 2>/dev/null | grep -q . && bad "an input file left behind by the daemon" || ok "the daemon's input file is gone"

echo "== export: a link / a .conf, a QR code, and back"
R=$(detour exit-export tadd); L=$(echo "$R" | jsonfilter -e '@.link')
printf '%s' "$L" > $T/in
[ "$(detour exit-parse $T/in | jsonfilter -e '@.candidates[0].server')" = 10.199.1.2 ] && [ "$(detour exit-parse $T/in | jsonfilter -e '@.candidates[0].port')" = 8443 ] \
	&& ok "exported ss link reads back" || bad "export ss: $R"
echo "$R" | jsonfilter -e '@.qr_svg' | grep -q '<svg' && ok "QR code (SVG)" || bad "no QR"
for x in tadd1 tadd2; do L=$(detour exit-export $x | jsonfilter -e '@.link'); printf '%s' "$L" > $T/in
	P=$(detour exit-parse $T/in | jsonfilter -e '@.candidates[0].proto'); [ "$P" = "$(detour exit-info | jsonfilter -e "@[@.name='$x'].proto")" ] && ok "$x: exported link reads back as $P" || bad "$x roundtrip: $L -> $P"; done
R=$(detour exit-export twg); echo "$R" | jsonfilter -e '@.text' > $T/back.conf
[ "$(detour exit-parse $T/back.conf | jsonfilter -e '@.candidates[0].server')" = 203.0.113.6 ] && grep -q "PrivateKey = $K1" $T/back.conf && ok "WireGuard export: a .conf that reads back" || bad "wg export: $R"
grep -q "$K1" /tmp/detour/qr-* 2>/dev/null && bad "QR input left" || ok "QR input file removed"

echo "== speed"
uci set detour.main.speed_url='https://speed.cloudflare.com/__down?bytes=3000000'; uci commit detour
R=$(ubus -t 30 call detour exit_speed '{"name":"sbx"}'); [ "$(echo "$R" | jsonfilter -e '@.ok')" = true ] && ok "through sbx: $(echo "$R" | jsonfilter -e '@.mbps') Mbit/s" || bad "speed sbx: $R"
R=$(ubus -t 30 call detour exit_speed '{"name":"sbx","direct":true}'); [ "$(echo "$R" | jsonfilter -e '@.ok')" = true ] && ok "directly: $(echo "$R" | jsonfilter -e '@.mbps') Mbit/s" || bad "speed direct: $R"

echo "== why an exit does not work"
mk() { printf 'vless://11111111-2222-3333-4444-555555555555@%s:443?security=tls&sni=x.example.org&type=tcp#%s' "$1" "$2" > $T/in; detour exit-add $T/in - "$2" >/dev/null; }
mk 1.1.1.1 tok; mk 192.0.2.1 tdown; mk 1.0.0.1 tblk
sleep 3
v() { ubus -t 30 call detour exit_diag "{\"name\":\"$1\"}" | jsonfilter -e '@.verdict'; }
[ "$(v tok)" = reachable ] && ok "server answers, the protocol fails: 'reachable'" || bad "tok: $(v tok)"
[ "$(v tdown)" = down ] && ok "nothing answers anywhere: 'down'" || bad "tdown: $(v tdown)"
# the provider "blocks" 1.0.0.1: only the direct check (user dtnotify) is dropped, a check through another exit passes
nft -f - <<N
table inet t25 {
	chain out { type filter hook output priority 0; meta skuid dtnotify ip daddr 1.0.0.1 drop; }
}
N
R=$(ubus -t 30 call detour exit_diag '{"name":"tblk"}'); [ "$(echo "$R" | jsonfilter -e '@.verdict')" = blocked ] && ok "silent directly, answers through $(echo "$R" | jsonfilter -e '@.other'): 'blocked'" || bad "tblk: $R"
[ "$(v warp)" = udp ] && ok "WireGuard: 'udp' (cannot tell)" || bad "warp: $(v warp)"
nft delete table inet t25

echo "== connect through another exit, no circles"
R=$(detour exit-set-via tblk sbx); [ "$(uci -q get detour.tblk_eng.via)" = sbx ] && ok "tblk now connects through sbx" || bad "set via: $R"
R=$(detour exit-set-via tadd tblk); R2=$(detour exit-set-via tblk tadd); echo "$R2" | grep -q circle && ok "a circle is refused" || bad "circle: $R2"
R=$(detour exit-set-via twg sbx); echo "$R" | grep -q 'WireGuard' && ok "a WireGuard exit cannot ride another" || bad "wg via: $R"
R=$(detour exit-set-via tblk -); [ -z "$(uci -q get detour.tblk_eng.via)" ] && ok "back to direct" || bad "unset via: $R"

cleanup
[ "$(uci -q get network.twg)" = "" ] && [ "$(uci show network | grep -c wireguard_twg)" = 0 ] && ok "cleanup removed the WireGuard interface and its peer" || bad "twg left"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
