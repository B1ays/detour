#!/bin/sh
# share links -> sing-box outbound: field checks for each scheme, then an ss:// link for the lab
# server drives a real sing-box exit end to end.
b64() { ucode -e 'print(b64enc(ARGV[0]))' "$1"; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
chk() { # $1 link, $2 jsonfilter expr, $3 expected
	v=$(detour link "$1" 2>&1 | jsonfilter -e "$2" 2>/dev/null)
	[ "$v" = "$3" ] && ok "$(echo "$1" | cut -c1-12)… $2 = $3" || bad "$(echo "$1" | cut -c1-40) $2: got '$v' want '$3'"
}
V='vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=reality&pbk=4IwI0ZTNP4TO_ulu7vuHcwPPLCyfkGOdRcj1RsqigH0&sid=ab12&sni=www.apple.com&fp=chrome&flow=xtls-rprx-vision#My%20server'
chk "$V" '@.type' vless
chk "$V" '@.uuid' 11111111-2222-3333-4444-555555555555
chk "$V" '@.flow' xtls-rprx-vision
chk "$V" '@.tls.server_name' www.apple.com
chk "$V" '@.tls.reality.public_key' 4IwI0ZTNP4TO_ulu7vuHcwPPLCyfkGOdRcj1RsqigH0
chk "$V" '@.tls.reality.short_id' ab12
chk "$V" '@.tls.utls.fingerprint' chrome
W='vless://uuid-x@[2001:db8::1]:8443?type=ws&security=tls&path=%2Fws&host=cdn.example.org'
chk "$W" '@.server' 2001:db8::1
chk "$W" '@.transport.type' ws
chk "$W" '@.transport.path' /ws
chk "$W" '@.transport.headers.Host' cdn.example.org
chk "$W" '@.tls.server_name' 2001:db8::1
G='vless://u@h.example:443?type=grpc&serviceName=svc&security=tls&sni=s.example'
chk "$G" '@.transport.service_name' svc
T='trojan://p%40ss@t.example:443#t'
chk "$T" '@.password' p@ss
chk "$T" '@.tls.server_name' t.example
VM=$(b64 '{"v":"2","ps":"vm","add":"vm.example","port":"443","id":"uuid-vm","aid":"0","net":"ws","host":"h.example","path":"/p","tls":"tls"}')
chk "vmess://$VM" '@.server_port' 443
chk "vmess://$VM" '@.transport.headers.Host' h.example
chk "vmess://$VM" '@.tls.server_name' h.example
S1="ss://$(b64 'aes-128-gcm:secret')@ss.example:8388#s"
chk "$S1" '@.method' aes-128-gcm
chk "$S1" '@.password' secret
S2="ss://$(b64 'chacha20-ietf-poly1305:pw@legacy.example:8389')"
chk "$S2" '@.server' legacy.example
chk "$S2" '@.server_port' 8389
H='hysteria2://pa@ss@hy.example:443?sni=sni.example&obfs=salamander&obfs-password=ob&insecure=1#h'
chk "$H" '@.password' pa@ss
chk "$H" '@.obfs.password' ob
chk "$H" '@.tls.insecure' true
detour link 'http://x' >/dev/null 2>&1 && bad "http:// accepted" || ok "unsupported scheme rejected"
detour link 'vless://nouser' >/dev/null 2>&1 && bad "broken link accepted" || ok "broken link rejected"

echo "== every converted outbound passes 'sing-box check' ($(sing-box version 2>/dev/null | head -n1))"
for L in "$V" "$W" "$G" "$T" "vmess://$VM" "$S1" "$S2" "$H"; do
	o=$(detour link "$L")
	printf '{"log":{"level":"error"},"outbounds":[%s]}' "$o" > /tmp/lnk.json
	if sing-box check -c /tmp/lnk.json >/tmp/lnk.err 2>&1; then ok "check $(echo "$L" | cut -c1-10)"; else bad "check $(echo "$L" | cut -c1-30): $(head -c 200 /tmp/lnk.err)"; fi
done

echo "== ss:// link for the lab server -> sing-box exit"
PW=$(cat /etc/enodia-lab/ss.pw)
L="ss://$(b64 "2022-blake3-aes-128-gcm:$PW")@10.199.1.2:8443#lab"
detour link "$L" /etc/detour/engines/sb.json && ok "outbound written" || bad "write"
ls -l /etc/detour/engines/sb.json | grep -q '^-rw-------' && ok "outbound file mode 600" || bad "mode"
reload_config; sleep 12
i=0; while [ $i -lt 30 ]; do [ "$(ubus call detour status | jsonfilter -e '@.exits[@.name="sbx"].healthy')" = true ] && break; sleep 1; i=$((i+1)); done
[ $i -lt 30 ] && ok "sing-box exit from the link is healthy" || bad "sbx not healthy"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
