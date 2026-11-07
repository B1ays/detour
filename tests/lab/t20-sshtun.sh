#!/bin/sh
# The panel through your own VPS (sshtun): the "VPS" is a dropbear in netns ex1 (10.199.1.2:2222). 10.199.1.2 is
# also in policy "vpn" - the tunnel (user dtssh) must still go directly. Checks: key, TOFU check, the port on
# the VPS leads to LuCI, strict host key afterwards (a changed key -> no tunnel), forget, off.
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
st() { detour sshtun status | jsonfilter -e "@.$1"; }
VK=/tmp/vps_hostkey
vps() {   # (re)start the VPS sshd with host key $VK
	for p in $(ip netns pids ex1); do grep -q dropbear /proc/$p/cmdline 2>/dev/null && kill $p; done
	sleep 1
	ip netns exec ex1 dropbear -p 2222 -r $VK -P /tmp/vps.pid
	sleep 1
}
cleanup() {
	uci -q delete detour.sshtun; uci commit detour; /etc/init.d/detour start
	for p in $(ip netns pids ex1); do grep -q dropbear /proc/$p/cmdline 2>/dev/null && kill $p; done
	# only the tunnel key's own line (by its key body): the lab's own key must stay
	kb=$(dropbearkey -y -f /etc/detour/sshtun/id_ed25519 2>/dev/null | awk '/^ssh-/{print $2}')
	[ -n "$kb" ] && grep -vF "$kb" /etc/dropbear/authorized_keys > /tmp/ak.$$ && cat /tmp/ak.$$ > /etc/dropbear/authorized_keys; rm -f /tmp/ak.$$
	rm -f /etc/detour/sshtun/home/.ssh/known_hosts $VK
}
ip netns list | grep -q '^ex1 ' || lab tests/lab/l2-exit.sh 1 >/dev/null 2>&1
cleanup
rm -f $VK; dropbearkey -t ed25519 -f $VK >/dev/null 2>&1; vps
grep -q '^dtssh:' /etc/passwd && ok "user dtssh" || bad "no user dtssh"

echo "== key and the first check (trust on first use)"
uci -q batch <<'U'
set detour.sshtun=sshtun
set detour.sshtun.enabled=1
set detour.sshtun.host=10.199.1.2
set detour.sshtun.port=2222
set detour.sshtun.user=root
set detour.sshtun.rport=18443
commit detour
U
PK=$(detour sshtun keygen | jsonfilter -e @.pubkey)
echo "$PK" | grep -q '^ssh-ed25519 ' && ok "router key ed25519" || bad "key: $PK"
ls -l /etc/detour/sshtun/id_ed25519 | grep -q '^-rw------- .* dtssh ' && ok "key file dtssh, 600" || bad "key file: $(ls -l /etc/detour/sshtun/id_ed25519)"
echo "$PK" >> /etc/dropbear/authorized_keys
/etc/init.d/detour start; sleep 2
[ "$(st running)" = false ] && ok "no tunnel before the server key is known" || bad "running before the check"
R=$(detour sshtun test)
[ "$(echo "$R" | jsonfilter -e @.ok)" = true ] && ok "check passed" || bad "check: $R"
FP=$(dropbearkey -y -f $VK | sed -n 's/.*SHA256:/SHA256:/p' | head -1)
echo "$R" | grep -q "$FP" && ok "server key fingerprint shown ($FP)" || bad "fp: $R vs $FP"

echo "== the tunnel: VPS 127.0.0.1:18443 -> LuCI at home, directly (not through the policy's exit)"
waitfor true "st connected" 30 && ok "connected" || bad "not connected: $(st last)"
sch=http; st target | grep -q ':443$' && sch=https
c=$(ip netns exec ex1 curl -sk -m 8 -o /dev/null -w '%{http_code}' $sch://127.0.0.1:18443/cgi-bin/luci/)
[ "$c" != 000 ] && ok "LuCI through the VPS port ($sch $c, target $(st target))" || bad "nothing on the VPS port ($sch)"
m=$(conntrack -L -p tcp -d 10.199.1.2 --dport 2222 2>/dev/null | sed -n 's/.*mark=\([0-9]*\).*/\1/p' | head -1)
[ "$m" = 0 ] && ok "SSH to the VPS unclassified (mark 0) although 10.199.1.2 is in policy vpn" || bad "mark '$m'"
ps w | grep '[d]bclient' | grep -q dtssh && ok "client runs as dtssh" || bad "client user: $(ps w | grep '[d]bclient')"

echo "== the server key changes -> strict: no tunnel"
rm -f $VK; dropbearkey -t ed25519 -f $VK >/dev/null 2>&1; vps
waitfor false "st connected" 30 && ok "tunnel gone after the key change" || bad "still connected"
sleep 15
[ "$(st connected)" = false ] && ok "not reconnected with a changed key" || bad "reconnected with a changed key"
detour sshtun forget >/dev/null
[ ! -e /etc/detour/sshtun/home/.ssh/known_hosts ] && ok "forgotten" || bad "known_hosts left: $(ls -l --full-time /etc/detour/sshtun/home/.ssh/known_hosts) now $(date +%T); $(ps w | grep [d]bclient)"
R=$(detour sshtun test); [ "$(echo "$R" | jsonfilter -e @.ok)" = true ] && ok "new key accepted by a new check" || bad "re-check: $R"
waitfor true "st connected" 40 && ok "connected again" || bad "not connected again"

echo "== off"
uci set detour.sshtun.enabled=0; uci commit detour; /etc/init.d/detour start
waitfor false "st running" 15 && ok "tunnel stopped" || bad "still running"
cleanup
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
