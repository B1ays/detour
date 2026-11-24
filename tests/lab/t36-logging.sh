#!/bin/sh
# The log: two levels (normal: the system log; verbose: every check, command and call in /tmp/detour/log, at most
# 24 h) and the archive of everything for a diagnosis (.tar.gz, LuCI Settings). The real secrets of the lab are put
# through the log on purpose - a WireGuard key, the Shadowsocks password inside a link, an Xray UUID, a Telegram
# token, a backup password - and none of them may be found in the log or in the archive.
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
D=/etc/enodia-lab
V=/tmp/detour/log/detour.log
F=/tmp/detour/log/on
X=/tmp/t36x
lvl() { ubus call detour log_level | jsonfilter -e '@.level'; }
TG=123456:LABTOKEN_not_a_real_token_t36xxxxxxxxxxxx
cleanup() {
	ubus call detour log_level '{"level":"normal"}' >/dev/null
	uci -q get detour.lg1 >/dev/null && /usr/sbin/detour exit-remove lg1 >/dev/null 2>&1   # its engine, interface, zone, file
	uci -q delete detour.notify; uci -q delete detour.socks; uci -q delete detour.lg1; uci -q delete detour.lg1_eng; uci -q delete network.lg1; uci commit
	rm -f /etc/detour/engines/lg1.json
	rm -rf $X /tmp/detour-logs.tar.gz /tmp/detour-backup.bin
	ubus call detour reload >/dev/null
}
cleanup
lab tests/lab/restart-sb.sh >/dev/null

# the secrets of this lab, as they are
SS=$(cat $D/ss.pw)
WGK=$(uci -q get network.wgx1.private_key)
UUID=6f1c2a9e-36ab-4c1d-9e2f-0123456789ab   # put through a VLESS link below
RPK=Zx3PqT7vB9wK2mN5cR8yL1hD4fG6jS0aE3uI7oV9t2Q   # its Reality key
BPW='lab-backup pw-horse-t36'   # with a space: a quoted value is masked whole, not up to the space
SPW='t36-socks-pw_7d1e'   # the SOCKS proxy's password (its section stays off)
[ -n "$SS" ] && [ -n "$WGK" ] && ok "secrets to look for: ss password, WG key, a VLESS UUID and Reality key, TG token, backup password" || bad "secrets: ss '${SS:+set}' wg '${WGK:+set}'"

echo "== normal: nothing in the verbose log"
rm -f $V
[ "$(lvl)" = normal ] && [ ! -e $F ] && ok "normal level, no flag" || bad "level $(lvl), flag $(ls $F 2>&1)"
sleep 8
[ ! -s $V ] && ok "nothing written at the normal level" || bad "written at normal: $(head -c 300 $V)"

echo "== verbose"
R=$(ubus call detour log_level '{"level":"verbose"}')
U=$(echo "$R" | jsonfilter -e '@.until'); NOW=$(date +%s)
[ "$(echo "$R" | jsonfilter -e '@.level')" = verbose ] && [ -e $F ] && ok "verbose, flag kept" || bad "verbose: $R"
[ $((U - NOW)) -gt 86000 ] && [ $((U - NOW)) -le 86400 ] && ok "ends by itself in 24 h" || bad "until $U, now $NOW"
[ "$(uci -q get detour.main.log_until)" = "$U" ] && ok "the end in UCI" || bad "uci log_until $(uci -q get detour.main.log_until)"

# the secrets go through: a link with the password, a Telegram token, a backup password, the probes and commands
uci -q batch <<U
set detour.notify=notify
set detour.notify.enabled=1
set detour.notify.tg_token=$TG
set detour.notify.tg_chat=4242
set detour.notify.tg_api=http://10.0.2.2:8766
set detour.socks=socks
set detour.socks.enabled=0
set detour.socks.username=t36user
set detour.socks.password=$SPW
commit detour
U
ubus call detour reload >/dev/null
L="ss://$(ucode -e 'print(b64enc(ARGV[0]))' "2022-blake3-aes-128-gcm:$SS")@10.199.1.2:8443#t36"
LP="ss://2022-blake3-aes-128-gcm:$SS@10.199.1.2:8443#t36plain"
r=$(ubus -t 90 call detour engine_add "{\"name\":\"lg1\",\"link\":\"$L\"}")
echo "$r" | grep -q exit_id && ok "an exit added from a link" || bad "engine_add: $r"
ubus -t 30 call detour exit_parse "{\"text\":\"$LP\"}" >/dev/null 2>&1
VL="vless://$UUID@203.0.113.36:443?security=reality&pbk=$RPK&sid=0123abcd&sni=example.org&type=tcp#t36vless"
ubus -t 30 call detour exit_parse "{\"text\":\"$VL\"}" >/dev/null 2>&1
ubus call detour notify_test >/dev/null
r=$(ubus -t 120 call detour backup_create "{\"password\":\"$BPW\"}"); echo "$r" | grep -q manifest && ok "a backup with a password" || bad "backup: $r"
sleep 15
grep -q '\[probe\] .* ok (' $V && ok "probes: $(grep -c '\[probe\]' $V)" || bad "no probes in the log"
grep -q '\[run\] .* -> [0-9]* ([0-9]* ms)' $V && ok "commands with code and time: $(grep -c '\[run\]' $V)" || bad "no commands"
grep -q '\[ubus\] engine_add .*\*\*\*' $V && ok "the call engine_add, its link masked" || bad "engine_add call: $(grep '\[ubus\] engine_add' $V | head -c 300)"
grep -q '\[ubus\] backup_create .*\*\*\*' $V && ok "the call backup_create, its password masked" || bad "backup call: $(grep '\[ubus\] backup_create' $V | head -c 300)"
grep -q '\[notify\] via ' $V && ok "notification attempts" || bad "no notify lines"
grep -q '\[event\] verbose log on' $V && ok "the switch is the first event" || bad "no switch event"
grep -q '\[ubus\] status ' $V && bad "status polls are written (noise)" || ok "status polls left out"

echo "== the archive"
r=$(ubus -t 180 call detour logs_archive)
P=$(echo "$r" | jsonfilter -e '@.path'); N=$(echo "$r" | jsonfilter -e '@.name')
[ "$P" = /tmp/detour-logs.tar.gz ] && ls -l $P | grep -q '^-rw-------' && ok "$N, $(echo "$r" | jsonfilter -e '@.size') bytes, mode 600" || bad "archive: $r"
mkdir -p $X && tar -xzf $P -C $X && ok "tar.gz reads back" || bad "tar"
A=$X/${N%.tar.gz}
for f in README.txt syslog.txt dmesg.txt status.json exits.json components.json config/detour.txt config/network.txt config/firewall.txt \
	net/nft-detour.txt net/ip.txt net/conntrack.txt system.txt detour/detour.log; do
	[ -s "$A/$f" ] || miss="$miss $f"
done
[ -z "$miss" ] && ok "all the parts are there" || bad "missing:$miss"
grep -q 'wgx1' $A/config/network.txt && grep -q "private_key '\*\*\*'" $A/config/network.txt && ok "network config, keys masked" || bad "network.txt"
grep -q 'flows by mark' $A/net/conntrack.txt && ! grep -q 'dst=' $A/net/conntrack.txt && ok "conntrack: counts, no flows" || bad "conntrack.txt"
ls $A/config | grep -q '^engine-' && ! ls $A/config | grep -qE 'engine-t(add|mp|blk)' && ok "only the engines that exist" || bad "engines: $(ls $A/config | tr '\n' ' ')"

echo "== no secret anywhere"
# "what:value" - only "what" is ever printed
for p in "Shadowsocks password:$SS" "WireGuard key:$WGK" "VLESS UUID:$UUID" "Reality key:$RPK" "Telegram token:$TG" \
	"backup password:$BPW" "backup password after its space:pw-horse-t36" "SOCKS password:$SPW" "token text:LABTOKEN" "2FA key:JBSWY3DPEHPK3PXP"; do
	w=${p%%:*}; s=${p#*:}
	[ -z "$s" ] && continue
	h=$(grep -rlF -- "$s" $V $A 2>/dev/null | sed "s#$X/##" | tr '\n' ' ')
	[ -z "$h" ] && ok "not found: $w" || bad "$w found in: $h"
done

echo "== back to normal, and the end by time"
sz=$(wc -c < $V)
ubus call detour log_level '{"level":"normal"}' >/dev/null
[ ! -e $F ] && [ -z "$(uci -q get detour.main.log_level)" ] && ok "normal: flag and option gone" || bad "normal: $(uci -q get detour.main.log_level)"
tail -n3 $V | grep -q 'verbose log off' && ok "the log ends saying so" || bad "last lines: $(tail -n3 $V)"
sleep 2; sz=$(wc -c < $V); sleep 10
[ "$(wc -c < $V)" = "$sz" ] && ok "nothing more written" || bad "written after normal: $(tail -n2 $V)"
ubus call detour log_level '{"level":"verbose"}' >/dev/null
uci set detour.main.log_until=$(( $(date +%s) - 1 )); uci commit detour
waitfor normal lvl 40 && [ ! -e $F ] && ok "past its end: back to normal by itself" || bad "still $(lvl)"
logread | tail -n 20 | grep -q 'verbose log: 24 h passed' && ok "said in the system log" || bad "no event: $(logread | grep 'verbose log' | tail -n1)"

cleanup
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
