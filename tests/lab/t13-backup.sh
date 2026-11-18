#!/bin/sh
# Backup and restore of Detour's settings (backup.uc, as LuCI calls it over ubus).
# Save -> change everything (an exit gone, a stray exit, a policy, an engine file, the zone) -> restore:
# Detour's settings must come back exactly, everything else of the router (LAN, WAN, other interfaces and
# zones, DHCP) must stay untouched; the exits must work again. Then what must be refused.
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
PW=lab-backup-pw
call() { ubus -t 180 call detour "$1" "{\"password\":\"${2:-$PW}\"}"; }
healthy() { ubus call detour status | jsonfilter -e '@.exits[@.healthy=true].name' | sort | tr '\n' ' '; }
waitfor() { i=0; while [ $i -lt ${3:-60} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 2; i=$((i+2)); done; return 1; }
# what is not Detour's: network without the exits' sections, firewall without the zone's network list
others() {
	ex=$(uci show detour | sed -n "s/^detour\.[a-z0-9_]*\.iface='\(.*\)'/\1/p")
	own=$(for i in $ex; do echo $i; uci show network | sed -n "s/^network\.\([a-z0-9_]*\)=\(wireguard\|amneziawg\)_$i$/\1/p"; done | tr '\n' '|')
	exl=$(echo $ex | tr ' ' '|')
	uci show network | grep -vE "^network\.(${own%|})[.=]" | grep -vE "^network\.@(wireguard|amneziawg)_($exl)\[" | sort
	uci show firewall | grep -v "\.network=" | sort
	uci show dhcp | sort
}
# the network config; peers without a name are numbered by their order, which means nothing to netifd
net() { uci show network | sed 's/^\(network\.@[a-z]*_[a-z0-9_]*\)\[[0-9]*\]/\1[*]/' | sort; }
fsum() { ( cd /etc/detour && find . -type f ! -name ruleset.good ! -name dom.save ! -name v2fly-names.txt ! -name before-restore.bin ! -path './traffic/*' | sort | while read -r f; do md5sum "$f"; done ); }
rm -f /tmp/detour-backup.bin /tmp/detour-restore.bin /etc/detour/before-restore.bin
# the lab servers of the exits (gone after a lab reboot): this test must not depend on running after others
for N in 1 2; do ip netns list | grep -q "^ex$N " || lab tests/lab/l2-exit.sh $N >/dev/null 2>&1; done
lab tests/lab/restart-sb.sh >/dev/null
# busybox has no diff: same or not, and the first lines that differ
same() { cmp -s "$1" "$2"; }
delta() { echo "$(wc -l < $1) -> $(wc -l < $2) lines; repeated: $(sort $1 | uniq -d | head -n 2) | $(sort $2 | uniq -d | head -n 2)"; { grep -vxFf "$2" "$1" | sed 's/^/- /'; grep -vxFf "$1" "$2" | sed 's/^/+ /'; } | head -n 6 | tr '
' ' '; }
# every exit healthy at the start is healthy again (others may come up meanwhile)
covers() { h=" $(healthy)"; for e in $H0; do case "$h" in *" $e "*) ;; *) return; esac; done; echo x; }

waitfor x "ubus call detour status >/dev/null 2>&1 && echo x" 60
# a peer without a name (as wgconf and the stock import make them): it must come back as one
A=$(uci add network wireguard_wgx2); uci set network.$A.description=t13anon; uci set network.$A.public_key=$(wg genkey | wg pubkey)
uci add_list network.$A.allowed_ips=10.255.255.1/32; uci commit network; /etc/init.d/network reload
sleep 20; H0=$(healthy)   # the lab servers just started: the probes need a moment
uci export detour > /tmp/t13.detour
net > /tmp/t13.network
others > /tmp/t13.others
fsum > /tmp/t13.files
uci show firewall | sed -n 's/\.network=/ /p' > /tmp/t13.zones

# a list with its snapshot on flash: after the restore its state must be back (the Lists page said "not loaded
# yet" of every list a restore brought back from a snapshot)
uci -q delete detour.t13l; uci set detour.t13l=list; uci set detour.t13l.policy=vpn; uci set detour.t13l.kind=cidr
uci add_list detour.t13l.url=http://10.0.2.2:8765/tests/stub/lists/cidr.txt; uci set detour.t13l.min_lines=1; uci commit detour
detour lists-update t13l >/dev/null 2>&1
[ -s /etc/detour/lists/t13l.snap ] && ok "list t13l with its snapshot" || bad "no snapshot of t13l: $(cat /tmp/detour/lists/t13l.status 2>&1)"
uci export detour > /tmp/t13.detour; fsum > /tmp/t13.files

echo "== save"
r=$(call backup_create short); echo "$r" | grep -q 'at least 8' && ok "a short password is refused" || bad "short: $r"
r=$(call backup_create)
[ -s /tmp/detour-backup.bin ] && [ "$(head -c 8 /tmp/detour-backup.bin)" = Salted__ ] && ok "encrypted file, $(wc -c < /tmp/detour-backup.bin) bytes" || bad "create: $r"
[ "$(ls -l /tmp/detour-backup.bin | cut -c1-10)" = "-rw-------" ] && ok "mode 600" || bad "mode: $(ls -l /tmp/detour-backup.bin)"
P=$(uci -q get network.wgx1.private_key)
grep -q "$P" /tmp/detour-backup.bin && bad "a private key is readable in the file" || ok "no key readable in the file"
[ -z "$(ls /tmp/detour 2>/dev/null | grep -E '^(backup|\.pw-|in-)')" ] && ok "nothing decrypted or a password left in /tmp/detour" || bad "left: $(ls -a /tmp/detour)"
cp /tmp/detour-backup.bin /tmp/t13.bak

echo "== change everything"
uci delete detour.alt
for s in $(uci show network | sed -n "s/^network\.\([a-z0-9_]*\)=wireguard_wgx2/\1/p"); do uci delete network.$s; done
uci delete network.wgx2; uci del_list firewall.vpn.network=wgx2
uci set network.jnk=interface; uci set network.jnk.proto=none; uci set network.jnk.device=jnktun; uci add_list firewall.vpn.network=jnk
uci set detour.jnk=exit; uci set detour.jnk.id=77; uci set detour.jnk.iface=jnk; uci set detour.jnk.device=jnktun
uci set detour.zzz=policy; uci set detour.zzz.id=9; uci set detour.zzz.exit=jnk
uci set detour.main.probe_period=7
uci commit; mv /etc/detour/engines/xr.json /tmp/t13.xr.json; echo junk > /etc/detour/junk.txt
ubus call detour reload >/dev/null 2>&1

echo "== check (dry run)"
cp /tmp/t13.bak /tmp/detour-restore.bin
r=$(call backup_check wrong-password); echo "$r" | grep -q 'wrong password' && ok "a wrong password is refused" || bad "wrong pw: $r"
r=$(call backup_check)
echo "$r" | jsonfilter -e '@.backup.exits' | grep -q alt && echo "$r" | jsonfilter -e '@.replaced.exits' | grep -q jnk && ok "preview: alt comes back, jnk goes" || bad "preview: $r"
echo "$r" | grep -qE "private_key|tg_token|$P" && bad "the preview shows secrets" || ok "no secrets in the preview"
[ "$(uci -q get detour.main.probe_period)" = 7 ] && [ -z "$(uci -q get detour.alt)" ] && ok "the dry run changed nothing" || bad "the dry run changed something"

echo "== restore"
r=$(call backup_restore)
echo "$r" | grep -q '"restored"' && ok "restored: $(echo "$r" | jsonfilter -e '@.restored' | tr -d '\n\t')" || bad "restore: $r"
uci export detour > /tmp/t13.n1; net > /tmp/t13.n2; others > /tmp/t13.n3; fsum > /tmp/t13.n4
same /tmp/t13.detour /tmp/t13.n1 && ok "/etc/config/detour is as it was" || bad "detour differs: $(delta /tmp/t13.detour /tmp/t13.n1)"
same /tmp/t13.network /tmp/t13.n2 && ok "network is as it was (jnk gone, wgx2 back)" || bad "network differs: $(delta /tmp/t13.network /tmp/t13.n2)"
same /tmp/t13.others /tmp/t13.n3 && ok "nothing else of the router changed (LAN, WAN, zones, DHCP)" || bad "others differ: $(delta /tmp/t13.others /tmp/t13.n3)"
for z in $(cut -d' ' -f1 /tmp/t13.zones); do
	a=$(grep -F "$z " /tmp/t13.zones | cut -d' ' -f2- | tr -d "'" | tr ' ' '\n' | sort | tr '\n' ' ')
	b=$(uci -q get $z.network | tr ' ' '
' | sort | tr '
' ' ')
	[ "$a" = "$b" ] && ok "zone $z: $a" || bad "zone $z: $a -> $b"
done
same /tmp/t13.files /tmp/t13.n4 && ok "files of /etc/detour are as they were" || bad "files differ: $(delta /tmp/t13.files /tmp/t13.n4)"
[ ! -e /etc/detour/junk.txt ] && ok "a stray file is gone" || bad "junk.txt stays"
[ "$(ls -l /etc/detour/sshtun/id_ed25519 2>/dev/null | awk '{print $3}')" = dtssh ] && ok "the panel tunnel key belongs to dtssh" || bad "sshtun owner: $(ls -l /etc/detour/sshtun)"
[ -n "$H0" ] || bad "no exit was healthy before the test"
waitfor x "covers" 120 && ok "the exits work again: $H0" || bad "healthy: $(healthy), before: $H0"
[ -s /etc/detour/before-restore.bin ] && ok "the previous settings were saved" || bad "no before-restore file"
waitfor true "jsonfilter -i /tmp/detour/lists/t13l.status -e '@.ok' 2>/dev/null" 60 && ok "the list's state is back: $(jsonfilter -i /tmp/detour/lists/t13l.status -e '@.message')" || bad "list state after the restore: $(ls /tmp/detour/lists/ | grep t13l | tr '
' ' ')"

echo "== undo: the saved previous settings restore the changed state"
cp /etc/detour/before-restore.bin /tmp/detour-restore.bin
r=$(call backup_restore)
[ "$(uci -q get detour.main.probe_period)" = 7 ] && [ "$(uci -q get detour.jnk)" = exit ] && [ -z "$(uci -q get detour.alt)" ] && ok "back to the changed state" || bad "undo: $r"
cp /tmp/t13.bak /tmp/detour-restore.bin; call backup_restore >/dev/null
uci export detour > /tmp/t13.n1; same /tmp/t13.detour /tmp/t13.n1 && ok "and forward again" || bad "forward again: $(delta /tmp/t13.detour /tmp/t13.n1)"

echo "== refused"
W=/tmp/t13w; rm -rf $W; mkdir -p $W/x
pf=$W/pw; echo -n "$PW" > $pf
dec() { openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:$pf -in /tmp/t13.bak | tar -xzf - -C $W/x; }
enc() { ( cd $W/x && rm -f sums.sha256 && find . -type f ! -name sums.sha256 | sort | xargs sha256sum > sums.sha256 ); tar -czf - -C $W/x . | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass file:$pf -out /tmp/detour-restore.bin; }
dec; ln -s /etc/shadow $W/x/files/evil; enc
r=$(call backup_check); echo "$r" | grep -q 'links or special' && ok "a link in the archive" || bad "link: $r"
rm -rf $W/x; mkdir -p $W/x; dec; sed -i 's/"schema": [0-9]*/"schema": 99/' $W/x/manifest.json; enc
r=$(call backup_check); echo "$r" | grep -q 'newer Detour' && ok "a backup of a newer Detour" || bad "schema: $r"
rm -rf $W/x; mkdir -p $W/x; dec; sed -i 's/"name": "wgx1"/"name": "lan"/' $W/x/network.json; enc
r=$(call backup_check); echo "$r" | grep -q "not an exit's" && ok "a network section that is no exit's (lan)" || bad "lan: $r"
rm -rf $W/x; mkdir -p $W/x; dec; echo "# changed" >> $W/x/detour.uci; tar -czf - -C $W/x . | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass file:$pf -out /tmp/detour-restore.bin
r=$(call backup_check); echo "$r" | grep -q "checksums do not match" && ok "a file changed after the backup was made: refused" || bad "sums: $r"
echo "not a backup" > /tmp/detour-restore.bin
r=$(call backup_check); echo "$r" | grep -q 'not a Detour backup' && ok "a file that is no backup" || bad "plain: $r"

# the router has wgx2 of its own (not an exit any more): the backup's exit wgx2 must not take it over
uci delete detour.alt; uci commit detour
cp /tmp/t13.bak /tmp/detour-restore.bin
r=$(call backup_check); [ "$(echo "$r" | jsonfilter -e '@.conflicts[0]')" = wgx2 ] && ok "preview names the clash: wgx2" || bad "conflict preview: $r"
r=$(call backup_restore); echo "$r" | grep -q 'already has network interfaces' && ok "the restore refuses it" || bad "conflict restore: $r"
uci -q get network.wgx2 >/dev/null && ok "the router's wgx2 is untouched" || bad "wgx2 gone"

echo "== a backup of another router: its LAN bridge is not taken, the traffic history is merged"
DAY=$(date +%d); M=$(date +%Y-%m); OD=01; [ "$DAY" = 01 ] && OD=02
uci import detour < /tmp/t13.detour; uci commit detour; ubus call detour reload >/dev/null 2>&1
rm -rf $W/x; mkdir -p $W/x; dec
sed -i "s/option lan_dev .*/option lan_dev 'br-other'/" $W/x/detour.uci
mkdir -p $W/x/files/traffic
echo '{"05":{"d":{"02:aa:bb:cc:dd:ee":[100,200]},"x":{},"v":[0,0]}}' > $W/x/files/traffic/2025-01.json
ucode -e 'let f=ARGV[0], d={}; try { d=json(fs.readfile(f)); } catch(e) {} d[ARGV[1]]={d:{"02:aa:bb:cc:dd:ef":[300,400]},x:{},v:[0,0]}; fs.writefile(f, sprintf("%J", d));' -l fs 	$W/x/files/traffic/$M.json $OD 2>/dev/null || echo "{\"$OD\":{\"d\":{\"02:aa:bb:cc:dd:ef\":[300,400]},\"x\":{},\"v\":[0,0]}}" > $W/x/files/traffic/$M.json
enc
LAN0=$(uci -q get detour.main.lan_dev)
r=$(call backup_restore); echo "$r" | grep -q '"restored"' || bad "restore of the crafted backup: $r"
[ "$(uci -q get detour.main.lan_dev)" = "$LAN0" ] && ok "lan_dev stays this router's ($LAN0)" || bad "lan_dev: $(uci -q get detour.main.lan_dev)"
/etc/init.d/detour restart; waitfor x "ubus call detour status >/dev/null 2>&1 && echo x" 60   # the daemon writes its month to flash on stop
grep -q '02:aa:bb:cc:dd:ee' /etc/detour/traffic/2025-01.json && ok "a month this router never had is restored" || bad "2025-01 missing"
grep -q '02:aa:bb:cc:dd:ef' /etc/detour/traffic/$M.json && ok "a day of this month this router had not counted survives the daemon's own writes" || bad "day $OD of $M lost: $(head -c 300 /etc/detour/traffic/$M.json)"
ubus call detour traffic '{"period":"month"}' | grep -q '02:aa:bb:cc:dd:ef' && ok "and shows in the report" || bad "report: no restored device"
drop_day() { ucode -e 'let f=ARGV[0], d=json(fs.readfile(f)); delete d[ARGV[1]]; fs.writefile(f, sprintf("%J", d));' -l fs "$1" "$2"; }

echo "== back to the start"
uci import detour < /tmp/t13.detour; uci commit detour
[ -e /tmp/t13.xr.json ] && [ ! -e /etc/detour/engines/xr.json ] && mv /tmp/t13.xr.json /etc/detour/engines/xr.json
ubus call detour reload >/dev/null 2>&1
waitfor x "covers" 120 || bad "healthy at the end: $(healthy), before: $H0"
# the lab's own traffic history without the test's records; the test's peer goes
/etc/init.d/detour stop; rm -f /etc/detour/traffic/2025-01.json /tmp/detour/traffic/2025-01.json
for f in /etc/detour/traffic/$M.json /tmp/detour/traffic/$M.json; do [ -e $f ] && grep -q 02:aa:bb:cc:dd:ef $f && drop_day $f $OD; done
/etc/init.d/detour start
for s in $(uci show network | sed -n "s/^network\.\(@wireguard_wgx2\[[0-9]*\]\)\.description='t13anon'/\1/p" | sort -r); do uci delete network.$s; done
uci commit network; /etc/init.d/network reload
rm -rf $W /tmp/t13.* /tmp/detour-backup.bin /tmp/detour-restore.bin /etc/detour/before-restore.bin
uci -q delete detour.t13l; uci commit detour; rm -f /etc/detour/lists/t13l.* /tmp/detour/lists/t13l.*; ubus call detour reload >/dev/null
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
