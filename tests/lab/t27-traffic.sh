#!/bin/sh
# Stage 4.3: traffic by device (nlbwmon) and by exit (the tunnels' counters). The client downloads 10 MB
# directly and 10 MB through the policy "vpn": the device gets ~20 MB, VPN ~10, directly ~10; a lab exit's
# server (a host in a private network outside the home networks) is not a device; a restart of the daemon or
# of nlbwmon counts nothing twice (nlbwmon counts a closed connection only when conntrack drops it); a stop of the daemon writes the day to flash.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
tr_() { ubus call detour traffic '{"period":"day"}' | jsonfilter -e "$1"; }
mb() { echo $(( ${1:-0} / 1048576 )); }
# a public mirror (speed.cloudflare.com answers 429 after a few runs); the first N bytes of a big file
U=https://mirror.yandex.ru/ubuntu-releases/24.04/ubuntu-24.04.4-desktop-amd64.iso
dl() { cl "nslookup mirror.yandex.ru >/dev/null; curl -s -r 0-$((${1:-10000000} - 1)) -o /dev/null -w '%{size_download}' $U"; }
ctd() { conntrack -D -s $CL -p tcp --dport 443 >/dev/null 2>&1; }
step() { sleep 12; }   # traffic_period 5 s: two steps at least

apk info -e nlbwmon >/dev/null || apk add -q nlbwmon
/etc/init.d/nlbwmon enabled || /etc/init.d/nlbwmon enable
pidof nlbwmon >/dev/null || /etc/init.d/nlbwmon start
cleanup() {
	uci -q del_list detour.vpn.domain=mirror.yandex.ru
	uci -q delete detour.main.traffic_period
	uci commit detour
	# the addresses the domain brought stay in the policy's set across reloads: out, or "directly" is not direct
	nft flush set inet detour dom4_p1 2>/dev/null; nft flush set inet detour dom6_p1 2>/dev/null
}
cleanup
/etc/init.d/detour stop
rm -rf /tmp/detour/traffic /etc/detour/traffic
uci set detour.main.traffic_period=5; uci commit detour
/etc/init.d/detour start
i=0; while [ ! -f /tmp/detour/traffic/last.json ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
step
[ "$(tr_ '@.source.running')" = true ] && ok "nlbwmon answers" || bad "nlbwmon: $(tr_ '@.source')"

T0=$(tr_ '@.total.rx'); V0=$(tr_ '@.vpn.rx'); D0=$(tr_ '@.direct.rx')
n=$(dl); [ "$n" = 10000000 ] && ok "10 MB directly" || bad "direct download: $n"
uci add_list detour.vpn.domain=mirror.yandex.ru; uci commit detour; ubus call detour reload >/dev/null; sleep 3
n=$(dl); [ "$n" = 10000000 ] && ok "10 MB through the policy vpn" || bad "vpn download: $n"
# nlbwmon counts a closed connection when conntrack drops it (TIME_WAIT, up to 2 min): drop them now
ctd
step
T=$(( $(tr_ '@.total.rx') - T0 )); V=$(( $(tr_ '@.vpn.rx') - V0 )); D=$(( $(tr_ '@.direct.rx') - D0 ))
[ $(mb $T) -ge 19 ] && [ $(mb $T) -le 23 ] && ok "the device: $(mb $T) MB" || bad "device total $(mb $T) MB, want ~20"
[ $(mb $V) -ge 9 ] && [ $(mb $V) -le 12 ] && ok "through VPN: $(mb $V) MB" || bad "VPN $(mb $V) MB, want ~10"
[ $(mb $D) -ge 8 ] && [ $(mb $D) -le 12 ] && ok "directly: $(mb $D) MB" || bad "directly $(mb $D) MB, want ~10"
W=$(ubus call detour traffic '{"period":"day"}' | jsonfilter -e '@.exits[@.name="warp"].rx' -e '@.exits[@.name="alt"].rx' | awk '{s+=$1} END{print s}')
[ $(mb $W) -ge 9 ] && ok "the exits of vpn carried $(mb $W) MB" || bad "exits warp+alt: $(mb $W) MB"
macs=$(ubus call detour traffic '{"period":"day"}' | jsonfilter -e '@.devices[*].mac')
bad_mac=""
for m in $macs; do ip neigh show | grep -i "lladdr $m" | grep -q " dev br-lan " || bad_mac="$bad_mac $m"; done
[ -z "$bad_mac" ] && ok "only home devices: $(echo $macs)" || bad "not home devices counted:$bad_mac"

T1=$(tr_ '@.total.rx')
/etc/init.d/detour restart; sleep 3; step
T2=$(tr_ '@.total.rx')
[ $(( (T2 - T1) / 1048576 )) -lt 1 ] && ok "daemon restart: nothing counted twice (+$(( (T2 - T1) / 1024 )) KB)" || bad "daemon restart added $(mb $((T2 - T1))) MB"
# nlbwmon keeps its numbers over a restart (it saves and restores its database): no reset seen, nothing twice
/etc/init.d/nlbwmon restart; sleep 3; step
T3=$(tr_ '@.total.rx')
[ $(( (T3 - T2) / 1048576 )) -lt 2 ] && ok "nlbwmon restart: nothing counted twice (+$(( (T3 - T2) / 1024 )) KB)" || bad "nlbwmon restart added $(mb $((T3 - T2))) MB"
# an interface coming up only reloads nlbwmon (procd keeps the process): its open connections are not lost
P=$(pidof nlbwmon); ifdown wgx2; sleep 2; ifup wgx2; sleep 5
[ "$(pidof nlbwmon)" = "$P" ] && ok "ifup: nlbwmon keeps running" || bad "ifup restarted nlbwmon ($P -> $(pidof nlbwmon))"

# flash: written at the first step after start (above) and then every 30 min - a stop writes what came since
F=/etc/detour/traffic/$(date +%Y-%m).json
D=$(date +%d)
fl() { jsonfilter -i $F -e "@['$D'].d['52:54:00:0c:00:01'][0]" 2>/dev/null; }
S1=$(fl)
n=$(dl 5000000); ctd; step
[ "$(fl)" = "$S1" ] && ok "5 MB more: not on flash yet ($(mb $S1) MB there)" || bad "flash changed before the stop: $(fl) vs $S1"
/etc/init.d/detour stop
S2=$(fl)
[ $(( (S2 - S1) / 1048576 )) -ge 4 ] && ok "stop: the day so far went to flash (+$(mb $((S2 - S1))) MB)" || bad "flash after stop: '$S2' was '$S1'"
cleanup
/etc/init.d/detour start
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
