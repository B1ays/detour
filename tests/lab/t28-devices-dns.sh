#!/bin/sh
# Stage 4.1/4.2: the devices of the home network (fixed address, name, online, no exit servers or router
# interfaces among them) and "what does it ask for": tcpdump for a while - the names a device asks, also from
# other DNS servers, its DoT connections noticed; stopped on request, at the end and when the daemon stops.
CL=192.168.1.145
MAC=52:54:00:0c:00:01
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
dev() { ubus call detour devices | jsonfilter -e "@.devices[@.mac='$MAC'].$1"; }
log() { ubus call detour dns_log "{\"mac\":\"$MAC\"}"; }
tcpd() { pgrep -x tcpdump | wc -l; }

apk info -e tcpdump-mini >/dev/null || apk info -e tcpdump >/dev/null || apk add -q tcpdump-mini

echo "== devices"
cl true; ping -c1 -W1 $CL >/dev/null
[ "$(dev name)" = client ] && ok "the lab client by its fixed-address name" || bad "name: $(dev name)"
[ "$(dev fixed)" = true ] && ok "fixed address" || bad "fixed: $(dev fixed)"
[ "$(dev online)" = true ] && ok "online" || bad "online: $(dev online)"
echo "$(dev ips)" | grep -q 192.168.1.145 && ok "its address" || bad "ips: $(dev ips)"
others=$(ubus call detour devices | jsonfilter -e '@.devices[*].mac' | tr '\n' ' ')
x=""
for m in $others; do ip neigh show | grep -i "lladdr $m" | grep -vq " dev br-lan " && x="$x $m"; done
for m in $(cat /sys/class/net/*/address); do echo " $others" | grep -qi " $m" && x="$x own:$m"; done
[ -z "$x" ] && ok "no exit servers, no router interfaces: $others" || bad "not devices:$x"

echo "== what does it ask for"
R=$(ubus call detour dns_watch '{"mac":"zz"}'); echo "$R" | grep -q "bad mac" && ok "a bad MAC is refused" || bad "bad mac: $R"
R=$(ubus call detour dns_watch "{\"mac\":\"$MAC\",\"seconds\":30}")
[ "$(echo "$R" | jsonfilter -e @.ok)" = true ] && ok "watching 30 s" || bad "start: $R"
sleep 1
[ "$(tcpd)" -ge 1 ] && ok "tcpdump runs" || bad "no tcpdump"
cl "nslookup t28-a.example.org; nslookup t28-a.example.org; nslookup t28-b.example.com 8.8.8.8; curl -s -m 3 -o /dev/null https://1.1.1.1:853/" >/dev/null
sleep 2
L=$(log)
[ "$(echo "$L" | jsonfilter -e '@.running')" = true ] && ok "running" || bad "running: $(echo "$L" | jsonfilter -e '@.running')"
n=$(echo "$L" | jsonfilter -e "@.queries[@.name='t28-a.example.org'].n")
[ "${n:-0}" -ge 2 ] && ok "t28-a.example.org asked $n times (A and AAAA, twice)" || bad "t28-a: '$n'"
[ -n "$(echo "$L" | jsonfilter -e "@.queries[@.name='t28-b.example.com'].n")" ] && ok "a query to another DNS server (8.8.8.8) is seen" || bad "8.8.8.8 query not seen"
[ "$(echo "$L" | jsonfilter -e '@.dot')" -ge 1 ] && ok "a DoT connection is noticed" || bad "dot: $(echo "$L" | jsonfilter -e '@.dot')"
ubus call detour dns_watch_stop >/dev/null; sleep 1
[ "$(tcpd)" = 0 ] && ok "stop: tcpdump is gone" || bad "tcpdump left: $(tcpd)"
[ "$(log | jsonfilter -e '@.running')" = false ] && ok "stopped: what was seen stays readable ($(log | jsonfilter -e '@.total') requests)" || bad "running after stop"

ubus call detour dns_watch "{\"mac\":\"$MAC\",\"seconds\":10}" >/dev/null; sleep 13
[ "$(tcpd)" = 0 ] && ok "ends by itself after its time" || bad "tcpdump after the time: $(tcpd)"
ubus call detour dns_watch "{\"mac\":\"$MAC\",\"seconds\":120}" >/dev/null; sleep 1
/etc/init.d/detour stop; sleep 1
[ "$(tcpd)" = 0 ] && ok "daemon stop: tcpdump is gone" || bad "tcpdump after the daemon stopped: $(tcpd)"
/etc/init.d/detour start
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
