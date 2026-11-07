#!/bin/sh
# Stage 1 acceptance: install from the signed feed, services up, uninstall leaves a stock router.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
chk() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
FAIL=0
apk del -q detour luci-app-detour >/dev/null 2>&1
echo "== install"
apk add detour 2>&1 | grep -E 'Installing|ERROR|untrusted|Executing' | head -5
sleep 3
chk "detour-fw enabled (S18 before dnsmasq S19)" "ls /etc/rc.d/S18detour-fw"
chk "daemon running" "pgrep -f /usr/sbin/detourd"
chk "ubus object" "ubus call detour status"
chk "table inet detour" "nft list table inet detour"
chk "watchdog in cron" "grep -q detour/watchdog /etc/crontabs/root"
chk "heartbeat fresh" "[ \$(( \$(date +%s) - \$(cat /tmp/detour/heartbeat) )) -lt 10 ]"
chk "client DNS works" "cl nslookup example.org 192.168.1.1 | grep -q 'Address: [0-9]'"
echo "== uninstall"
apk del detour luci-app-detour 2>&1 | grep -E 'Purging|ERROR' | head -3
sleep 2
chk "no table" "! nft list table inet detour"
chk "no ip rules 110xx" "! ip rule show | grep -q '^110'"
chk "no daemon" "! pgrep -f /usr/sbin/detourd"
chk "cron cleaned" "! grep -q detour/watchdog /etc/crontabs/root"
chk "dnsmasq not managed" "! uci -q get dhcp.@dnsmasq[0].detour_managed"
chk "no conf in dnsmasq dir" "! ls /tmp/dnsmasq.*.d/detour.conf"
chk "client DNS works" "cl nslookup example.org 192.168.1.1 | grep -q 'Address: [0-9]'"
chk "client internet works" "cl curl -s -m 8 -o /dev/null http://example.org"
apk add -q detour luci-app-detour >/dev/null 2>&1
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
