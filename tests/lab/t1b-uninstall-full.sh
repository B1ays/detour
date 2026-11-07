#!/bin/sh
# uninstall with everything switched on (dns=tunnel + 2FA guard active) -> stock router
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
uci set detour.main.ssh_guard=0; uci commit detour   # A-9 would restart dropbear and cut this SSH session (tested in t8)
P=bb4ea47fcffb44ec9bb3d3673c9b4ed2; F=/usr/share/rpcd/acl.d/unauthenticated.json
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
uci set detour.main.dns=tunnel; uci set detour.main.dns_policy=vpn; uci commit detour
uci set luci_plugins.global.enabled=1; uci set luci_plugins.global.auth_login_enabled=1; uci set luci_plugins.$P.enabled=1
uci set luci_plugins.$P.key_root=JBSWY3DPEHPK3PXP; uci commit luci_plugins
reload_config; sleep 3; ubus call detour reload >/dev/null
waitfor 0 "grep -c '\"login\"' $F" 20 && ok "2FA guard active" || bad "guard"
waitfor /tmp/detour/dns.servers "uci -q get dhcp.@dnsmasq[0].serversfile" 20 && ok "dns tunnel active" || bad "dns tunnel"
apk del -q detour luci-app-detour >/dev/null 2>&1; sleep 3
grep -q '"login"' $F && ok "rpcd ACL restored" || bad "ACL not restored"
[ -z "$(uci -q get dhcp.@dnsmasq[0].serversfile)$(uci -q get dhcp.@dnsmasq[0].noresolv)" ] && ok "dnsmasq upstreams restored" || bad "dnsmasq still managed"
! nft list table inet detour >/dev/null 2>&1 && ok "no table" || bad "table left"
waitfor ok "cl 'nslookup example.org 192.168.1.1' | awk '/^Address: [0-9.]+\$/{a=1} END{print a?\"ok\":\"no\"}'" 20 && ok "client DNS" || bad "client DNS"
# back to the lab state: 2FA off, packages back, dns off
uci set luci_plugins.$P.enabled=0; uci set luci_plugins.global.auth_login_enabled=0; uci -q delete luci_plugins.$P.key_root; uci commit luci_plugins
uci set detour.main.dns=off; uci commit detour
apk add -q detour luci-app-detour >/dev/null 2>&1
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
uci -q delete detour.main.ssh_guard; uci commit detour
