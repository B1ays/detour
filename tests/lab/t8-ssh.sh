#!/bin/sh
# A-9: 2FA on -> SSH password only on LAN-zone addresses, keys-only elsewhere; 2FA off -> stock dropbear.
# Restarting dropbear kills processes started from SSH (even detached), so the test runs in phases,
# each from a fresh SSH call:  t8-ssh.sh on; t8-ssh.sh check-on; t8-ssh.sh off; t8-ssh.sh check-off
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
P=bb4ea47fcffb44ec9bb3d3673c9b4ed2
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
methods() { cl "ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o ConnectTimeout=5 nobody@$1 true 2>&1" | sed -n 's/.*Permission denied (\(.*\)).*/\1/p'; }
case "$1" in
on)
	uci set luci_plugins.global.enabled=1; uci set luci_plugins.global.auth_login_enabled=1
	uci set luci_plugins.$P.enabled=1; uci set luci_plugins.$P.key_root=JBSWY3DPEHPK3PXP; uci commit luci_plugins
	ubus call detour reload >/dev/null; echo "2FA on, dropbear restarting" ;;
off)
	uci set luci_plugins.$P.enabled=0; uci set luci_plugins.global.auth_login_enabled=0; uci -q delete luci_plugins.$P.key_root; uci commit luci_plugins
	ubus call detour reload >/dev/null; echo "2FA off, dropbear restarting" ;;
check-on)
	[ "$(uci -q get dropbear.detour_pw_lan.Interface)" = lan ] && ok "password instance on lan" || bad "no lan instance"
	[ "$(uci -q get dropbear.detour_pw_mgmt.Interface)" = mgmt ] && ok "password instance on mgmt (lab mgmt is in the lan zone)" || bad "no mgmt instance"
	[ "$(uci -q get dropbear.detour_key_wan.PasswordAuth)" = off ] && ok "keys-only instance on wan" || bad "no wan keys instance"
	[ "$(uci -q get dropbear.main.enable)" = 0 ] && ok "wildcard instance disabled" || bad "main still enabled"
	[ "$(methods 192.168.1.1)" = "publickey,password" ] && ok "LAN address: publickey,password" || bad "LAN: $(methods 192.168.1.1)"
	[ "$(methods 10.0.2.15)" = "publickey" ] && ok "WAN address: publickey only" || bad "WAN: $(methods 10.0.2.15)"
	ubus call detour status | jsonfilter -e '@.auth.ssh_lan_password_only' | grep -q true && ok "status reports it" || bad "status"
	echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)" ;;
check-off)
	[ -z "$(uci show dropbear | grep -E 'detour_(pw|key)_')" ] && ok "Detour instances removed" || bad "instances left"
	[ "$(uci -q get dropbear.main.enable)" = 1 ] && ok "wildcard instance back" || bad "main: $(uci -q get dropbear.main.enable)"
	[ "$(methods 10.0.2.15)" = "publickey,password" ] && ok "password everywhere again" || bad "after: $(methods 10.0.2.15)"
	echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)" ;;
*) echo "usage: $0 on|check-on|off|check-off" ;;
esac
