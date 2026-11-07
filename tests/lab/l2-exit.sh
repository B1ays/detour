#!/bin/sh
# L2 lab: a fake VPN exit on the router itself.
#   router  --wgx<N> (netifd proto wireguard, 10.200.N.1)--> netns exN (wgex 10.200.N.2) --vexNp--> router vexN --> WAN
# The netns masquerades and counts what leaves through it, so we can see which exit carried a flow.
# Usage: l2-exit.sh N   (N = 1, 2 ...). Idempotent.
N=${1:-1}
NS=ex$N; V=vex$N; VP=vex${N}p; WG=wgx$N
D=/etc/enodia-lab; mkdir -p $D; cd $D; umask 077
lsmod | grep -q '^veth' || apk add -q kmod-veth >/dev/null 2>&1

ip netns add $NS 2>/dev/null
# DNS inside the exit (a proxy server there resolves domains): QEMU user-net resolver via the router WAN
mkdir -p /etc/netns/$NS; echo "nameserver 10.0.2.3" > /etc/netns/$NS/resolv.conf
ip link show $V >/dev/null 2>&1 || ip link add $V type veth peer name $VP
ip link set $VP netns $NS 2>/dev/null
ip addr replace 10.199.$N.1/30 dev $V; ip link set $V up
ip -n $NS link set lo up
ip -n $NS addr replace 10.199.$N.2/30 dev $VP; ip -n $NS link set $VP up
ip -n $NS route replace default via 10.199.$N.1

[ -f ex$N.key ] || { wg genkey > ex$N.key; wg pubkey < ex$N.key > ex$N.pub; wg genkey > rt$N.key; wg pubkey < rt$N.key > rt$N.pub; }

ip -n $NS link show wgex >/dev/null 2>&1 || ip -n $NS link add wgex type wireguard
ip netns exec $NS wg set wgex private-key $D/ex$N.key listen-port 51820 peer "$(cat rt$N.pub)" allowed-ips 0.0.0.0/0
ip -n $NS addr replace 10.200.$N.2/30 dev wgex; ip -n $NS link set wgex up
ip -n $NS route replace 192.168.1.0/24 dev wgex
ip netns exec $NS sysctl -qw net.ipv4.ip_forward=1
ip netns exec $NS nft -f - <<EOF
table ip exnat
delete table ip exnat
table ip exnat {
	chain cnt {
		type filter hook forward priority 0;
		iifname "wgex" counter
	}
	chain post {
		type nat hook postrouting priority 100;
		oifname "$VP" masquerade
	}
}
EOF

# router side: netifd-managed WireGuard interface + firewall zones
uci -q batch <<EOF
set network.$WG=interface
set network.$WG.proto='wireguard'
set network.$WG.private_key='$(cat rt$N.key)'
set network.$WG.nohostroute='1'
delete network.$WG.addresses
add_list network.$WG.addresses='10.200.$N.1/30'
set network.wgpeer$N=wireguard_$WG
set network.wgpeer$N.public_key='$(cat ex$N.pub)'
set network.wgpeer$N.endpoint_host='10.199.$N.2'
set network.wgpeer$N.endpoint_port='51820'
delete network.wgpeer$N.allowed_ips
add_list network.wgpeer$N.allowed_ips='0.0.0.0/0'
set network.wgpeer$N.route_allowed_ips='0'
set network.wgpeer$N.persistent_keepalive='15'
commit network
EOF

# firewall: zone "vpn" (all wgx*), zone "labex" (veth underlay) - created once
if ! uci -q get firewall.vpn >/dev/null; then
	uci -q batch <<EOF
set firewall.vpn=zone
set firewall.vpn.name='vpn'
set firewall.vpn.input='REJECT'
set firewall.vpn.output='ACCEPT'
set firewall.vpn.forward='REJECT'
set firewall.vpn.masq='1'
set firewall.vpn.mtu_fix='1'
set firewall.lan2vpn=forwarding
set firewall.lan2vpn.src='lan'
set firewall.lan2vpn.dest='vpn'
set firewall.labex=zone
set firewall.labex.name='labex'
set firewall.labex.input='ACCEPT'
set firewall.labex.output='ACCEPT'
set firewall.labex.forward='ACCEPT'
set firewall.labex2wan=forwarding
set firewall.labex2wan.src='labex'
set firewall.labex2wan.dest='wan'
commit firewall
EOF
fi
uci -q get firewall.vpn.network | grep -qw $WG || { uci add_list firewall.vpn.network=$WG; uci commit firewall; }
uci -q get firewall.labex.device | grep -qw $V || { uci add_list firewall.labex.device=$V; uci commit firewall; }

/etc/init.d/network reload
sleep 4
fw4 -q reload
sleep 2
ping -c 2 -W 2 -I $WG 10.200.$N.2 >/dev/null 2>&1 && echo "exit $N: tunnel up ($WG -> $NS)" || echo "exit $N: tunnel DOWN"
wg show $WG latest-handshakes
