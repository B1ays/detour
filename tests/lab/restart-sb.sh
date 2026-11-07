#!/bin/sh
# (re)start the lab shadowsocks server in netns ex1. Its DNS is set explicitly (QEMU user-net resolver
# 10.0.2.3): inside the netns sing-box sometimes fell back to [::1]:53, and urltest probes need names.
D=/etc/enodia-lab
PW=$(cat $D/ss.pw)
# after a reboot of the lab router the netns are gone: the server must not be started before ex1 exists
ip netns list | grep -q '^ex1 ' || lab tests/lab/l2-exit.sh 1 >/dev/null 2>&1
cat > $D/sb-server.json <<J
{ "log": {"level": "warn"},
  "dns": { "servers": [ {"type": "udp", "tag": "qemu", "server": "10.0.2.3"} ] },
  "inbounds": [ {"type": "shadowsocks", "tag": "ss-in", "listen": "0.0.0.0", "listen_port": 8443, "method": "2022-blake3-aes-128-gcm", "password": "$PW"} ],
  "outbounds": [ {"type": "direct", "tag": "direct"} ],
  "route": { "default_domain_resolver": "qemu" } }
J
sing-box check -c $D/sb-server.json || echo "sb-server.json rejected"
for p in $(ip netns pids ex1); do kill $p 2>/dev/null; done
sleep 1
(ip netns exec ex1 sing-box run -c $D/sb-server.json > /tmp/sb-server.log 2>&1 &)
sleep 2
echo "ex1 processes: $(ip netns pids ex1 | wc -l)"
