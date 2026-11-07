#!/bin/sh
# Lab router: drop the research prototype, trust the dev feed key, add the dev feed.
kill $(pgrep -f detourd-lab.uc) 2>/dev/null
apk info -e detour >/dev/null 2>&1 && apk del -q detour
nft delete table inet detour 2>/dev/null
for p in $(ip rule show | sed -n 's/^\(110[0-9][0-9]\):.*/\1/p'); do ip rule del priority $p; done
for t in 1001 1002 1003 1004; do ip route flush table $t 2>/dev/null; done
rm -f /etc/apk/keys/detour-lab.pem
wget -qO /etc/apk/keys/detour-dev.pem http://10.0.2.2:8765/feed/detour-dev.pem
grep -q detour /etc/apk/repositories.d/customfeeds.list || echo 'http://10.0.2.2:8765/feed/packages.adb' >> /etc/apk/repositories.d/customfeeds.list
sed -i 's#^wget -qO /tmp/lab-\$n .*#b=$(basename $n); wget -qO /tmp/lab-$b http://10.0.2.2:8765/$n || { echo "fetch $n failed"; exit 1; }#; s#^sh /tmp/lab-\$n #sh /tmp/lab-$b #' /usr/bin/lab
cat /usr/bin/lab | tail -2
apk update 2>&1 | grep -iE 'detour|error|untrusted' ; apk search -e detour
