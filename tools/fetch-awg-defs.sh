#!/bin/sh
# Research helper (WSL): download luci-proto-amneziawg and amneziawg-tools from the Quarx2k feed
# into an empty directory and print the netifd/LuCI option names of the amneziawg protocol.
# Downloaded packages are data: they are only unpacked and read, never executed.
set -eu
D=/root/q2k
B=https://openwrt.quarx2k.dev/packages
rm -rf "$D"; mkdir -p "$D"; cd "$D"
R=${R:-r37983+126-382a2109c8}
: > c.txt
for f in "common/aarch64_cortex-a53" "$R/qualcommbe/ipq95xx"; do
	if curl -sf -m 30 -o i.adb "$B/$f/packages.adb"; then
		apk3 adbdump i.adb 2>/dev/null | sed "s|^|$f\t|" >> c.txt || true
	fi
done
echo "feeds: $(cut -f1 c.txt | sort -u | tr '\n' ' ')"
grep -oE 'name: [a-z0-9-]*amnezia[a-z0-9-]*' c.txt | sort -u
for n in amneziawg-tools luci-proto-amneziawg; do
	line=$(grep -n -E "	  - name: $n$" c.txt | head -n1 | cut -d: -f1)
	[ -n "$line" ] || { echo "$n: not in these feeds"; continue; }
	feed=$(sed -n "${line}p" c.txt | cut -f1)
	v=$(tail -n +"$line" c.txt | grep -m1 'version:' | awk '{print $NF}')
	echo "$n $v ($feed)"
	curl -s -m 60 -o "$n.apk" "$B/$feed/$n-$v.apk"
	mkdir -p "x-$n"
	apk3 extract --allow-untrusted --destination "x-$n" "$n.apk" 2>&1 | tail -n 2 || true
done
find "$D" -path '*/x-*' -type f | sed "s|$D/||"
