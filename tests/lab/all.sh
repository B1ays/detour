#!/bin/sh
# run the lab acceptance suite in order; t1 reinstalls the package (needs the feed on 10.0.2.2:8765)
for t in t1-lifecycle t2-routing t3-dns t4-auth t1b-uninstall-full; do
	echo "######## $t"
	[ $t = t2-routing ] && apk add -q detour
	lab tests/lab/$t.sh 2>&1 | grep -E "FAIL|RESULT"
done
