#!/bin/sh
# run the lab acceptance suite in order; needs on the PC: the repo served on :8765 and the stubs
# tests/stub/tg_stub.py 8766 (Telegram) and tests/stub/warp_stub.py 8767 (WARP API)
for t in t1-lifecycle t2-routing t3-dns t4-auth t9-notify t10-engines t11-links t12-warp t13-import t1b-uninstall-full; do
	echo "######## $t"
	[ $t = t2-routing ] && apk add -q detour
	lab tests/lab/$t.sh 2>&1 | grep -E "FAIL|RESULT"
done
