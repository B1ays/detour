#!/bin/sh
# run the lab acceptance suite in order; needs on the PC: the repo served on :8765 and the stubs
# tests/stub/tg_stub.py 8766 (Telegram), warp_stub.py 8767 (WARP API), sub_stub.py 8768 (subscriptions)
for t in t0-compile t1-lifecycle t2-routing t3-dns t4-auth t9-notify t10-engines t11-links t12-warp t13-backup t14-lists t15-luci-actions t16-chain t17-warp-dme t18-subs t19-flowreset t20-sshtun t21-ports t22-exits-ui t23-notify-subs t24-failclosed t25-exit-add t26-block-open-site t27-traffic t28-devices-dns t29-overview t30-engine-choice t31-lists-memory t32-direct-policy t33-review-stage1 t34-review-stage2 t35-packages t1b-uninstall-full; do
	echo "######## $t"
	[ $t = t2-routing ] && apk add -q detour
	lab tests/lab/$t.sh 2>&1 | grep -E "FAIL|RESULT"
done
