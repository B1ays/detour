#!/bin/sh
# run the lab acceptance suite in order; needs on the PC: the repo served on :8765 and the stubs
# tests/stub/tg_stub.py 8766 (Telegram), warp_stub.py 8767 (WARP API), sub_stub.py 8768 (subscriptions)
#   lab tests/lab/all.sh                 every test, in order
#   lab tests/lab/all.sh 10 15 t25       only these (a number, "tN" or the full name), in the suite's order
#   lab tests/lab/all.sh --from 20       from this test on
#   lab tests/lab/all.sh --list          the names
ALL="t0-compile t1-lifecycle t2-routing t3-dns t4-auth t9-notify t10-engines t11-links t12-warp t13-backup t14-lists t15-luci-actions t16-chain t17-warp-dme t18-subs t19-flowreset t21-ports t22-exits-ui t23-notify-subs t24-failclosed t25-exit-add t26-block-open-site t27-traffic t28-devices-dns t29-overview t30-engine-choice t31-lists-memory t32-direct-policy t33-review-stage1 t34-review-stage2 t35-packages t36-logging t37-awg-server t38-socks t39-idle-engines t40-warp-pool t1b-uninstall-full"

key() { k=${1%.sh}; k=${k#t}; echo "t${k%%-*}"; }   # "10", "t10", "t10-engines" -> "t10"
FROM=; WANT=
while [ $# -gt 0 ]; do
	case "$1" in
	--list) for t in $ALL; do echo $t; done; exit 0 ;;
	--from) FROM=$(key "$2"); shift ;;
	*) WANT="$WANT $(key "$1") " ;;
	esac
	shift
done
for w in $WANT $FROM; do
	echo " $ALL " | grep -q " $w-" || { echo "no test $w (all.sh --list)"; exit 1; }
done

# packages the tests remove and add again (dnsproxy, qrencode, detour ...) come from a cache on the root fs, not the
# internet every time; "apk update" (tools/dev-push.sh) still refreshes the indexes in it
[ -e /etc/apk/cache ] || { mkdir -p /root/apk-cache && ln -s /root/apk-cache /etc/apk/cache; }

up() { cut -d. -f1 /proc/uptime; }
T0=$(up); n=0; nf=0; failed=
on=${FROM:+0}
for t in $ALL; do
	k=$(key $t)
	[ "$k" = "$FROM" ] && on=
	[ -n "$on" ] && continue
	[ -n "$WANT" ] && ! echo "$WANT" | grep -q " $k " && continue
	echo "######## $t"
	[ $t = t2-routing ] && apk add -q detour
	s=$(up)
	r=$(lab tests/lab/$t.sh 2>&1 | grep -E "FAIL|RESULT|-- diag")
	echo "$r"
	echo "   ($(( $(up) - s )) s)"
	n=$((n + 1))
	echo "$r" | grep -q "RESULT: PASS" || { nf=$((nf + 1)); failed="$failed $t"; }
done
echo "======== $((n - nf))/$n passed in $(( ($(up) - T0) / 60 )) min $(( ($(up) - T0) % 60 )) s${failed:+; failed:$failed}"
