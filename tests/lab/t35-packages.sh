#!/bin/sh
# LuCI "Components" (detourd pkg_list / pkg_run / pkg_job, detour.pkgs, /usr/libexec/detour/pkg): the state of the
# components from apk's index, an action detached from the daemon (it survives a restart of the daemon), a removal
# and an install of a small package (qrencode), and what is refused: Detour itself, a package that is not Detour's,
# a second action while one runs, a feed out of reach. Needs the internet of the lab (the OpenWrt repositories).
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
c() { ubus -t 60 call detour "$@"; }
comp() { c pkg_list | jsonfilter -e "@.components[@.id=\"$1\"].$2"; }
running() { c pkg_job | jsonfilter -e '@.job.running'; }
code() { c pkg_job | jsonfilter -e '@.job.code'; }

# the daemon may be starting (a test before this one restarted it)
waitfor true "ubus call detour status >/dev/null 2>&1 && echo true" 60

echo "== the components"
[ "$(comp detour installed)" = true ] && [ "$(comp detour core)" = true ] && ok "Detour: installed, not removable" || bad "detour: $(c pkg_list | head -c 300)"
[ "$(comp singbox installed)" = "$(apk info -e sing-box >/dev/null && echo true || echo false)" ] && ok "sing-box state matches apk" || bad "singbox state"
[ "$(comp awg available)" = false ] && ok "AmneziaWG: not in the repositories of the lab's firmware" || echo "  note: AmneziaWG available here"
[ -n "$(c pkg_list | jsonfilter -e '@.index_ts')" ] && ok "the index time is reported" || bad "no index_ts"

echo "== an action runs detached from the daemon"
r=$(c pkg_run '{"action":"update"}'); echo "$r" | grep -q '"started": true' && ok "update started" || bad "update: $r"
/etc/init.d/detour restart; sleep 2
waitfor true "ubus call detour status >/dev/null 2>&1 && echo true" 30
waitfor false running 90 && [ "$(code)" = 0 ] && ok "it finished after the daemon restarted (code 0)" || bad "update job: $(c pkg_job | head -c 400)"
c pkg_job | jsonfilter -e '@.job.log' | grep -q 'OK\|packages\|fetch\|\[' && ok "its log is there" || bad "no log"

echo "== refused"
c pkg_run '{"action":"remove","packages":"detour"}' | grep -q 'not removed from here' && ok "Detour itself is not removed from here" || bad "removing detour"
c pkg_run '{"action":"install","packages":"vim"}' | grep -q 'not a package of Detour' && ok "only Detour's packages" || bad "vim"
c pkg_run '{"action":"reboot"}' | grep -q 'unknown action' && ok "only the four actions" || bad "unknown action"
c pkg_run '{"action":"update"}' >/dev/null
c pkg_run '{"action":"update"}' | grep -q 'another action is running' && ok "one action at a time" || bad "two at once"
waitfor false running 90

echo "== remove and install a small component (qrencode)"
had=$(apk info -e qrencode >/dev/null && echo 1 || echo 0)
if [ "$had" = 1 ]; then
	c pkg_run '{"action":"remove","packages":"qrencode"}' >/dev/null
	waitfor false running 60 && [ "$(code)" = 0 ] && ! apk info -e qrencode >/dev/null && ok "removed" || bad "remove: $(c pkg_job | head -c 400)"
	[ "$(comp qrencode installed)" = false ] && [ "$(comp qrencode available)" = true ] && ok "now: not installed, available" || bad "state after remove"
fi
c pkg_run '{"action":"install","packages":"qrencode"}' >/dev/null
waitfor false running 120 && [ "$(code)" = 0 ] && apk info -e qrencode >/dev/null && ok "installed" || bad "install: $(c pkg_job | head -c 400)"
[ "$(comp qrencode installed)" = true ] && ok "now: installed" || bad "state after install"

echo "== a feed out of reach (a PC's feed while the PC is off) does not stop the others"
L=/etc/apk/repositories.d/customfeeds.list
cp $L /tmp/t35-feeds
trap 'cp /tmp/t35-feeds $L; rm -f /tmp/t35-feeds' EXIT
echo http://127.0.0.1:9/feed/packages.adb >> $L
c pkg_run '{"action":"update"}' >/dev/null
waitfor false running 120 && [ "$(code)" = 0 ] && grep -q '127.0.0.1:9/feed' /tmp/detour/pkg/log && ok "update: done, the feed out of reach named" || bad "update: $(cat /tmp/detour/pkg/log | tail -5)"
c pkg_run '{"action":"remove","packages":"qrencode"}' >/dev/null
waitfor false running 60
c pkg_run '{"action":"install","packages":"qrencode"}' >/dev/null
waitfor false running 120 && [ "$(code)" = 0 ] && apk info -e qrencode >/dev/null && ok "install: done" || bad "install: $(tail -5 /tmp/detour/pkg/log)"
c pkg_run '{"action":"upgrade","packages":"qrencode"}' >/dev/null
waitfor false running 120 && [ "$(code)" = 0 ] && ! grep -q 'Not continuing' /tmp/detour/pkg/log && ok "upgrade: done" || bad "upgrade: $(tail -5 /tmp/detour/pkg/log)"
cp /tmp/t35-feeds $L
apk update -q >/dev/null 2>&1

echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
