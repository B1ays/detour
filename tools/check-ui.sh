#!/bin/sh
# Checks of the LuCI views before a build (tools/build-feed.sh and tools/dev-push.sh run it; it stops them):
#  - a page's data by name, never by position: data[<digit>] and Promise.all are refused in the views and the shared
#    modules (detour/load.js: pdata.all({ name: promise, ... })). With an array, removing one part silently gave
#    every later part the next one's data (the router DNS mode said "install dnsproxy" with dnsproxy installed).
#  - the syntax of every .js (node --check), when node is there.
# usage: sh tools/check-ui.sh
cd "$(dirname "$0")/.." || exit 1
R=packages/luci-app-detour/root/www/luci-static/resources
fail=0
bad() { echo "check-ui: $*"; fail=1; }

# the views and the shared modules, but not load.js itself (it is where Promise.all belongs)
FILES=$(ls $R/view/detour/*.js $R/detour/*.js | grep -v '/detour/load\.js$')
for f in $FILES; do
	grep -n 'data\[[0-9]' "$f" | while IFS= read -r l; do echo "check-ui: $f:${l%%:*}: data by position - use a named part (pdata.all)"; done
	grep -n 'Promise\.all *(' "$f" | while IFS= read -r l; do echo "check-ui: $f:${l%%:*}: Promise.all - use pdata.all({ name: promise, ... }) (detour/load.js)"; done
done | { out=$(cat); [ -z "$out" ] || { echo "$out"; exit 1; }; } || fail=1

if command -v node >/dev/null 2>&1; then
	for f in $R/view/detour/*.js $R/detour/*.js; do
		node --check "$f" 2>/dev/null || bad "$f: syntax error ($(node --check "$f" 2>&1 | grep -m1 -E 'Error'))"
	done
else
	echo "check-ui: no node here - syntax not checked"
fi

[ $fail = 0 ] && echo "check-ui: ok" || exit 1
