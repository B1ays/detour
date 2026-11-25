#!/bin/sh
# nlbwmon that hangs (its process is there, nlbw gets no answer - OpenWrt 25.12 after many reloads) is restarted by
# Detour after two silent checks; LuCI Components and the traffic page say so instead of "not running".
# The checks run in one ucode process, as in the daemon (the count of silent checks lives in the module).
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
S=/tmp/detour/traffic/nlbwmon.json
js() { jsonfilter -i $S -e "@.$1" 2>/dev/null; }
[ -x /usr/sbin/nlbwmon ] || { echo "  skip: no nlbwmon"; echo "RESULT: PASS"; exit 0; }
/etc/init.d/nlbwmon restart; sleep 2
cat > /tmp/t41.uc <<'EOF'
import * as t from 'detour.traffic';
import * as fs from 'fs';
const S = '/tmp/detour/traffic/nlbwmon.json';
const st = () => json(fs.readfile(S));
const out = {};
t.nlbw_check(); out.a = st();
const P = trim(fs.readfile('/tmp/t41.pid') ?? '');
system('kill -STOP ' + P);
t.nlbw_check(); out.b = st();
t.nlbw_check(); out.c = st();
for (let i = 0; i < 10; i++) { system('sleep 1'); t.nlbw_check(); out.d = st(); if (out.d.running) break; }
printf('%J\n', out);
EOF
pidof nlbwmon > /tmp/t41.pid; P=$(cat /tmp/t41.pid)
R=$(ucode /tmp/t41.uc 2>/dev/null | tail -n 1)   # "Terminated" of the waits that ran out goes to stderr
j() { echo "$R" | jsonfilter -e "$1" 2>/dev/null; }
[ "$(j @.a.running)" = true ] && ok "running, answers" || bad "a: $R"
[ "$(j @.b.hung)" = true ] && [ "$(j @.b.restarted)" = 0 ] && ok "first silent check: hung, not restarted yet" || bad "b: $R"
[ "$(j @.c.restarted)" -gt 0 ] 2>/dev/null && ok "second silent check: restarted" || bad "c: $R"
N=$(pidof nlbwmon); [ -n "$N" ] && [ "$N" != "$P" ] && ok "a new nlbwmon ($P -> $N)" || { bad "same process ($P -> $N)"; kill -CONT $P 2>/dev/null; }
[ "$(j @.d.running)" = true ] && ok "answers again" || bad "d: $R"
logread | tail -30 | grep -q "nlbwmon does not answer: restarted" && ok "logged" || bad "no log line"

echo "== Components shows it"
ubus -t 60 call detour pkg_list > /tmp/t41.json 2>/dev/null
[ "$(jsonfilter -i /tmp/t41.json -e '@.components[@.id="nlbwmon"].service.state')" = ok ] && ok "service state ok" || bad "pkg_list: $(jsonfilter -i /tmp/t41.json -e '@.components[@.id="nlbwmon"].service')"

echo "== stopped"
/etc/init.d/nlbwmon stop
ucode -e "import * as t from 'detour.traffic'; t.nlbw_check();"
[ "$(js process)" = false ] && [ "$(js hung)" = false ] && ok "stopped is not hung" || bad "stopped: $(cat $S)"
/etc/init.d/nlbwmon start; sleep 2
ucode -e "import * as t from 'detour.traffic'; t.nlbw_check();"
rm -f /tmp/t41.uc /tmp/t41.pid /tmp/t41.json
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
