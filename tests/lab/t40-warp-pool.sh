#!/bin/sh
# WARP pool logic (warppool.uc) without tunnels: filters, ranking, rotation, the flash snapshot
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
cat > /tmp/t40.uc <<'EOF'
import * as P from 'detour.warppool';
const s = P.settings_of({}, {});
const s2 = P.settings_of({ warp_colo: 'hel arn', warp_exclude_country: 'SE' }, {});
const s3 = P.settings_of({ warp_country: 'FI', warp_pool: '2' }, { warp_bad_colo: 'DME WAW' });
const out = {};
out.dme = P.passes(s, 'DME', 'RU');
out.hel = P.passes(s, 'HEL', 'FI');
out.only_hel = P.passes(s2, 'HEL', 'FI');
out.only_waw = P.passes(s2, 'WAW', 'PL');
out.arn_se = P.passes(s2, 'ARN', 'SE');
out.country_unknown = P.passes(s3, 'HEL', null);
out.old_bad = P.passes(s3, 'WAW', 'FI');
// rotation
const pool = [];
P.apply(pool, s3, { host: '1.1.1.1', port: 500, verdict: 'pass', colo: 'HEL', country: 'FI', ms: 50, loss: 0 }, 1000);
P.apply(pool, s3, { host: '1.1.1.2', port: 500, verdict: 'pass', colo: 'HEL', country: 'FI', ms: 30, loss: 0 }, 1000);
P.apply(pool, s3, { host: '1.1.1.3', port: 500, verdict: 'pass', colo: 'HEL', country: 'FI', ms: 90, loss: 10 }, 1000);
out.f1 = P.apply(pool, s3, { host: '1.1.1.1', port: 500, verdict: 'none' }, 1100);
out.f2 = P.apply(pool, s3, { host: '1.1.1.1', port: 500, verdict: 'none' }, 1200);
out.torn = P.apply(pool, s3, { host: '1.1.1.2', port: 500, verdict: 'torn' }, 1200);
out.new_unknown_fail = P.apply(pool, s3, { host: '9.9.9.9', port: 500, verdict: 'none' }, 1200);
let r = P.prune(pool, s3, 1300, null);
out.after = map(r.pool, P.key);
out.dropped = map(r.dropped, (x) => P.key(x) + '/' + x.drop);
// size cut keeps the best, and always the current one
const p2 = [];
for (let i = 1; i <= 4; i++) P.apply(p2, s3, { host: '2.2.2.' + i, port: 500, verdict: 'pass', colo: 'HEL', country: 'FI', ms: i * 10, loss: 0 }, 1000);
r = P.prune(p2, s3, 1000, '2.2.2.4:500');
out.cut = map(r.pool, P.key);
// stale
const p3 = [ { host: '3.3.3.3', port: 500, colo: 'HEL', country: 'FI', ok: 1000, fails: 0 } ];
out.stale = length(P.prune(p3, s3, 1000 + P.STALE + 1, null).pool);
// a filter changed: entries that no longer pass leave
const p4 = [ { host: '4.4.4.4', port: 500, colo: 'ARN', country: 'SE', ok: 1000 } ];
out.refilter = length(P.prune(p4, s2, 1001, null).pool);
out.usable = map(P.usable(r.pool, '2.2.2.1:500'), P.key);
// a run where nothing got a handshake: WARP is down, not the addresses
const p5 = [ { host: '5.5.5.5', port: 500, colo: 'HEL', country: 'FI', ok: 1000, fails: 1 } ];
out.outage = P.settle(p5, s, [ { host: '5.5.5.5', port: 500, verdict: 'none' }, { host: '6.6.6.6', port: 500, verdict: 'none' } ], 1100);
out.outage_fails = p5[0].fails;
out.real = P.settle(p5, s, [ { host: '5.5.5.5', port: 500, verdict: 'none' }, { host: '6.6.6.6', port: 500, verdict: 'hs' } ], 1200);
out.real_drop = p5[0].drop;
printf('%J\n', out);
EOF
R=$(ucode /tmp/t40.uc 2>&1); rm -f /tmp/t40.uc
j() { echo "$R" | jsonfilter -e "$1" 2>/dev/null; }
[ "$(j @.dme)" = false ] && [ "$(j @.hel)" = true ] && ok "DME excluded by default" || bad "default filter: $R"
[ "$(j @.only_hel)" = true ] && [ "$(j @.only_waw)" = false ] && ok "only these points" || bad "colo list: $R"
[ "$(j @.arn_se)" = false ] && ok "country excluded" || bad "xcountry: $R"
[ "$(j @.country_unknown)" = false ] && ok "unknown country fails an 'only these countries'" || bad "country unknown: $R"
[ "$(j @.old_bad)" = false ] && ok "old main.warp_bad_colo still counts" || bad "old option: $R"
[ "$(j @.f1)" = fail ] && [ "$(j @.f2)" = out ] && ok "two failures in a row: out" || bad "fails: $R"
[ "$(j @.torn)" = out ] && ok "torn: out at once" || bad "torn: $R"
[ -z "$(j @.new_unknown_fail)" ] && ok "a failed new address is not added" || bad "new fail: $R"
[ "$(j '@.after[0]')" = 1.1.1.3:500 ] && [ "$(j '@.after[1]')" = "" ] && ok "pool after rotation: only the good one" || bad "after: $R"
[ "$(j '@.cut[0]')" = 2.2.2.1:500 ] && [ "$(j '@.cut[1]')" = 2.2.2.4:500 ] && [ "$(j '@.cut[2]')" = "" ] && ok "size 2: the best plus the current" || bad "cut: $R"
[ "$(j @.stale)" = 0 ] && ok "not confirmed for 3 days: out" || bad "stale: $R"
[ "$(j @.refilter)" = 0 ] && ok "changed filter applies to the pool" || bad "refilter: $R"
[ "$(j '@.usable[0]')" = 2.2.2.4:500 ] && ok "failover list skips the current one" || bad "usable: $R"
[ "$(j @.outage)" = outage ] && [ "$(j @.outage_fails)" = 1 ] && ok "no handshake at all: an outage, nothing counted" || bad "outage: $R"
[ "$(j @.real)" = applied ] && [ "$(j @.real_drop)" = fails ] && ok "another address shook hands: the failure counts" || bad "real failure: $R"
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
