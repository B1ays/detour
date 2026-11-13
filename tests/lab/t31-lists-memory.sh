#!/bin/sh
# Lists always fit in memory and never fill it (listmem.uc): with small limits set through main.lists_mem_max /
# lists_mem_reserve - a list that fits loads; one that does not stays empty and says why; two lists that fit
# alone but not together: the second is refused; an existing list that grows past the limit keeps its old data;
# a list that does not grow is never refused; a download over what memory can take is cut off; a boot (--restore)
# loads what was accepted before without asking. The budget is in "status" for LuCI.
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
T=/tmp/t31; rm -rf $T; mkdir -p $T
R=/tmp/detour/lists
POL=$(uci show detour | sed -n 's/^detour\.\([^.=]*\)=policy$/\1/p' | head -1)
st() { jsonfilter -i $R/$1.status -e "@.$2" 2>/dev/null; }
mk() { awk -v n=$2 -v p=$3 'BEGIN { for (i = 0; i < n; i++) printf "%s%d.example%d.org\n", p, i, i % 13 }' > $T/$1.txt; }
lst() { uci set detour.$1=list; uci set detour.$1.policy=$POL; uci set detour.$1.file=$T/$1.txt; uci set detour.$1.kind=domain; uci set detour.$1.min_lines=1; }
lim() { uci set detour.main.lists_mem_max=$1; uci set detour.main.lists_mem_reserve=$2; uci commit detour; }
upd() { /usr/libexec/detour/lists-update "$@" >/dev/null 2>&1; }
cleanup() {
	for s in ma mb mc; do uci -q delete detour.$s; done
	uci -q delete detour.main.lists_mem_max; uci -q delete detour.main.lists_mem_reserve; uci commit detour
	upd
}
cleanup
INST=$(detour lists-mem | jsonfilter -e '@.instances')
echo "policy $POL, dnsmasq instances $INST (a domain costs $((300 * INST)) B)"

echo "== the budget"
B=$(ubus call detour status | jsonfilter -e '@.lists_memory.left')
[ -n "$B" ] && [ "$B" -gt 0 ] && ok "status has lists_memory (left $((B / 1048576)) MB)" || bad "no lists_memory in status"
lim 2 64
L=$(detour lists-mem | jsonfilter -e '@.cap'); [ "$L" = 2097152 ] && ok "main.lists_mem_max sets the cap" || bad "cap $L"

echo "== fits, then two that fit alone but not together"
# a cap of 2 MB: ma = 3000 domains (~0.9 MB), mb = 4000 (~1.2 MB): each fits alone, both do not
mk ma 3000 a; mk mb 4000 b; lst ma; lst mb; uci commit detour
upd
[ "$(st ma ok)" = true ] && [ "$(wc -l < $R/ma.data)" = 3000 ] && ok "ma (0.9 MB of 2) loaded" || bad "ma: $(cat $R/ma.status)"
[ "$(st mb ok)" = false ] && [ ! -s $R/mb.data ] && echo "$(st mb message)" | grep -q '^not enough memory: needs ~1.2 MB, 1.1 MB left for lists' \
	&& ok "mb refused in the same run: $(st mb message)" || bad "mb: $(cat $R/mb.status)"
grep -q "b1.example" /tmp/dnsmasq.*.d/detour-list-mb.conf 2>/dev/null && bad "mb reached dnsmasq" || ok "nothing of mb in dnsmasq"

echo "== an existing list that grows past the limit keeps its old data"
uci -q delete detour.mb; uci commit detour
mk ma 8000 a; upd ma
[ "$(st ma ok)" = false ] && [ "$(wc -l < $R/ma.data)" = 3000 ] && [ "$(st ma count)" = 3000 ] \
	&& ok "ma grown to 8000: refused, its 3000 stay ($(st ma message))" || bad "ma grown: $(cat $R/ma.status)"

echo "== a list that does not grow is never refused"
mk ma 3000 a; lim 0 100000
upd ma
[ "$(st ma ok)" = true ] && ok "ma unchanged with a cap of 0 and a huge reserve: still loads" || bad "unchanged refused: $(cat $R/ma.status)"

echo "== the reserve: what must stay free"
lim 4000 100000
mk mc 500 c; lst mc; uci commit detour; upd mc
[ "$(st mc ok)" = false ] && echo "$(st mc message)" | grep -q '^not enough memory' && ok "a reserve bigger than the free memory refuses a new list" || bad "reserve: $(cat $R/mc.status)"

echo "== a download over what memory can take is cut off"
# a reserve of (free - 4 MB) leaves rawmax near its 1 MB floor (the free memory moves a little); a 12 MB file is over it
AV=$(awk '/MemAvailable/ {print int($2 / 1024)}' /proc/meminfo)
lim 4000 $((AV - 4))
awk 'BEGIN { for (i = 0; i < 550000; i++) printf "big%d.example.org\n", i }' > $T/big.txt
uci -q delete detour.mc.file; uci -q delete detour.mc.url; uci add_list detour.mc.url=file://$T/big.txt; uci commit detour
upd mc
echo "$(st mc message)" | grep -qE '^download too big for the memory: over [0-9]+ MB' && [ ! -s $R/mc.data ] && ok "cut off: $(st mc message)" || bad "big download: $(cat $R/mc.status)"
ls $R/mc.raw $R/mc.new 2>/dev/null && bad "work files left" || ok "no work files left"

echo "== boot (--restore) loads what was accepted before, whatever the limits"
lim 0 100000
rm -f $R/ma.data
upd --restore
[ -s $R/ma.data ] && [ "$(wc -l < $R/ma.data)" = 3000 ] && ok "ma restored from its snapshot with a cap of 0" || bad "restore: $(cat $R/ma.status)"

echo "== the reason in words (notification)"
grep -q "не хватает памяти роутера" /usr/share/ucode/detour/watch.uc && ok "the notification has the Russian reason" || bad "no reason text"

echo "== cleanup"
cleanup
[ -z "$(uci -q get detour.ma)$(uci -q get detour.main.lists_mem_max)" ] && [ ! -e $R/ma.data ] && ok "test lists and limits removed" || bad "left"
rm -rf $T
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
