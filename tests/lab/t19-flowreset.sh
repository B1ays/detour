#!/bin/sh
# A destination / device that comes under a policy: its direct flows (ct mark "decided: directly") are reset, so that the next
# packets are classified. On the BE7000 offloaded flows (fw4 flowtable: software for Wi-Fi and the engines'
# tun, PPE for wired ports) otherwise keep going directly - seen on the real router: a running download
# stayed on the WAN after a policy for its address was added. In the lab nothing is offloaded; what is
# checked is the reset itself and that the flow then carries the policy mark.
CL=192.168.1.145
cl() { ssh -y -i /root/.ssh/id_dropbear root@$CL "$@" 2>/dev/null; }
FAIL=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; FAIL=1; }
waitfor() { i=0; while [ $i -lt ${3:-15} ]; do [ "$(eval "$2")" = "$1" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }
D=208.67.222.222   # in no lab policy (9.9.9.9 is in "vpn")
mark() { conntrack -L -p icmp -s $CL -d $D 2>/dev/null | sed -n 's/.*mark=\([0-9]*\).*/\1/p' | head -1; }
cleanup() { uci -q delete detour.tfr; uci commit detour; ubus call detour reload >/dev/null; }
cleanup; conntrack -D -d $D >/dev/null 2>&1
cl "nohup ping -c 60 -i 0.5 $D >/dev/null 2>&1 </dev/null &"
# the decision for a flow no policy takes is cached in its ct mark (0xff00 with the default layout): classified once
waitfor $((0xff << 8)) "mark" 10 && ok "direct flow to $D, decided once: mark 0xff00" || bad "direct flow mark: '$(mark)'"
echo "== policy for $D through warp"
uci -q batch <<'U'
set detour.tfr=policy
set detour.tfr.id=19
add_list detour.tfr.exit=warp
add_list detour.tfr.dst=208.67.222.0/24
commit detour
U
ubus call detour reload >/dev/null
logread | tail -20 | grep -q 'new under a policy: 1 destinations' && ok "reset logged" || bad "no reset event"
waitfor $(( (1 << 16) | (19 << 8) )) "mark" 10 && ok "the flow now carries the policy mark ($(mark))" || bad "mark: '$(mark)'"
echo "== reload without changes: nothing reset"
n=$(logread | grep -c 'new under a policy')
ubus call detour reload >/dev/null
[ "$(logread | grep -c 'new under a policy')" = "$n" ] && ok "no reset on an unchanged reload" || bad "reset on an unchanged reload"
cleanup
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
