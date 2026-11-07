#!/bin/sh
# a hung daemon (SIGSTOP: procd sees it alive) is restarted by the cron watchdog via the stale heartbeat
P=$(pgrep -f /usr/sbin/detourd); kill -STOP $P; t=$(date +%s)
i=0; while [ $i -lt 300 ]; do sleep 5; i=$((i+5)); N=$(pgrep -f /usr/sbin/detourd); [ -n "$N" ] && [ "$N" != "$P" ] && break; done
N=$(pgrep -f /usr/sbin/detourd)
if [ -n "$N" ] && [ "$N" != "$P" ]; then echo "  ok   hung daemon restarted after $(( $(date +%s) - t )) s"; echo "RESULT: PASS"; else kill -CONT $P; echo "  FAIL not restarted"; echo "RESULT: FAIL"; fi
logread | grep 'watchdog: heartbeat' | tail -1
