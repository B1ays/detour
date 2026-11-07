#!/bin/sh
# run.sh <name> [args] - fetch a lab test script to /tmp and run it from the file (not from a pipe:
# commands like ssh/apk read stdin and would swallow the rest of a piped script).
n=$1; shift
wget -qO /tmp/lab-$n http://10.0.2.2:8765/$n || { echo "fetch $n failed"; exit 1; }
sh /tmp/lab-$n "$@" < /dev/null
