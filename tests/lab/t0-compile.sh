#!/bin/sh
# every module and script of the installed package compiles; ucode reports such errors only at run time.
# Modules: loaded by an import (as the CLI/daemon load them; `ucode -c` would treat them as scripts).
FAIL=0
for f in /usr/share/ucode/detour/*.uc; do
	m=$(basename "$f" .uc)
	printf "import * as m from 'detour.%s';\n" "$m" > /tmp/t0.uc
	if ucode /tmp/t0.uc >/tmp/t0.err 2>&1; then echo "  ok   module $m"; else echo "  FAIL module $m: $(head -n 4 /tmp/t0.err | tr '\n' ' ')"; FAIL=1; fi
done
for f in /usr/sbin/detour /usr/sbin/detourd /usr/libexec/detour/* /etc/init.d/detour /etc/init.d/detour-fw; do
	case "$(head -n1 "$f")" in
	*ucode*) ucode -c -o /tmp/t0.bin "$f" >/tmp/t0.err 2>&1 ;;
	*) sh -n "$f" >/tmp/t0.err 2>&1 ;;
	esac && echo "  ok   $f" || { echo "  FAIL $f: $(head -n 4 /tmp/t0.err | tr '\n' ' ')"; FAIL=1; }
done
rm -f /tmp/t0.uc /tmp/t0.bin /tmp/t0.err
echo "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
