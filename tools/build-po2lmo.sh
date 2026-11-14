#!/bin/sh
# Build po2lmo (LuCI's .po -> .lmo compiler) from the LuCI sources, once. Used by build-feed.sh to compile
# luci-app-detour's translations (po/<lang>/detour.po -> /usr/lib/lua/luci/i18n/detour.<lang>.lmo).
# Run as root in WSL: sh tools/build-po2lmo.sh   -> /usr/local/bin/po2lmo
# Layout as in luci master (modules/luci-base/src): po2lmo.c + lib/lmo.c + lib/plural_formula.y (lemon).
set -e
command -v po2lmo >/dev/null 2>&1 && { echo "po2lmo: $(command -v po2lmo)"; exit 0; }
command -v cc >/dev/null 2>&1 || { apt-get update -q >/dev/null; apt-get install -y -q gcc >/dev/null; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
B=https://raw.githubusercontent.com/openwrt/luci/master/modules/luci-base/src
mkdir -p "$W/lib" "$W/contrib"
for f in po2lmo.c lib/lmo.c lib/lmo.h lib/plural_formula.y contrib/lemon.c contrib/lempar.c; do
	curl -fsSL -o "$W/$f" "$B/$f"
done
cd "$W"
# gnu17: the old K&R-style prototypes of lemon.c are errors under C23, the default of GCC 15
cc -O2 -std=gnu17 -o contrib/lemon contrib/lemon.c
./contrib/lemon -q -Tcontrib/lempar.c lib/plural_formula.y
cc -O2 -std=gnu17 -I lib -o /usr/local/bin/po2lmo po2lmo.c lib/lmo.c lib/plural_formula.c
echo "po2lmo: /usr/local/bin/po2lmo"
