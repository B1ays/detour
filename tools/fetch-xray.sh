#!/bin/sh
# Put the official Xray binary into a package root: tools/fetch-xray.sh <root> <version> <arch>
# Called by build-feed.sh for packages/xray-core (control: prepare=tools/fetch-xray.sh).
# Downloads the XTLS release zip for the CPU, checks it against the SHA2-256 from the release's .dgst file,
# and installs xray as <root>/usr/bin/xray. The zip is cached in build/xray-cache/ (not in git).
# The release binaries are static Go builds: one arm64 build runs on every aarch64_* OpenWrt target.
set -eu
ROOT=$1
VER=${2%-r*}
ARCH=$3
case "$ARCH" in
	aarch64_*) ASSET=Xray-linux-arm64-v8a.zip ;;
	x86_64) ASSET=Xray-linux-64.zip ;;
	*) echo "fetch-xray: no Xray release for $ARCH"; exit 1 ;;
esac
REPO=$(cd "$(dirname "$0")/.." && pwd)
CACHE=$REPO/build/xray-cache/v$VER
URL=https://github.com/XTLS/Xray-core/releases/download/v$VER/$ASSET
mkdir -p "$CACHE"
[ -s "$CACHE/$ASSET.dgst" ] || curl -fsSL -o "$CACHE/$ASSET.dgst" "$URL.dgst"
[ -s "$CACHE/$ASSET" ] || curl -fsSL -o "$CACHE/$ASSET" "$URL"
want=$(sed -n 's/^SHA2-256= *\([0-9a-f]\{64\}\).*/\1/p' "$CACHE/$ASSET.dgst" | head -1)
have=$(sha256sum "$CACHE/$ASSET" | cut -d' ' -f1)
if [ -z "$want" ] || [ "$want" != "$have" ]; then
	echo "fetch-xray: $ASSET checksum mismatch (want ${want:-none}, have $have)"
	rm -f "$CACHE/$ASSET" "$CACHE/$ASSET.dgst"
	exit 1
fi
mkdir -p "$ROOT/usr/bin"
python3 -c 'import sys, zipfile; open(sys.argv[2], "wb").write(zipfile.ZipFile(sys.argv[1]).read("xray"))' \
	"$CACHE/$ASSET" "$ROOT/usr/bin/xray"
chmod 755 "$ROOT/usr/bin/xray"
echo "fetch-xray: Xray v$VER ($ASSET, sha256 $have)"
