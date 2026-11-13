#!/bin/sh
# Put the official AdGuard dnsproxy binary into a package root: tools/fetch-dnsproxy.sh <root> <version> <arch>
# Called by build-feed.sh for packages/dnsproxy (control: prepare=tools/fetch-dnsproxy.sh).
# The release has no checksum file, so the SHA-256 of the archive is pinned below per version (taken from the
# GitHub release asset digest). The archive is cached in build/dnsproxy-cache/ (not in git).
# Release binaries are static Go builds: one arm64 build runs on every aarch64_* OpenWrt target.
set -eu
ROOT=$1
VER=${2%-r*}
ARCH=$3
case "$ARCH" in
	aarch64_*) OS=linux-arm64 ;;
	x86_64) OS=linux-amd64 ;;
	*) echo "fetch-dnsproxy: no dnsproxy release for $ARCH"; exit 1 ;;
esac
case "$VER-$OS" in
	0.86.0-linux-arm64) want=eda840d39da0c2777ea2431d3d73407e813e3fc0e411bfe256a9fb4b97d08247 ;;
	*) echo "fetch-dnsproxy: no pinned SHA-256 for v$VER $OS; add it to $0"; exit 1 ;;
esac
ASSET=dnsproxy-$OS-v$VER.tar.gz
REPO=$(cd "$(dirname "$0")/.." && pwd)
CACHE=$REPO/build/dnsproxy-cache
mkdir -p "$CACHE"
[ -s "$CACHE/$ASSET" ] || curl -fsSL -o "$CACHE/$ASSET" "https://github.com/AdguardTeam/dnsproxy/releases/download/v$VER/$ASSET"
have=$(sha256sum "$CACHE/$ASSET" | cut -d' ' -f1)
if [ "$want" != "$have" ]; then
	echo "fetch-dnsproxy: $ASSET checksum mismatch (want $want, have $have)"
	rm -f "$CACHE/$ASSET"
	exit 1
fi
mkdir -p "$ROOT/usr/bin"
python3 -c 'import sys, tarfile; t = tarfile.open(sys.argv[1]); open(sys.argv[2], "wb").write(t.extractfile(sys.argv[3]).read())' \
	"$CACHE/$ASSET" "$ROOT/usr/bin/dnsproxy" "./$OS/dnsproxy"
chmod 755 "$ROOT/usr/bin/dnsproxy"
echo "fetch-dnsproxy: dnsproxy v$VER ($ASSET, sha256 $have)"
