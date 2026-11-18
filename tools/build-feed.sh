#!/bin/sh
# Build every package in packages/*/ into a signed apk v3 feed with apk-tools 3. Packages are noarch unless
# their control sets arch=; prepare=<script> fills the package root first (sh <script> <root> <version> <arch>),
# e.g. tools/fetch-xray.sh puts in a release binary that is not kept in git.
# No OpenWrt SDK needed. Run as root on Linux (WSL: wsl -u root -- sh tools/build-feed.sh).
#   KEY   private ECDSA P-256 key (default /root/detour-keys/detour-dev.key, created if missing)
#   OUT   output dir (default <repo>/feed)
#   APK   apk-tools 3 binary (default: apk3, else apk)
#   PKGS  space-separated package directories to build (default: all)
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
KEY=${KEY:-/root/detour-keys/detour-dev.key}
OUT=${OUT:-$REPO/feed}
APK=${APK:-$(command -v apk3 || command -v apk)}
"$APK" --version | grep -q '^apk-tools 3' || { echo "need apk-tools 3"; exit 1; }
# the LuCI views: data by name, not by position (and their syntax, where node is installed)
sh "$REPO/tools/check-ui.sh" || exit 1

if [ ! -f "$KEY" ]; then
	mkdir -p "$(dirname "$KEY")"; umask 077
	openssl ecparam -name prime256v1 -genkey -noout -out "$KEY"
	openssl ec -in "$KEY" -pubout -out "${KEY%.key}.pem" 2>/dev/null
	echo "new signing key: $KEY (public: ${KEY%.key}.pem)"
fi

# build in a Linux filesystem: owners/modes are recorded as-is (/mnt/c has no real ownership)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
rm -rf "$OUT"; mkdir -p "$OUT"
for d in "$REPO"/packages/*/; do
	[ -f "$d/control" ] || continue
	# PKGS="detour luci-app-detour": only these (the public feed has no architecture-bound builds)
	if [ -n "${PKGS:-}" ]; then case " $PKGS " in *" $(basename "$d") "*) ;; *) continue;; esac; fi
	name= version= description= license= depends= arch=noarch prepare=
	while IFS='=' read -r k v; do
		case "$k" in name|version|description|license|depends|arch|prepare) eval "$k=\$v";; esac
	done < "$d/control"
	cp -a "$d" "$W/$name"
	P="$W/$name"
	mkdir -p "$P/root"
	[ -z "$prepare" ] || sh "$REPO/$prepare" "$P/root" "$version" "$arch"
	find "$P/root" -type d -exec chmod 755 {} +
	find "$P/root" -type f -exec chmod 644 {} +
	for x in "$P"/root/etc/init.d/* "$P"/root/usr/sbin/* "$P"/root/usr/bin/* "$P"/root/usr/libexec/*/* "$P"/root/etc/uci-defaults/* "$P"/scripts/*; do
		[ -f "$x" ] && chmod 755 "$x"
	done
	# LuCI translations: po/<lang>/<domain>.po -> /usr/lib/lua/luci/i18n/<domain>.<lang>.lmo (po2lmo from
	# tools/build-po2lmo.sh); LuCI merges every catalogue of the page language
	if [ -d "$P/po" ]; then
		command -v po2lmo >/dev/null || sh "$REPO/tools/build-po2lmo.sh" >/dev/null
		mkdir -p "$P/root/usr/lib/lua/luci/i18n"
		for po in "$P"/po/*/*.po; do
			lang=$(basename "$(dirname "$po")"); dom=$(basename "$po" .po)
			po2lmo "$po" "$P/root/usr/lib/lua/luci/i18n/$dom.$lang.lmo"
			chmod 644 "$P/root/usr/lib/lua/luci/i18n/$dom.$lang.lmo"
		done
		chmod 755 "$P/root/usr/lib" "$P/root/usr/lib/lua" "$P/root/usr/lib/lua/luci" "$P/root/usr/lib/lua/luci/i18n"
	fi
	chown -R root:root "$P"
	set -- -I "name:$name" -I "version:$version" -I "arch:$arch" -I "description:$description" -I "license:$license"
	[ -n "$depends" ] && set -- "$@" -I "depends:$depends"
	for s in post-install post-upgrade pre-deinstall post-deinstall pre-install pre-upgrade; do
		[ -f "$P/scripts/$s" ] && set -- "$@" -s "$s:$P/scripts/$s"
	done
	"$APK" mkpkg "$@" -F "$P/root" -o "$OUT/$name-$version.apk"
	echo "built $name-$version.apk"
done
"$APK" mkndx --allow-untrusted --sign-key "$KEY" -o "$OUT/packages.adb" "$OUT"/*.apk
cp "${KEY%.key}.pem" "$OUT/"
chmod 644 "$OUT/$(basename "${KEY%.key}.pem")"   # a key made here was written under umask 077
ls -la "$OUT"
