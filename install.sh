#!/bin/sh
# Detour quick install for OpenWrt 25.12+ (apk):
#   wget -qO- @FEED_URL@/install.sh | sh
# Adds the Detour feed and its signing key, replaces dnsmasq with dnsmasq-full (Detour needs its nftset
# support), installs detour and luci-app-detour. Run again to upgrade.
#   DETOUR_FEED   the feed URL (default: the one this script was published with)
#   DETOUR_NO_LUCI=1   install without the web interface
set -e
FEED=${DETOUR_FEED:-@FEED_URL@}
FEED=${FEED%/}
KEY=/etc/apk/keys/detour.pem
LIST=/etc/apk/repositories.d/customfeeds.list

say() { echo "detour: $*"; }
die() { echo "detour: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
[ -f /etc/openwrt_release ] || die "this is not OpenWrt"
command -v apk >/dev/null || die "needs OpenWrt 25.12 or a snapshot (apk); firmware with opkg is not supported"
case "$FEED" in @*|'') die "no feed URL: set DETOUR_FEED";; esac

say "feed: $FEED"
mkdir -p /etc/apk/keys /etc/apk/repositories.d
wget -qO /tmp/detour.pem.new "$FEED/detour.pem" || die "cannot download the signing key from $FEED"
grep -q 'BEGIN PUBLIC KEY' /tmp/detour.pem.new || die "the downloaded key is not a public key"
mv /tmp/detour.pem.new "$KEY"
grep -qxF "$FEED/packages.adb" "$LIST" 2>/dev/null || echo "$FEED/packages.adb" >> "$LIST"
apk update >/dev/null || die "apk update failed (no internet, or the feed is unreachable)"

# dnsmasq -> dnsmasq-full. While dnsmasq is away the router has no DNS of its own, so for the swap it asks
# the provider's servers directly; the stock resolver comes back right after (or on any failure).
if ! apk info -e dnsmasq-full >/dev/null 2>&1; then
	say "replacing dnsmasq with dnsmasq-full"
	R=/tmp/resolv.conf
	AUTO=$(ls /tmp/resolv.conf.d/resolv.conf.auto /tmp/resolv.conf.auto 2>/dev/null | head -n1)
	cp -L "$R" /tmp/resolv.conf.detour-save 2>/dev/null || true
	if [ -n "$AUTO" ] && grep -q '^nameserver' "$AUTO"; then
		grep '^nameserver' "$AUTO" > "$R.new" && mv "$R.new" "$R"
	else
		printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "$R.new" && mv "$R.new" "$R"
	fi
	restore() { [ -f /tmp/resolv.conf.detour-save ] && mv /tmp/resolv.conf.detour-save "$R"; }
	if ! { apk del dnsmasq >/dev/null && apk add dnsmasq-full >/dev/null; }; then
		apk add dnsmasq >/dev/null 2>&1 || true
		restore
		/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
		die "could not install dnsmasq-full; dnsmasq was put back"
	fi
	restore
	/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
fi

PKGS="detour luci-app-detour"
[ "${DETOUR_NO_LUCI:-0}" = 1 ] && PKGS=detour
if apk info -e detour >/dev/null 2>&1; then
	say "upgrading $PKGS"
	apk upgrade $PKGS
else
	say "installing $PKGS"
	apk add $PKGS
fi

say "done: $(apk list -I detour 2>/dev/null | cut -d' ' -f1)"
[ "$PKGS" = detour ] || say "open LuCI: Services -> Detour (log in again if LuCI was open)"
