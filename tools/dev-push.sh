#!/bin/sh
# Dev loop (Git Bash on Windows): bump -rN of a package, rebuild the feed in WSL, upgrade it on the lab router.
# usage: tools/dev-push.sh [package]   (default detour)
set -e
cd "$(dirname "$0")/.."
P=${1:-detour}
LAB_KEY=${LAB_KEY:-../../qemu-owrt/lab_ed25519}   # the lab router's SSH key
C=packages/$P/control
v=$(sed -n 's/^version=//p' $C); base=${v%-r*}; r=${v##*-r}; nv="$base-r$((r+1))"
sed -i "s/^version=.*/version=$nv/" $C
# WSL starts in the current directory (the repository root, cd above)
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- sh tools/build-feed.sh >/dev/null
ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$LAB_KEY" -p 2222 root@127.0.0.1 \
	"apk update -q >/dev/null 2>&1; apk add -q $P >/dev/null 2>&1; apk upgrade -q $P 2>&1 | tail -3; apk info -e $P | head -1; apk list -I $P 2>/dev/null"
