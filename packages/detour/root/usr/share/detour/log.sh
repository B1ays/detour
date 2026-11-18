# The verbose log for the shell scripts: . /usr/share/detour/log.sh; vlog <area> <message>
# On while the daemon keeps /tmp/detour/log/on (main.log_level verbose, 24 h at most); only appends - the daemon
# rotates. A URL's query values are masked (a list's or a subscription's token).
vlog() {
	[ -e /tmp/detour/log/on ] || return 0
	printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" \
		"$(printf '%s' "$2" | tr '\n' ' ' | sed -E 's/([?&][A-Za-z0-9_.-]+=)[^& "]{8,}/\1***/g')" >> /tmp/detour/log/detour.log
}
