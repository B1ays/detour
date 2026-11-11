// "What does the device ask for": its DNS queries for a few minutes, caught by tcpdump on the home networks.
// Nothing runs and nothing is written while nobody watches; dnsmasq is not touched. One device at a time.
// Seen: the device's queries to any DNS server over plain DNS (port 53, also past the router). Not seen:
// encrypted DNS (DoH in a browser looks like any HTTPS); DoT (port 853) is noticed and reported.
'use strict';

import * as fs from 'fs';
import * as uloop from 'uloop';
import * as core from 'detour.core';
import * as traffic from 'detour.traffic';

const DIR = core.RUN + '/dnswatch';
const MAX_S = 600;

let w = null;   // { mac, started, until, procs: [ uloop.process ], files: [] }

export function available() { return !!fs.access('/usr/bin/tcpdump') || !!fs.access('/usr/sbin/tcpdump'); }

export function stop() {
	if (!w) return { ok: true };
	for (let p in w.procs) { const pid = p.pid(); if (pid) core.run('kill ' + pid + ' 2>/dev/null'); }
	w.procs = [];
	w.until = time();
	return { ok: true };
}

export function start(mac, seconds) {
	mac = lc(mac ?? '');
	if (!match(mac, /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/)) return { error: 'bad mac' };
	if (!available()) return { error: 'no tcpdump' };
	const devs = keys(traffic.home_devs() ?? {});
	if (!length(devs)) return { error: 'no home network' };
	seconds = int(seconds ?? 120);
	if (seconds < 10) seconds = 10;
	if (seconds > MAX_S) seconds = MAX_S;
	stop();
	fs.mkdir(core.RUN); fs.mkdir(DIR);
	for (let f in fs.glob(DIR + '/*') ?? []) fs.unlink(f);
	const t = time();
	w = { mac, started: t, until: t + seconds, procs: [], files: [] };
	// the queries this device sends (plain DNS, UDP and TCP) and the start of its DoT connections
	const filter = sprintf('ether src %s and (udp dst port 53 or tcp dst port 53 or (tcp dst port 853 and tcp[tcpflags] & tcp-syn != 0))', mac);
	for (let d in devs) {
		// a bridge port carries the bridge's traffic too: only the top devices (the bridge itself) are watched
		if (fs.access('/sys/class/net/' + d + '/brport')) continue;
		const f = sprintf('%s/%s.txt', DIR, d);
		push(w.files, f);
		// exec: the process uloop knows is tcpdump itself (busybox timeout execs the command), so stop() reaches it
		const p = uloop.process('/bin/sh', [ '-c', sprintf('exec timeout %d tcpdump -i %s -n -l -tt -s 512 -c 20000 %s > %s 2>/dev/null',
			seconds, core.shq(d), core.shq(filter), f) ], {}, function() { });
		if (p) push(w.procs, p);
	}
	if (!length(w.procs)) { w = null; return { error: 'tcpdump did not start' }; }
	return { ok: true, mac, until: w.until, seconds };
}

// the names asked, most asked first: { name, n, types, first, last }
export function log(mac) {
	mac = lc(mac ?? '');
	if (!w || (length(mac) && w.mac != mac)) return { running: false, mac: w?.mac, queries: [] };
	const q = {};
	let dot = 0, total = 0;
	for (let f in w.files) {
		const fh = fs.open(f);
		if (!fh) continue;
		let l;
		while ((l = fh.read('line')) != null && length(l)) {
			if (match(l, /\.853: Flags \[S\]/)) { dot++; continue; }
			const m = match(l, /^([0-9]+)\.[0-9]+ .* ([A-Z0-9]+)\? ([^ ]+)\. /);
			if (!m) continue;
			const name = lc(m[3]);
			const t = int(m[1]);
			total++;
			const e = (q[name] ??= { name, n: 0, types: [], first: t, last: t });
			e.n++; e.last = t;
			if (index(e.types, m[2]) < 0) push(e.types, m[2]);
		}
		fh.close();
	}
	const list = sort(values(q), (a, b) => (b.n - a.n) || (b.last - a.last));
	return { running: time() < w.until && length(w.procs) > 0, mac: w.mac, started: w.started, until: w.until, now: time(),
		total, dot, queries: list };
}
