// Detour routing: one table per exit, "ip rule fwmark" per exit, permanent unreachable.
// The tables are registered in /etc/iproute2/rt_tables as detour_<exit>, numbered after the last table in use
// (as pbr does); the rules sit at free priorities from RULE_PRIO_BASE on. Only what is ours is ever removed:
// a rule is ours by the table it looks up, never by its priority.
'use strict';

import * as fs from 'fs';
import { run, shq, marks, pol_mark, exit_mark, RULE_PRIO_BASE, UNREACH_METRIC } from 'detour.core';

const RT = '/etc/iproute2/rt_tables';
const PREFIX = 'detour_';
let cache = {};      // detour_<exit> -> table number

// rt_tables: { names: { name: num }, nums: { num: name }, lines: [ ... ] }
function rt_read() {
	const o = { names: {}, nums: {}, lines: split(fs.readfile(RT) ?? '', '\n') };
	for (let l in o.lines) {
		const m = match(trim(l), /^([0-9]+)[ \t]+([^ \t#]+)/);
		if (m) { o.names[m[2]] = int(m[1]); o.nums[m[1]] = m[2]; }
	}
	return o;
}

function rt_write(lines) {
	while (length(lines) && lines[length(lines) - 1] == '') pop(lines);
	fs.mkdir('/etc/iproute2');
	fs.writefile(RT + '.tmp', join('\n', lines) + '\n');
	fs.rename(RT + '.tmp', RT);
}

// a table number of "lookup X" (a number or a name from rt_tables)
function tnum(x, rt) { return match(x, /^[0-9]+$/) ? int(x) : (rt.names[x] ?? null); }

// every table some rule, route or rt_tables entry refers to (the next one of ours goes after the last)
function tables_in_use(rt) {
	const used = {};
	for (let n, nm in rt.nums) used[n] = true;
	for (let fam in [ '-4', '-6' ]) {
		for (let l in split(run('ip ' + fam + ' rule show').out, '\n')) {
			const m = match(l, /lookup ([^ ]+)/);
			if (m) { const t = tnum(m[1], rt); if (t != null) used[t] = true; }
		}
		for (let l in split(run('ip ' + fam + ' route show table all').out, '\n')) {
			const m = match(l, / table ([^ ]+)/);
			if (m) { const t = tnum(m[1], rt); if (t != null) used[t] = true; }
		}
	}
	return used;
}

// the table of an exit (an exit object or its name): registered once, then always the same number
export function table_of(ex) {
	const name = PREFIX + (type(ex) == 'object' ? ex.name : ex);
	if (cache[name]) return cache[name];
	const rt = rt_read();
	if (rt.names[name]) return cache[name] = rt.names[name];
	let top = 255;     // after local/main/default (253..255) at least
	for (let n in keys(tables_in_use(rt))) if (int(n) > top && int(n) < 0x7fffffff) top = int(n);
	const num = top + 1;
	push(rt.lines, sprintf('%d\t%s', num, name));
	rt_write(rt.lines);
	return cache[name] = num;
}

// our tables now: { num: exit name }
function our_tables(rt) {
	const o = {};
	for (let nm, n in rt.names) if (substr(nm, 0, length(PREFIX)) == PREFIX) o[n] = substr(nm, length(PREFIX));
	return o;
}

// fail-closed baseline: the table exists and is unreachable even when the exit device is gone
export function ensure_unreachable(ex) {
	return run(sprintf('ip route replace unreachable default metric %d table %d', UNREACH_METRIC, table_of(ex)));
}

export function dev_up(dev) {
	const op = fs.readfile(sprintf('/sys/class/net/%s/operstate', dev));
	const fl = fs.readfile(sprintf('/sys/class/net/%s/flags', dev));
	if (op == null) return false;
	// tun/wireguard report "unknown"; use IFF_UP
	return trim(op) == 'up' || (fl != null && (hex(trim(fl)) & 1) == 1);
}

export function ensure_route(ex) {
	ensure_unreachable(ex);
	if (!dev_up(ex.device)) return false;
	const r = run(sprintf('ip route replace default dev %s table %d', shq(ex.device), table_of(ex)));
	return r.code == 0;
}

export function drop_route(ex) {
	run(sprintf('ip route del default dev %s table %d', shq(ex.device), table_of(ex)));
	ensure_unreachable(ex);
}

// all IPv4 rules: [ { prio, mark, mask, table } ] (table: a number, or null for a name rt_tables does not know)
function rules_now(rt) {
	const out = [];
	for (let l in split(run('ip -4 rule show').out, '\n')) {
		const m = match(l, /^([0-9]+):/);
		if (!m) continue;
		const f = match(l, /fwmark (0x[0-9a-f]+)(\/(0x[0-9a-f]+))?/), t = match(l, /lookup ([^ ]+)/);
		push(out, { prio: int(m[1]), mark: f ? hex(f[1]) : null, mask: (f && f[3]) ? hex(f[3]) : null, table: t ? tnum(t[1], rt) : null });
	}
	return out;
}

// make "ip rule" match the exits exactly: our rules (by their table) that are not wanted go, missing ones are added
// at free priorities; the tables of removed exits are flushed and leave rt_tables
export function sync_rules(cfg) {
	const L = marks();
	const want = {};     // table -> exit mark
	for (let e in cfg.exits) want[table_of(e)] = exit_mark(e.id);
	const rt = rt_read();
	const ours = our_tables(rt);
	const busy = {}, have = {};
	for (let r in rules_now(rt)) {
		// a rule of the versions before named tables: priority 11000+N, table 1000+N, mark N<<16/0xff0000 - all
		// three at once, so no one else's rule matches; it goes with its table
		const n = r.prio - 11000;
		if (n >= 1 && n <= 250 && r.table == 1000 + n && r.mark == (n << 16) && r.mask == 0xff0000 && !ours[r.table]) {
			run(sprintf('ip rule del priority %d lookup %d', r.prio, r.table));
			run(sprintf('ip route flush table %d', r.table));
			continue;
		}
		busy[r.prio] = true;
		if (r.table == null || !ours[r.table]) continue;
		if (want[r.table] == null || r.mark != want[r.table] || r.mask != L.exit || have[r.table])
			run(sprintf('ip rule del priority %d lookup %d', r.prio, r.table));
		else have[r.table] = true;
	}
	let prio = RULE_PRIO_BASE;
	for (let t, mk in want) {
		if (have[t]) continue;
		prio++;
		while (busy[prio]) prio++;
		busy[prio] = true;
		run(sprintf('ip rule add fwmark 0x%x/0x%x lookup %d priority %d', mk, L.exit, int(t), prio));
	}
	// exits that are gone: their table empties and its name is released
	let lines = rt.lines, gone = false;
	for (let n, nm in ours) {
		if (want[n] != null) continue;
		run(sprintf('ip route flush table %d', int(n)));
		lines = filter(lines, (l) => !match(trim(l), regexp('^' + n + '[ \t]+' + PREFIX)));
		delete cache[PREFIX + nm];
		gone = true;
	}
	if (gone) rt_write(lines);
	for (let e in cfg.exits) ensure_unreachable(e);
}

// the AAAA answer for policy domains (dns.uc DISCARD6) must fail at once, also for LAN devices that
// have an IPv6 route through the router
export function discard6(on) {
	run(on ? 'ip -6 route replace unreachable 100::/64 metric 1' : 'ip -6 route del unreachable 100::/64 2>/dev/null');
}

// down (switched off, stopped, removed): our rules and routes go; forget = the table names leave rt_tables too
export function remove_all(forget) {
	const rt = rt_read();
	const ours = our_tables(rt);
	for (let r in rules_now(rt))
		if (r.table != null && ours[r.table]) run(sprintf('ip rule del priority %d lookup %d', r.prio, r.table));
	for (let n in keys(ours)) run(sprintf('ip route flush table %d', int(n)));
	if (forget && length(keys(ours))) {
		rt_write(filter(rt.lines, (l) => !match(trim(l), regexp('^[0-9]+[ \t]+' + PREFIX))));
		cache = {};
	}
	discard6(false);
}

// Flows that took no policy (ct mark 0, or "decided: directly") towards destinations / from devices that have just
// come under a policy. Unoffloaded, their next packet is classified anew and moves to the exit; offloaded
// (fw4 flowtable - BE7000: software for Wi-Fi and the engines' tun, PPE for wired ports) they keep going
// directly and never meet our rules again. Deleting the entry gives both cases the same outcome.
export function flush_unclassified(dsts, macs, ports, srcs) {
	const L = marks();
	// both kinds: never classified (0) and classified as "directly" (the cached decision)
	const del = (args) => { for (let v in [ 0, L.direct ]) run(sprintf('conntrack -D -m 0x%x/0x%x %s', v, L.both, args)); };
	let n = 0;
	// "1.2.3.0/24" -> [ "1.2.3.0", "255.255.255.0" ]
	const net4 = (d) => {
		const m = match(d, /^([0-9.]+)(\/([0-9]+))?$/);
		if (!m) return null;
		const len = (m[3] != null) ? int(m[3]) : 32;
		const v = (len == 0) ? 0 : ((0xffffffff << (32 - len)) & 0xffffffff);
		return [ m[1], sprintf('%d.%d.%d.%d', (v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255) ];
	};
	for (let d in dsts) { const x = net4(d); if (x) { del(sprintf('-d %s --mask-dst %s', x[0], x[1])); n++; } }
	for (let d in srcs ?? []) { const x = net4(d); if (x) { del(sprintf('-s %s --mask-src %s', x[0], x[1])); n++; } }
	if (length(macs)) {
		const neigh = run('ip -4 neigh show').out;
		for (let l in split(neigh, '\n')) {
			const x = match(l, /^([0-9.]+) .*lladdr ([0-9a-f:]+)/);
			if (x && index(macs, x[2]) >= 0) { del('-s ' + x[1]); n++; }
		}
	}
	for (let pp in ports ?? []) {
		const x = match(pp, /^(tcp|udp)\/([0-9]+)$/);   // "tcp/443"; ranges are left to expire
		if (x) { del(sprintf('-p %s --dport %s', x[1], x[2])); n++; }
	}
	return n;
}

export function flush_conntrack_exit(eid) {
	return run(sprintf('conntrack -D -m 0x%x/0x%x', exit_mark(eid), marks().exit));
}

// the flows of a policy through one exit (eid 0: those it opened directly while its exits were down)
export function flush_conntrack_policy(pid, eid) {
	return run(sprintf('conntrack -D -m 0x%x/0x%x', pol_mark(pid) | exit_mark(eid ?? 0), marks().both));
}

// probe an exit: ICMP through its device, or an HTTP(S) URL bound to the device
export function probe_cmd(ex, timeout) {
	const t = ex.probe;
	if (!t) return null;
	// run through sh to silence the output (it would go to the daemon's log via procd)
	if (match(t, /^https?:\/\//))
		return [ '/bin/sh', '-c', sprintf('curl -sf -o /dev/null -m %d --interface %s %s >/dev/null 2>&1', timeout ?? 8, shq(ex.device), shq(t)) ];
	return [ '/bin/sh', '-c', sprintf('ping -q -c 1 -W 2 -I %s %s >/dev/null 2>&1', shq(ex.device), shq(t)) ];
}
