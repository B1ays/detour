// How much memory the big lists take and may take, so that they always fit and never fill the router.
// Measured on the lab (OpenWrt, dnsmasq-full, nftables), 100 000 entries each:
//   a domain: ~200 B in every dnsmasq instance (its nftset/address rules) + ~90 B of files in /tmp (the data and
//     the conf-dir file of every instance) -> counted as 300 B per instance;
//   a CIDR: ~200 B in the kernel's interval set + its data file -> counted as 250 B.
// Rounded up on purpose: erring high only refuses a list a little earlier.
// Two rules, both checked by lists-update for what a run adds (never for a list that stays as big as it was):
//   - after loading, a reserve stays free (main.lists_mem_reserve, MB; default 12 % of the RAM, 32 to 96 MB - a
//     fixed 64 MB floor took a quarter of a 256 MB router, which then had almost nothing for its lists);
//   - all lists together stay under a cap (main.lists_mem_max, MB; default half of what the reserve leaves).
// The cap holds even when MemAvailable is generous (right after a boot, before the engines have grown).
// A download is a moment, not a load: its raw text, the normalised copy and the sort live in /tmp only while the
// list is processed, so it may dip into the reserve down to TMP_FLOOR (unless the reserve was set by hand).
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { RUN } from 'detour.core';

const LISTS = RUN + '/lists';
const MB = 1048576;
const TMP_FLOOR = 24 * MB;
export const COST = { domain: 300, cidr: 250 };

function meminfo() {
	const m = {};
	for (let l in split(fs.readfile('/proc/meminfo') ?? '', '\n')) {
		const x = match(l, /^(MemTotal|MemAvailable):[ 	]+([0-9]+) kB/);
		if (x) m[x[1]] = int(x[2]) * 1024;
	}
	return { total: m.MemTotal ?? 0, avail: m.MemAvailable ?? 0 };
}

// domain lists are written into every dnsmasq instance's conf-dir and each instance keeps its own copy
export function instances() {
	let n = 0;
	cursor().foreach('dhcp', 'dnsmasq', () => { n++; });
	return n || 1;
};

export function cost(kind, n, inst) {
	n = int(n ?? 0);
	return (kind == 'domain') ? n * COST.domain * (inst ?? instances()) : n * COST.cidr;
};

function lines(f) {
	const fh = fs.open(f);
	if (!fh) return 0;
	let n = 0, b;
	while (length(b = fh.read(65536))) n += length(b) - length(replace(b, '\n', ''));
	fh.close();
	return n;
}

// what a list holds now (its data in RAM): { kind, n }. The count from its status (written with every change of
// the data; LuCI asks often and a big list is megabytes to count), else counted
export function current(name) {
	const data = sprintf('%s/%s.data', LISTS, name);
	if (!fs.access(data)) return { kind: 'cidr', n: 0 };
	const kind = trim(fs.readfile(sprintf('%s/%s.kind', LISTS, name)) ?? '') || 'cidr';
	let st = null;
	try { st = json(fs.readfile(sprintf('%s/%s.status', LISTS, name)) ?? 'null'); } catch (e) { }
	return { kind, n: (type(st?.count) == 'int') ? st.count : lines(data) };
};

function opt_mb(c, k) {
	const v = c.get('detour', 'main', k);
	return match(v ?? '', /^[0-9]+$/) ? int(v) * MB : null;
}

// the budget now: { total, avail, cap, reserve, used, left, per: { domain, cidr } } (bytes); used: the lists loaded
export function budget() {
	const c = cursor(), m = meminfo(), inst = instances();
	const own_reserve = opt_mb(c, 'lists_mem_reserve');
	const reserve = own_reserve ?? min(96 * MB, max(32 * MB, int(m.total * 0.12)));
	const cap = opt_mb(c, 'lists_mem_max') ?? int(max(0, m.total - reserve) / 2);
	let used = 0;
	for (let f in fs.glob(LISTS + '/*.data') ?? []) {
		const name = replace(replace(f, /^.*\//, ''), /\.data$/, '');
		if (c.get('detour', name) != 'list') continue;
		const cur = current(name);
		used += cost(cur.kind, cur.n, inst);
	}
	const left = max(0, min(cap - used, m.avail - reserve));
	return { total: m.total, avail: m.avail, cap, reserve, own_reserve: own_reserve != null, used, left, instances: inst,
		per: { domain: COST.domain * inst, cidr: COST.cidr } };
};

// MB with one decimal: what is needed rounded up, what is left rounded down (never "needs 2, 2 left")
function mb_up(b) { return sprintf('%.1f', int((b * 10 + MB - 1) / MB) / 10.0); }
function mb_down(b) { return sprintf('%.1f', int(b * 10 / MB) / 10.0); }

// what loading holds on top for a moment: an address set is rebuilt in one nft transaction (flush + add), so its
// old elements - of every list going to that target - live until the new ones are in; a domain list only writes
// its new files before the old ones go (dnsmasq stops before it starts again)
function transient(kind, n, target, inst) {
	if (kind != 'cidr') return n * 50 * inst;
	let t = 0;
	for (let f in fs.glob(LISTS + '/*.status') ?? []) {
		let st = null;
		try { st = json(fs.readfile(f)); } catch (e) { }
		if (st?.target != target || st?.kind != 'cidr') continue;
		const cur = current(st.name);
		if (cur.kind == 'cidr') t += cost('cidr', cur.n);
	}
	return t;
}

// may list <name> become <n> entries of <kind> (going to <target>: p<id> / direct)? accepted: bytes this run
// already let in (not yet seen in MemAvailable). null when it may, else the reason (English; LuCI and the
// notification translate it)
export function check(name, kind, n, target, accepted) {
	const b = budget();
	const old = current(name);
	const now = cost(kind, n, b.instances), was = cost(old.kind, old.n, b.instances);
	const delta = now - was;
	if (delta <= 0) return null;   // as big as before or smaller: never refused
	accepted = int(accepted ?? 0);
	const peak = transient(kind, int(n), target, b.instances);
	const by_cap = b.cap - b.used;   // b.used already holds the lists this run replaced
	const by_free = b.avail - b.reserve - accepted - peak;
	const room = max(0, min(by_cap, by_free));
	if (delta <= room) return null;
	// which rule refused, with its numbers (LuCI and the notification say it in words)
	const why = (by_cap <= by_free)
		? sprintf(' (cap: the lists may take %s MB, they take %s MB)', mb_down(b.cap), mb_up(b.used))
		: sprintf(' (free: %s MB free, %s MB stay free)', mb_down(b.avail - accepted - peak), mb_down(b.reserve));
	return sprintf('not enough memory: needs ~%s MB, %s MB left for lists', mb_up(delta), mb_down(room)) + why;
};

// what list <name> adds when it becomes <n> entries of <kind> (bytes, 0 when it does not grow)
export function delta(name, kind, n) {
	const inst = instances(), old = current(name);
	return max(0, cost(kind, n, inst) - cost(old.kind, old.n, inst));
};

// the biggest download a list may take now: its raw text sits in /tmp, the normalised copy next to it, and the sort
// holds it once more - a third of what is free above the floor (the reserve when set by hand, else TMP_FLOOR)
export function rawmax(accepted) {
	const b = budget();
	const floor = b.own_reserve ? b.reserve : min(b.reserve, TMP_FLOOR);
	return max(MB, min(256 * MB, int((b.avail - floor - int(accepted ?? 0)) / 3)));
};

// why a download was cut (the tail of its reason): what is free, and the reserve when it was set by hand
export function raw_why() {
	const b = budget();
	return b.own_reserve ? sprintf(' (free: %s MB free, %s MB stay free)', mb_down(b.avail), mb_down(b.reserve))
		: sprintf(' (free: %d MB free)', int(b.avail / MB));
};
