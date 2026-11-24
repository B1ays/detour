// WARP endpoint pool: the addresses (endpoint ip:port) a WARP exit can move to at once, each with the
// Cloudflare point (colo) and its country it led to, the ping and loss through it, when it last worked.
// The pure part (filters, ranking, merging scan results, rotation) is here; warppick.uc probes and scans.
//   working copy: /tmp/detour/warp-<exit>.pool.json (every change); on flash: /etc/detour/warp/<exit>.pool,
//   only when the set of addresses changed and not more often than once an hour (flash wear).
// Settings of a WARP exit (detour.<exit>, the old global main.warp_* still count when an exit has none):
//   warp_colo / warp_exclude_colo (default DME) / warp_country / warp_exclude_country - lists
//   warp_pool (size, 6), warp_pool_min (refill below it, 3), warp_check (s, 900), warp_scan_every (s, 21600),
//   warp_ports (list), warp_budget (s a scan may take, 150)
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { PERSIST, RUN } from 'detour.core';

export const PORTS = [ 891, 500, 1701, 4500, 854, 878, 894, 908, 2408 ];
export const NETS = [ '8.6.112', '8.34.70', '8.34.146', '8.35.211', '8.39.125', '8.39.204', '8.39.214', '8.47.69',
	'162.159.192', '162.159.195', '162.159.198', '162.159.199', '188.114.96', '188.114.97', '188.114.98', '188.114.99' ];
export const MAX_FAILS = 2;          // failed checks in a row: out of the pool
export const STALE = 3 * 86400;      // not confirmed for 3 days: out
const SAVE_EVERY = 3600;

export function as_list(v) {
	if (v == null) return [];
	return filter((type(v) == 'array') ? v : split(v, /[ \t\n,]+/), (x) => length(x));
};
function upper(l) { return map(l, (x) => uc(x)); }
function num(v, def, lo, hi) {
	const n = int(v ?? def);
	return (n >= lo && n <= hi) ? n : def;
}

// the settings of a WARP exit, with the defaults
export function settings_of(e, m) {
	m ??= {};
	const ex = e.warp_exclude_colo ?? m.warp_bad_colo ?? 'DME';
	const ports = as_list(e.warp_ports ?? m.warp_ports);
	return {
		colo: upper(as_list(e.warp_colo)),
		xcolo: upper(as_list(ex)),
		country: upper(as_list(e.warp_country)),
		xcountry: upper(as_list(e.warp_exclude_country)),
		size: num(e.warp_pool, 6, 1, 20),
		min: num(e.warp_pool_min, 3, 0, 20),
		check: num(e.warp_check ?? m.warp_check, 900, 0, 86400),
		scan_every: num(e.warp_scan_every, 21600, 600, 7 * 86400),
		budget: num(e.warp_budget ?? m.warp_pick_budget, 150, 20, 900),
		ports: length(ports) ? map(ports, (p) => int(p)) : PORTS,
		// lab: fixed candidate hosts, the probe URLs and the ping target inside the lab "WARP"
		hosts: as_list(m.warp_hosts),
		meta: m.warp_meta ?? 'https://speed.cloudflare.com/meta',
		trace: m.warp_trace ?? 'https://1.1.1.1/cdn-cgi/trace',
		ping: m.warp_ping ?? '1.1.1.1',
	};
};
export function settings(name) {
	const c = cursor();
	const e = c.get_all('detour', name);
	if (e?.['.type'] != 'exit' || e.warp != '1') return null;
	return settings_of(e, c.get_all('detour', 'main'));
};

// does a point pass the exit's filters? (an unknown country passes the exclusions, not an "only these")
export function passes(s, colo, country) {
	if (!colo) return false;
	colo = uc(colo); country = country ? uc(country) : null;
	if (index(s.xcolo, colo) >= 0) return false;
	if (length(s.colo) && index(s.colo, colo) < 0) return false;
	if (country && index(s.xcountry, country) >= 0) return false;
	if (length(s.country) && (!country || index(s.country, country) < 0)) return false;
	return true;
};
// why not, in words for the log and the page
export function why_not(s, colo, country) {
	if (!colo) return 'no point';
	if (index(s.xcolo, uc(colo)) >= 0 || (length(s.colo) && index(s.colo, uc(colo)) < 0)) return 'point ' + colo + ' filtered';
	return 'country ' + (country ?? '?') + ' filtered';
};

export function key(x) { return sprintf('%s:%d', x.host, x.port); };
export function parse_key(k) {
	const m = match(k ?? '', /^([0-9.]+):([0-9]+)$/);
	return m ? { host: m[1], port: int(m[2]) } : null;
};

// lower is better: the ping, a lost packet weighs as 20 ms; not measured yet - after the measured ones
export function rank(x) {
	return (x.ms ?? 1000) + (x.loss ?? 0) * 20 + (x.fails ?? 0) * 500;
};
export function sorted(pool) {
	return sort([ ...pool ], (a, b) => rank(a) - rank(b));
};

// one check of an entry (from a scan or a failover try) into the pool. r: { host, port, verdict, colo, country, ms, loss }
//   verdict pass: in (new) or updated; filtered / torn: out at once (the address now leads elsewhere, or DPI cuts it);
//   none / hs / error: one more failure (out after MAX_FAILS)
export function apply(pool, s, r, now) {
	const k = key(r);
	let e = null;
	for (let x in pool) if (key(x) == k) e = x;
	if (r.verdict == 'pass') {
		if (!e) { e = { host: r.host, port: r.port, src: r.src ?? 'scan', added: now }; push(pool, e); }
		e.colo = r.colo; e.country = r.country; e.fails = 0; e.ok = now; e.seen = now;
		if (r.ms != null) e.ms = r.ms;
		if (r.loss != null) e.loss = r.loss;
		return 'in';
	}
	if (!e) return null;
	e.seen = now;
	if (r.verdict == 'filtered' || r.verdict == 'torn') { e.drop = r.verdict; return 'out'; }
	e.fails = (e.fails ?? 0) + 1;
	if (e.fails >= MAX_FAILS) { e.drop = 'fails'; return 'out'; }
	return 'fail';
};

// a run's checks into the pool at once. When none of them got even a handshake, WARP itself (or the way to it) is
// down - not the addresses: nothing is counted against them, the pool stays for when WARP is back.
//   -> 'outage' | 'applied'
const HS = { pass: 1, filtered: 1, torn: 1, hs: 1 };
export function settle(pool, s, tries, now) {
	let any = false;
	for (let r in tries) if (HS[r.verdict]) any = true;
	if (!any && length(tries)) return 'outage';
	for (let r in tries) apply(pool, s, r, now);
	return 'applied';
};

// rotation: out what failed, what is stale, what no longer passes the filters (they may have changed);
// then the best <size>, the current address always kept while it works. Returns { pool, dropped: [entries] }
export function prune(pool, s, now, current) {
	const keep = [], dropped = [];
	for (let x in pool) {
		const cur = current && key(x) == current;
		if (x.drop || (!cur && x.ok && now - x.ok > STALE) || (!cur && x.ok == null && now - (x.added ?? now) > STALE)
				|| (x.colo && !passes(s, x.colo, x.country))) { x.drop ??= 'stale'; push(dropped, x); }
		else push(keep, x);
	}
	let out = sorted(keep);
	if (length(out) > s.size) {
		const extra = [];
		const top = [];
		for (let x in out) {
			if (length(top) < s.size || (current && key(x) == current)) push(top, x); else push(extra, x);
		}
		// the current one made the list longer: the worst of the rest goes
		while (length(top) > s.size) {
			let worst = null;
			for (let i = length(top) - 1; i >= 0; i--) if (!(current && key(top[i]) == current)) { worst = i; break; }
			if (worst == null) break;
			push(extra, splice(top, worst, 1)[0]);
		}
		for (let x in extra) { x.drop = 'worse'; push(dropped, x); }
		out = top;
	}
	return { pool: out, dropped };
};

// entries that worked (the ones a failover may use)
export function usable(pool, current) {
	return filter(sorted(pool), (x) => x.ok && !x.drop && key(x) != current);
};

// --- files ---
function run_file(name) { return sprintf('%s/warp-%s.pool.json', RUN, name); }
function flash_file(name) { return sprintf('%s/warp/%s.pool', PERSIST, name); }

export function load(name) {
	let st = null;
	try { st = json(fs.readfile(run_file(name))); } catch (x) { }
	if (type(st) == 'object' && type(st.entries) == 'array') return st;
	// after a reboot: the snapshot on flash (also the pool of the versions before: "host<TAB>port<TAB>colo")
	st = { entries: [], scan: 0, saved: 0, keys: '' };
	for (let l in split(fs.readfile(flash_file(name)) ?? '', '\n')) {
		const f = split(l, '\t');
		if (!match(f[0] ?? '', /^[0-9.]+$/) || !int(f[1])) continue;
		push(st.entries, { host: f[0], port: int(f[1]), colo: length(f[2] ?? '') ? f[2] : null, country: length(f[3] ?? '') ? f[3] : null,
			ms: length(f[4] ?? '') ? int(f[4]) : null, src: 'saved', added: time(), fails: 0 });
	}
	st.keys = join(' ', sort(map(st.entries, key)));
	return st;
};

export function save(name, st, force) {
	fs.mkdir(RUN);
	const tmp = run_file(name) + '.new';
	fs.writefile(tmp, sprintf('%J', st));
	fs.rename(tmp, run_file(name));
	const keys = join(' ', sort(map(st.entries, key)));
	if (keys == st.keys && !force) return false;
	if (!force && time() - (st.saved ?? 0) < SAVE_EVERY && fs.access(flash_file(name))) return false;
	fs.mkdir(PERSIST + '/warp');
	fs.writefile(flash_file(name), join('', map(st.entries, (x) =>
		sprintf('%s\t%d\t%s\t%s\t%s\n', x.host, x.port, x.colo ?? '', x.country ?? '', x.ms ?? ''))));
	st.saved = time(); st.keys = keys;
	fs.writefile(tmp, sprintf('%J', st));
	fs.rename(tmp, run_file(name));
	return true;
};

export function remove(name) {
	fs.unlink(run_file(name));
	fs.unlink(flash_file(name));
};
