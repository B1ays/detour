// LuCI "Components": the packages Detour can use, installed, upgraded and removed from LuCI.
// The state comes from apk's local index (no network: "apk list" of the known names, one call); an action
// runs detached from the daemon (/usr/libexec/detour/pkg: an upgrade of Detour itself restarts the daemon),
// one at a time, with its log and result in RUN/pkg.
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, shq, RUN } from 'detour.core';

const D = RUN + '/pkg';

// id: what LuCI names; pkgs: installed together; any: one of them is enough (tcpdump or tcpdump-mini);
// core: never removed from here; uses(c): what in the configuration needs it (shown before a removal)
export const COMPONENTS = [
	{ id: 'detour', pkgs: [ 'detour', 'luci-app-detour' ], core: true },
	{ id: 'singbox', pkgs: [ 'sing-box' ] },
	{ id: 'xray', pkgs: [ 'xray-core' ] },
	{ id: 'awg', pkgs: [ 'kmod-amneziawg', 'amneziawg-tools' ] },
	{ id: 'dnsproxy', pkgs: [ 'dnsproxy' ] },
	{ id: 'zlib', pkgs: [ 'ucode-mod-zlib' ] },
	{ id: 'qrencode', pkgs: [ 'qrencode' ] },
	{ id: 'tcpdump', pkgs: [ 'tcpdump-mini', 'tcpdump' ], any: true },
	{ id: 'nlbwmon', pkgs: [ 'nlbwmon' ], core: true },
];

// every package name LuCI may act on
export function names() {
	const out = [];
	for (let c in COMPONENTS) for (let p in c.pkgs) push(out, p);
	return out;
}

// what the configuration has that needs a component: [ { kind: exit | dns, name } ] (LuCI words them)
function used_by(id) {
	const c = cursor(), out = [];
	// an engine and the exit on its device; the exit's label is what people know
	const exit_of = (dev) => { let x = null; c.foreach('detour', 'exit', (e) => { if ((e.device ?? e.iface ?? e['.name']) == dev) x ??= e.label ?? e['.name']; }); return x; };
	if (id == 'singbox' || id == 'xray')
		c.foreach('detour', 'engine', (s) => {
			if (((s.type ?? 'singbox') == 'xray') == (id == 'xray')) push(out, { kind: 'exit', name: exit_of(s.device) ?? s['.name'] });
		});
	if (id == 'awg')
		c.foreach('network', 'interface', (s) => { if (s.proto == 'amneziawg') push(out, { kind: 'exit', name: exit_of(s['.name']) ?? s['.name'] }); });
	if (id == 'dnsproxy') {
		const m = c.get('detour', 'main', 'dns');
		if (m == 'encrypted' || m == 'tunnel') push(out, { kind: 'dns', name: m });
	}
	return out;
}

// "apk list a b c" -> { name: { installed, upgrade, available } } (versions; the local index only)
function apk_state(list) {
	const st = {};
	for (let n in list) st[n] = { installed: null, upgrade: null, available: null };
	const out = run('apk list ' + join(' ', map(list, shq)) + ' 2>/dev/null').out;
	for (let l in split(out, '\n')) {
		for (let n in list) {
			const m = match(l, regexp('^' + replace(n, /[.+]/g, '\\$&') + '-([0-9][^ ]*) '));
			if (!m) continue;
			if (index(l, '[installed]') >= 0) st[n].installed = m[1];
			else if (index(l, '[upgradable from:') >= 0) st[n].upgrade = m[1];
			else st[n].available ??= m[1];
		}
	}
	return st;
}

// when the package index was last downloaded (apk update), 0 = never
function index_time() {
	let t = 0;
	for (let f in fs.glob('/var/cache/apk/APKINDEX.*') ?? [])
		t = max(t, fs.stat(f)?.mtime ?? 0);
	return t;
}

export function job() {
	let s = null;
	try { s = json(fs.readfile(D + '/state.json') ?? 'null'); } catch (e) { s = null; }
	if (!s) return null;
	// a job that died without writing its end (a reboot, a kill) is not running; one the daemon has just started
	// has no pid yet (the job writes it) - for 20 s it counts as running, then as a start that failed
	if (s.running && s.pid && !fs.access('/proc/' + s.pid)) { s.running = false; s.code ??= -1; }
	if (s.running && !s.pid && time() - (s.started ?? 0) > 20) { s.running = false; s.code ??= -1; }
	const log = fs.readfile(D + '/log') ?? '';
	s.log = length(log) > 6000 ? '…' + substr(log, -6000) : log;
	return s;
}

function list_now() {
	const st = apk_state(names());
	const out = [];
	for (let c in COMPONENTS) {
		const pk = map(c.pkgs, (n) => ({ name: n, ...st[n] }));
		const inst = filter(pk, (p) => p.installed);
		const installed = c.any ? length(inst) > 0 : length(inst) == length(pk);
		// what an install takes: the first that the index has (any), or all of them
		const can = c.any ? length(filter(pk, (p) => p.installed || p.available || p.upgrade)) > 0
			: length(filter(pk, (p) => p.installed || p.available || p.upgrade)) == length(pk);
		push(out, { id: c.id, core: !!c.core, installed, available: can, upgradable: length(filter(pk, (p) => p.upgrade)) > 0,
			packages: pk, used: installed ? used_by(c.id) : [] });
	}
	return { components: out, index_ts: index_time() };
}

export function list() {
	// while an action runs apk's index is being replaced: "apk list" then misses packages - the last state read
	// before it is shown instead, with the job
	const j = job();
	if (j?.running) {
		let last = null;
		try { last = json(fs.readfile(D + '/list.json') ?? 'null'); } catch (e) { last = null; }
		if (last) { last.job = j; return last; }
	}
	const r = list_now();
	if (!j?.running) { fs.mkdir(RUN); fs.mkdir(D); fs.writefile(D + '/list.json', sprintf('%J', { ...r, job: null })); }
	r.job = j;
	return r;
}

// action: update | install | upgrade | remove; pkgs: names from COMPONENTS
export function start(action, pkgs) {
	if (index([ 'update', 'install', 'upgrade', 'remove' ], action) < 0) return { error: 'unknown action' };
	pkgs = (type(pkgs) == 'array') ? pkgs : split(pkgs ?? '', /[ ,]+/);
	pkgs = filter(pkgs, (p) => length(p));
	const known = names();
	for (let p in pkgs) if (index(known, p) < 0) return { error: 'not a package of Detour: ' + p };
	if (action != 'update' && !length(pkgs)) return { error: 'no package' };
	if (action == 'remove')
		for (let c in COMPONENTS) if (c.core) for (let p in pkgs) if (index(c.pkgs, p) >= 0) return { error: p + ' is not removed from here' };
	const j = job();
	if (j?.running) return { error: 'another action is running: ' + j.action + ' ' + j.packages };
	fs.mkdir(RUN); fs.mkdir(D);
	// "running" before the job starts: a second action asked for at once is refused (the job then writes its pid)
	fs.writefile(D + '/state.json', sprintf('%J', { action, packages: join(' ', pkgs), pid: 0, started: time(), running: true, code: null, finished: null }));
	// start-stop-daemon -b: detached, not a child of the daemon (its restart does not end the action)
	const r = run(sprintf('start-stop-daemon -S -b -x /usr/libexec/detour/pkg -- %s %s', shq(action), join(' ', map(pkgs, shq))));
	if (r.code != 0) { fs.unlink(D + '/state.json'); return { error: 'could not start: ' + trim(r.out) }; }
	return { started: true, action, packages: join(' ', pkgs) };
}
