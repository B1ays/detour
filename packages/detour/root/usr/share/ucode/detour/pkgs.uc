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
};

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

// the components a configuration needs: { id: true } - its engines, AmneziaWG exits, the router's encrypted DNS.
// c: a cursor with the detour config; protos: the proto of every exit interface (a backup has them apart)
export function needed(c, protos) {
	const out = {};
	c.foreach('detour', 'engine', (s) => { out[(s.type ?? 'singbox') == 'xray' ? 'xray' : 'singbox'] = true; });
	if (index(protos ?? [], 'amneziawg') >= 0) out.awg = true;
	const m = c.get('detour', 'main', 'dns');
	if (m == 'encrypted' || m == 'tunnel') out.dnsproxy = true;
	return out;
};

// the output of a command through a file: in the daemon a pipe read can be cut short by a signal (its probes'
// processes end all the time), and a long apk answer then came back empty now and then
let nout = 0;
function out_of(cmd) {
	fs.mkdir(RUN); fs.mkdir(D);
	const f = sprintf('%s/.out%d', D, ++nout);
	run(cmd + ' > ' + f + ' 2>/dev/null');
	const o = fs.readfile(f) ?? '';
	fs.unlink(f);
	return o;
}

// "apk list a b c" -> { name: { installed, upgrade, available } } (versions; the local index only)
function apk_state(list) {
	const st = {};
	for (let n in list) st[n] = { installed: null, upgrade: null, available: null };
	const out = out_of('apk list ' + join(' ', map(list, shq)));
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

// the components that are installed now, by id (the core ones too): { id: true }; one "apk list", no network
export function installed() {
	const st = apk_state(names()), out = {};
	for (let c in COMPONENTS) {
		const inst = filter(c.pkgs, (n) => st[n]?.installed);
		if (c.any ? length(inst) > 0 : length(inst) == length(c.pkgs)) out[c.id] = true;
	}
	return out;
};

// the packages that install these components: every missing package of one, or the first of an any-of one (the
// index decides after "apk update", so the first name it knows, else the first name)
export function packages_of(ids) {
	const st = apk_state(names()), out = [];
	for (let c in COMPONENTS) {
		if (index(ids, c.id) < 0 || c.core) continue;
		if (c.any) {
			if (length(filter(c.pkgs, (n) => st[n]?.installed))) continue;
			push(out, filter(c.pkgs, (n) => st[n]?.available || st[n]?.upgrade)[0] ?? c.pkgs[0]);
		}
		else for (let n in c.pkgs) if (!st[n]?.installed) push(out, n);
	}
	return out;
};

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
};

// "apk query" as JSON: [ { name, version, installed-size, file-size, status } ] (opts: --installed, --from
// repositories, --recursive: what an install takes with its dependencies)
function apk_query(opts, list) {
	if (!length(list)) return [];
	const o = out_of(sprintf('apk query %s --format json --fields name,version,installed-size,file-size,status %s', opts, join(' ', map(list, shq))));
	let j = null;
	try { j = json(o); } catch (e) { j = null; }
	return (type(j) == 'array') ? j : [];
}
const is_inst = (q) => index(q.status ?? [], 'installed') >= 0;

// the space where packages go (the root, or the overlay over it): { free, total } in bytes; df's numbers are
// counted from the end of its line (a long device name may come first)
function space() {
	const L = filter(split(trim(out_of('df -k /usr/lib')), '\n'), (l) => match(l, /[0-9]+%/));
	const f = split(trim(L[length(L) - 1] ?? ''), /\s+/), n = length(f);
	if (n < 5) return null;
	return { total: int(f[n - 5]) * 1024, free: int(f[n - 3]) * 1024 };
}

// the packages an install of a component takes: all its missing ones, or the first the index has (any)
function install_set(c, pk) {
	if (c.any) { const p = filter(pk, (x) => x.installed || x.available || x.upgrade)[0]; return p ? [ p.name ] : []; }
	return map(filter(pk, (x) => !x.installed), (x) => x.name);
}

// nlbwmon as the traffic counting saw it last (traffic.uc, every 5 min): ok | hung (its process is there and does
// not answer) | stopped; restarted: when Detour restarted it for not answering. null: not seen yet
function nlbw_service() {
	let s = null;
	try { s = json(fs.readfile(RUN + '/traffic/nlbwmon.json') ?? 'null'); } catch (e) { }
	if (!s) return null;
	return { state: s.running ? 'ok' : (s.process ? 'hung' : 'stopped'), restarted: s.restarted || null, ts: s.ts };
}

function list_now() {
	const st = apk_state(names());
	// the sizes: of what is installed, and of the repositories' versions (for an update)
	const isz = {}, rsz = {};
	for (let q in apk_query('--installed', names())) isz[q.name] = q;
	for (let q in apk_query('--from repositories', names())) rsz[q.name] = q;
	const out = [];
	for (let c in COMPONENTS) {
		const pk = map(c.pkgs, (n) => ({ name: n, ...st[n] }));
		const inst_pk = (l) => filter(l, (p) => p.installed);
		const inst = inst_pk(pk);
		const installed = c.any ? length(inst) > 0 : length(inst) == length(pk);
		// what an install takes: the first that the index has (any), or all of them
		const can = c.any ? length(filter(pk, (p) => p.installed || p.available || p.upgrade)) > 0
			: length(filter(pk, (p) => p.installed || p.available || p.upgrade)) == length(pk);
		const upgradable = length(filter(pk, (p) => p.upgrade)) > 0;
		// installed: what it takes now; not yet: what an install adds (with the dependencies not installed yet) and
		// downloads; an update: how much bigger it gets
		let size = 0, need = null, up = null;
		for (let p in inst) size += isz[p.name]?.['installed-size'] ?? 0;
		if (!installed && can) {
			const set = install_set(c, pk), rq = apk_query('--recursive', set);
			if (length(rq)) {
				need = { add: 0, download: 0, deps: [] };
				for (let q in rq) {
					if (is_inst(q)) continue;
					need.add += q['installed-size'] ?? 0;
					need.download += q['file-size'] ?? 0;
					if (index(set, q.name) < 0) push(need.deps, q.name);
				}
			}
		}
		if (installed && upgradable) {
			up = { add: 0, download: 0 };
			for (let p in pk) if (p.upgrade && rsz[p.name] && isz[p.name]) {
				up.add += max(0, (rsz[p.name]['installed-size'] ?? 0) - (isz[p.name]['installed-size'] ?? 0));
				up.download += rsz[p.name]['file-size'] ?? 0;
			}
		}
		push(out, { id: c.id, core: !!c.core, installed, available: can, upgradable,
			packages: pk, used: installed ? used_by(c.id) : [], size, need, upgrade_need: up,
			service: (c.id == 'nlbwmon' && installed) ? nlbw_service() : null });
	}
	return { components: out, index_ts: index_time(), space: space() };
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
};

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
};
