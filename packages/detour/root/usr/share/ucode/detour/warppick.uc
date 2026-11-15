// WARP: away from DME. Stock finding (warp.sh, spring 2026): Cloudflare's Moscow point (DME) filters by
// destination, and from Russia most anycast addresses land there. A config cannot ask for a colo - only
// the endpoint address/port changes where it lands. So: ask the tunnel itself (https://1.1.1.1/cdn-cgi/trace
// answers warp=on and colo=XXX only through WARP); if the colo is unwanted or the trace fails although
// the tunnel shakes hands, try other endpoints and keep the first that lands elsewhere.
//   candidates: the current address on other ports -> the pool of addresses that worked before ->
//   one address of each WARP anycast /24. A pass on an unwanted colo is kept only as the last resort.
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, shq, log, PERSIST, RUN } from 'detour.core';

const TRACE = 'https://1.1.1.1/cdn-cgi/trace';
const PORTS = [ 891, 500, 1701, 4500, 854, 878, 894, 908, 2408 ];
const POOLS = [ '8.6.112', '8.34.70', '8.34.146', '8.35.211', '8.39.125', '8.39.204', '8.39.214', '8.47.69',
	'162.159.192', '162.159.195', '162.159.198', '162.159.199', '188.114.96', '188.114.97', '188.114.98', '188.114.99' ];
const POOL_MAX = 10;

function as_list(v) { return (v == null) ? [] : ((type(v) == 'array') ? v : split(v, /\s+/)); }

function settings(name) {
	const c = cursor();
	const m = c.get_all('detour', 'main') ?? {};
	const e = c.get_all('detour', name);
	if (e?.['.type'] != 'exit' || e.warp != '1') return null;
	const iface = e.iface ?? name;
	const proto = c.get('network', iface, 'proto');
	const ptype = (proto == 'amneziawg') ? 'amneziawg_' + iface : 'wireguard_' + iface;
	let peer = null;
	c.foreach('network', ptype, (s) => { if (!peer) peer = s; });
	if (!peer) return null;
	return {
		name, iface, dev: e.device ?? iface, peer_sec: peer['.name'], ptype,
		tool: (proto == 'amneziawg') ? 'awg' : 'wg',
		pub: peer.public_key, host: peer.endpoint_host, port: int(peer.endpoint_port ?? 2408),
		trace: m.warp_trace ?? TRACE,
		bad: as_list(m.warp_bad_colo ?? 'DME'),
		ports: length(as_list(m.warp_ports)) ? map(as_list(m.warp_ports), (p) => int(p)) : PORTS,
		// lab: full candidate addresses instead of one random host per anycast /24
		hosts: as_list(m.warp_hosts),
		budget: int(m.warp_pick_budget ?? 90),
	};
}

export function trace(s) {
	const r = run(sprintf('curl -s -m 6 --interface %s %s', shq(s.dev), shq(s.trace)));
	const warp = match(r.out, /(^|\n)warp=([a-z]+)/), colo = match(r.out, /(^|\n)colo=([A-Z0-9]+)/);
	return { ok: warp?.[2] == 'on' || warp?.[2] == 'plus', colo: colo?.[2] };
};

function handshake(s) {
	const r = run(sprintf('%s show %s latest-handshakes', s.tool, shq(s.dev)));
	const m = match(r.out, /\t([0-9]+)/);
	return m ? int(m[1]) : 0;
}

// Changing only the endpoint keeps the old session keys: another WARP point does not know that session,
// so nothing would pass until WireGuard gives up on it (~15 s). Re-creating the peer drops the session
// and the next packet starts a fresh handshake with the new point.
function set_endpoint(s, host, port) {
	run(sprintf('%s set %s peer %s remove', s.tool, shq(s.dev), shq(s.pub)));
	return run(sprintf('%s set %s peer %s endpoint %s:%d allowed-ips 0.0.0.0/0 persistent-keepalive 25',
		s.tool, shq(s.dev), shq(s.pub), shq(host), port)).code == 0;
}

// one candidate: new endpoint -> wait for a handshake newer than the switch -> trace
function try_one(s, host, port) {
	const t0 = time();
	if (!set_endpoint(s, host, port)) return { verdict: 'error' };
	// ping through the tunnel kicks the handshake
	run(sprintf('ping -q -c 1 -W 1 -I %s 1.1.1.1 >/dev/null 2>&1', shq(s.dev)));
	let hs = 0;
	for (let i = 0; i < 5 && hs < t0; i++) { hs = handshake(s); if (hs < t0) system('sleep 1'); }
	if (hs < t0) return { verdict: 'none' };
	const t = trace(s);
	if (!t.ok) return { verdict: 'hs' };
	return { verdict: 'pass', colo: t.colo };
}

function pool_file(name) { return sprintf('%s/warp/%s.pool', PERSIST, name); }
function pool_read(name) {
	const out = [];
	for (let l in split(fs.readfile(pool_file(name)) ?? '', '\n')) {
		const f = split(l, '\t');
		if (match(f[0] ?? '', /^[0-9.]+$/)) push(out, { host: f[0], port: int(f[1]), colo: f[2] });
	}
	return out;
}
function pool_add(name, host, port, colo) {
	let p = filter(pool_read(name), (x) => !(x.host == host && x.port == port));
	unshift(p, { host, port, colo });
	p = slice(p, 0, POOL_MAX);
	fs.mkdir(PERSIST + '/warp');
	fs.writefile(pool_file(name), join('', map(p, (x) => sprintf('%s\t%d\t%s\n', x.host, x.port, x.colo ?? ''))));
}

function persist(s, host, port) {
	const c = cursor();
	c.set('network', s.peer_sec, 'endpoint_host', host);
	c.set('network', s.peer_sec, 'endpoint_port', '' + port);
	c.commit('network');   // no reload: the running tunnel already uses it, the next ifup too
}

function bad_colo(s, colo) { return colo == null || index(s.bad, colo) >= 0; }

// check and, when needed, move the WARP exit <name>. Returns { colo, moved, endpoint, tried, note }.
export function pick(name, force) {
	const s = settings(name);
	if (!s) return { error: name + ' is not a WARP exit' };
	fs.mkdir(RUN);
	const cur = trace(s);
	if (cur.ok && !bad_colo(s, cur.colo) && !force) {
		pool_add(name, s.host, s.port, cur.colo);
		fs.writefile(sprintf('%s/warp-%s.colo', RUN, name), cur.colo + '\n');
		return { colo: cur.colo, moved: false, endpoint: sprintf('%s:%d', s.host, s.port), tried: 0 };
	}
	const cands = [], seen = {};
	const add = (h, p) => { const k = h + ':' + p; if (!seen[k]) { seen[k] = 1; push(cands, { host: h, port: p }); } };
	for (let p in s.ports) add(s.host, p);
	for (let x in pool_read(name)) add(x.host, x.port);
	if (length(s.hosts)) { for (let h in s.hosts) for (let p in [ s.port, ...s.ports ]) add(h, p); }
	else for (let pre in POOLS) add(sprintf('%s.%d', pre, 1 + (int(time() / 7 + length(cands)) % 254)), s.port);

	const t_end = time() + s.budget;
	let fallback = null, tried = 0;
	for (let c in cands) {
		if (time() >= t_end) break;
		if (c.host == s.host && c.port == s.port) continue;   // the current one was just asked
		tried++;
		const r = try_one(s, c.host, c.port);
		if (r.verdict != 'pass') continue;
		if (bad_colo(s, r.colo)) { fallback ??= { ...c, colo: r.colo }; continue; }
		persist(s, c.host, c.port);
		pool_add(name, c.host, c.port, r.colo);
		fs.writefile(sprintf('%s/warp-%s.colo', RUN, name), r.colo + '\n');
		log(sprintf('WARP %s: %s -> %s:%d (colo %s)', name, cur.colo ?? 'no answer', c.host, c.port, r.colo));
		return { colo: r.colo, moved: true, from: cur.colo, endpoint: sprintf('%s:%d', c.host, c.port), tried };
	}
	// nothing better: an unwanted colo that works beats a dead tunnel; else back to where we were
	const keep = (cur.ok) ? { host: s.host, port: s.port, colo: cur.colo } : fallback;
	if (keep) {
		set_endpoint(s, keep.host, keep.port);
		if (keep.host != s.host || keep.port != s.port) persist(s, keep.host, keep.port);
		fs.writefile(sprintf('%s/warp-%s.colo', RUN, name), (keep.colo ?? '?') + '\n');
		return { colo: keep.colo, moved: keep.host != s.host || keep.port != s.port, endpoint: sprintf('%s:%d', keep.host, keep.port), tried, note: 'no endpoint outside ' + join(' ', s.bad) + ' answered' };
	}
	set_endpoint(s, s.host, s.port);
	return { colo: null, moved: false, endpoint: sprintf('%s:%d', s.host, s.port), tried, note: 'no endpoint answered through the tunnel' };
};
