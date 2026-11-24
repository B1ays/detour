// WARP exits: keep them on a good Cloudflare point. A config cannot ask for a point (colo) - the endpoint address
// and port decide where the tunnel lands (from Russia mostly DME, Moscow, which filters by destination).
//   tend(): the live tunnel is asked where it is (speed.cloudflare.com/meta through it: the point and its country;
//   /cdn-cgi/trace as the fallback, the point only). Fine - nothing moves. Not fine (no answer, or a point the
//   filters exclude) - the next address of the exit's pool goes into the live tunnel (a few seconds), checked
//   the same way. The pool is filled and refreshed by scan().
//   scan(): a second tunnel ("scanner") with the exit's own key next to the live one - verified on a real
//   router: WARP keeps both sessions, the live tunnel does not notice - tries candidate addresses one by one:
//   handshake -> meta (point, country) -> the filters -> a burst of pings (a tunnel DPI cuts after the
//   handshake loses the tail of it). Candidates: the pool's entries not checked for a while, then one
//   random address of each WARP anycast /24 on the ports that answered.
// One run at a time (detourd starts them one by one; by hand: a lock directory).
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, shq, log, vlog, PERSIST, RUN } from 'detour.core';
import * as P from 'detour.warppool';

const SCAN_TABLE = 31999, SCAN_PREF = 90, NFT_T = 'inet detour';
const LOCK = RUN + '/warp-pick.lock';

function rnd(n) {
	// no math module needed: the kernel's random uuid
	const u = replace(fs.readfile('/proc/sys/kernel/random/uuid') ?? '', /[^0-9a-f]/g, '');
	return n > 0 ? (int(substr(u, 0, 7), 16) % n) : 0;
}

// the live tunnel of a WARP exit: device, its peer section, the tool
function live_of(name) {
	const c = cursor();
	const e = c.get_all('detour', name);
	if (e?.['.type'] != 'exit' || e.warp != '1') return null;
	const iface = e.iface ?? name;
	const proto = c.get('network', iface, 'proto');
	const ptype = (proto == 'amneziawg') ? 'amneziawg_' + iface : 'wireguard_' + iface;
	let peer = null;
	c.foreach('network', ptype, (s) => { if (!peer) peer = s; });
	if (!peer) return null;
	let addr = null;
	for (let a in P.as_list(c.get('network', iface, 'addresses'))) if (!addr && match(a, /^[0-9.]+(\/[0-9]+)?$/)) addr = a;
	return {
		name, iface, dev: e.device ?? iface, peer_sec: peer['.name'], proto,
		tool: (proto == 'amneziawg') ? 'awg' : 'wg',
		pub: peer.public_key, host: peer.endpoint_host, port: int(peer.endpoint_port ?? 2408),
		addr: addr ? (index(addr, '/') < 0 ? addr + '/32' : addr) : null,
	};
}

// --- asking a tunnel where it lands ---
export function meta(dev, s) {
	const r = run(sprintf("curl -s -m 6 --interface %s -H 'Referer: https://speed.cloudflare.com' %s", shq(dev), shq(s.meta)));
	let j = null;
	try { j = json(r.out); } catch (x) { }
	const colo = (type(j?.colo) == 'object') ? j.colo.iata : j?.colo;
	if (r.code == 0 && type(colo) == 'string' && match(colo, /^[A-Z]{3}$/))
		return { ok: true, colo, country: (type(j.colo) == 'object' && match(j.colo.cca2 ?? '', /^[A-Z]{2}$/)) ? j.colo.cca2 : null };
	// speed.cloudflare.com unreachable (blocked, or the lab): the trace tells the point, not its country
	const t = run(sprintf('curl -s -m 6 --interface %s %s', shq(dev), shq(s.trace)));
	const w = match(t.out, /(^|\n)warp=([a-z]+)/), c = match(t.out, /(^|\n)colo=([A-Z0-9]+)/);
	return { ok: w?.[2] == 'on' || w?.[2] == 'plus', colo: c?.[2], country: null };
};

// n pings 1 s apart (busybox: whole seconds only): the round trip, the loss, and the tail of losses in a row
// at the end - a tunnel DPI tears down answers first and then nothing
export function burst(dev, s, n) {
	const r = run(sprintf('ping -c %d -W 1 -I %s %s 2>/dev/null', n, shq(dev), shq(s.ping)));
	let last = -1, got = 0, sum = 0;
	for (let l in split(r.out, '\n')) {
		const m = match(l, /seq=([0-9]+).*time=([0-9.]+)/);
		if (!m) continue;
		got++; sum += +m[2];
		if (int(m[1]) > last) last = int(m[1]);
	}
	return { got, ms: got ? int(sum / got + 0.5) : null, loss: int((n - got) * 100 / n), tail: n - 1 - last };
};

function handshake(t, dev) {
	const r = run(sprintf('%s show %s latest-handshakes', t.tool, shq(dev)));
	const m = match(r.out, /\t([0-9]+)/);
	return m ? int(m[1]) : 0;
}

// Changing only the endpoint keeps the old session keys: another WARP point does not know that session,
// so nothing would pass until WireGuard gives up on it (~15 s). Re-creating the peer drops the session
// and the next packet starts a fresh handshake with the new point.
function set_endpoint(t, dev, host, port) {
	run(sprintf('%s set %s peer %s remove', t.tool, shq(dev), shq(t.pub)));
	return run(sprintf('%s set %s peer %s endpoint %s:%d allowed-ips 0.0.0.0/0 persistent-keepalive 25',
		t.tool, shq(dev), shq(t.pub), shq(host), port)).code == 0;
}

// one address in a tunnel: handshake newer than the switch -> where it lands -> the filters -> (deep) the pings
//   -> { verdict: pass | filtered | torn | hs (handshake, no answer) | none (no handshake) | error, colo, country, ms, loss }
function try_one(t, dev, s, host, port, deep) {
	const t0 = time();
	if (!set_endpoint(t, dev, host, port)) return { host, port, verdict: 'error' };
	run(sprintf('ping -q -c 1 -W 1 -I %s %s >/dev/null 2>&1', shq(dev), shq(s.ping)));   // kicks the handshake
	let hs = 0;
	for (let i = 0; i < 5 && hs < t0; i++) { hs = handshake(t, dev); if (hs < t0) system('sleep 1'); }
	if (hs < t0) return { host, port, verdict: 'none' };
	const m = meta(dev, s);
	if (!m.ok) return { host, port, verdict: 'hs' };
	const r = { host, port, colo: m.colo, country: m.country };
	if (!P.passes(s, m.colo, m.country)) { r.verdict = 'filtered'; return r; }
	const b = burst(dev, s, deep ? 6 : 2);
	r.ms = b.ms; r.loss = b.loss;
	r.verdict = (b.got > 0 && b.tail >= 3) || (b.got == 0 && deep) ? 'torn' : 'pass';
	return r;
}

function persist(t, host, port) {
	const c = cursor();
	c.set('network', t.peer_sec, 'endpoint_host', host);
	c.set('network', t.peer_sec, 'endpoint_port', '' + port);
	c.commit('network');   // no reload: the running tunnel already uses it, the next ifup too
}

function write_colo(name, colo, country) {
	fs.writefile(sprintf('%s/warp-%s.colo', RUN, name), (colo ?? '?') + (country ? ' ' + country : '') + '\n');
}

// --- the scanner tunnel ---
function scan_dev(t) { return substr('dws' + t.name, 0, 15); }
function side_down(dev) {
	run(sprintf('ip rule del oif %s lookup %d pref %d 2>/dev/null; ip route flush table %d 2>/dev/null; ip link del %s 2>/dev/null; nft delete element %s exit_devs { %s } 2>/dev/null',
		shq(dev), SCAN_TABLE, SCAN_PREF, SCAN_TABLE, shq(dev), NFT_T, shq(dev)));
}
// its policy routing would send the scanner's packets to an exit: an exit device for nft, its own table
function side_route(dev) {
	run(sprintf('nft add element %s exit_devs { %s } 2>/dev/null', NFT_T, shq(dev)));
}
function side_up(t) {
	const dev = scan_dev(t);
	side_down(dev);
	if (!t.addr) return { error: 'the WARP interface has no IPv4 address' };
	// the live tunnel's settings (key, masking, mark) without its port and endpoint, in a file only root reads
	const conf = run(sprintf('%s showconf %s', t.tool, shq(t.dev)));
	if (conf.code != 0 || !match(conf.out, /PrivateKey/)) return { error: 'cannot read the settings of ' + t.dev };
	const lines = filter(split(conf.out, '\n'), (l) => !match(l, /^(ListenPort|Endpoint)[ \t]*=/));
	const f = RUN + '/warp-scan.conf';
	fs.writefile(f, '');
	fs.chmod(f, 0600);   // empty, then the key: never readable by others
	fs.writefile(f, join('\n', lines) + '\n');
	const kind = (t.tool == 'awg') ? 'amneziawg' : 'wireguard';
	const r = run(sprintf('ip link add %s type %s && %s setconf %s %s && ip addr add %s dev %s && ip link set %s mtu 1280 up',
		shq(dev), kind, t.tool, shq(dev), shq(f), shq(t.addr), shq(dev), shq(dev)));
	fs.unlink(f);
	if (r.code != 0) { side_down(dev); return { error: 'scanner tunnel: ' + trim(r.out) }; }
	run(sprintf('ip route replace default dev %s table %d && ip rule add oif %s lookup %d pref %d',
		shq(dev), SCAN_TABLE, shq(dev), SCAN_TABLE, SCAN_PREF));
	side_route(dev);
	return { dev };
}

// candidates for a scan: the pool's entries not checked for scan_every/2 (oldest first), then fresh addresses -
// one random host of each anycast /24 (lab: the fixed hosts), the port of the last good one first
function candidates(t, s, st, current, recheck, all) {
	const out = [], seen = {};
	const add = (h, p, src) => { const k = h + ':' + p; if (!seen[k] && k != current) { seen[k] = 1; push(out, { host: h, port: p, src }); } };
	const now = time();
	if (recheck) {
		const old = sort(filter(st.entries, (x) => all || now - (x.seen ?? 0) >= s.scan_every / 2), (a, b) => (a.seen ?? 0) - (b.seen ?? 0));
		for (let x in old) add(x.host, x.port, x.src);
	}
	const ports = [];
	for (let x in P.sorted(st.entries)) if (x.ok && index(ports, x.port) < 0) push(ports, x.port);
	if (t.port && index(ports, t.port) < 0) push(ports, t.port);
	for (let p in s.ports) if (index(ports, p) < 0) push(ports, p);
	if (length(s.hosts)) {
		for (let h in s.hosts) for (let p in ports) add(h, p, 'scan');
		return out;
	}
	// the current address on the other ports: often another point
	if (t.host) for (let i = 0; i < length(ports) && i < 4; i++) add(t.host, ports[i], 'scan');
	const nets = [ ...P.NETS ];
	for (let i = length(nets) - 1; i > 0; i--) { const j = rnd(i + 1); const x = nets[i]; nets[i] = nets[j]; nets[j] = x; }
	// two rounds: each /24 once, then again with another host and the next port
	for (let round = 0; round < 2; round++)
		for (let i = 0; i < length(nets); i++)
			add(sprintf('%s.%d', nets[i], 1 + rnd(254)), ports[(i + round) % length(ports)], 'scan');
	return out;
}

// fill / refresh the pool through the scanner tunnel; stops when <need> new good ones were found or the budget is gone
function scan(t, s, st, current, need, t_end, all) {
	const res = { tried: 0, added: 0, dropped: 0, results: [] };
	const tries = [];
	const up = side_up(t);
	if (up.error) { res.error = up.error; return res; }
	const now = time();
	try {
		for (let c in candidates(t, s, st, current, true, all)) {
			if (time() >= t_end) { res.out_of_time = true; break; }
			const was = filter(st.entries, (x) => P.key(x) == P.key(c))[0];
			if (!was && res.added >= need) continue;   // enough new ones: only the rechecks go on
			side_route(up.dev);   // a Detour reload in between flushed the set
			const r = try_one(t, up.dev, s, c.host, c.port, true);
			r.src = c.src;
			res.tried++;
			push(res.results, { endpoint: P.key(r), verdict: r.verdict, colo: r.colo, country: r.country, ms: r.ms, loss: r.loss });
			push(tries, r);
			if (r.verdict == 'pass' && !was) res.added++;
			vlog('warp', sprintf('%s scan %s:%d -> %s %s%s', t.name, c.host, c.port, r.verdict, r.colo ?? '', r.ms != null ? sprintf(' %d ms %d%%', r.ms, r.loss) : ''));
		}
	}
	catch (x) { res.error = '' + x; }
	side_down(up.dev);
	const n0 = length(filter(st.entries, (x) => x.drop));
	res.outage = P.settle(st.entries, s, tries, time()) == 'outage';
	if (res.outage) res.added = 0;
	res.dropped = length(filter(st.entries, (x) => x.drop)) - n0;
	st.scan = now;
	return res;
}

// waits for a run of the daemon (by hand) up to <wait> s
function lock(wait) {
	const until = time() + wait;
	while (true) {
		if (fs.mkdir(LOCK)) return true;
		// a run killed before it cleaned up: its lock is older than any run can be
		const st = fs.stat(LOCK);
		if (st && time() - st.mtime > 1200) { fs.rmdir(LOCK); continue; }
		if (time() >= until) return false;
		system('sleep 1');
	}
}
function unlock() { fs.rmdir(LOCK); }

function tend_locked(t, s, opts) {
	const name = t.name, now = time();
	const st = P.load(name);
	const current = sprintf('%s:%d', t.host, t.port);
	const out = { endpoint: current, moved: false, scanned: 0, added: 0, dropped: 0 };
	const t_end = now + s.budget;

	if (opts.drop) {
		const n0 = length(st.entries);
		st.entries = filter(st.entries, (x) => P.key(x) != opts.drop);
		out.dropped = n0 - length(st.entries);
		P.save(name, st);
		out.pool = length(st.entries);
		return out;
	}

	const cur = meta(t.dev, s);
	out.colo = cur.colo; out.country = cur.country;
	const fine = cur.ok && P.passes(s, cur.colo, cur.country);
	// the live tunnel's own answer and the tries in it count together at the end (an outage counts against nothing)
	const live = [];
	if (cur.ok) P.apply(st.entries, s, { host: t.host, port: t.port, verdict: fine ? 'pass' : 'filtered', colo: cur.colo, country: cur.country, src: 'live' }, now);
	else push(live, { host: t.host, port: t.port, verdict: handshake(t, t.dev) > now - 180 ? 'hs' : 'none' });

	// into the live tunnel, checked: the pool's best first
	const move_to = function(list, why) {
		for (let x in list) {
			if (time() >= t_end) break;
			const r = try_one(t, t.dev, s, x.host, x.port, false);
			r.src = x.src;
			push(live, r);
			if (r.verdict == 'pass') P.apply(st.entries, s, r, time());   // the failover target counts now: the scan below must see it
			vlog('warp', sprintf('%s %s %s:%d -> %s %s', name, why, x.host, x.port, r.verdict, r.colo ?? ''));
			if (r.verdict != 'pass') continue;
			persist(t, x.host, x.port);
			write_colo(name, r.colo, r.country);
			log(sprintf('WARP %s: %s -> %s:%d (colo %s)', name, cur.colo ?? 'no answer', x.host, x.port, r.colo));
			out.moved = true; out.from = cur.colo; out.endpoint = P.key(x); out.colo = r.colo; out.country = r.country;
			return true;
		}
		return false;
	};

	if (opts.use) {
		const u = P.parse_key(opts.use);
		if (!u) return { error: 'not an address: ' + opts.use };
		if (!move_to([ u ], 'use')) {
			set_endpoint(t, t.dev, t.host, t.port);
			out.note = opts.use + ' did not work: kept ' + current;
		}
	}
	else if (!fine || opts.force) {
		let done = move_to(P.usable(st.entries, current), 'failover');
		if (!done) {
			// the pool had nothing: scan (the live tunnel stays as it is meanwhile), then the new ones
			const sc = scan(t, s, st, current, s.size, t_end);
			out.scanned = sc.tried; out.added = sc.added; out.results = sc.results; out.scan_ran = true;
			if (sc.error) out.note = sc.error;
			if (sc.outage) out.outage = true;
			done = move_to(P.usable(st.entries, current), 'failover');
		}
		if (!done) {
			// nothing better: a point the filters exclude that works beats a dead tunnel; else back where it was
			set_endpoint(t, t.dev, t.host, t.port);
			write_colo(name, cur.ok ? cur.colo : null, cur.country);
			out.note = cur.ok ? sprintf('no endpoint outside the filters answered (%s)', P.why_not(s, cur.colo, cur.country))
				: 'no endpoint answered through the tunnel';
		}
	}
	else write_colo(name, cur.colo, cur.country);

	// keep the pool full and fresh (the scanner does not touch the live tunnel)
	const good = length(P.usable(st.entries, null));
	if (!out.scanned && time() < t_end && (opts.scan || good < s.min || now - (st.scan ?? 0) >= s.scan_every)) {
		const sc = scan(t, s, st, out.endpoint, max(0, s.size - good), t_end, opts.scan);
		out.scanned = sc.tried; out.added += sc.added; out.results = sc.results; out.scan_ran = true;
		if (sc.error) out.note = sc.error;
		if (sc.outage) out.outage = true;
	}
	if (P.settle(st.entries, s, live, time()) == 'outage') out.outage = true;
	const pr = P.prune(st.entries, s, time(), out.endpoint);
	st.entries = pr.pool;
	out.dropped += length(pr.dropped);
	for (let x in pr.dropped) vlog('warp', sprintf('%s pool: %s out (%s)', name, P.key(x), x.drop));
	P.save(name, st);
	out.pool = length(filter(st.entries, (x) => x.ok));
	return out;
}

// opts: { force: move even when fine, scan: scan now, use: 'ip:port' into the live tunnel, drop: 'ip:port' out of the pool }
// -> { colo, country, endpoint, moved, from, pool, scanned, added, dropped, note, results }
export function tend(name, opts) {
	opts ??= {};
	const t = live_of(name);
	const s = P.settings(name);
	if (!t || !s) return { error: name + ' is not a WARP exit' };
	fs.mkdir(RUN);
	if (!lock(opts.wait ?? 0)) return { error: 'another WARP check is running' };
	let r;
	try { r = tend_locked(t, s, opts); }
	catch (x) { r = { error: '' + x }; }
	unlock();
	return r;
};

// for the page: the pool with the settings and the current address
export function state(name) {
	const t = live_of(name), s = P.settings(name);
	if (!t || !s) return { error: name + ' is not a WARP exit' };
	const st = P.load(name);
	const cf = split(trim(fs.readfile(sprintf('%s/warp-%s.colo', RUN, name)) ?? ''), ' ');
	let last = null;
	try { last = json(fs.readfile(sprintf('%s/warp-pick-%s.json', RUN, name))); } catch (x) { }
	return { name, endpoint: sprintf('%s:%d', t.host, t.port), colo: length(cf[0]) ? cf[0] : null, country: cf[1] ?? null,
		scan: st.scan ?? 0, busy: fs.access(LOCK) ? true : false,
		last: last ? { results: last.results ?? [], note: last.note, outage: last.outage ?? false, moved: last.moved ?? false } : null,
		settings: { colo: s.colo, xcolo: s.xcolo, country: s.country, xcountry: s.xcountry, size: s.size, min: s.min, check: s.check, scan_every: s.scan_every },
		entries: map(P.sorted(st.entries), (x) => ({ endpoint: P.key(x), colo: x.colo, country: x.country, ms: x.ms, loss: x.loss, ok: x.ok, seen: x.seen, fails: x.fails ?? 0, src: x.src })) };
};

// the old command: check, move when needed
export function pick(name, force) { return tend(name, { force }); };
