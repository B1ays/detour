// Detour core: configuration model, validation, small helpers.
// UCI holds intent (/etc/config/detour); runtime state lives in /tmp/detour and nftables.
'use strict';

import { cursor } from 'uci';
import * as fs from 'fs';

export const VERSION = '0.1.0';
export const RUN = '/tmp/detour';
export const PERSIST = '/etc/detour';

// fwmark layout 0x00EE PP00: EE = exit id, PP = policy id
export const M_POL = 0x0000ff00;
export const M_EXIT = 0x00ff0000;
export const M_BOTH = 0x00ffff00;
// transport underlay (WG fwmark, sing-box routing_mark, Xray sockopt.mark) + zapret nfqws packets
export const M_UNDERLAY = 0x10000000;
export const M_SKIP = 0x50000000;

export const TABLE_BASE = 1000;      // exit N -> routing table 1000+N
export const RULE_PRIO_BASE = 11000; // exit N -> ip rule priority 11000+N
export const UNREACH_METRIC = 4278198272;

export function log(msg) {
	system(['logger', '-t', 'detour', msg]);
}

// single-quote for /bin/sh
export function shq(s) {
	return "'" + replace('' + s, "'", "'\\''") + "'";
}

// run a shell command line, return { code, out }
export function run(cmd) {
	const p = fs.popen(cmd + ' 2>&1', 'r');
	if (!p) return { code: -1, out: '' };
	const out = p.read('all') ?? '';
	const code = p.close();
	return { code, out };
}

export function hex(n) {
	return sprintf('0x%08x', n);
}

function as_list(v) {
	if (v == null) return [];
	return type(v) == 'array' ? v : [ v ];
}

function bool(v, dflt) {
	if (v == null) return dflt;
	return v == '1' || v == 'on' || v == 'true' || v == 'yes';
}

// Addresses go into the nft script as they are, and nft takes a script whole or not at all: one address it
// cannot read would cost the entire ruleset (at boot: no table, no kill-switch). So they are checked fully here.
const RE_V4 = /^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})(\/(0|[1-9][0-9]?))?$/;
const RE_V6 = /^([0-9a-fA-F:]+)(\/(0|[1-9][0-9]{0,2}))?$/;
const RE_TIMEOUT = /^([1-9][0-9]{0,5}[dhms])+$/;

export function is_v4(a) {
	const m = match(a, RE_V4);
	if (!m) return false;
	for (let i = 1; i <= 4; i++) if (int(m[i]) > 255) return false;
	return !length(m[6] ?? '') || int(m[6]) <= 32;
}

export function is_v6(a) {
	const m = match(a, RE_V6);
	if (!m || index(m[1], ':') < 0) return false;
	if (length(m[3] ?? '') && int(m[3]) > 128) return false;
	const halves = split(m[1], '::');
	if (length(halves) > 2) return false;
	let n = 0;
	for (let h in halves) {
		if (h == '') continue;
		for (let g in split(h, ':')) {
			if (!match(g, /^[0-9a-fA-F]{1,4}$/)) return false;
			n++;
		}
	}
	return (length(halves) == 2) ? n <= 7 : n == 8;
}

const RE_MAC = /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/;
const RE_DOMAIN = /^[A-Za-z0-9_]([A-Za-z0-9_.-]*[A-Za-z0-9])?$/;
const RE_IFNAME = /^[A-Za-z0-9_.-]{1,15}$/;

function split_addrs(list, errors, where) {
	const v4 = [], v6 = [];
	for (let a in list) {
		if (is_v4(a)) push(v4, a);
		else if (is_v6(a)) push(v6, lc(a));
		else push(errors, sprintf('%s: bad address "%s"', where, a));
	}
	return { v4, v6 };
}

// Read and validate /etc/config/detour (or another config name for tests).
// Returns { main, exits[], policies[], direct4[], direct6[], errors[] }.
// Invalid items are dropped and reported; the rest still applies. A policy left without a valid exit is
// kept and blocks its traffic (exits: []).
export function load(conf) {
	const c = cursor();
	const name = conf ?? 'detour';
	const errors = [];
	const m = c.get_all(name, 'main') ?? {};

	const main = {
		enabled: bool(m.enabled, true),
		lan: as_list(m.lan_dev ?? 'br-lan'),
		probe_period: int(m.probe_period ?? 2) || 2,
		fails: int(m.fails ?? 2) || 2,
		// an HTTPS probe through a chained proxy takes 2-4 s when all is well (measured on the BE7000): the limit
		// must be well above that, or a slow handshake counts as a failure
		probe_timeout: int(m.probe_timeout ?? 8) || 8,
		// "exit down" / "policy blocked" are told only when it lasts this long, seconds (0 = at once)
		alert_hold: int(m.alert_hold ?? 10),
		ipv6_block: m.ipv6_block,              // null = auto (on when a policy takes all IPv4: 0.0.0.0/0)
		dns: m.dns ?? 'off',                   // off | tunnel
		dns_policy: m.dns_policy,              // policy whose exits carry the router's DNS
		dns_servers: as_list(m.dns_server ?? [ '1.1.1.1', '1.0.0.1' ]),
		dns_fallback: as_list(m.dns_fallback ?? [ 'quic://dns.adguard-dns.com', 'tls://1.1.1.1', 'https://dns.google/dns-query' ]),
		dns_bootstrap: as_list(m.dns_bootstrap ?? [ '9.9.9.9:53' ]),
		dns_fallback_port: int(m.dns_fallback_port ?? 5354) || 5354,
		dom_timeout: m.dom_timeout ?? '6h',
		schema: int(m.schema ?? 0),
		force_dns: m.force_dns,               // null = auto (on when a policy has domains)
	};
	// what is wrong here is reported and left out (or replaced by the default): it must not reach nft
	for (let d in main.lan)
		if (!match(d, RE_IFNAME)) push(errors, sprintf('main: bad lan_dev "%s"', d));
	main.lan = filter(main.lan, (d) => match(d, RE_IFNAME));
	if (!match(main.dom_timeout, RE_TIMEOUT)) {
		push(errors, sprintf('main: bad dom_timeout "%s" (like 6h, 30m, 1d), 6h is used', main.dom_timeout));
		main.dom_timeout = '6h';
	}
	for (let s in main.dns_servers)
		if (!is_v4(s) || index(s, '/') >= 0) push(errors, sprintf('main: bad dns_server "%s"', s));
	main.dns_servers = filter(main.dns_servers, (s) => is_v4(s) && index(s, '/') < 0);
	if (!length(main.dns_servers)) main.dns_servers = [ '1.1.1.1', '1.0.0.1' ];
	if (main.probe_period < 1) main.probe_period = 2;
	if (main.fails < 1) main.fails = 2;
	if (main.probe_timeout < 2) main.probe_timeout = 2;
	if (main.probe_timeout > 30) main.probe_timeout = 30;
	if (!(main.alert_hold >= 0)) main.alert_hold = 10;

	const exits = [], by_name = {}, ids = {};
	c.foreach(name, 'exit', function(s) {
		const n = s['.name'];
		const id = int(s.id);
		if (!(id >= 1 && id <= 250)) { push(errors, sprintf('exit %s: id must be 1..250', n)); return; }
		if (ids[id]) { push(errors, sprintf('exit %s: id %d already used by %s', n, id, ids[id])); return; }
		const iface = s.iface ?? n;
		const dev = s.device ?? iface;
		if (!match(dev, RE_IFNAME)) { push(errors, sprintf('exit %s: bad device "%s"', n, dev)); return; }
		const ex = {
			name: n, id, iface, device: dev,
			enabled: bool(s.enabled, true),
			probe: s.probe,                  // IP to ping through the device, or http(s) URL
			label: s.label ?? n,
		};
		ids[id] = n;
		by_name[n] = ex;
		push(exits, ex);
	});

	const policies = [], pids = {};
	c.foreach(name, 'policy', function(s) {
		const n = s['.name'];
		const id = int(s.id);
		if (!(id >= 1 && id <= 250)) { push(errors, sprintf('policy %s: id must be 1..250', n)); return; }
		if (pids[id]) { push(errors, sprintf('policy %s: id %d already used by %s', n, id, pids[id])); return; }
		// action 'block': what the policy covers gets no internet at all (rejected at once; its domains get "no such
		// name" from dnsmasq) - the target "Block" for sites, addresses, lists and devices. It has no exits.
		const block = s.action == 'block';
		const ex = [];
		if (!block) for (let e in as_list(s.exit)) {
			if (by_name[e]) push(ex, e);
			else push(errors, sprintf('policy %s: unknown exit "%s"', n, e));
		}
		// a policy without an exit stays: its traffic is blocked (nft: pol2exit -> drop). Dropping the policy
		// would send what it covers directly - the opposite of what removing its last exit should do.
		// (the text is matched by LuCI's msg.js: "policy … has no exit - its traffic is blocked")
		if (!block && !length(ex)) push(errors, sprintf('policy %s: no valid exit', n));
		// when every exit is down: 'block' (default, fail-closed) or 'direct' (the owner chose to let it through)
		const on_down = (s.on_down == 'direct' && !block) ? 'direct' : 'block';
		const a = split_addrs(as_list(s.dst), errors, 'policy ' + n);
		const doms = [];
		for (let d in as_list(s.domain)) {
			d = lc(trim(d));
			if (match(d, RE_DOMAIN)) push(doms, d);
			else push(errors, sprintf('policy %s: bad domain "%s"', n, d));
		}
		const devs = [];
		for (let d in as_list(s.device)) {
			if (match(d, RE_MAC)) push(devs, lc(d));
			else push(errors, sprintf('policy %s: bad device MAC "%s"', n, d));
		}
		// destination ports: "443" (TCP and UDP), "udp/443", "tcp/6000-6100" - one more "or" condition
		const ports = { tcp: [], udp: [] };
		for (let x in as_list(s.port)) {
			const m = match(lc(trim(x)), /^(tcp\/|udp\/)?([0-9]{1,5})(-([0-9]{1,5}))?$/);
			const lo = m ? int(m[2]) : 0, hi = (m && m[4] != null) ? int(m[4]) : lo;
			if (!m || lo < 1 || hi > 65535 || hi < lo) { push(errors, sprintf('policy %s: bad port "%s"', n, x)); continue; }
			const spec = (hi > lo) ? sprintf('%d-%d', lo, hi) : sprintf('%d', lo);
			for (let pr in (m[1] ? [ substr(m[1], 0, 3) ] : [ 'tcp', 'udp' ]))
				if (index(ports[pr], spec) < 0) push(ports[pr], spec);
		}
		pids[id] = n;
		push(policies, {
			name: n, id, exits: ex, block, on_down,
			enabled: bool(s.enabled, true),
			dst4: a.v4, dst6: a.v6, domains: doms, devices: devs, ports,
			label: s.label ?? n,
		});
	});

	const d = c.get_all(name, 'direct') ?? {};
	const da = split_addrs(as_list(d.dst), errors, 'direct');
	const ddev = [], ddom = [];
	for (let x in as_list(d.device)) {
		if (match(x, RE_MAC)) push(ddev, lc(x));
		else push(errors, sprintf('direct: bad device MAC "%s"', x));
	}
	for (let x in as_list(d.domain)) {
		x = lc(trim(x));
		if (match(x, RE_DOMAIN)) push(ddom, x);
		else push(errors, sprintf('direct: bad domain "%s"', x));
	}

	if (main.dns == 'tunnel') {
		let ok = false;
		for (let p in policies) if (p.name == main.dns_policy && !p.block) ok = true;
		if (!ok) { push(errors, sprintf('main: dns_policy "%s" is not a valid policy, DNS stays as is', main.dns_policy)); main.dns = 'off'; }
	}

	if (main.force_dns == null) {
		main.force_dns = false;
		for (let p in policies) if (p.enabled && length(p.domains)) main.force_dns = true;
		if (length(ddom)) main.force_dns = true;
	}
	else main.force_dns = bool(main.force_dns, true);

	// IPv6 is not tunnelled. A policy that takes all IPv4 (a full tunnel) would leave all IPv6 of the home
	// network going directly: then forwarded IPv6 is rejected altogether (devices fall back to IPv4).
	if (main.ipv6_block == null) {
		main.ipv6_block = false;
		for (let p in policies)
			if (p.enabled) for (let a in p.dst4) if (match(a, /\/0$/)) main.ipv6_block = true;
	}
	else main.ipv6_block = bool(main.ipv6_block, false);

	return { main, exits, policies, direct4: da.v4, direct6: da.v6, direct_dev: ddev, direct_dom: ddom, errors, by_name };
}

export function exit_by_id(cfg, id) {
	for (let e in cfg.exits) if (e.id == id) return e;
	return null;
}

// numeric uid of a system user, or null (nft resolves names at load time; a missing user breaks nft -f)
export function uid_of(user) {
	const pw = fs.readfile('/etc/passwd') ?? '';
	for (let l in split(pw, '\n')) {
		const f = split(l, ':');
		if (f[0] == user) return int(f[2]);
	}
	return null;
}

export function read_json(path) {
	const s = fs.readfile(path);
	if (!s) return null;
	try { return json(s); } catch (e) { return null; }
}

export function write_json(path, v) {
	const tmp = path + '.tmp';
	fs.writefile(tmp, sprintf('%J', v));
	fs.rename(tmp, path);
}
