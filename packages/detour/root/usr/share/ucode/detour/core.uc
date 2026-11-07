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

const RE_V4 = /^[0-9]{1,3}(\.[0-9]{1,3}){3}(\/[0-9]{1,2})?$/;
const RE_V6 = /^[0-9a-fA-F:]+(\/[0-9]{1,3})?$/;
const RE_MAC = /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/;
const RE_DOMAIN = /^[A-Za-z0-9_]([A-Za-z0-9_.-]*[A-Za-z0-9])?$/;
const RE_IFNAME = /^[A-Za-z0-9_.-]{1,15}$/;

function split_addrs(list, errors, where) {
	const v4 = [], v6 = [];
	for (let a in list) {
		if (match(a, RE_V4)) push(v4, a);
		else if (index(a, ':') >= 0 && match(a, RE_V6)) push(v6, lc(a));
		else push(errors, sprintf('%s: bad address "%s"', where, a));
	}
	return { v4, v6 };
}

// Read and validate /etc/config/detour (or another config name for tests).
// Returns { main, exits[], policies[], direct4[], direct6[], errors[] }.
// Invalid items are dropped and reported; the rest still applies (fail-closed per item).
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
	for (let d in main.lan)
		if (!match(d, RE_IFNAME)) push(errors, sprintf('main: bad lan_dev "%s"', d));

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
		const ex = [];
		for (let e in as_list(s.exit)) {
			if (by_name[e]) push(ex, e);
			else push(errors, sprintf('policy %s: unknown exit "%s"', n, e));
		}
		if (!length(ex)) { push(errors, sprintf('policy %s: no valid exit', n)); return; }
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
		pids[id] = n;
		push(policies, {
			name: n, id, exits: ex,
			enabled: bool(s.enabled, true),
			dst4: a.v4, dst6: a.v6, domains: doms, devices: devs,
			label: s.label ?? n,
		});
	});

	const d = c.get_all(name, 'direct') ?? {};
	const da = split_addrs(as_list(d.dst), errors, 'direct');

	if (main.dns == 'tunnel') {
		let ok = false;
		for (let p in policies) if (p.name == main.dns_policy) ok = true;
		if (!ok) { push(errors, sprintf('main: dns_policy "%s" is not a valid policy, DNS stays as is', main.dns_policy)); main.dns = 'off'; }
	}

	if (main.force_dns == null) {
		main.force_dns = false;
		for (let p in policies) if (p.enabled && length(p.domains)) main.force_dns = true;
	}
	else main.force_dns = bool(main.force_dns, true);

	return { main, exits, policies, direct4: da.v4, direct6: da.v6, errors, by_name };
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
