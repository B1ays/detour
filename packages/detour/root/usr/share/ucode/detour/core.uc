// Detour core: configuration model, validation, small helpers.
// UCI holds intent (/etc/config/detour); runtime state lives in /tmp/detour and nftables.
'use strict';

import { cursor } from 'uci';
import * as fs from 'fs';

export const VERSION = '0.1.0';
export const RUN = '/tmp/detour';
export const PERSIST = '/etc/detour';

// transport underlay (WG fwmark, sing-box routing_mark, Xray sockopt.mark) + zapret nfqws packets
export const M_UNDERLAY = 0x10000000;
export const M_SKIP = 0x50000000;

// fwmark layout: two bytes, the policy id below the exit id - 0x00EEPP00 by default. main.fw_mask moves them
// (any 0xffff << n up to bit 27, clear of M_SKIP): pbr (0x00ff0000) and mwan3 (0x3f00) use the default's bits.
// Policy byte 0xff (ids end at 250) = "decided: directly" in the ct mark - a flow that matched no policy is
// classified once, not on every packet.
export const FW_MASK_DEFAULT = 0x00ffff00;
export function mark_layout(mask) {
	mask ??= FW_MASK_DEFAULT;
	for (let s = 0; s <= 12; s++)
		if (mask == (0xffff << s)) return { shift: s, pol: 0xff << s, exit: 0xff << (s + 8), both: mask, direct: 0xff << s };
	return null;
};
let LAYOUT = null;      // of the last load(); read from UCI by whoever needs it before
function parse_mask(v) {
	if (v == null) return null;
	const m = match(lc(trim('' + v)), /^(0x)?([0-9a-f]{1,8})$/);
	if (!m) return -1;
	let n = 0;
	for (let ch in split(m[2], '')) n = n * 16 + index('0123456789abcdef', ch);
	return n;
}
export function marks() {
	return LAYOUT ??= (mark_layout(parse_mask(cursor().get('detour', 'main', 'fw_mask'))) ?? mark_layout());
};
export function pol_mark(id) { return id << marks().shift; };
export function exit_mark(id) { return id << (marks().shift + 8); };

// other users of the same fwmark bits: pbr and mwan3 (with their own masks, or their defaults)
function mark_conflicts(L) {
	const c = cursor(), out = [];
	if (fs.access('/etc/config/pbr') && c.get('pbr', 'config', 'enabled') == '1') {
		const m = parse_mask(c.get('pbr', 'config', 'fw_mask') ?? '00ff0000');
		if (m > 0 && (m & L.both)) push(out, sprintf('pbr (fw_mask 0x%08x)', m));
	}
	if (fs.access('/etc/config/mwan3') && fs.access('/etc/init.d/mwan3') && system('/etc/init.d/mwan3 enabled 2>/dev/null') == 0) {
		const m = parse_mask(c.get('mwan3', 'globals', 'mmx_mask') ?? '0x3F00');
		if (m > 0 && (m & L.both)) push(out, sprintf('mwan3 (mmx_mask 0x%08x)', m));
	}
	return out;
}

// never classified or refused: local, private, multicast, link-local, CGNAT (nft and the site check share them)
export const PRIVATE4 = [ '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/3' ];
export const PRIVATE6 = [ '::/127', '::ffff:0:0/96', 'fc00::/7', 'fe80::/10', 'ff00::/8' ];
// the first 16 bits of an IPv6 address, or null (declared before its user: ucode does not hoist)
function hex4(a) {
	const m = match(a, /^([0-9a-f]{1,4}):/);
	if (!m) return null;
	let n = 0;
	for (let ch in split(m[1], '')) n = n * 16 + index('0123456789abcdef', ch);
	return n;
}
// an IPv6 address in PRIVATE6
export function is_private6(a) {
	a = lc(a ?? '');
	if (a == '::' || a == '::1' || match(a, /^::ffff:[0-9.]+$/)) return true;
	const h = hex4(a);
	if (h == null) return false;
	return (h & 0xfe00) == 0xfc00 || (h & 0xffc0) == 0xfe80 || (h & 0xff00) == 0xff00;
};

// routing tables of the exits: registered in rt_tables as detour_<exit>, numbered after the last table in use
// (as pbr does); rules at free priorities from here on (net.uc)
export const RULE_PRIO_BASE = 11000;
export const UNREACH_METRIC = 4278198272;

export function log(msg) {
	system(['logger', '-t', 'detour', msg]);
};

// single-quote for /bin/sh
// a name that came from outside (a server's remark in a link, a subscription, a Clash or JSON config): no markup
// characters, no control characters, at most 64 characters - it is shown on pages and in messages
export function clean_label(s) {
	if (s == null) return null;
	s = trim(replace('' + s, /[<>&"[:cntrl:]]/g, ''));
	return length(s) ? substr(s, 0, 64) : null;
};

export function shq(s) {
	return "'" + replace('' + s, "'", "'\\''") + "'";
};

// run a shell command line, return { code, out }
export function run(cmd) {
	const p = fs.popen(cmd + ' 2>&1', 'r');
	if (!p) return { code: -1, out: '' };
	const out = p.read('all') ?? '';
	const code = p.close();
	return { code, out };
};

// a simple command (no pipes, no ";") that may hang - a client of a service that stopped answering: at most
// secs seconds, then it is killed (code 143) and what it wrote so far is the output. Busybox of OpenWrt 25.12
// has no "timeout". The output goes through a file: the killer's sleep must not hold a pipe open.
let nlim = 0;
export function run_for(secs, cmd) {
	fs.mkdir(RUN);
	const f = sprintf('%s/.run%d', RUN, ++nlim % 4);
	const r = run(sprintf('%s > %s 2>/dev/null & p=$!; ( sleep %d; kill $p ) >/dev/null 2>&1 & k=$!; wait $p 2>/dev/null; c=$?; kill $k 2>/dev/null; exit $c',
		cmd, f, secs));
	const out = fs.readfile(f) ?? '';
	fs.unlink(f);
	return { code: r.code, out };
};

export function hex(n) {
	return sprintf('0x%08x', n);
};

function as_list(v) {
	if (v == null) return [];
	return type(v) == 'array' ? v : [ v ];
}

// an option or a list, its words
function words(v) { return (v == null) ? [] : filter((type(v) == 'array') ? v : split('' + v, /\s+/), (x) => length(x)); }

// the firewall zones of the home network: those holding an interface on a LAN device (main.lan_dev, default
// br-lan), not a zone that happens to be named "lan"; [ 'lan' ] when nothing matches (a stock config)
export function lan_zones() {
	const c = cursor();
	const devs = words(c.get('detour', 'main', 'lan_dev') ?? 'br-lan');
	const ifs = [];
	c.foreach('network', 'interface', function(s) {
		const d = s.device ?? s.ifname;
		if (d && index(devs, d) >= 0) push(ifs, s['.name']);
	});
	const out = [];
	c.foreach('firewall', 'zone', function(z) {
		const nets = words(z.network ?? (z.name == 'lan' ? 'lan' : null));
		if (z.name && length(filter(nets, (n) => index(ifs, n) >= 0)) && index(out, z.name) < 0) push(out, z.name);
	});
	return length(out) ? out : [ 'lan' ];
};

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
};

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
};

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
// Returns { main, exits[], policies[], errors[], by_name }.
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
		// a working exit with no traffic is probed this often (its counters say the rest, see detourd probe_due)
		probe_idle: int(m.probe_idle ?? 30) || 30,
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
	if (main.probe_idle < main.probe_period) main.probe_idle = main.probe_period;
	if (main.probe_idle > 600) main.probe_idle = 600;
	if (main.fails < 1) main.fails = 2;
	if (main.probe_timeout < 2) main.probe_timeout = 2;
	if (main.probe_timeout > 30) main.probe_timeout = 30;
	if (!(main.alert_hold >= 0)) main.alert_hold = 10;
	main.marks = mark_layout(parse_mask(m.fw_mask));
	if (!main.marks) {
		push(errors, sprintf('main: bad fw_mask "%s" (0xffff shifted left by 0..12, like 0x00ffff00), the default is used', m.fw_mask));
		main.marks = mark_layout();
	}
	LAYOUT = main.marks;
	for (let x in mark_conflicts(main.marks))
		push(errors, sprintf('main: fwmark bits 0x%08x are also used by %s - set main.fw_mask to other bits', main.marks.both, x));

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
		// action 'direct': what it covers never goes through a tunnel (the provider's line, no mark) - "Always
		// direct" when it is first, an exception for what the policies below it would take otherwise. No exits.
		const block = s.action == 'block';
		const direct = s.action == 'direct';
		const ex = [];
		if (!block && !direct) for (let e in as_list(s.exit)) {
			if (by_name[e]) push(ex, e);
			else push(errors, sprintf('policy %s: unknown exit "%s"', n, e));
		}
		// a policy without an exit stays: its traffic is blocked (nft: pol2exit -> drop). Dropping the policy
		// would send what it covers directly - the opposite of what removing its last exit should do.
		// (the text is matched by LuCI's msg.js: "policy … has no exit - its traffic is blocked")
		if (!block && !direct && !length(ex)) push(errors, sprintf('policy %s: no valid exit', n));
		// when every exit is down: 'block' (default, fail-closed) or 'direct' (the owner chose to let it through)
		const on_down = (s.on_down == 'direct' && !block && !direct) ? 'direct' : 'block';
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
		// devices by their address (a fixed one, a subnet, devices behind another router where no MAC is seen) and
		// whole networks of the router (guest, IoT ...: their logical names; fw.apply finds the devices)
		const src = split_addrs(as_list(s.src), errors, 'policy ' + n);
		const nets = [];
		for (let x in as_list(s.network)) {
			if (match(x, /^[A-Za-z0-9_]{1,15}$/)) push(nets, x);
			else push(errors, sprintf('policy %s: bad network "%s"', n, x));
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
			name: n, id, exits: ex, block, direct, on_down,
			enabled: bool(s.enabled, true),
			dst4: a.v4, dst6: a.v6, domains: doms, devices: devs, ports,
			src4: src.v4, src6: src.v6, networks: nets, ifdevs: [],
			// IPv6 is not tunnelled: an address policy does not know the IPv6 addresses of what it covers, so it
			// may refuse all forwarded IPv6 from where it stands in the order (devices fall back to IPv4)
			ipv6_block: !block && !direct && bool(s.ipv6_block, false),
			label: s.label ?? n,
		});
	});

	if (main.dns == 'tunnel') {
		let ok = false;
		for (let p in policies) if (p.name == main.dns_policy && !p.block && !p.direct) ok = true;
		if (!ok) { push(errors, sprintf('main: dns_policy "%s" is not a valid policy, DNS stays as is', main.dns_policy)); main.dns = 'off'; }
	}

	if (main.force_dns == null) {
		main.force_dns = false;
		for (let p in policies) if (p.enabled && length(p.domains)) main.force_dns = true;
	}
	else main.force_dns = bool(main.force_dns, true);

	// IPv6 is not tunnelled. A policy that takes all IPv4 (a full tunnel) would leave all IPv6 of the home
	// network going directly: then forwarded IPv6 is rejected altogether (devices fall back to IPv4).
	if (main.ipv6_block == null) {
		main.ipv6_block = false;
		for (let p in policies)
			if (p.enabled && !p.direct) for (let a in p.dst4) if (match(a, /\/0$/)) main.ipv6_block = true;
	}
	else main.ipv6_block = bool(main.ipv6_block, false);

	return { main, exits, policies, errors, by_name };
};

export function exit_by_id(cfg, id) {
	for (let e in cfg.exits) if (e.id == id) return e;
	return null;
};

// numeric uid of a system user, or null (nft resolves names at load time; a missing user breaks nft -f)
export function uid_of(user) {
	const pw = fs.readfile('/etc/passwd') ?? '';
	for (let l in split(pw, '\n')) {
		const f = split(l, ':');
		if (f[0] == user) return int(f[2]);
	}
	return null;
};

export function read_json(path) {
	const s = fs.readfile(path);
	if (!s) return null;
	try { return json(s); } catch (e) { return null; }
};

export function write_json(path, v) {
	const tmp = path + '.tmp';
	fs.writefile(tmp, sprintf('%J', v));
	fs.rename(tmp, path);
};
