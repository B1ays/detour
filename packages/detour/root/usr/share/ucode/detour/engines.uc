// Proxy engines as exits: sing-box (tun inbound, gvisor stack) and Xray (native tun inbound).
// The user provides only the outbound (JSON object, e.g. converted from a vless:// link); Detour
// builds the rest: tun inbound named after the exit device, no auto-route (Detour routes by mark),
// and the underlay mark 0x10000000 on the outbound so the engine's own traffic is never classified.
//   config engine 'sb'
//     option type 'singbox'          # singbox | xray
//     option device 'sbtun'          # tun device = the exit's device
//     option outbound '/etc/detour/engines/sb.json'
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { M_UNDERLAY, RUN, PERSIST, run, log } from 'detour.core';
import * as links from 'detour.links';
import { ensure_zone } from 'detour.warp';

export const DIR = RUN + '/engines';
const BIN = { singbox: '/usr/bin/sing-box', xray: '/usr/bin/xray' };

// the sing-box tun address of an engine (render and devices_up must agree)
function tun_addr(e) { return sprintf('172.19.%d.1/30', e.idx % 500 % 256); }

export function check_name(name) {
	return match(name ?? '', /^[a-z][a-z0-9_]{0,10}$/) ? null : 'name: a-z, 0-9, _ (max 11, starts with a letter)';
};

// a subscription server's names (remarks of its links) are kept beside the outbounds: sing-box takes no
// unknown fields. A server's identity across updates: its remark and address.
export function names_file(exit) { return sprintf('%s/engines/%s.names.json', PERSIST, exit); };
export function server_key(o, name) {
	const v = o?.protocol ? (o.settings?.vnext?.[0] ?? o.settings?.servers?.[0]) : null;
	const host = v ? v.address : o?.server, port = v ? v.port : o?.server_port;
	return (name ?? '') + '|' + (host ?? '') + ':' + (port ?? '');
};

// write the outbound(s) of a sing-box engine; one object or an array (several -> urltest group)
export function write_outbound(name, outbound) {
	fs.mkdir(PERSIST); fs.mkdir(PERSIST + '/engines');
	const f = sprintf('%s/engines/%s.json', PERSIST, name);
	fs.writefile(f + '.tmp', ''); fs.chmod(f + '.tmp', 0600);
	fs.writefile(f + '.tmp', sprintf('%.J\n', outbound));
	fs.rename(f + '.tmp', f);
	return f;
};

// engine (sing-box, or Xray for an Xray outbound) + netifd interface (proto none) + firewall zone + Detour exit,
// for an existing outbound file
export function create_exit(name, f, via, label, dev, etype) {
	const c = cursor();
	dev ??= name + 'tun';
	const used = {};
	c.foreach('detour', 'exit', (s) => { used[int(s.id)] = true; });
	let id = 1;
	while (id <= 250 && used[id]) id++;
	if (id > 250) return { error: 'no free exit id: 250 exits is the limit' };
	c.set('detour', name + '_eng', 'engine');
	c.set('detour', name + '_eng', 'type', etype ?? 'singbox');
	c.set('detour', name + '_eng', 'device', dev);
	c.set('detour', name + '_eng', 'outbound', f);
	if (via) c.set('detour', name + '_eng', 'via', via);
	c.set('detour', name, 'exit');
	c.set('detour', name, 'id', '' + id);
	c.set('detour', name, 'iface', name);
	c.set('detour', name, 'device', dev);
	c.set('detour', name, 'label', label ?? name);
	c.set('detour', name, 'probe', 'https://1.1.1.1/cdn-cgi/trace');
	c.set('network', name, 'interface');
	c.set('network', name, 'proto', 'none');
	c.set('network', name, 'device', dev);
	ensure_zone(c, name);
	c.commit('detour'); c.commit('network'); c.commit('firewall');
	// the engine itself starts with the service's reload (procd instances of engines.prepare())
	run('/etc/init.d/network reload; fw4 -q reload; /etc/init.d/detour reload');
	return { exit_id: id, device: dev };
};

// a share link -> sing-box engine exit
export function add_from_link(name, link, via) {
	const ne = check_name(name);
	if (ne) return { error: ne };
	const c = cursor();
	if (c.get('detour', name) || c.get('network', name)) return { error: name + ' is already used' };
	if (!fs.access(BIN.singbox)) return { error: 'sing-box is not installed (apk add sing-box)' };
	if (via && c.get('detour', via) != 'exit') return { error: 'via: "' + via + '" is not an exit' };
	const r = links.parse(link);
	if (r.error) return r;
	const x = create_exit(name, write_outbound(name, r.outbound), via, r.remark ?? name);
	if (x.error) return x;
	return { name, exit_id: x.exit_id, device: x.device, server: r.outbound.server, type: r.outbound.type };
};

export function list() {
	const out = [];
	let i = 0;
	const c = cursor();
	// an engine's number (its tun address, its control API port) is the id of its exit: stable when other
	// engines come and go. An engine without an exit keeps its position, away from the ids (1..250 -> 0..249)
	const exit_id = {};
	c.foreach('detour', 'exit', (x) => { exit_id[x.device ?? x.iface ?? x['.name']] = int(x.id); });
	c.foreach('detour', 'engine', function(s) {
		i++;
		const t = s.type;
		if (!BIN[t]) return;
		// chain: the engine's own connections leave through another exit (e.g. VLESS over WARP)
		let via_dev = null;
		if (s.via) {
			const x = c.get_all('detour', s.via);
			if (x?.['.type'] == 'exit') via_dev = x.device ?? x.iface ?? s.via;
		}
		push(out, {
			name: s['.name'], type: t, idx: exit_id[s.device ?? s['.name']] ?? (250 + i),
			device: s.device ?? s['.name'],
			outbound: s.outbound,
			via: s.via, via_dev,
			pick: s.pick,
			enabled: s.enabled != '0',
			installed: fs.access(BIN[t]) ? true : false,
		});
	});
	return out;
};

// A group of servers (a subscription) gets a control API on 127.0.0.1: which server the group chose and each
// server's delay, without switching. sing-box: its clash API behind a secret, written as a curl config (mode 600) -
// the secret never shows on a command line. Xray: its own API (the balancer's choice, "xray api bi"). Both: a SOCKS
// inbound whose user "sN" leaves through server N only (a check of one server, its speed), password = the secret.
export function api_file(engine) { return sprintf('%s/%s.api', DIR, engine); };
function api_conf(e) {
	fs.mkdir(RUN); fs.mkdir(DIR);
	const port = 19100 + e.idx % 500;
	let secret = null;
	const m = match(fs.readfile(api_file(e.name)) ?? '', /Bearer ([0-9a-f]{32})/);
	if (m) secret = m[1];
	else {
		const fh = fs.open('/dev/urandom');
		if (!fh) return null;
		secret = hexenc(fh.read(16));
		fh.close();
		if (!match(secret ?? '', /^[0-9a-f]{32}$/)) return null;
	}
	const f = api_file(e.name);
	// the check inbound (both engines): the ports after the API ones (19100..19599)
	const socks = 19600 + e.idx % 500;
	fs.writefile(f + '.tmp', ''); fs.chmod(f + '.tmp', 0600);
	fs.writefile(f + '.tmp', sprintf('header = "Authorization: Bearer %s"\n# url http://127.0.0.1:%d\n', secret, port) +
		(e.type == 'xray' ? '# engine xray\n' : '') + sprintf('# socks 127.0.0.1:%d\n', socks));
	fs.rename(f + '.tmp', f);
	return { external_controller: sprintf('127.0.0.1:%d', port), secret, port, socks };
}
export function api_port(engine) {
	const m = match(fs.readfile(api_file(engine)) ?? '', /# url http:\/\/127\.0\.0\.1:([0-9]+)/);
	return m ? int(m[1]) : null;
};
// the API of a group: { engine: singbox | xray, port, socks (the check inbound), secret } | null
export function api_info(engine) {
	const t = fs.readfile(api_file(engine)) ?? '';
	const p = match(t, /# url http:\/\/127\.0\.0\.1:([0-9]+)/), s = match(t, /Bearer ([0-9a-f]{32})/);
	if (!p || !s) return null;
	const k = match(t, /# socks 127\.0\.0\.1:([0-9]+)/);
	return { engine: match(t, /# engine xray/) ? 'xray' : 'singbox', port: int(p[1]), socks: k ? int(k[1]) : null, secret: s[1] };
};

function read_outbound(e) {
	if (e.given) return { o: e.given, all: [ e.given ] };   // test(): an outbound not written anywhere yet
	const s = e.outbound ? fs.readfile(e.outbound) : null;
	if (!s) return { error: 'outbound file missing: ' + (e.outbound ?? '(not set)') };
	let o;
	try { o = json(s); } catch (x) { return { error: 'outbound is not valid JSON' }; }
	// a full config was given: its outbounds
	if (type(o?.outbounds) == 'array') o = o.outbounds;
	const list = (type(o) == 'array') ? filter(o, (x) => type(x) == 'object') : [ o ];
	if (!length(list) || type(list[0]) != 'object') return { error: 'outbound must be a JSON object or an array of them' };
	return { o: list[0], all: list };
}

export function render(e) {
	const r = read_outbound(e);
	if (r.error) return r;
	if (e.via && !e.via_dev) return { error: 'via: "' + e.via + '" is not an exit' };
	// several servers (a subscription): a group picks a working, fast one and keeps checking. One server chosen
	// in LuCI (option pick = its key): only that one; a key that is gone after an update falls back to the group
	let all = r.all;
	if (e.pick) {
		let names = [];
		try { names = json(fs.readfile(names_file(replace(e.name, /_eng$/, ''))) ?? '[]'); } catch (x) { }
		const hit = filter(map(all, (x, i) => [ x, i ]), (p) => server_key(p[0], names[p[1]]) == e.pick);
		if (length(hit)) all = [ hit[0][0] ];
	}
	const group = length(all) > 1;
	const url = cursor().get('detour', 'main', 'urltest_url') ?? 'https://www.gstatic.com/generate_204';
	const api = group ? api_conf(e) : null;
	if (!group) fs.unlink(api_file(e.name));   // no group, no API: LuCI then knows there is nothing to ask
	let cfg;
	if (e.type == 'singbox') {
		// each server dials with the underlay mark / via; a urltest group over them
		const outs = [];
		for (let i, x0 in all) {
			const x = links.for_singbox(x0);   // what only Xray reads (links.uc "_x") is an error to sing-box
			x.tag = group ? sprintf('s%d', i + 1) : 'out';
			x.routing_mark = M_UNDERLAY;
			if (e.via_dev) x.bind_interface = e.via_dev;
			push(outs, x);
		}
		if (group)
			push(outs, { type: 'urltest', tag: 'out', outbounds: map(outs, (x) => x.tag), url, interval: '3m', tolerance: 100 });
		cfg = {
			log: { level: 'warn' },
			inbounds: [ { type: 'tun', tag: 'tun-in', interface_name: e.device,
				address: [ tun_addr(e) ], mtu: 1400,
				auto_route: false, stack: 'gvisor' } ],
			outbounds: outs,
			route: { final: 'out', auto_detect_interface: false }
		};
		if (api) {
			cfg.experimental = { clash_api: { external_controller: api.external_controller, secret: api.secret } };
			// a check of one server (its speed): a SOCKS inbound whose user sN leaves through server N only
			const tags = map(filter(outs, (x) => x.type != 'urltest'), (x) => x.tag);
			push(cfg.inbounds, { type: 'socks', tag: 'check', listen: '127.0.0.1', listen_port: api.socks,
				users: map(tags, (t) => ({ username: t, password: api.secret })) });
			cfg.route.rules = map(tags, (t) => ({ inbound: [ 'check' ], auth_user: [ t ], action: 'route', outbound: t }));
		}
	}
	else {
		// every server with the underlay mark (its own traffic, the observatory's probes too) / via
		const outs = [];
		for (let i, x0 in all) {
			const x = json(sprintf('%J', x0));
			x.tag = group ? sprintf('s%d', i + 1) : 'out';
			x.streamSettings ??= {};
			x.streamSettings.sockopt ??= {};
			x.streamSettings.sockopt.mark = M_UNDERLAY;
			if (e.via_dev) x.streamSettings.sockopt.interface = e.via_dev;
			push(outs, x);
		}
		cfg = {
			log: { loglevel: 'warning' },
			inbounds: [ { tag: 'tun-in', protocol: 'tun', settings: { name: e.device, MTU: 1400 } } ],
			outbounds: outs
		};
		if (group) {
			// the observatory measures every server, the balancer takes the fastest that answers (the first
			// while nothing has been measured); the tunnel's traffic goes to the balancer
			const tags = map(outs, (x) => x.tag);
			cfg.observatory = { subjectSelector: tags, probeUrl: url, probeInterval: '3m', enableConcurrency: true };
			cfg.routing = {
				balancers: [ { tag: 'out', selector: tags, strategy: { type: 'leastPing' }, fallbackTag: tags[0] } ],
				rules: [ { type: 'field', inboundTag: [ 'tun-in' ], balancerTag: 'out' } ]
			};
			if (api) {
				cfg.api = { tag: 'api', listen: sprintf('127.0.0.1:%d', api.port), services: [ 'RoutingService' ] };
				push(cfg.inbounds, { tag: 'check', listen: '127.0.0.1', port: api.socks, protocol: 'socks',
					settings: { auth: 'password', udp: false, accounts: map(tags, (t) => ({ user: t, pass: api.secret })) } });
				for (let t in tags)
					push(cfg.routing.rules, { type: 'field', inboundTag: [ 'check' ], user: [ t ], outboundTag: t });
			}
		}
	}
	return { config: cfg };
};

// writes the configs; returns lines "name<TAB>binary<TAB>args" for the init script
export function prepare() {
	fs.mkdir(RUN);
	fs.mkdir(DIR);
	const lines = [], errors = [];
	for (let e in list()) {
		if (!e.enabled) continue;
		if (!e.installed) { push(errors, sprintf('engine %s: %s is not installed', e.name, BIN[e.type])); continue; }
		// both engines make their device through /dev/net/tun: without kmod-tun (xray-core does not pull it in,
		// sing-box does) the engine starts and the exit never comes up
		if (!fs.access('/dev/net/tun')) { push(errors, sprintf('engine %s: no /dev/net/tun (apk add kmod-tun)', e.name)); continue; }
		const r = render(e);
		if (r.error) { push(errors, sprintf('engine %s: %s', e.name, r.error)); continue; }
		const f = sprintf('%s/%s.json', DIR, e.name);
		fs.writefile(f, sprintf('%.J\n', r.config));
		fs.chmod(f, 0600);
		push(lines, sprintf('%s\t%s\trun -c %s', e.name, BIN[e.type], f));
	}
	return { lines, errors };
};

// does the engine itself take this outbound? The config an exit would get, checked by the binary
// ("sing-box check" / "xray run -test"); null when it does, else the engine's first complaint
export function test(etype, outbound) {
	if (!BIN[etype] || !fs.access(BIN[etype])) return (etype == 'xray' ? 'xray-core' : 'sing-box') + ' is not installed';
	const r = render({ name: 'test', type: etype, idx: 499, device: 'entest0', given: json(sprintf('%J', outbound)) });
	if (r.error) return r.error;
	fs.mkdir(RUN); fs.mkdir(DIR);
	const f = sprintf('%s/.test-%s.json', DIR, etype);
	fs.writefile(f, ''); fs.chmod(f, 0600);
	fs.writefile(f, sprintf('%J', r.config));
	const t = run(etype == 'xray' ? sprintf("xray run -test -c '%s' 2>&1", f) : sprintf("sing-box check -c '%s' 2>&1", f));
	fs.unlink(f);
	if (t.code == 0) return null;
	// the reason, without the engine's prefixes and colours
	let why = trim(replace(t.out, /\x1b\[[0-9;]*m/g, ''));
	const ls = filter(split(why, '\n'), (l) => match(l, /Failed to start|FATAL|ERROR|error/));
	why = length(ls) ? ls[length(ls) - 1] : why;
	why = replace(why, /^.*(Failed to start: main: failed to load config files: \[[^\]]*\] > |FATAL\[[0-9]+\] )/, '');
	return substr(why, 0, 300);
};

// Xray creates its tun device down; sing-box brings its own up
export function devices_up() {
	for (let e in list()) {
		if (!e.enabled) continue;
		const fl = fs.readfile(sprintf('/sys/class/net/%s/flags', e.device));
		if (fl == null) continue;
		if (e.type == 'xray') {
			if ((hex(trim(fl)) & 1) == 0) system(sprintf("ip link set '%s' up", e.device));
			continue;
		}
		// sing-box sets its tun address once, at start. netifd (proto none) flushes it when the interface
		// is set up again (/etc/init.d/network restart on the BE7000) - without an address the router's own
		// packets (probes) get no source and the exit stays down until sing-box restarts. Put it back.
		const a = tun_addr(e);
		if (index(run(sprintf("ip -4 -o addr show dev '%s'", e.device)).out, ' ' + a + ' ') < 0) {
			system(sprintf("ip addr replace '%s' dev '%s'", a, e.device));
			log(sprintf('engine %s: tun address %s restored on %s', e.name, a, e.device));
		}
	}
};
