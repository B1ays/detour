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
function tun_addr(e) { return sprintf('172.19.%d.1/30', e.idx % 250); }

export function check_name(name) {
	return match(name ?? '', /^[a-z][a-z0-9_]{0,10}$/) ? null : 'name: a-z, 0-9, _ (max 11, starts with a letter)';
}

// write the outbound(s) of a sing-box engine; one object or an array (several -> urltest group)
export function write_outbound(name, outbound) {
	fs.mkdir(PERSIST); fs.mkdir(PERSIST + '/engines');
	const f = sprintf('%s/engines/%s.json', PERSIST, name);
	fs.writefile(f + '.tmp', ''); fs.chmod(f + '.tmp', 0600);
	fs.writefile(f + '.tmp', sprintf('%.J\n', outbound));
	fs.rename(f + '.tmp', f);
	return f;
}

// sing-box engine + netifd interface (proto none) + firewall zone + Detour exit, for an existing outbound file
export function create_exit(name, f, via, label, dev) {
	const c = cursor();
	dev ??= name + 'tun';
	const used = {};
	c.foreach('detour', 'exit', (s) => { used[int(s.id)] = true; });
	let id = 1;
	while (id <= 250 && used[id]) id++;
	c.set('detour', name + '_eng', 'engine');
	c.set('detour', name + '_eng', 'type', 'singbox');
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
	run('/etc/init.d/network reload; fw4 -q reload');
	return { exit_id: id, device: dev };
}

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
	return { name, exit_id: x.exit_id, device: x.device, server: r.outbound.server, type: r.outbound.type };
}

export function list() {
	const out = [];
	let i = 0;
	const c = cursor();
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
			name: s['.name'], type: t, idx: i,
			device: s.device ?? s['.name'],
			outbound: s.outbound,
			via: s.via, via_dev,
			enabled: s.enabled != '0',
			installed: fs.access(BIN[t]) ? true : false,
		});
	});
	return out;
}

function read_outbound(e) {
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
	const o = r.o;
	o.tag = 'out';
	let cfg;
	if (e.via && !e.via_dev) return { error: 'via: "' + e.via + '" is not an exit' };
	if (e.type == 'singbox') {
		// several servers (a subscription): each one dials with the underlay mark / via, a urltest
		// group picks a working, fast one and keeps checking
		const outs = [];
		for (let i, x in r.all) {
			x.tag = (length(r.all) > 1) ? sprintf('s%d', i + 1) : 'out';
			x.routing_mark = M_UNDERLAY;
			if (e.via_dev) x.bind_interface = e.via_dev;
			push(outs, x);
		}
		if (length(outs) > 1)
			push(outs, { type: 'urltest', tag: 'out', outbounds: map(outs, (x) => x.tag),
				url: cursor().get('detour', 'main', 'urltest_url') ?? 'https://www.gstatic.com/generate_204',
				interval: '3m', tolerance: 100 });
		cfg = {
			log: { level: 'warn' },
			inbounds: [ { type: 'tun', tag: 'tun-in', interface_name: e.device,
				address: [ tun_addr(e) ], mtu: 1400,
				auto_route: false, stack: 'gvisor' } ],
			outbounds: outs,
			route: { final: 'out', auto_detect_interface: false }
		};
	}
	else {
		o.streamSettings ??= {};
		o.streamSettings.sockopt ??= {};
		o.streamSettings.sockopt.mark = M_UNDERLAY;
		if (e.via_dev) o.streamSettings.sockopt.interface = e.via_dev;
		cfg = {
			log: { loglevel: 'warning' },
			inbounds: [ { tag: 'tun-in', protocol: 'tun', settings: { name: e.device, MTU: 1400 } } ],
			outbounds: [ o ]
		};
	}
	return { config: cfg };
}

// writes the configs; returns lines "name<TAB>binary<TAB>args" for the init script
export function prepare() {
	fs.mkdir(RUN);
	fs.mkdir(DIR);
	const lines = [], errors = [];
	for (let e in list()) {
		if (!e.enabled) continue;
		if (!e.installed) { push(errors, sprintf('engine %s: %s is not installed', e.name, BIN[e.type])); continue; }
		const r = render(e);
		if (r.error) { push(errors, sprintf('engine %s: %s', e.name, r.error)); continue; }
		const f = sprintf('%s/%s.json', DIR, e.name);
		fs.writefile(f, sprintf('%.J\n', r.config));
		fs.chmod(f, 0600);
		push(lines, sprintf('%s\t%s\trun -c %s', e.name, BIN[e.type], f));
	}
	return { lines, errors };
}

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
}
