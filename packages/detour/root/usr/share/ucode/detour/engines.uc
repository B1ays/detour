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
import { M_UNDERLAY, RUN } from 'detour.core';

export const DIR = RUN + '/engines';
const BIN = { singbox: '/usr/bin/sing-box', xray: '/usr/bin/xray' };

export function list() {
	const out = [];
	let i = 0;
	cursor().foreach('detour', 'engine', function(s) {
		i++;
		const t = s.type;
		if (!BIN[t]) return;
		push(out, {
			name: s['.name'], type: t, idx: i,
			device: s.device ?? s['.name'],
			outbound: s.outbound,
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
	if (type(o) == 'array') o = o[0];
	// a full config was given: take its first outbound
	if (type(o?.outbounds) == 'array') o = o.outbounds[0];
	if (type(o) != 'object') return { error: 'outbound must be a JSON object' };
	return { o };
}

export function render(e) {
	const r = read_outbound(e);
	if (r.error) return r;
	const o = r.o;
	o.tag = 'out';
	let cfg;
	if (e.type == 'singbox') {
		o.routing_mark = M_UNDERLAY;
		cfg = {
			log: { level: 'warn' },
			inbounds: [ { type: 'tun', tag: 'tun-in', interface_name: e.device,
				address: [ sprintf('172.19.%d.1/30', e.idx % 250) ], mtu: 1400,
				auto_route: false, stack: 'gvisor' } ],
			outbounds: [ o ],
			route: { final: 'out', auto_detect_interface: false }
		};
	}
	else {
		o.streamSettings ??= {};
		o.streamSettings.sockopt ??= {};
		o.streamSettings.sockopt.mark = M_UNDERLAY;
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
		if (!e.enabled || e.type != 'xray') continue;
		const fl = fs.readfile(sprintf('/sys/class/net/%s/flags', e.device));
		if (fl != null && (hex(trim(fl)) & 1) == 0) system(sprintf("ip link set '%s' up", e.device));
	}
}
