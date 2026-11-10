// What LuCI shows and does with exits: a readable description of each exit (protocol, security, transport,
// server, the exit it rides, a subscription's servers) without secrets, removing an exit with everything it
// owns, choosing one server of a subscription, editing or replacing a proxy exit's configuration.
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, log, PERSIST, RUN } from 'detour.core';
import * as links from 'detour.links';
import * as engines from 'detour.engines';

const UP = { vless: 'VLESS', vmess: 'VMess', trojan: 'Trojan', shadowsocks: 'Shadowsocks', hysteria2: 'Hysteria2',
	hysteria: 'Hysteria', tuic: 'TUIC', wireguard: 'WireGuard', anytls: 'AnyTLS', shadowtls: 'ShadowTLS',
	socks: 'SOCKS', http: 'HTTP' };
const NET = { tcp: 'TCP', raw: 'TCP', ws: 'WebSocket', grpc: 'gRPC', http: 'HTTP/2', h2: 'HTTP/2',
	httpupgrade: 'HTTPUpgrade', xhttp: 'XHTTP', splithttp: 'XHTTP', quic: 'QUIC', kcp: 'mKCP' };

// "VLESS · Reality · TCP · Vision" from a sing-box or an Xray outbound
export function summary(o) {
	if (type(o) != 'object') return '';
	const p = [];
	if (o.protocol) {   // Xray
		const ss = o.streamSettings ?? {};
		push(p, UP[o.protocol] ?? o.protocol);
		if (ss.security == 'reality') push(p, 'Reality'); else if (ss.security == 'tls') push(p, 'TLS');
		// a transport is a word only for the protocols that have one (Shadowsocks over "tcp" says nothing)
		if (o.protocol != 'shadowsocks' || (ss.network && ss.network != 'tcp')) push(p, NET[ss.network ?? 'tcp'] ?? ss.network);
		const flow = o.settings?.vnext?.[0]?.users?.[0]?.flow;
		if (flow && index(flow, 'vision') >= 0) push(p, 'Vision');
	}
	else {              // sing-box
		push(p, UP[o.type] ?? o.type);
		if (o.tls?.reality?.enabled) push(p, 'Reality'); else if (o.tls?.enabled && index([ 'hysteria2', 'hysteria', 'tuic' ], o.type) < 0) push(p, 'TLS');
		if (o.transport?.type) push(p, NET[o.transport.type] ?? o.transport.type);
		else if (index([ 'vless', 'vmess', 'trojan' ], o.type) >= 0) push(p, 'TCP');
		if (o.flow && index(o.flow, 'vision') >= 0) push(p, 'Vision');
		if (o.type == 'hysteria2' && o.obfs?.type) push(p, 'obfs');
	}
	return join(' · ', filter(p, (x) => x));
}

function server_of(o) {
	if (o?.protocol) {
		const v = o.settings?.vnext?.[0] ?? o.settings?.servers?.[0];
		return { server: v?.address, port: v?.port };
	}
	return { server: o?.server, port: o?.server_port };
}

function read_json(f) {
	try { return json(fs.readfile(f) ?? 'null'); } catch (e) { return null; }
}

function outbounds_of(f) {
	let o = read_json(f);
	if (type(o?.outbounds) == 'array') o = o.outbounds;
	return filter((type(o) == 'array') ? o : [ o ], (x) => type(x) == 'object');
}

// the engine of an exit: "<exit>_eng", or the one whose device is the exit's device
function engine_of(c, name) {
	if (c.get('detour', name + '_eng') == 'engine') return name + '_eng';
	// the exit's device: "device", else its interface name (core.load does the same)
	const dev = c.get('detour', name, 'device') ?? c.get('detour', name, 'iface') ?? name;
	let e = null;
	c.foreach('detour', 'engine', (s) => { if (!e && dev && s.device == dev) e = s['.name']; });
	return e;
}

// the subscription an exit belongs to ("<sub>_sub")
function sub_of(c, name) {
	const m = match(name, /^(.+)_sub$/);
	return (m && c.get('detour', m[1]) == 'subscription') ? m[1] : null;
}

export function info() {
	const c = cursor(), out = [];
	c.foreach('detour', 'exit', function(s) {
		const n = s['.name'];
		const iface = s.iface ?? n;
		const x = { name: n, label: s.label ?? n, enabled: s.enabled != '0', device: s.device ?? iface, iface,
			warp: s.warp == '1', kind: null, proto: '', server: null, port: null, via: null };
		const eng = engine_of(c, n);
		const nproto = c.get('network', iface, 'proto');
		if (eng) {
			const e = c.get_all('detour', eng);
			x.engine = eng;
			x.kind = e.type == 'xray' ? 'xray' : 'singbox';
			x.via = e.via ?? null;
			x.engine_enabled = e.enabled != '0';
			const outs = outbounds_of(e.outbound);
			const sub = sub_of(c, n);
			if (sub) {
				x.kind = 'subscription';
				x.subscription = sub;
				x.pick = e.pick ?? null;
				const names = read_json(engines.names_file(n)) ?? [];
				x.servers = [];
				for (let i, o in outs) {
					const nm = names[i] ?? null;
					const sv = server_of(o);
					push(x.servers, { key: engines.server_key(o, nm), name: nm ?? sprintf('%s:%s', sv.server, sv.port), proto: summary(o), server: sv.server, port: sv.port });
				}
				const st = c.get_all('detour', sub);
				const ss = read_json(sprintf('%s/subs/%s.status', RUN, sub));
				x.sub_info = ss?.info ?? null;   // traffic and expiry the provider reported
				x.sub_interval = int(st.interval ?? x.sub_info?.update_hours ?? 24);
				x.sub_auto = !!engines.api_port(eng) && !e.pick;
			}
			else if (length(outs)) {
				x.proto = summary(outs[0]);
				const sv = server_of(outs[0]);
				x.server = sv.server; x.port = sv.port;
			}
		}
		else if (nproto == 'wireguard' || nproto == 'amneziawg') {
			x.kind = (nproto == 'amneziawg') ? 'amneziawg' : 'wireguard';
			let peer = null;
			c.foreach('network', nproto + '_' + iface, (p) => { if (!peer) peer = p; });
			x.server = peer?.endpoint_host; x.port = peer?.endpoint_port;
			const masked = nproto == 'amneziawg' && (int(c.get('network', iface, 'awg_jc') ?? 0) > 0 || c.get('network', iface, 'awg_i1'));
			x.proto = (nproto == 'amneziawg' ? 'AmneziaWG' : 'WireGuard') + (masked ? ' · ' + 'masking' : '');
			x.mtu = c.get('network', iface, 'mtu');
		}
		else x.kind = nproto ?? 'other';
		if (x.via) x.via_label = c.get('detour', x.via, 'label') ?? x.via;
		push(out, x);
	});
	return out;
}

// remove an exit with everything it owns: its engine and outbound files, its netifd interface (and WG/AWG
// peers), its place in the firewall zone, its place in policies; a subscription's exit takes the
// subscription with it; a WARP exit is deregistered at Cloudflare when it has a registration
export function remove(name) {
	const c = cursor();
	if (c.get('detour', name) != 'exit') return { error: 'no exit ' + name };
	const used_by = [];
	c.foreach('detour', 'engine', function(s) {
		if (s.via != name) return;
		const x = replace(s['.name'], /_eng$/, '');
		push(used_by, c.get('detour', x, 'label') ?? x);
	});
	if (length(used_by)) return { error: 'other exits connect through it: ' + join(', ', used_by) };
	if (c.get('detour', name, 'warp') == '1' && fs.access(sprintf('%s/warp/%s.json', PERSIST, name))) {
		const r = run('/usr/sbin/detour warp-unregister ' + name);
		return { name, removed: true, output: trim(r.out) };
	}
	const iface = c.get('detour', name, 'iface') ?? name;
	const sub = sub_of(c, name);
	const eng = engine_of(c, name);
	if (eng) {
		const f = c.get('detour', eng, 'outbound');
		if (f && index(f, PERSIST + '/engines/') == 0) fs.unlink(f);
		c.delete('detour', eng);
	}
	fs.unlink(engines.names_file(name));
	if (sub) { c.delete('detour', sub); run(sprintf("rm -f '/tmp/detour/subs/%s.status'", sub)); }
	c.foreach('detour', 'policy', function(p) {
		const ex = (type(p.exit) == 'array') ? p.exit : (p.exit ? [ p.exit ] : []);
		if (index(ex, name) >= 0) {
			const rest = filter(ex, (x) => x != name);
			if (length(rest)) c.set('detour', p['.name'], 'exit', rest); else c.delete('detour', p['.name'], 'exit');
		}
	});
	const peers = [];
	for (let t in [ 'wireguard_' + iface, 'amneziawg_' + iface ]) c.foreach('network', t, (p) => push(peers, p['.name']));
	for (let p in peers) c.delete('network', p);
	if (c.get('network', iface)) c.delete('network', iface);
	c.foreach('firewall', 'zone', function(z) {
		const nets = (type(z.network) == 'array') ? z.network : (z.network ? split(z.network, ' ') : []);
		if (index(nets, iface) >= 0) c.set('firewall', z['.name'], 'network', filter(nets, (x) => x != iface));
	});
	c.delete('detour', name);
	c.commit('detour'); c.commit('network'); c.commit('firewall');
	run('/etc/init.d/network reload; fw4 -q reload; /etc/init.d/detour reload');
	log(sprintf('exit %s removed%s', name, sub ? ' with its subscription ' + sub : ''));
	return { name, removed: true, subscription: sub };
}

// one server of a subscription ("" = automatic: the urltest group picks)
export function pick(name, key) {
	const c = cursor();
	const eng = engine_of(c, name);
	if (!eng || !sub_of(c, name)) return { error: name + ' is not a subscription exit' };
	if (key && length(key)) {
		const known = filter(info(), (x) => x.name == name)[0]?.servers ?? [];
		if (!length(filter(known, (s) => s.key == key))) return { error: 'no such server in the subscription' };
		c.set('detour', eng, 'pick', key);
	}
	else c.delete('detour', eng, 'pick');
	c.commit('detour');
	run('/etc/init.d/detour reload');
	return { name, pick: key || null };
}

// the configuration of a proxy exit, for the editor (an admin's LuCI session; it holds the exit's secrets)
export function outbound_get(name) {
	const c = cursor();
	const eng = engine_of(c, name);
	if (!eng || sub_of(c, name)) return { error: 'only a proxy exit (not a subscription) has an editable configuration' };
	const outs = outbounds_of(c.get('detour', eng, 'outbound'));
	if (!length(outs)) return { error: 'the configuration file is missing' };
	return { name, engine: c.get('detour', eng, 'type'), config: sprintf('%.J', outs[0]) };
}

export function outbound_set(name, text) {
	const c = cursor();
	const eng = engine_of(c, name);
	if (!eng || sub_of(c, name)) return { error: 'only a proxy exit (not a subscription) has an editable configuration' };
	let o;
	try { o = json(text); } catch (e) { return { error: 'not valid JSON' }; }
	if (type(o) != 'object') return { error: 'the configuration must be one JSON object' };
	const xray = c.get('detour', eng, 'type') == 'xray';
	if (xray ? !o.protocol : !o.type) return { error: xray ? 'an Xray outbound needs "protocol"' : 'a sing-box outbound needs "type"' };
	const f = c.get('detour', eng, 'outbound') ?? sprintf('%s/engines/%s.json', PERSIST, name);
	fs.writefile(f + '.tmp', ''); fs.chmod(f + '.tmp', 0600);
	fs.writefile(f + '.tmp', sprintf('%.J\n', o));
	fs.rename(f + '.tmp', f);
	c.set('detour', eng, 'outbound', f); c.commit('detour');
	run('/etc/init.d/detour reload');
	log(sprintf('exit %s: configuration edited', name));
	return { name, proto: summary(o) };
}

// another server for the same exit from a share link (its place in policies stays); an Xray exit becomes sing-box
export function set_link(name, link) {
	const c = cursor();
	const eng = engine_of(c, name);
	if (!eng || sub_of(c, name)) return { error: 'only a proxy exit (not a subscription) can take a link' };
	const r = links.parse(link ?? '');
	if (r.error) return r;
	const f = engines.write_outbound(name, r.outbound);
	c.set('detour', eng, 'type', 'singbox');
	c.set('detour', eng, 'outbound', f);
	c.commit('detour');
	run('/etc/init.d/detour reload');
	log(sprintf('exit %s: server replaced from a link', name));
	return { name, proto: summary(r.outbound), server: r.outbound.server };
}
