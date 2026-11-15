// Adding exits from whatever a person has: share links (one or many, or a base64 list as a subscription
// gives), an Amnezia vpn:// key, a WireGuard / AmneziaWG .conf or wireguard:// link, a sing-box or Xray JSON
// (one outbound, a list, a whole config), a Clash / Mihomo YAML (its "proxies"). candidates() only reads and
// tells what it found, without secrets; add() makes exits of the chosen ones.
// The text holds keys and passwords: it is never logged; the CLI gets it through a file (mode 600).
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, PERSIST, clean_label } from 'detour.core';
import * as links from 'detour.links';
import * as engines from 'detour.engines';
import * as wgconf from 'detour.wgconf';
import { summary } from 'detour.exitui';
import { ensure_zone } from 'detour.warp';

const PROXY_TYPES = [ 'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'hysteria', 'tuic', 'anytls', 'shadowtls', 'socks', 'http' ];
const XRAY_PROTOS = [ 'vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'hysteria' ];

function b64any(s) {
	s = replace(replace(replace(trim(s), /\s+/g, ''), '-', '+'), '_', '/');
	while (length(s) % 4) s += '=';
	return b64dec(s);
}

// --- a tiny YAML reader: enough for the "proxies" of a Clash / Mihomo config ---------------------------------

function unq(s) {
	s = trim(s);
	if (substr(s, 0, 1) == '"') { try { return json(s); } catch (e) { return substr(s, 1, length(s) - 2); } }
	if (substr(s, 0, 1) == "'") return replace(substr(s, 1, length(s) - 2), "''", "'");
	return s;
}

// a flow value: {a: b, c: [d, e]} / [..] / a scalar
function flow(s, pos) {
	const n = length(s);
	const ws = () => { while (pos < n && index(' \t', substr(s, pos, 1)) >= 0) pos++; };
	const scal = (stops) => {
		ws();
		const c = substr(s, pos, 1);
		if (c == '"' || c == "'") {
			let j = pos + 1;
			while (j < n && (substr(s, j, 1) != c || (c == '"' && substr(s, j - 1, 1) == '\\'))) j++;
			const v = unq(substr(s, pos, j - pos + 1));
			pos = j + 1;
			return v;
		}
		let j = pos;
		while (j < n && index(stops, substr(s, j, 1)) < 0) j++;
		const v = trim(substr(s, pos, j - pos));
		pos = j;
		return v == 'true' ? true : (v == 'false' ? false : v);
	};
	let val;
	val = function() {
		ws();
		const c = substr(s, pos, 1);
		if (c == '{') {
			pos++;
			const o = {};
			while (pos < n) {
				ws();
				if (substr(s, pos, 1) == '}') { pos++; break; }
				const p0 = pos;
				const k = scal(':}');
				if (substr(s, pos, 1) == ':') pos++;
				o[k] = val();
				ws();
				if (substr(s, pos, 1) == ',') pos++;
				if (pos == p0) break;   // broken text (a stray ']'): stop instead of looping forever
			}
			return o;
		}
		if (c == '[') {
			pos++;
			const a = [];
			while (pos < n) {
				ws();
				if (substr(s, pos, 1) == ']') { pos++; break; }
				const p0 = pos;
				push(a, val());
				ws();
				if (substr(s, pos, 1) == ',') pos++;
				if (pos == p0) break;   // broken text (a stray '}'): stop instead of looping forever
			}
			return a;
		}
		return scal(',}]');
	};
	return val();
}

function scalar(s) {
	s = trim(s);
	const c = substr(s, 0, 1);
	if (c == '{' || c == '[') return flow(s, 0);
	if (c != '"' && c != "'") { const h = index(s, ' #'); if (h >= 0) s = trim(substr(s, 0, h)); }
	if (s == 'true') return true;
	if (s == 'false') return false;
	return unq(s);
}

// lines [{ ind, text }] -> value, by indentation
// the two call each other: declared first (ucode does not hoist functions)
let ymap;
function yblock(L, i, ind) {
	if (i >= length(L)) return [ null, i ];
	if (match(L[i].text, /^-( |$)/)) {
		const a = [];
		while (i < length(L) && L[i].ind == ind && match(L[i].text, /^-( |$)/)) {
			const rest = trim(substr(L[i].text, 1));
			if (!length(rest)) {
				const r = (i + 1 < length(L) && L[i + 1].ind > ind) ? yblock(L, i + 1, L[i + 1].ind) : [ null, i + 1 ];
				push(a, r[0]); i = r[1];
			}
			else if (match(rest, /^[^ {\["'][^:]*:( |$)/)) {
				// "- key: value" starts a map whose keys sit where "key" does
				const col = ind + length(L[i].text) - length(rest);
				L[i] = { ind: col, text: rest };
				const r = ymap(L, i, col);
				push(a, r[0]); i = r[1];
			}
			else { push(a, scalar(rest)); i++; }
		}
		return [ a, i ];
	}
	return ymap(L, i, ind);
}

ymap = function(L, i, ind) {
	const o = {};
	while (i < length(L) && L[i].ind == ind && !match(L[i].text, /^-( |$)/)) {
		const t = L[i].text;
		let k = index(t, ': '), key, v;
		if (k < 0 && substr(t, -1) == ':') { key = substr(t, 0, length(t) - 1); v = ''; }
		else if (k >= 0) { key = substr(t, 0, k); v = trim(substr(t, k + 2)); }
		else { i++; continue; }
		key = unq(key);
		i++;
		if (length(v)) o[key] = scalar(v);
		else if (i < length(L) && (L[i].ind > ind || (L[i].ind == ind && match(L[i].text, /^-( |$)/)))) {
			const r = yblock(L, i, L[i].ind);
			o[key] = r[0]; i = r[1];
		}
		else o[key] = null;
	}
	return [ o, i ];
};

// the "proxies:" list of a Clash config (other sections are not read: they may use YAML this reader does not know)
function clash_proxies(text) {
	const all = split(replace(text, '\r', ''), '\n');
	let s = -1;
	for (let i, l in all) if (match(l, /^proxies:[ \t]*$/)) { s = i; break; }
	if (s < 0) return null;
	const L = [];
	for (let i = s + 1; i < length(all); i++) {
		const l = all[i];
		if (!length(trim(l)) || match(trim(l), /^#/)) continue;
		const ind = length(l) - length(ltrim(l));
		if (ind == 0 && !match(l, /^-/)) break;
		push(L, { ind, text: trim(l) });
	}
	if (!length(L)) return [];
	const r = yblock(L, 0, L[0].ind);
	return (type(r[0]) == 'array') ? r[0] : [];
}

function clean(o) {
	for (let k in keys(o)) {
		if (o[k] == null || o[k] == '') delete o[k];
		else if (type(o[k]) == 'object') { clean(o[k]); if (!length(keys(o[k]))) delete o[k]; }
	}
	return o;
}

function arr(v) { return (v == null) ? null : ((type(v) == 'array') ? v : split('' + v, ',')); }

// a Clash proxy -> { outbound } | { wg } | { error }
function from_clash(p) {
	if (type(p) != 'object' || !p.server || !p.port) return { error: 'a proxy without server/port' };
	const base = { server: '' + p.server, server_port: int(p.port) };
	const sni = p.servername ?? p.sni ?? null;
	const tls = (on) => on ? { enabled: true, server_name: sni ?? base.server, insecure: p['skip-cert-verify'] ? true : null,
		alpn: arr(p.alpn), utls: p['client-fingerprint'] ? { enabled: true, fingerprint: p['client-fingerprint'] } : null,
		reality: p['reality-opts'] ? { enabled: true, public_key: p['reality-opts']['public-key'], short_id: p['reality-opts']['short-id'] ?? '' } : null } : null;
	const tr = () => {
		const w = p['ws-opts'] ?? {}, g = p['grpc-opts'] ?? {}, h = p['h2-opts'] ?? p['http-opts'] ?? {};
		switch (p.network ?? 'tcp') {
		case 'tcp': return null;
		case 'ws': return w['v2ray-http-upgrade'] ? { type: 'httpupgrade', path: w.path ?? '/', host: w.headers?.Host }
			: { type: 'ws', path: w.path ?? p['ws-path'] ?? '/', headers: (w.headers?.Host) ? { Host: w.headers.Host } : null };
		case 'grpc': return { type: 'grpc', service_name: g['grpc-service-name'] ?? '' };
		case 'h2': case 'http': return { type: 'http', host: arr(h.host), path: (type(h.path) == 'array') ? h.path[0] : h.path };
		default: return { error: 'transport ' + p.network };
		}
	};
	let o;
	switch (p.type) {
	case 'ss':
		if (p.plugin) return { error: 'Shadowsocks plugin ' + p.plugin + ' is not supported' };
		o = { type: 'shadowsocks', ...base, method: p.cipher, password: '' + p.password };
		break;
	case 'vmess': case 'vless': case 'trojan': {
		const t = tr();
		if (t?.error) return { error: t.error + ' is not supported' };
		o = { type: p.type, ...base, transport: t };
		if (p.type == 'trojan') { o.password = '' + p.password; o.tls = tls(true); }
		else {
			o.uuid = p.uuid;
			o.tls = tls(p.tls == true || !!p['reality-opts']);
			if (p.type == 'vmess') { o.alter_id = int(p.alterId ?? 0); o.security = p.cipher ?? 'auto'; }
			else if (p.flow) o.flow = p.flow;
		}
		if (o.tls?.reality && !o.tls.utls) o.tls.utls = { enabled: true, fingerprint: 'chrome' };
		break;
	}
	case 'hysteria2':
		o = { type: 'hysteria2', ...base, password: '' + (p.password ?? p.auth ?? ''), tls: tls(true),
			obfs: p.obfs ? { type: p.obfs, password: p['obfs-password'] ?? '' } : null };
		break;
	case 'tuic':
		o = { type: 'tuic', ...base, uuid: p.uuid, password: '' + (p.password ?? ''), tls: tls(true),
			congestion_control: p['congestion-controller'], udp_relay_mode: p['udp-relay-mode'] };
		if (!o.tls.alpn) o.tls.alpn = [ 'h3' ];
		break;
	case 'wireguard': {
		const I = { PrivateKey: p['private-key'], Address: p.ip, MTU: p.mtu };
		for (let k, v in p['amnezia-wg-option'] ?? {}) I[uc(substr(k, 0, 1)) + substr(k, 1)] = '' + v;
		const r = wgconf.from_conf(sprintf('[Interface]\nPrivateKey = %s\nAddress = %s\n%s%s[Peer]\nPublicKey = %s\n%sEndpoint = %s:%s\n',
			I.PrivateKey, I.Address ?? '', I.MTU ? 'MTU = ' + I.MTU + '\n' : '',
			join('', map(filter(wgconf.AWG_KEYS, (k) => I[k] != null), (k) => k + ' = ' + I[k] + '\n')),
			p['public-key'], p['pre-shared-key'] ? 'PresharedKey = ' + p['pre-shared-key'] + '\n' : '', p.server, p.port), 'Clash proxy');
		return r.error ? r : { wg: r };
	}
	default: return { error: 'type ' + p.type + ' is not supported' };
	}
	return { outbound: clean(o) };
}

// --- Amnezia vpn:// ---------------------------------------------------------------------------------------------

// vpn://<base64url of qCompress(JSON)>: 4 bytes of length, then a zlib stream (newer keys: plain JSON)
function amnezia(link) {
	const raw = b64any(substr(trim(link), 6));
	if (!raw) return { error: 'vpn://: not base64' };
	let text = raw;
	if (substr(raw, 0, 1) != '{') {
		let z = null;
		try { z = require('zlib'); } catch (e) { }
		if (!z) return { error: 'vpn://: the ucode-mod-zlib package is needed to read this key (apk add ucode-mod-zlib)' };
		try { text = z.inflate(substr(raw, 4)); } catch (e) { text = null; }
		if (!text) return { error: 'vpn://: cannot unpack the key' };
	}
	let j;
	try { j = json(text); } catch (e) { return { error: 'vpn://: not an Amnezia key' }; }
	const out = [], name = j.description ?? j.name ?? null;
	for (let c in j.containers ?? []) {
		for (let k in [ 'awg', 'wireguard' ]) {
			const lc = c[k]?.last_config;
			if (!lc) continue;
			let cfg = null;
			try { cfg = json(lc)?.config; } catch (e) { }
			if (!cfg) continue;
			const r = wgconf.from_conf(cfg, 'Amnezia ' + c.container);
			push(out, r.error ? { error: r.error } : { wg: r, label: name });
		}
		if (c.xray?.last_config) {
			let x = null;
			try { x = json(c.xray.last_config); } catch (e) { }
			for (let o in x?.outbounds ?? [])
				if (index(XRAY_PROTOS, o.protocol) >= 0) push(out, { xray: o, label: name });
		}
	}
	if (!length(out)) return { error: 'vpn://: no AmneziaWG, WireGuard or Xray in the key (other Amnezia protocols are not supported)' };
	return { list: out };
}

// --- what is in a text ------------------------------------------------------------------------------------------

function from_json(j) {
	const out = [];
	const take = (o) => {
		if (type(o) != 'object') return;
		if (index(PROXY_TYPES, o.type) >= 0) { const x = { ...o }; delete x.tag; delete x.detour; push(out, { outbound: x, label: o.tag }); }   // .detour: sing-box's own field (dial through another outbound), not this project
		else if (index(XRAY_PROTOS, o.protocol) >= 0) push(out, { xray: o, label: o.tag });
	};
	if (type(j) == 'array') for (let o in j) take(o);
	else if (type(j?.outbounds) == 'array') for (let o in j.outbounds) take(o);
	else take(j);
	return out;
}

function from_text0(text) {
	text = trim(replace(text ?? '', '\r', ''));
	if (!length(text)) return { error: 'empty' };
	if (match(text, /^vpn:\/\//)) return amnezia(text);
	if (match(text, /(^|\n)\[Interface\]/)) {
		const r = wgconf.from_conf(text, 'the config');
		return r.error ? r : { list: [ { wg: r } ] };
	}
	const c0 = substr(text, 0, 1);
	if (c0 == '{' || c0 == '[') {
		let j;
		try { j = json(text); } catch (e) { return { error: 'not valid JSON' }; }
		const l = from_json(j);
		return length(l) ? { list: l } : { error: 'no proxy in this JSON' };
	}
	const px = clash_proxies(text);
	if (px != null) {
		const l = [];
		for (let p in px) {
			const r = from_clash(p);
			push(l, r.error ? { error: (p?.name ? p.name + ': ' : '') + r.error } : { ...r, label: p.name });
		}
		return length(l) ? { list: l } : { error: 'the proxies list is empty' };
	}
	// links, one per line; a whole base64 block (as a subscription answers) is unpacked first
	if (index(text, '://') < 0) {
		const d = b64any(text);
		if (d && index(d, '://') >= 0) text = trim(replace(d, '\r', ''));
	}
	const l = [];
	for (let line in split(text, '\n')) {
		line = trim(line);
		if (!length(line) || substr(line, 0, 1) == '#') continue;
		if (match(line, /^(wireguard|wg):\/\//)) {
			const r = wgconf.from_link(line);
			push(l, r.error ? { error: r.error } : { wg: r, label: r.remark });
		}
		else if (match(line, /^vpn:\/\//)) {
			const r = amnezia(line);
			if (r.error) push(l, { error: r.error }); else for (let x in r.list) push(l, x);
		}
		else {
			const r = links.parse(line);
			push(l, r.error ? { error: r.error } : { outbound: r.outbound, label: r.remark });
		}
	}
	return length(l) ? { list: l } : { error: 'nothing recognised: a link, a key, a WireGuard config, JSON or Clash YAML is expected' };
}

// the names inside (remarks, Clash names, JSON tags) come from whoever made the text: cleaned for the pages
function from_text(text) {
	const r = from_text0(text);
	for (let x in r.list ?? []) if (x.label != null) x.label = clean_label(x.label);
	return r;
}

// --- which engine runs a proxy ----------------------------------------------------------------------------------

const ENGINE_BIN = { singbox: '/usr/bin/sing-box', xray: '/usr/bin/xray' };
function installed(et) { return !!fs.access(ENGINE_BIN[et]); }

// a proxy in both forms where it has them, the engines that can run it (its own format first: a link or a
// sing-box / Clash config -> sing-box, an Xray config or an Amnezia key -> Xray), and why the others cannot
function engines_of(x) {
	if (x.xray) {
		const sb = links.from_xray(x.xray);
		const sb_why = sb.error ?? links.singbox_why(sb.outbound);
		return { xray: x.xray, outbound: sb.error ? null : sb.outbound, can: sb_why ? [ 'xray' ] : [ 'xray', 'singbox' ], why: { singbox: sb_why } };
	}
	const sb_why = links.singbox_why(x.outbound), xr = links.to_xray(x.outbound);
	const can = filter([ sb_why ? null : 'singbox', xr.error ? null : 'xray' ], (e) => e);
	return { outbound: x.outbound, xray: xr.xray, can, why: { singbox: sb_why, xray: xr.error } };
}

// the engine when the person did not choose: its own one if installed, else another installed one that can
function default_engine(can) {
	for (let et in can) if (installed(et)) return et;
	return can[0];
}

function describe(x) {
	if (x.error) return { error: x.error };
	if (x.wg) return { kind: x.wg.kind, label: x.label, proto: x.wg.kind == 'awg' ? 'AmneziaWG · masking' : 'WireGuard',
		server: x.wg.peer.endpoint_host, port: int(x.wg.peer.endpoint_port), warp: x.wg.warp };
	const o = x.xray ?? x.outbound;
	const v = o.protocol ? (o.settings?.vnext?.[0] ?? o.settings?.servers?.[0] ?? o.settings) : null;
	const en = engines_of(x);
	if (!length(en.can)) return { error: en.why.singbox ?? en.why.xray };
	return { kind: default_engine(en.can), engines: en.can, label: x.label, proto: summary(o),
		server: v ? v.address : o.server, port: v ? v.port : o.server_port };
}

// what a text holds, without secrets: [{ kind, engines, label, proto, server, port } | { error }]; installed: the
// engines on this router (LuCI marks the others)
export function candidates(text) {
	const r = from_text(text);
	if (r.error) return { error: r.error };
	return { candidates: map(r.list, describe), installed: { singbox: installed('singbox'), xray: installed('xray') } };
};

function free_id(c) {
	const used = {};
	c.foreach('detour', 'exit', (s) => { used[int(s.id)] = true; });
	let id = 1;
	while (id <= 250 && used[id]) id++;
	return id;
}

function used_name(c, n) { return !!(c.get('detour', n) || c.get('detour', n + '_eng') || c.get('network', n)); }

function make_wg(n, w, label) {
	const c = cursor();
	const id = free_id(c);
	if (id > 250) return null;   // 250 exits is the limit
	wgconf.write(c, n, w);
	ensure_zone(c, n);
	c.set('detour', n, 'exit');
	c.set('detour', n, 'id', '' + id);
	c.set('detour', n, 'iface', n);
	c.set('detour', n, 'label', label ?? n);
	c.set('detour', n, 'probe', 'https://1.1.1.1/cdn-cgi/trace');
	if (w.warp) c.set('detour', n, 'warp', '1');
	c.commit('detour'); c.commit('network'); c.commit('firewall');
	run('/etc/init.d/network reload; fw4 -q reload');
	return id;
}

// picks: indices of candidates (empty = all usable); name: the exit's name (several: name1, name2 ..);
// engs: the engine chosen for a candidate, by its index ('singbox' / 'xray'; none or one that cannot: the default)
export function add(text, picks, name, via, label, engs) {
	const r = from_text(text);
	if (r.error) return { error: r.error };
	const ne = engines.check_name(name);
	if (ne) return { error: ne };
	const c = cursor();
	if (via && c.get('detour', via) != 'exit') return { error: 'via: "' + via + '" is not an exit' };
	let idx = (type(picks) == 'array' && length(picks)) ? picks : map(r.list, (x, i) => i);
	idx = filter(idx, (i) => r.list[int(i)] && !r.list[int(i)].error);
	if (!length(idx)) return { error: 'nothing usable was chosen' };
	const out = [], notes = [];
	for (let k, i in idx) {
		const x = r.list[int(i)];
		const n = (length(idx) == 1) ? name : substr(name, 0, 9) + (k + 1);
		if (used_name(c, n)) { push(notes, n + ' is already used, skipped'); continue; }
		const lab = clean_label((length(idx) == 1 && label) ? label : x.label) ?? n;
		if (x.wg) {
			const id = make_wg(n, x.wg, lab);
			if (id == null) { push(notes, n + ': no free exit id (250 exits is the limit)'); continue; }
			if (via) push(notes, n + ': a WireGuard exit always connects directly');
			push(out, { name: n, id, kind: x.wg.kind });
			continue;
		}
		const en = engines_of(x);
		if (!length(en.can)) { push(notes, n + ': ' + (en.why.singbox ?? en.why.xray)); continue; }
		const want = (type(engs) == 'array') ? engs[int(i)] : null;
		const et = (want && index(en.can, want) >= 0) ? want : default_engine(en.can);
		if (!installed(et)) { push(notes, n + ': ' + (et == 'xray' ? 'xray-core' : 'sing-box') + ' is not installed'); continue; }
		const ob = (et == 'xray') ? en.xray : links.for_singbox(en.outbound);
		// the engine itself must take it: an exit that never starts is worse than none
		const bad = engines.test(et, ob);
		if (bad) { push(notes, n + ': ' + (et == 'xray' ? 'Xray' : 'sing-box') + ' refused the configuration: ' + bad); continue; }
		const f = engines.write_outbound(n, ob);
		const e = engines.create_exit(n, f, via, lab, null, et);
		if (e.error) { push(notes, n + ': ' + e.error); continue; }
		push(out, { name: n, id: e.exit_id, kind: et });
	}
	if (!length(out)) return { error: join('; ', notes) || 'nothing was added' };
	return { added: out, notes };
};
