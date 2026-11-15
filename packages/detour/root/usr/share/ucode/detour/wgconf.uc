// WireGuard / AmneziaWG exits as netifd interfaces: from a .conf (wg-quick INI, AmneziaWG keys Jc..I5), from a
// wireguard:// link, into network UCI (proto wireguard | amneziawg, a peer section), and back into a .conf for export.
// Used when adding an exit from a link or a file, and for its export.
'use strict';

import { M_UNDERLAY } from 'detour.core';

// AmneziaWG masking keys (amneziawg-tools 3.1 names; UCI options awg_jc .. awg_i5)
export const AWG_KEYS = [ 'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5' ];
// the key every Cloudflare WARP endpoint presents: a WG/AWG exit with this peer is WARP
export const WARP_PUB = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';

const RE_V4 = /^[0-9]{1,3}(\.[0-9]{1,3}){3}(\/[0-9]{1,2})?$/;
const RE_KEY = /^[A-Za-z0-9+\/]{42}[AEIMQUYcgkosw048]=$/;

export function ini(text) {
	const o = { Interface: {}, Peer: {} };
	let sec = null;
	for (let l in split(text ?? '', '\n')) {
		l = trim(replace(l, '\r', ''));
		if (!length(l) || substr(l, 0, 1) == '#' || substr(l, 0, 1) == ';') continue;
		const m = match(l, /^\[(.+)\]$/);
		if (m) { sec = m[1]; continue; }
		const i = index(l, '=');
		if (i < 0 || !o[sec]) continue;
		o[sec][trim(substr(l, 0, i))] = trim(substr(l, i + 1));
	}
	return o;
};

// masking really on: plain WireGuard is Jc 0, S 0, H 1..4, no I
function masked(I) {
	for (let k in AWG_KEYS) {
		const v = I[k];
		if (v == null || !length('' + v)) continue;
		if (match(k, /^[JS]/) && int(v) != 0) return true;
		if (match(k, /^H([1-4])$/) && v != substr(k, 1)) return true;
		if (match(k, /^I/)) return true;
	}
	return false;
}

function endpoint(s) {
	return match(s ?? '', /^\[?([^\]\[]+)\]?:([0-9]{1,5})$/);
}

// { kind: 'wg'|'awg', net: { private_key, addresses, mtu, awg }, peer: { public_key, preshared_key, endpoint_host,
//   endpoint_port, persistent_keepalive } } or { error }
function build(I, P, from) {
	if (!I.PrivateKey || !P.PublicKey || !P.Endpoint) return { error: from + ': not a WireGuard config (keys or endpoint missing)' };
	if (!match(I.PrivateKey, RE_KEY) || !match(P.PublicKey, RE_KEY)) return { error: from + ': a key is not a WireGuard key' };
	const ep = endpoint(P.Endpoint);
	if (!ep || int(ep[2]) < 1 || int(ep[2]) > 65535) return { error: from + ': bad Endpoint' };
	const addrs = filter(map(split(I.Address ?? '', ','), (a) => trim(a)), (a) => match(a, RE_V4));
	if (!length(addrs)) return { error: from + ': no IPv4 Address' };
	const awg = masked(I);
	return { kind: awg ? 'awg' : 'wg',
		net: { private_key: I.PrivateKey, addresses: addrs, mtu: I.MTU ?? '1280', awg: awg ? I : null },
		peer: { public_key: P.PublicKey, preshared_key: P.PresharedKey, endpoint_host: ep[1], endpoint_port: ep[2],
			persistent_keepalive: P.PersistentKeepalive ?? '25' },
		warp: P.PublicKey == WARP_PUB };
}

export function from_conf(text, from) { const c = ini(text); return build(c.Interface, c.Peer, from ?? 'config'); };

function pct(s) { return replace(s ?? '', /%([0-9A-Fa-f]{2})/g, (m, h) => chr(hex(h))); }

// wireguard://<private key>@host:port?publickey=..&address=10.0.0.2/32&presharedkey=..&mtu=..&jc=..#remark
// (the form of v2rayN / Hiddify / NekoBox; the key is percent-encoded, "+" stays "+")
export function from_link(link) {
	const m = match(trim(link ?? ''), /^(wireguard|wg):\/\/([^@]+)@([^?#]+)(\?[^#]*)?(#.*)?$/);
	if (!m) return { error: 'not a wireguard:// link' };
	const q = {};
	for (let kv in split(substr(m[4] ?? '', 1), '&')) {
		const i = index(kv, '=');
		if (i > 0) q[lc(substr(kv, 0, i))] = pct(substr(kv, i + 1));
	}
	const I = { PrivateKey: pct(m[2]), Address: q.address ?? q.ip ?? '', MTU: q.mtu };
	for (let k in AWG_KEYS) if (q[lc(k)] != null) I[k] = q[lc(k)];
	const P = { PublicKey: q.publickey ?? q.peer_public_key ?? q.pbk, PresharedKey: q.presharedkey ?? q.psk,
		Endpoint: replace(m[3], /\/$/, ''), PersistentKeepalive: q.keepalive };
	const r = build(I, P, 'link');
	if (r.error) return r;
	r.remark = m[5] ? pct(substr(m[5], 1)) : null;
	return r;
};

// network UCI: the interface and its one peer (a repeated write does not stack peers)
export function write(c, n, e) {
	const proto = e.kind == 'awg' ? 'amneziawg' : 'wireguard';
	c.set('network', n, 'interface');
	c.set('network', n, 'proto', proto);
	c.set('network', n, 'private_key', e.net.private_key);
	c.set('network', n, 'addresses', e.net.addresses);
	c.set('network', n, 'mtu', '' + e.net.mtu);
	c.set('network', n, 'fwmark', sprintf('0x%x', M_UNDERLAY));
	for (let k in AWG_KEYS) c.delete('network', n, 'awg_' + lc(k));
	if (e.net.awg)
		for (let k in AWG_KEYS) if (e.net.awg[k] != null && length('' + e.net.awg[k])) c.set('network', n, 'awg_' + lc(k), e.net.awg[k]);
	const old = [];
	for (let t in [ 'wireguard_' + n, 'amneziawg_' + n ]) c.foreach('network', t, (s) => push(old, s['.name']));
	for (let s in old) c.delete('network', s);
	const ps = c.add('network', proto + '_' + n);
	for (let k, v in e.peer) if (v != null && length('' + v)) c.set('network', ps, k, v);
	c.set('network', ps, 'allowed_ips', [ '0.0.0.0/0' ]);
	c.set('network', ps, 'route_allowed_ips', '0');
};

// network UCI -> a wg-quick .conf (export); null when the interface is not WG/AWG
export function to_conf(c, iface) {
	const s = c.get_all('network', iface);
	if (s?.proto != 'wireguard' && s?.proto != 'amneziawg') return null;
	let peer = null;
	c.foreach('network', s.proto + '_' + iface, (p) => { peer ??= p; });
	if (!peer) return null;
	const L = [ '[Interface]', 'PrivateKey = ' + s.private_key ];
	const addrs = (type(s.addresses) == 'array') ? s.addresses : split(s.addresses ?? '', /\s+/);
	if (length(addrs)) push(L, 'Address = ' + join(', ', addrs));
	if (s.mtu) push(L, 'MTU = ' + s.mtu);
	if (s.proto == 'amneziawg') for (let k in AWG_KEYS) if (s['awg_' + lc(k)] != null) push(L, k + ' = ' + s['awg_' + lc(k)]);
	push(L, '', '[Peer]', 'PublicKey = ' + peer.public_key);
	if (peer.preshared_key) push(L, 'PresharedKey = ' + peer.preshared_key);
	push(L, 'AllowedIPs = 0.0.0.0/0');
	const h = peer.endpoint_host ?? '';
	push(L, 'Endpoint = ' + (index(h, ':') >= 0 ? '[' + h + ']' : h) + ':' + (peer.endpoint_port ?? '51820'));
	if (peer.persistent_keepalive) push(L, 'PersistentKeepalive = ' + peer.persistent_keepalive);
	return join('\n', L) + '\n';
};
