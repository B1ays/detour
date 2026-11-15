// Share links -> sing-box outbound (vless, vmess, trojan, ss, hysteria2/hy2, tuic), and back (to_link, export).
// What only Xray can run rides in the same object: the XHTTP transport ({ type: 'xhttp' }) and, under "_x", VLESS
// encryption, Reality's spiderX and ML-DSA key. to_xray() / from_xray() convert between that form and an Xray
// outbound; singbox_why() / xray_why() tell why an engine cannot run a server (null: it can). The "_x" part never
// reaches a sing-box config (for_singbox() drops it; engines.render calls it for every server).
// Mirrors the stock Detour parser (subs-update.sh parse_link/parse_vmess/parse_ss/parse_hy2):
// SIP002 and legacy ss, '@' allowed inside the hy2 auth (split on the last one), sni defaults
// to the host for TLS, IPv6 hosts in brackets.
'use strict';

// plus: "+" is a space only in query values (form encoding); in the user part and the remark it is itself
// (a password with "+" - Shadowsocks 2022 keys are base64 - must stay as it is)
function pct(s, plus) {
	if (s == null) return null;
	if (plus) s = replace(s, '+', ' ');
	return replace(s, /%([0-9A-Fa-f]{2})/g, (m, h) => chr(hex(h)));
}

function b64(s) {
	s = trim(replace(replace(s, '-', '+'), '_', '/'));
	while (length(s) % 4) s += '=';
	return b64dec(s);
}

function query(q) {
	const o = {};
	for (let kv in split(q ?? '', '&')) {
		if (!length(kv)) continue;
		const i = index(kv, '=');
		if (i < 0) o[kv] = '';
		else o[substr(kv, 0, i)] = pct(substr(kv, i + 1), true);
	}
	return o;
}

// "host:port" / "[v6]:port" -> { host, port } or null
function hostport(hp) {
	let m = match(hp, /^\[([0-9A-Fa-f:.]+)\]:([0-9]{1,5})$/);
	if (!m) m = match(hp, /^([A-Za-z0-9._-]+):([0-9]{1,5})$/);
	if (!m) return null;
	const port = int(m[2]);
	if (port < 1 || port > 65535) return null;
	return { host: m[1], port };
}

// common pieces of a link: scheme://userinfo@host:port?query#remark
function split_link(body, last_at) {
	let remark = null, q = '';
	let i = index(body, '#');
	if (i >= 0) { remark = pct(substr(body, i + 1)); body = substr(body, 0, i); }
	i = index(body, '?');
	if (i >= 0) { q = substr(body, i + 1); body = substr(body, 0, i); }
	i = last_at ? rindex(body, '@') : index(body, '@');
	if (i < 0) return null;
	const hp = hostport(replace(substr(body, i + 1), /\/$/, ''));
	if (!hp) return null;
	return { user: pct(substr(body, 0, i)), host: hp.host, port: hp.port, q: query(q), remark };
}

function tls_of(q, host, sec) {
	if (sec != 'tls' && sec != 'reality') return null;
	const t = { enabled: true, server_name: q.sni ?? q.peer ?? host };
	if (q.alpn) t.alpn = split(q.alpn, ',');
	if (q.allowInsecure == '1' || q.insecure == '1') t.insecure = true;
	if (q.fp) t.utls = { enabled: true, fingerprint: q.fp };
	if (sec == 'reality') {
		t.reality = { enabled: true, public_key: q.pbk ?? '', short_id: q.sid ?? '' };
		t.utls ??= { enabled: true, fingerprint: 'chrome' };   // reality needs uTLS
	}
	return t;
}

function transport_of(type, q) {
	switch (type ?? 'tcp') {
	case 'tcp': case 'raw': return (q.headerType == 'http') ? { type: 'http', host: q.host ? split(q.host, ',') : null, path: q.path ?? '/' } : null;
	case 'ws': return { type: 'ws', path: q.path ?? '/', headers: q.host ? { Host: q.host } : null };
	case 'grpc': return { type: 'grpc', service_name: q.serviceName ?? '' };
	case 'http': case 'h2': return { type: 'http', host: q.host ? split(q.host, ',') : null, path: q.path ?? '/' };
	case 'httpupgrade': return { type: 'httpupgrade', host: q.host, path: q.path ?? '/' };
	case 'xhttp': case 'splithttp': {
		let extra = null;
		if (length(q.extra ?? '')) { try { extra = json(q.extra); } catch (e) { return { error: 'xhttp: "extra" is not valid JSON' }; } }
		// ("type" is this function's argument here, not the builtin)
		return { type: 'xhttp', path: q.path ?? '/', host: q.host, mode: q.mode, extra: (extra != null && length(keys(extra) ?? [])) ? extra : null };
	}
	default: return { error: 'transport "' + type + '" is not supported' };
	}
}

function clean(o) {
	for (let k in keys(o)) {
		if (o[k] == null) delete o[k];
		else if (type(o[k]) == 'object') clean(o[k]);
	}
	return o;
}

function vless_trojan(proto, body) {
	const l = split_link(body, false);
	if (!l || !length(l.user)) return { error: 'cannot parse the link' };
	const q = l.q;
	const sec = q.security ?? (proto == 'trojan' ? 'tls' : 'none');
	const o = { type: proto, server: l.host, server_port: l.port };
	if (proto == 'vless') { o.uuid = l.user; if (q.flow) o.flow = q.flow; }
	else o.password = l.user;
	o.tls = tls_of(q, l.host, sec);
	const t = transport_of(q.type, q);
	if (t?.error) return t;
	o.transport = t;
	const x = {};
	if (proto == 'vless' && length(q.encryption ?? '') && q.encryption != 'none') x.encryption = q.encryption;
	if (sec == 'reality') { if (length(q.spx ?? '')) x.spx = q.spx; if (length(q.pqv ?? '')) x.pqv = q.pqv; }
	if (length(keys(x))) o._x = x;
	return { outbound: clean(o), remark: l.remark };
}

function vmess(body) {
	let j;
	try { j = json(b64(body)); } catch (e) { return { error: 'vmess: bad base64 JSON' }; }
	if (!j?.add || !j?.port || !j?.id) return { error: 'vmess: missing add/port/id' };
	const sec = (j.tls == 'reality') ? 'reality' : (length(j.tls ?? '') ? 'tls' : 'none');
	const q = { sni: j.sni ?? (sec != 'none' ? j.host : null), fp: j.fp, alpn: j.alpn, host: j.host, path: j.path,
		serviceName: (j.net == 'grpc') ? j.path : null, pbk: j.pbk, sid: j.sid };
	const o = { type: 'vmess', server: j.add, server_port: int(j.port), uuid: j.id,
		alter_id: int(j.aid ?? 0), security: j.scy ?? 'auto' };
	o.tls = tls_of(q, j.add, sec);
	const t = transport_of(j.net ?? 'tcp', q);
	if (t?.error) return t;
	o.transport = t;
	return { outbound: clean(o), remark: j.ps };
}

function ss(body) {
	let remark = null;
	let i = index(body, '#');
	if (i >= 0) { remark = pct(substr(body, i + 1)); body = substr(body, 0, i); }
	i = index(body, '?');
	if (i >= 0) body = substr(body, 0, i);              // plugins are not supported (as in stock)
	let ui, hp;
	if (rindex(body, '@') >= 0) {
		ui = substr(body, 0, rindex(body, '@')); hp = substr(body, rindex(body, '@') + 1);
		ui = (index(ui, ':') >= 0) ? pct(ui) : b64(ui);
	}
	else {
		const d = b64(body);
		if (!d || rindex(d, '@') < 0) return { error: 'ss: cannot decode' };
		ui = substr(d, 0, rindex(d, '@')); hp = substr(d, rindex(d, '@') + 1);
	}
	if (!ui || index(ui, ':') < 0) return { error: 'ss: no method:password' };
	const h = hostport(replace(hp, /\/$/, ''));
	if (!h) return { error: 'ss: bad host:port' };
	const c = index(ui, ':');
	return { outbound: { type: 'shadowsocks', server: h.host, server_port: h.port,
		method: substr(ui, 0, c), password: substr(ui, c + 1) }, remark };
}

function hy2(body) {
	const l = split_link(body, true);
	if (!l || !length(l.user)) return { error: 'hy2: cannot parse the link' };
	const q = l.q;
	const o = { type: 'hysteria2', server: l.host, server_port: l.port, password: l.user,
		tls: { enabled: true, server_name: q.sni ?? l.host, insecure: (q.insecure == '1') ? true : null,
			alpn: q.alpn ? split(q.alpn, ',') : null } };
	if (q.obfs == 'salamander') o.obfs = { type: 'salamander', password: q['obfs-password'] ?? '' };
	return { outbound: clean(o), remark: l.remark };
}

// tuic://uuid:password@host:port?sni=..&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#name
function tuic(body) {
	const l = split_link(body, true);
	if (!l || index(l.user ?? '', ':') < 0) return { error: 'tuic: cannot parse the link' };
	const q = l.q, c = index(l.user, ':');
	const o = { type: 'tuic', server: l.host, server_port: l.port, uuid: substr(l.user, 0, c), password: substr(l.user, c + 1),
		congestion_control: q.congestion_control ?? q.congestion ?? null, udp_relay_mode: q.udp_relay_mode ?? null,
		tls: { enabled: true, server_name: q.sni ?? l.host, alpn: q.alpn ? split(q.alpn, ',') : [ 'h3' ],
			insecure: (q.allow_insecure == '1' || q.insecure == '1') ? true : null } };
	return { outbound: clean(o), remark: l.remark };
}

// returns { outbound, remark } or { error }
export function parse(link) {
	link = trim(replace(link ?? '', '\r', ''));
	const m = match(link, /^([a-z0-9]+):\/\/(.*)$/);
	if (!m) return { error: 'not a share link' };
	switch (m[1]) {
	case 'vless': return vless_trojan('vless', m[2]);
	case 'trojan': return vless_trojan('trojan', m[2]);
	case 'vmess': return vmess(m[2]);
	case 'ss': return ss(m[2]);
	case 'hysteria2': case 'hy2': return hy2(m[2]);
	case 'tuic': return tuic(m[2]);
	default: return { error: 'unsupported scheme ' + m[1] };
	}
};

// --- back: an outbound -> a share link (export) ----------------------------------------------------------------

function enc(s) {
	return replace('' + (s ?? ''), /[^A-Za-z0-9._~-]/g, (c) => {
		let o = '';
		for (let i = 0; i < length(c); i++) o += sprintf('%%%02X', ord(c, i));
		return o;
	});
}

function qs(o) {
	const a = [];
	for (let k, v in o) if (v != null && length('' + v)) push(a, k + '=' + enc(v));
	return length(a) ? '?' + join('&', a) : '';
}

function hp(o) { return (index(o.server ?? '', ':') >= 0 ? '[' + o.server + ']' : o.server) + ':' + o.server_port; }

// the query of a vless / trojan link: security and transport, as parse() reads them
function tq(o) {
	const t = o.tls ?? {}, tr = o.transport ?? {};
	const q = {};
	q.security = t.reality?.enabled ? 'reality' : (t.enabled ? 'tls' : null);
	if (t.enabled) {
		q.sni = t.server_name; q.fp = t.utls?.fingerprint;
		q.alpn = (type(t.alpn) == 'array') ? join(',', t.alpn) : t.alpn;
		if (t.insecure) q.allowInsecure = '1';
		if (t.reality?.enabled) { q.pbk = t.reality.public_key; q.sid = t.reality.short_id; }
	}
	q.type = tr.type ?? 'tcp';
	if (tr.type == 'ws') { q.path = tr.path; q.host = tr.headers?.Host; }
	else if (tr.type == 'grpc') q.serviceName = tr.service_name;
	else if (tr.type == 'http') { q.path = tr.path; q.host = (type(tr.host) == 'array') ? join(',', tr.host) : tr.host; }
	else if (tr.type == 'httpupgrade') { q.path = tr.path; q.host = tr.host; }
	else if (tr.type == 'xhttp') { q.path = tr.path; q.host = tr.host; q.mode = tr.mode; q.extra = tr.extra ? sprintf('%J', tr.extra) : null; }
	if (t.reality?.enabled) { q.spx = o._x?.spx; q.pqv = o._x?.pqv; }
	return q;
}

// returns the link or null (a type with no common link form)
export function to_link(o, remark) {
	const r = remark ? '#' + enc(remark) : '';
	switch (o?.type) {
	case 'vless': {
		const q = tq(o);
		return 'vless://' + enc(o.uuid) + '@' + hp(o) + qs({ encryption: o._x?.encryption ?? 'none', flow: o.flow, ...q }) + r;
	}
	case 'trojan': return 'trojan://' + enc(o.password) + '@' + hp(o) + qs(tq(o)) + r;
	case 'vmess': {
		const t = o.tls ?? {}, tr = o.transport ?? {};
		const j = { v: '2', ps: remark ?? '', add: o.server, port: '' + o.server_port, id: o.uuid, aid: '' + (o.alter_id ?? 0),
			scy: o.security ?? 'auto', net: tr.type ?? 'tcp', type: 'none',
			host: tr.headers?.Host ?? ((type(tr.host) == 'array') ? join(',', tr.host) : tr.host) ?? '',
			path: (tr.type == 'grpc') ? tr.service_name : (tr.path ?? ''),
			tls: t.reality?.enabled ? 'reality' : (t.enabled ? 'tls' : ''), sni: t.server_name ?? '', fp: t.utls?.fingerprint ?? '' };
		return 'vmess://' + b64enc(sprintf('%J', j));
	}
	case 'shadowsocks': return 'ss://' + replace(replace(replace(b64enc(o.method + ':' + o.password), '+', '-'), '/', '_'), /=+$/, '') + '@' + hp(o) + r;
	case 'hysteria2': {
		const t = o.tls ?? {};
		return 'hysteria2://' + enc(o.password) + '@' + hp(o) + qs({ sni: t.server_name, insecure: t.insecure ? '1' : null,
			alpn: (type(t.alpn) == 'array') ? join(',', t.alpn) : t.alpn,
			obfs: o.obfs?.type, 'obfs-password': o.obfs?.password }) + r;
	}
	case 'tuic': {
		const t = o.tls ?? {};
		return 'tuic://' + enc(o.uuid) + ':' + enc(o.password) + '@' + hp(o) + qs({ sni: t.server_name,
			alpn: (type(t.alpn) == 'array') ? join(',', t.alpn) : t.alpn, allow_insecure: t.insecure ? '1' : null,
			congestion_control: o.congestion_control, udp_relay_mode: o.udp_relay_mode }) + r;
	}
	}
	return null;
};

// --- one server, two engines -----------------------------------------------------------------------------------

// Checked with "xray run -test" (Xray 26.10) and "sing-box check" (1.14): both run VLESS, VMess, Trojan and
// Shadowsocks over TCP, WebSocket, gRPC and HTTPUpgrade, with TLS or Reality. Xray has no HTTP/2 transport and no
// "skip the certificate check" any more; sing-box has no XHTTP, no VLESS encryption and no ML-DSA Reality check.
const XRAY_TYPES = [ 'vless', 'vmess', 'trojan', 'shadowsocks' ];

export function singbox_why(o) {
	if (o?.transport?.type == 'xhttp') return 'sing-box has no XHTTP transport';
	if (o?._x?.encryption) return 'sing-box has no VLESS encryption';
	if (o?._x?.pqv) return 'sing-box has no ML-DSA check of Reality';
	return null;
};

// a server in the form above -> { xray: outbound } | { error }
export function to_xray(o) {
	if (index(XRAY_TYPES, o?.type) < 0) return { error: 'Xray runs here only VLESS, VMess, Trojan and Shadowsocks' };
	const t = o.tls ?? {}, tr = o.transport ?? {}, x = o._x ?? {};
	if (t.enabled && t.insecure) return { error: 'Xray no longer skips the certificate check' };
	const ss = { network: 'tcp' };
	switch (tr.type ?? 'tcp') {
	case 'tcp': break;
	case 'ws': ss.network = 'ws'; ss.wsSettings = { path: tr.path ?? '/', host: tr.headers?.Host }; break;
	case 'grpc': ss.network = 'grpc'; ss.grpcSettings = { serviceName: tr.service_name ?? '' }; break;
	case 'httpupgrade': ss.network = 'httpupgrade'; ss.httpupgradeSettings = { path: tr.path ?? '/', host: tr.host }; break;
	case 'xhttp': ss.network = 'xhttp'; ss.xhttpSettings = { path: tr.path ?? '/', host: tr.host, mode: tr.mode, extra: tr.extra }; break;
	case 'http': return { error: 'Xray has no HTTP/2 transport any more' };
	default: return { error: 'Xray has no transport ' + tr.type };
	}
	if (t.enabled && t.reality?.enabled) {
		ss.security = 'reality';
		ss.realitySettings = { serverName: t.server_name, fingerprint: t.utls?.fingerprint ?? 'chrome',
			publicKey: t.reality.public_key, shortId: t.reality.short_id ?? '', spiderX: x.spx, mldsa65Verify: x.pqv };
	}
	else if (t.enabled) {
		ss.security = 'tls';
		ss.tlsSettings = { serverName: t.server_name, alpn: t.alpn, fingerprint: t.utls?.fingerprint };
	}
	let settings;
	if (o.type == 'vless')
		settings = { vnext: [ { address: o.server, port: o.server_port, users: [ { id: o.uuid, encryption: x.encryption ?? 'none', flow: o.flow } ] } ] };
	else if (o.type == 'vmess')
		settings = { vnext: [ { address: o.server, port: o.server_port, users: [ { id: o.uuid, alterId: o.alter_id ?? 0, security: o.security ?? 'auto' } ] } ] };
	else if (o.type == 'trojan')
		settings = { servers: [ { address: o.server, port: o.server_port, password: o.password } ] };
	else
		settings = { servers: [ { address: o.server, port: o.server_port, method: o.method, password: o.password } ] };
	return { xray: clean({ protocol: o.type, settings, streamSettings: ss }) };
};

export function xray_why(o) { return to_xray(o).error; };

// an Xray outbound -> { outbound } in the form above | { error } (then it stays an Xray-only server)
export function from_xray(xo) {
	const p = xo?.protocol, st = xo?.settings ?? {}, ss = xo?.streamSettings ?? {};
	if (index(XRAY_TYPES, p) < 0) return { error: 'no sing-box form for Xray ' + p };
	// "vnext" / "servers", or the newer flat form (address, port, id right in settings)
	const srv = (p == 'vless' || p == 'vmess') ? (st.vnext?.[0] ?? st) : (st.servers?.[0] ?? st);
	const u = (p == 'vless' || p == 'vmess') ? (srv.users?.[0] ?? srv) : srv;
	if (!srv?.address || !srv?.port) return { error: 'no server address' };
	const o = { type: p, server: '' + srv.address, server_port: int(srv.port) }, x = {};
	if (p == 'vless') {
		o.uuid = u.id;
		if (length(u.flow ?? '')) o.flow = u.flow;
		if (length(u.encryption ?? '') && u.encryption != 'none') x.encryption = u.encryption;
	}
	else if (p == 'vmess') { o.uuid = u.id; o.alter_id = int(u.alterId ?? 0); o.security = u.security ?? 'auto'; }
	else if (p == 'trojan') o.password = u.password;
	else { o.method = u.method; o.password = u.password; }
	const net = ss.network ?? 'tcp';
	switch (net) {
	case 'tcp': case 'raw':
		if ((ss.tcpSettings ?? ss.rawSettings)?.header?.type == 'http') return { error: 'no sing-box form for TCP with an HTTP header' };
		break;
	case 'ws': {
		const w = ss.wsSettings ?? {}, h = w.host ?? w.headers?.Host;
		o.transport = { type: 'ws', path: w.path ?? '/', headers: h ? { Host: h } : null };
		break;
	}
	case 'grpc': o.transport = { type: 'grpc', service_name: ss.grpcSettings?.serviceName ?? '' }; break;
	case 'httpupgrade': { const h = ss.httpupgradeSettings ?? {}; o.transport = { type: 'httpupgrade', path: h.path ?? '/', host: h.host }; break; }
	case 'xhttp': case 'splithttp': {
		const h = ss.xhttpSettings ?? ss.splithttpSettings ?? {};
		o.transport = { type: 'xhttp', path: h.path ?? '/', host: h.host, mode: h.mode, extra: h.extra };
		break;
	}
	default: return { error: 'no sing-box form for the transport ' + net };
	}
	if (ss.security == 'reality') {
		const r = ss.realitySettings ?? {};
		o.tls = { enabled: true, server_name: r.serverName, utls: { enabled: true, fingerprint: r.fingerprint ?? 'chrome' },
			reality: { enabled: true, public_key: r.publicKey ?? '', short_id: r.shortId ?? '' } };
		if (length(r.spiderX ?? '')) x.spx = r.spiderX;
		if (length(r.mldsa65Verify ?? '')) x.pqv = r.mldsa65Verify;
	}
	else if (ss.security == 'tls') {
		const t = ss.tlsSettings ?? {};
		o.tls = { enabled: true, server_name: t.serverName ?? o.server, alpn: t.alpn, insecure: t.allowInsecure ? true : null,
			utls: t.fingerprint ? { enabled: true, fingerprint: t.fingerprint } : null };
	}
	else if (length(ss.security ?? '') && ss.security != 'none') return { error: 'no sing-box form for the security ' + ss.security };
	if (length(keys(x))) o._x = x;
	return { outbound: clean(o) };
};

// the server in sing-box's own terms: what only Xray needs left out
export function for_singbox(o) {
	if (type(o) != 'object' || o._x == null) return o;
	const c = { ...o };
	delete c._x;
	return c;
};
