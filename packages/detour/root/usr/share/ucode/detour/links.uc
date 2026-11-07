// Share links -> sing-box outbound (vless, vmess, trojan, ss, hysteria2/hy2).
// Mirrors the stock Detour parser (subs-update.sh parse_link/parse_vmess/parse_ss/parse_hy2):
// SIP002 and legacy ss, '@' allowed inside the hy2 auth (split on the last one), sni defaults
// to the host for TLS, IPv6 hosts in brackets.
'use strict';

function pct(s) {
	if (s == null) return null;
	s = replace(s, '+', ' ');
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
		else o[substr(kv, 0, i)] = pct(substr(kv, i + 1));
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
	default: return { error: 'unsupported scheme ' + m[1] };
	}
}
