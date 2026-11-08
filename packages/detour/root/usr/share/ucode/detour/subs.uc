// Subscriptions (stock: subs-lib.sh / subs-update.sh): a provider URL that returns the current server list.
//   config subscription 'prov'
//     option url 'https://…'          # a credential: never logged, passed to curl through a file
//     option user_agent 'v2rayNG/1.10.0'   # many panels pick the format by the client
//     option hwid '…'                  # optional x-hwid (panels that count devices)
//     option via 'warp1'               # optional: the servers are reached through another exit
//     option max '30'
// One exit per subscription: a sing-box engine whose servers form a urltest group (a working, fast one is
// picked and re-checked). Formats: base64 or plain share links, a sing-box config (outbounds).
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, shq, log, RUN } from 'detour.core';
import * as links from 'detour.links';
import * as engines from 'detour.engines';

const SDIR = RUN + '/subs';
const PROXY_TYPES = [ 'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'hysteria', 'tuic', 'wireguard', 'anytls', 'shadowtls' ];

// code: a stable key LuCI translates (the message stays English for the CLI and the log)
function status(name, ok, count, msg, code, skipped) {
	fs.mkdir(RUN); fs.mkdir(SDIR);
	fs.writefile(sprintf('%s/%s.status', SDIR, name), sprintf('%J\n', { name, ok, count, skipped: skipped ?? 0, code, ts: time(), message: msg }));
}

// the stock SSRF guard: the URL must not point into the router's own networks (unless allowed - lab)
function private_host(url) {
	const m = match(url, /^https?:\/\/(\[[^\]]+\]|[^\/:?#]+)/);
	if (!m) return true;
	let h = replace(m[1], /^\[|\]$/g, '');
	if (!match(h, /^[0-9.]+$/) && index(h, ':') < 0) {
		const r = run(sprintf('nslookup %s 127.0.0.1 2>/dev/null', shq(h)));
		for (let l in split(r.out, '\n')) {
			const a = match(l, /^Address:? ([0-9.]+)\s*$/);
			if (a && a[1] != '127.0.0.1') h = a[1];
		}
	}
	return !!match(h, /^(127\.|10\.|192\.168\.|169\.254\.|0\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) || h == 'localhost' ||
		!!match(lc(h), /^(::1?|fe[89ab].*|f[cd].*)$/);
}

export function parse_body(body) {
	body = trim(body ?? '');
	let j = null;
	if (substr(body, 0, 1) == '{' || substr(body, 0, 1) == '[') try { j = json(body); } catch (e) { }
	const out = [], skipped = [], names = [];
	if (j) {
		const list = (type(j) == 'array') ? j : (j.outbounds ?? []);
		for (let o in list) {
			if (type(o) == 'object' && index(PROXY_TYPES, o.type) >= 0) { delete o.detour; push(names, o.tag ?? null); push(out, o); }
			else if (type(o) == 'object' && index([ 'direct', 'block', 'dns', 'selector', 'urltest' ], o.type) < 0) push(skipped, o.type);
		}
		return { outbounds: out, skipped, names };
	}
	if (index(body, '://') < 0) {   // base64 (also url-safe, unpadded)
		let b = replace(replace(replace(body, /\s+/g, ''), /-/g, '+'), /_/g, '/');
		while (length(b) % 4) b += '=';
		const d = b64dec(b);
		if (d && index(d, '://') >= 0) body = d;
	}
	for (let l in split(body, /\r?\n/)) {
		l = trim(l);
		if (!length(l) || index(l, '://') < 0) continue;
		const r = links.parse(l);
		if (r.error) { push(skipped, r.error); continue; }
		push(names, r.remark ?? null);
		push(out, r.outbound);
	}
	return { outbounds: out, skipped, names };
}

export function update(name) {
	const c = cursor();
	const s = c.get_all('detour', name);
	if (s?.['.type'] != 'subscription') return { error: 'no subscription ' + name };
	if (s.enabled == '0') { status(name, true, 0, 'disabled', 'disabled'); return { name, disabled: true }; }
	const ne = engines.check_name(name);
	if (ne) return { error: ne };
	const url = s.url ?? '';
	if (!match(url, /^https?:\/\/\S+$/)) { status(name, false, 0, 'bad URL', 'bad_url'); return { error: 'bad URL' }; }
	if (s.allow_private != '1' && private_host(url)) { status(name, false, 0, 'the URL points into a private network', 'private'); return { error: 'the URL points into a private network' }; }
	if (s.via && c.get('detour', s.via) != 'exit') return { error: 'via: "' + s.via + '" is not an exit' };

	fs.mkdir(RUN); fs.mkdir(SDIR);
	const k = sprintf('%s/%s.curl', SDIR, name);
	fs.writefile(k, ''); fs.chmod(k, 0600);
	let cfg = sprintf('url = "%s"\nuser-agent = "%s"\n', replace(url, '"', '%22'), replace(s.user_agent ?? 'v2rayNG/1.10.0', '"', ''));
	if (s.hwid) cfg += sprintf('header = "x-hwid: %s"\n', replace(s.hwid, '"', ''));
	fs.writefile(k, cfg);
	const body_f = sprintf('%s/%s.body', SDIR, name);
	const r = run(sprintf('curl -fsSL --compressed -m 40 -K %s -o %s', k, body_f));
	fs.unlink(k);
	const body = fs.readfile(body_f);
	fs.unlink(body_f);
	if (r.code != 0 || !body) {
		status(name, false, 0, 'download failed, previous servers kept', 'download_failed');
		log(sprintf('subscription %s: download failed, previous servers kept', name));
		return { error: 'download failed' };
	}
	const p = parse_body(body);
	const max = int(s.max ?? 30) || 30;
	const outs = slice(p.outbounds, 0, max);
	if (!length(outs)) { status(name, false, 0, 'no usable servers in the answer, previous servers kept', 'no_servers'); return { error: 'no usable servers' }; }
	// the exit is "<name>_sub" (exits and subscriptions share the UCI namespace), its tun "<name>tun"
	const xn = name + '_sub';
	const f = engines.write_outbound(xn, outs);
	// the servers' names for LuCI (and for a chosen server's key): not in the outbounds, sing-box takes no unknown fields
	fs.writefile(engines.names_file(xn), sprintf('%J\n', slice(p.names, 0, max)));
	let created = false;
	if (c.get('detour', xn) != 'exit') {
		if (c.get('network', xn)) return { error: xn + ' is already used by another interface' };
		engines.create_exit(xn, f, s.via, s.label ?? name, name + 'tun');
		created = true;
	}
	else if ((c.get('detour', xn + '_eng', 'via') ?? '') != (s.via ?? '')) {
		if (s.via) c.set('detour', xn + '_eng', 'via', s.via); else c.delete('detour', xn + '_eng', 'via');
		c.commit('detour');
	}
	status(name, true, length(outs), sprintf('%d servers%s', length(outs), length(p.skipped) ? sprintf(', %d skipped', length(p.skipped)) : ''), 'updated', length(p.skipped));
	log(sprintf('subscription %s: %d servers', name, length(outs)));
	// procd restarts the engine when its generated config changed (procd "file" param)
	run('/etc/init.d/detour reload');
	return { name, exit: xn, servers: length(outs), skipped: length(p.skipped), created };
}

// cron, hourly: the subscriptions whose interval (option interval, hours, default 24) has passed
export function update_due() {
	const out = [];
	cursor().foreach('detour', 'subscription', function(s) {
		if (s.enabled == '0') return;
		const hours = int(s.interval ?? 24) || 24;
		let st = null;
		try { st = json(fs.readfile(sprintf('%s/%s.status', SDIR, s['.name'])) ?? 'null'); } catch (e) { }
		if (st?.ts && time() - st.ts < hours * 3600 - 300) return;
		push(out, update(s['.name']));
	});
	return out;
}

export function update_all() {
	const out = [];
	cursor().foreach('detour', 'subscription', (s) => { push(out, update(s['.name'])); });
	return out;
}
