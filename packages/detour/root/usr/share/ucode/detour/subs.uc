// Subscriptions (stock: subs-lib.sh / subs-update.sh): a provider URL that returns the current server list.
//   config subscription 'prov'
//     option url 'https://…'          # a credential: never logged, passed to curl through a file
//     option user_agent 'v2rayNG/1.10.0'   # many panels pick the format by the client
//     option hwid '…'                  # optional x-hwid (panels that count devices)
//     option via 'warp1'               # optional: the servers are reached through another exit
//     option max '30'
//     option engine 'xray'             # singbox (default) | xray: what runs the servers
// One exit per subscription: an engine whose servers form a group (a working, fast one is picked and
// re-checked: sing-box urltest, Xray observatory + balancer). Formats: base64 or plain share links, a sing-box
// config (outbounds). Each engine gets what it can run; the rest is skipped, saying why.
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, shq, log, RUN, clean_label } from 'detour.core';
import * as links from 'detour.links';
import * as engines from 'detour.engines';

const SDIR = RUN + '/subs';
const PROXY_TYPES = [ 'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'hysteria', 'tuic', 'wireguard', 'anytls', 'shadowtls' ];

// code: a stable key LuCI translates (the message stays English for the CLI and the log)
// what the provider said about the subscription itself (headers subscription-userinfo, profile-update-interval)
// survives a failed update: it is carried over from the previous status
function status(name, ok, count, msg, code, skipped, info) {
	fs.mkdir(RUN); fs.mkdir(SDIR);
	const f = sprintf('%s/%s.status', SDIR, name);
	if (info == null) try { info = json(fs.readfile(f) ?? 'null')?.info; } catch (e) { }
	fs.writefile(f, sprintf('%J\n', { name, ok, count, skipped: skipped ?? 0, code, ts: time(), message: msg, info }));
}

// subscription-userinfo: upload=1; download=2; total=3; expire=1700000000 (bytes, unix time; 0 or absent = none)
export function parse_headers(text) {
	let info = null;
	for (let l in split(text ?? '', /\r?\n/)) {
		const m = match(trim(l), /^([A-Za-z-]+):[ \t]*(.*)$/);
		if (!m) continue;
		const k = lc(m[1]);
		if (k == 'subscription-userinfo') {
			info ??= {};
			for (let kv in split(m[2], ';')) {
				const x = match(trim(kv), /^(upload|download|total|expire)=([0-9.eE+]+)$/);
				if (x) info[x[1]] = int(+x[2]);
			}
		}
		else if (k == 'profile-update-interval' && match(m[2], /^[0-9]+$/)) {
			info ??= {};
			info.update_hours = int(m[2]);
		}
	}
	return info;
};

// the stock SSRF guard: the URL must not point into the router's own networks (unless allowed - lab).
// -> { private, host, port, addr }: addr is the address that was checked, curl is then pinned to it (--resolve),
// so a name cannot answer a public address here and a private one to curl
function url_target(url) {
	const m = match(url, /^(https?):\/\/(\[[^\]]+\]|[^\/:?#@]+)(:([0-9]{1,5}))?([\/?#]|$)/);
	if (!m) return { private: true };
	const host = replace(m[2], /^\[|\]$/g, '');
	const port = m[4] ? int(m[4]) : (m[1] == 'http' ? 80 : 443);
	let h = host, addr = null;
	if (!match(h, /^[0-9.]+$/) && index(h, ':') < 0) {
		const r = run(sprintf('nslookup %s 127.0.0.1 2>/dev/null', shq(h)));
		for (let l in split(r.out, '\n')) {
			const a = match(l, /^Address:? ([0-9.]+)\s*$/);
			if (a && a[1] != '127.0.0.1' && !addr) addr = a[1];
		}
		if (!addr) return { private: false, host, port };   // no IPv4: curl finds none either (or IPv6 only)
		h = addr;
	}
	const priv = !!match(h, /^(127\.|10\.|192\.168\.|169\.254\.|0\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) ||
		h == 'localhost' || !!match(lc(h), /^(::1?|::ffff:.*|fe[89ab].*|f[cd].*)$/);
	return { private: priv, host, port, addr };
}

// -> the servers in the engine's own form: sing-box outbounds, or Xray ones (etype 'xray'); what the engine
// cannot run is left out, saying why
export function parse_body(body, etype) {
	const xray = etype == 'xray';
	body = trim(body ?? '');
	let j = null;
	if (substr(body, 0, 1) == '{' || substr(body, 0, 1) == '[') try { j = json(body); } catch (e) { }
	const out = [], skipped = [], names = [];
	// one server for the engine: sing-box takes it as it is (what only Xray reads dropped), Xray converted
	const take = function(o, label) {
		if (xray) {
			const x = links.to_xray(o);
			if (x.error) { push(skipped, sprintf('%s: %s', label ?? o.server, x.error)); return; }
			push(out, x.xray);
		}
		else {
			const why = links.singbox_why(o);
			if (why) { push(skipped, sprintf('%s: %s, needs Xray', label ?? o.server, why)); return; }
			push(out, links.for_singbox(o));
		}
		push(names, clean_label(label));
	};
	if (j) {
		const list = (type(j) == 'array') ? j : (j.outbounds ?? []);
		for (let o in list) {
			if (type(o) == 'object' && index(PROXY_TYPES, o.type) >= 0) { delete o.detour; take(o, o.tag); }   // .detour: sing-box's own field (dial through another outbound), not this project
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
		take(r.outbound, r.remark);
	}
	return { outbounds: out, skipped, names };
};

// one update of a subscription at a time (cron, the daemon and LuCI may all ask): a lock directory, taken
// over when it is older than any update can last
function lock(name) {
	fs.mkdir(RUN); fs.mkdir(SDIR);
	const d = sprintf('%s/%s.lock', SDIR, name);
	if (fs.mkdir(d)) return d;
	const st = fs.stat(d);
	if (st && time() - st.mtime > 180) { fs.rmdir(d); if (fs.mkdir(d)) return d; }
	return null;
}

function update_locked(name) {
	const c = cursor();
	const s = c.get_all('detour', name);
	if (s?.['.type'] != 'subscription') return { error: 'no subscription ' + name };
	if (s.enabled == '0') { status(name, true, 0, 'disabled', 'disabled'); return { name, disabled: true }; }
	const ne = engines.check_name(name);
	if (ne) return { error: ne };
	const url = s.url ?? '';
	if (!match(url, /^https?:\/\/\S+$/)) { status(name, false, 0, 'bad URL', 'bad_url'); return { error: 'bad URL' }; }
	if (s.via && c.get('detour', s.via) != 'exit') return { error: 'via: "' + s.via + '" is not an exit' };
	// the engine that runs the servers: sing-box unless Xray is chosen; not installed - nothing changes
	const etype = (s.engine == 'xray') ? 'xray' : 'singbox';
	if (!fs.access(etype == 'xray' ? '/usr/bin/xray' : '/usr/bin/sing-box')) {
		const msg = (etype == 'xray' ? 'xray-core' : 'sing-box') + ' is not installed';
		status(name, false, 0, msg + ', previous servers kept', 'no_engine');
		return { error: msg };
	}

	fs.mkdir(RUN); fs.mkdir(SDIR);
	const k = sprintf('%s/%s.curl', SDIR, name);
	const body_f = sprintf('%s/%s.body', SDIR, name);
	const head_f = sprintf('%s/%s.head', SDIR, name);
	// redirects are followed here, not by curl: every hop is checked (a public URL must not redirect into the
	// router's networks) and pinned to the address that was checked
	let cur = url, r = null;
	for (let hop = 0; ; hop++) {
		const t = url_target(cur);
		if (s.allow_private != '1' && t.private) {
			status(name, false, 0, 'the URL points into a private network', 'private');
			return { error: 'the URL points into a private network' };
		}
		fs.writefile(k, ''); fs.chmod(k, 0600);
		let cfg = sprintf('url = "%s"\nuser-agent = "%s"\n', replace(cur, '"', '%22'), replace(s.user_agent ?? 'v2rayNG/1.10.0', '"', ''));
		if (s.hwid) cfg += sprintf('header = "x-hwid: %s"\n', replace(s.hwid, '"', ''));
		if (t.addr) cfg += sprintf('resolve = "%s:%d:%s"\n', t.host, t.port, t.addr);
		fs.writefile(k, cfg);
		r = run(sprintf("curl -fsS --compressed -m 40 -K %s -D %s -o %s -w '%%{http_code} %%{redirect_url}'", k, head_f, body_f));
		fs.unlink(k);
		const w = match(trim(r.out ?? ''), /^([0-9]{3}) ?(.*)$/);
		if (r.code == 0 && w && match(w[1], /^30[12378]$/) && match(w[2], /^https?:\/\/\S+$/)) {
			if (hop >= 5) { r = { code: 1 }; break; }
			cur = w[2];
			continue;
		}
		break;
	}
	const body = fs.readfile(body_f);
	// the headers of the last hop (redirects are followed above, one request each)
	const heads = split(fs.readfile(head_f) ?? '', /\r?\n\r?\n/);
	let info = null;
	for (let h in heads) if (length(trim(h))) info = parse_headers(h);
	fs.unlink(body_f); fs.unlink(head_f);
	if (r.code != 0 || !body) {
		status(name, false, 0, 'download failed, previous servers kept', 'download_failed');
		log(sprintf('subscription %s: download failed, previous servers kept', name));
		return { error: 'download failed' };
	}
	const p = parse_body(body, etype);
	const max = int(s.max ?? 30) || 30;
	const outs = slice(p.outbounds, 0, max);
	if (!length(outs)) { status(name, false, 0, 'no usable servers in the answer, previous servers kept', 'no_servers'); return { error: 'no usable servers' }; }
	// the exit is "<name>_sub" (exits and subscriptions share the UCI namespace), its tun "<name>tun"
	const xn = name + '_sub';
	// the file and the engine type change together: the file is in the engine's own form
	const f = engines.write_outbound(xn, outs);
	// the servers' names for LuCI (and for a chosen server's key): not in the outbounds, sing-box takes no unknown fields
	fs.writefile(engines.names_file(xn), sprintf('%J\n', slice(p.names, 0, max)));
	let created = false;
	if (c.get('detour', xn) != 'exit') {
		if (c.get('network', xn)) return { error: xn + ' is already used by another interface' };
		const e = engines.create_exit(xn, f, s.via, s.label ?? name, name + 'tun', etype);
		if (e.error) return e;
		created = true;
	}
	else {
		let changed = false;
		if ((c.get('detour', xn + '_eng', 'via') ?? '') != (s.via ?? '')) {
			if (s.via) c.set('detour', xn + '_eng', 'via', s.via); else c.delete('detour', xn + '_eng', 'via');
			changed = true;
		}
		if ((c.get('detour', xn + '_eng', 'type') ?? 'singbox') != etype) {
			c.set('detour', xn + '_eng', 'type', etype);
			changed = true;
			log(sprintf('subscription %s: now on %s', name, etype == 'xray' ? 'Xray' : 'sing-box'));
		}
		if (changed) c.commit('detour');
	}
	status(name, true, length(outs), sprintf('%d servers%s', length(outs), length(p.skipped) ? sprintf(', %d skipped', length(p.skipped)) : ''), 'updated', length(p.skipped), info ?? {});
	log(sprintf('subscription %s: %d servers', name, length(outs)));
	// procd restarts the engine when its generated config changed (procd "file" param)
	run('/etc/init.d/detour reload');
	return { name, exit: xn, engine: etype, servers: length(outs), skipped: length(p.skipped), created };
}

export function update(name) {
	if (!match(name ?? '', /^[a-z][a-z0-9_]*$/)) return { error: 'no subscription ' + (name ?? '') };
	const l = lock(name);
	if (!l) return { error: 'this subscription is being updated right now' };
	let r;
	try { r = update_locked(name); } catch (e) { r = { error: 'update failed: ' + e }; }
	fs.rmdir(l);
	return r;
};

// cron, hourly: the subscriptions whose interval (option interval, hours, default 24) has passed
export function update_due() {
	const out = [];
	cursor().foreach('detour', 'subscription', function(s) {
		if (s.enabled == '0') return;
		let st = null;
		try { st = json(fs.readfile(sprintf('%s/%s.status', SDIR, s['.name'])) ?? 'null'); } catch (e) { }
		// its own interval, else what the provider recommends, else a day
		const hours = int(s.interval ?? st?.info?.update_hours ?? 24) || 24;
		if (st?.ts && time() - st.ts < hours * 3600 - 300) return;
		push(out, update(s['.name']));
	});
	return out;
};

export function update_all() {
	const out = [];
	cursor().foreach('detour', 'subscription', (s) => { push(out, update(s['.name'])); });
	return out;
};
