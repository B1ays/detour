// WARP: register a device with the Cloudflare client API and turn it into a Detour exit
// (netifd WireGuard/AmneziaWG interface + firewall zone + detour exit). Mirrors stock warp.sh:
// same API version and client headers (the API refuses other clients), the server key must be
// WARP's own, the token never appears on a command line (curl -K file).
// Endpoint pool/scanner and moving away from DME (colo check via /cdn-cgi/trace) - not yet.
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, shq, log, load, PERSIST, RUN, M_UNDERLAY } from 'detour.core';
import { dev_up } from 'detour.net';

export const API = 'https://api.cloudflareclient.com/v0a2158';
const UA = 'okhttp/3.12.1', CV = 'a-6.10-2158';
export const WARP_PUB = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';
const DIR = PERSIST + '/warp';
const RE_ID = /^[A-Za-z0-9_.-]{1,64}$/;

function tmpfile(name, text) {
	fs.mkdir(RUN);
	const f = RUN + '/' + name;
	fs.writefile(f, '');
	fs.chmod(f, 0600);
	fs.writefile(f, text);
	return f;
}

function keypair(tool) {
	const priv = trim(run(tool + ' genkey').out);
	if (!match(priv, /^[A-Za-z0-9+\/]{43}=$/)) return null;
	const f = tmpfile('warp.key', priv + '\n');
	const pub = trim(run(sprintf('%s pubkey < %s', tool, f)).out);
	fs.unlink(f);
	return match(pub, /^[A-Za-z0-9+\/]{43}=$/) ? { priv, pub } : null;
}

function iso_now() {
	const t = gmtime(time());
	return sprintf('%04d-%02d-%02dT%02d:%02d:%02d.000Z', t.year, t.mon, t.mday, t.hour, t.min, t.sec);
}

function free_id(c) {
	const used = {};
	c.foreach('detour', 'exit', (s) => { used[int(s.id)] = true; });
	for (let i = 1; i <= 250; i++) if (!used[i]) return i;
	return null;
}

// the firewall zone that holds the existing exits ("vpn" in the lab); created when missing
export function ensure_zone(c, iface) {
	let zone = null;
	c.foreach('firewall', 'zone', function(z) {
		const nets = (type(z.network) == 'array') ? z.network : split(z.network ?? '', /\s+/);
		if (z.name == 'vpn' || z.name == 'detour') zone = z['.name'];
		if (index(nets, iface) >= 0) zone = z['.name'];
	});
	if (!zone) {
		zone = 'detour';
		c.set('firewall', zone, 'zone');
		c.set('firewall', zone, 'name', 'detour');
		c.set('firewall', zone, 'input', 'REJECT');
		c.set('firewall', zone, 'output', 'ACCEPT');
		c.set('firewall', zone, 'forward', 'REJECT');
		c.set('firewall', zone, 'masq', '1');
		c.set('firewall', zone, 'mtu_fix', '1');
		c.set('firewall', 'detour_fwd', 'forwarding');
		c.set('firewall', 'detour_fwd', 'src', 'lan');
		c.set('firewall', 'detour_fwd', 'dest', 'detour');
	}
	const nets = c.get('firewall', zone, 'network');
	const list = (type(nets) == 'array') ? nets : (nets ? split(nets, /\s+/) : []);
	if (index(list, iface) < 0) { push(list, iface); c.set('firewall', zone, 'network', list); }
}

// opts: { name, api, peer_key, port, awg }
// where the API is asked from: via=<exit> -> only through it; else direct, then every enabled exit that is up
function api_routes(via) {
	const cfg = load();
	if (via) {
		const e = filter(cfg.exits, (x) => x.name == via)[0];
		if (!e) return [ { error: 'via: "' + via + '" is not an exit' } ];
		return [ e.device ];
	}
	const out = [ null ];
	for (let e in cfg.exits) if (e.enabled && dev_up(e.device)) push(out, e.device);
	return out;
}

// Other addresses of the API host: on the BE7000's ISP the DNS answer (8.47.69.0) is cut even through a
// Russian exit, while 162.159.137.105/138.105 answer there (the SNI is the same; directly the SNI is cut).
const API_HOST = 'api.cloudflareclient.com';
const API_IPS = [ '162.159.137.105', '162.159.138.105' ];

// curl to the API over each route (see api_routes) and, for the real API host, each known address;
// stops at the first answer. args: everything after "curl -s" except the URL. -> { code, dev, ip }
function api_try(url, args, via, skip_dev) {
	const routes = api_routes(via);
	if (type(routes[0]) == 'object') return { error: routes[0].error };
	const ips = (index(url, 'https://' + API_HOST + '/') == 0) ? [ null, ...API_IPS ] : [ null ];
	let code = '';
	for (let dev in routes) {
		if (dev != null && dev == skip_dev) continue;
		for (let ip in ips) {
			const t = run(sprintf("curl -s --connect-timeout 8 -m 15 %s %s %s %s",
				dev ? '--interface ' + shq(dev) : '', ip ? '--resolve ' + shq(API_HOST + ':443:' + ip) : '', args, shq(url)));
			code = trim(t.out);
			if (code != '000' && code != '') return { code, dev, ip };
		}
	}
	return { code };
}

export function register(opts) {
	const name = opts.name;
	if (!match(name ?? '', /^[a-z][a-z0-9_]{0,11}$/)) return { error: 'name: a-z, 0-9, _ (max 12, starts with a letter)' };
	const c = cursor();
	if (c.get('network', name)) return { error: 'network interface ' + name + ' already exists' };
	// AmneziaWG keys are WireGuard keys: awg when present, else wg (the tunnel itself needs kmod-amneziawg)
	const tool = (opts.awg && fs.access('/usr/bin/awg')) ? 'awg' : 'wg';
	const kp = keypair(tool);
	if (!kp) return { error: tool + ' genkey failed (is ' + (opts.awg ? 'amneziawg-tools' : 'wireguard-tools') + ' installed?)' };

	const api = opts.api ?? API;
	const body = tmpfile('warp.req', sprintf('%J', { key: kp.pub, install_id: '', fcm_token: '', tos: iso_now(),
		model: 'PC', serial_number: '', locale: 'en_US' }));
	// ISPs that filter WARP drop the API too (BE7000: the SNI is cut over the WAN; the stock warp.sh notes
	// the API answers only through a tunnel): direct first, then through each enabled exit that is up
	const r = api_try(api + '/reg', sprintf("-X POST -H %s -H %s -H 'Content-Type: application/json' --data-binary @%s -o %s/warp.resp -w '%%{http_code}'",
		shq('User-Agent: ' + UA), shq('CF-Client-Version: ' + CV), body, RUN), opts.via, null);
	if (r.error) { fs.unlink(body); return r; }
	if (r.dev || r.ip) log(sprintf('WARP %s: API reached %s%s', name, r.dev ? 'through ' + r.dev : 'directly', r.ip ? ' at ' + r.ip : ''));
	fs.unlink(body);
	const resp_s = fs.readfile(RUN + '/warp.resp');
	fs.unlink(RUN + '/warp.resp');
	if (r.code != '200') return { error: 'registration failed, HTTP ' + r.code };
	let j;
	try { j = json(resp_s); } catch (e) { return { error: 'bad API answer' }; }
	const peer = j?.config?.peers?.[0];
	const want = opts.peer_key ?? WARP_PUB;
	if (peer?.public_key != want) return { error: 'the server key is not WARP\'s - refusing' };
	const v4 = j?.config?.interface?.addresses?.v4;
	const ep = replace(peer?.endpoint?.v4 ?? '', /:[0-9]+$/, '');
	if (!match(v4 ?? '', /^[0-9.]+$/) || !match(ep, /^[0-9.]+$/)) return { error: 'API answer without addresses' };
	if (!match(j.id ?? '', RE_ID) || !match(j.token ?? '', RE_ID)) return { error: 'API answer without id/token' };

	fs.mkdir(DIR);
	const reg = tmpfile('warp.reg', sprintf('%.J\n', { name, id: j.id, token: j.token, api, pub: kp.pub,
		peer: peer.public_key, v4, v6: j.config.interface.addresses.v6, endpoint: ep, at: time() }));
	run(sprintf('mv %s %s', reg, shq(DIR + '/' + name + '.json')));

	// netifd interface; the underlay mark keeps WARP's own packets out of the policies
	c.set('network', name, 'interface');
	c.set('network', name, 'proto', opts.awg ? 'amneziawg' : 'wireguard');
	c.set('network', name, 'private_key', kp.priv);
	c.set('network', name, 'addresses', [ v4 + '/32' ]);
	c.set('network', name, 'mtu', '1280');
	c.set('network', name, 'fwmark', sprintf('0x%x', M_UNDERLAY));
	if (opts.awg) {   // stock WARP masking: junk packets + I1 = a real QUIC Initial (warp-i1); kmod-amneziawg needed
		for (let k, v in { awg_jc: '4', awg_jmin: '40', awg_jmax: '70', awg_s1: '0', awg_s2: '0', awg_h1: '1', awg_h2: '2', awg_h3: '3', awg_h4: '4' })
			c.set('network', name, k, v);
		const i1 = trim(run('/usr/libexec/detour/warp-i1 ' + shq(opts.mask ?? 'quic')).out);
		if (match(i1, /^(<(b 0x[0-9a-fA-F]+|r [0-9]+)>)+$/)) c.set('network', name, 'awg_i1', i1);
	}
	const ps = (opts.awg ? 'amneziawg_' : 'wireguard_') + name;
	const psec = c.add('network', ps);
	c.set('network', psec, 'public_key', peer.public_key);
	c.set('network', psec, 'endpoint_host', ep);
	c.set('network', psec, 'endpoint_port', '' + (opts.port ?? 2408));
	c.set('network', psec, 'allowed_ips', [ '0.0.0.0/0' ]);
	c.set('network', psec, 'route_allowed_ips', '0');
	c.set('network', psec, 'persistent_keepalive', '25');
	ensure_zone(c, name);

	const id = free_id(c);
	c.set('detour', name, 'exit');
	c.set('detour', name, 'id', '' + id);
	c.set('detour', name, 'iface', name);
	c.set('detour', name, 'label', 'WARP ' + name);
	c.set('detour', name, 'probe', opts.probe ?? 'https://1.1.1.1/cdn-cgi/trace');
	c.set('detour', name, 'warp', '1');
	c.commit('network'); c.commit('firewall'); c.commit('detour');
	run('/etc/init.d/network reload; fw4 -q reload');
	log(sprintf('WARP %s registered (exit id %d)', name, id));
	return { name, exit_id: id, address: v4, endpoint: ep };
}

export function unregister(name) {
	const f = DIR + '/' + name + '.json';
	let reg;
	try { reg = json(fs.readfile(f)); } catch (e) { return { error: 'no WARP registration ' + name }; }
	let api_ok = false;
	const c0 = cursor();
	if (match(reg.id ?? '', RE_ID) && match(reg.token ?? '', RE_ID)) {
		const k = tmpfile('warp.curl', sprintf('header = "Authorization: Bearer %s"\n', reg.token));
		const r = api_try(reg.api + '/reg/' + reg.id, sprintf("-X DELETE -K %s -H %s -H %s -o /dev/null -w '%%{http_code}'",
			k, shq('User-Agent: ' + UA), shq('CF-Client-Version: ' + CV)), null, c0.get('network', name, 'device') ?? name);   // not through itself
		api_ok = (substr(r.code ?? '', 0, 1) == '2');
		fs.unlink(k);
	}
	const c = cursor();
	c.delete('detour', name);
	c.foreach('detour', 'policy', function(p) {
		const ex = (type(p.exit) == 'array') ? p.exit : (p.exit ? [ p.exit ] : []);
		if (index(ex, name) >= 0) c.set('detour', p['.name'], 'exit', filter(ex, (x) => x != name));
	});
	const del = [];
	c.foreach('network', 'wireguard_' + name, (s) => push(del, s['.name']));
	c.foreach('network', 'amneziawg_' + name, (s) => push(del, s['.name']));
	for (let s in del) c.delete('network', s);
	c.delete('network', name);
	c.foreach('firewall', 'zone', function(z) {
		const nets = (type(z.network) == 'array') ? z.network : split(z.network ?? '', /\s+/);
		if (index(nets, name) >= 0) c.set('firewall', z['.name'], 'network', filter(nets, (x) => x != name));
	});
	c.commit('detour'); c.commit('network'); c.commit('firewall');
	fs.unlink(f);
	run('/etc/init.d/network reload; fw4 -q reload');
	log(sprintf('WARP %s removed (API deregistration: %s)', name, api_ok ? 'ok' : 'failed'));
	return { name, deregistered: api_ok };
}
