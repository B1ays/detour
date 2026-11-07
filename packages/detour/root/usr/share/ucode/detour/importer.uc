// Import of stock Detour (Xiaomi firmware) settings: a backup archive (tar.gz of $DETOUR_STATE
// files) or a copy of the state directory. Formats per the stock code: web/cgi-bin/backup
// (SETTINGS/SECRETS), slots.sh (.slots), groups.sh (groups/groups.tsv + <id>.list), domain.sh
// (.detour-custom.conf), apply-bypass.sh (.bypass-ips, .fullvpn-ips), dhcp-static.sh, notify-tg.sh.
// plan() only reads and reports; apply() writes UCI + engine outbound files.
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, shq, M_UNDERLAY, PERSIST } from 'detour.core';

const RE_V4 = /^[0-9]{1,3}(\.[0-9]{1,3}){3}(\/[0-9]{1,2})?$/;
const RE_V6 = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*(\/[0-9]{1,3})?$/;
const RE_DOM = /^[A-Za-z0-9_]([A-Za-z0-9_.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$/;
const RE_MAC = /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/;

function rd(dir, rel) { return fs.readfile(dir + '/' + rel); }

function lines(dir, rel) {
	const s = rd(dir, rel);
	if (!s) return [];
	return filter(map(split(s, '\n'), (l) => trim(replace(l, '\r', ''))), (l) => length(l) && substr(l, 0, 1) != '#');
}

function word(dir, rel) { const l = lines(dir, rel); return length(l) ? l[0] : null; }
function tsv(dir, rel) { return map(lines(dir, rel), (l) => split(l, '\t')); }

// WireGuard/AmneziaWG INI
function ini(text) {
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
}

const AWG_KEYS = [ 'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5' ];

function wg_exit(name, text, from) {
	const c = ini(text);
	const I = c.Interface, P = c.Peer;
	if (!I.PrivateKey || !P.PublicKey || !P.Endpoint) return { error: from + ': not a WireGuard config (keys/endpoint missing)' };
	const ep = match(P.Endpoint, /^\[?([^\]]+)\]?:([0-9]+)$/);
	if (!ep) return { error: from + ': bad Endpoint' };
	let awg = false;
	for (let k in AWG_KEYS) {
		const v = I[k];
		if (v == null) continue;
		// plain WireGuard = all masking off (Jc 0, S 0, H 1..4)
		if (match(k, /^J/) && int(v) != 0) awg = true;
		if (match(k, /^S/) && int(v) != 0) awg = true;
		if (match(k, /^H([1-4])$/) && v != substr(k, 1)) awg = true;
		if (match(k, /^I/) && length(v)) awg = true;
	}
	const addrs = filter(map(split(I.Address ?? '', ','), (a) => trim(a)), (a) => match(a, RE_V4));
	return { name, kind: awg ? 'awg' : 'wg', from,
		net: { private_key: I.PrivateKey, addresses: addrs, mtu: I.MTU ?? '1280',
			awg: awg ? I : null },
		peer: { public_key: P.PublicKey, preshared_key: P.PresharedKey, endpoint_host: ep[1], endpoint_port: ep[2],
			persistent_keepalive: P.PersistentKeepalive ?? '25' } };
}

function xray_exit(name, text, from) {
	let j;
	try { j = json(text); } catch (e) { return { error: from + ': bad JSON' }; }
	let ob = null;
	for (let o in j?.outbounds ?? []) {
		if (!ob && index([ 'freedom', 'blackhole', 'dns', 'loopback' ], o.protocol) < 0) ob = o;
	}
	if (!ob) return { error: from + ': no proxy outbound' };
	return { name, kind: 'xray', from, outbound: ob };
}

// hysteria2 YAML (stock writes a small flat file): server, auth, tls.sni/insecure, obfs.salamander.password
function hy2_exit(name, text, from) {
	const g = (re) => { const m = match(text ?? '', re); return m ? trim(replace(m[1], /^["']|["']$/g, '')) : null; };
	const server = g(/(?:^|\n)server:\s*(\S+)/), auth = g(/(?:^|\n)auth:\s*(.+)/);
	if (!server || !auth) return { error: from + ': no server/auth' };
	const hp = match(server, /^\[?([^\]]+)\]?:([0-9]+)/);
	if (!hp) return { error: from + ': bad server' };
	const o = { type: 'hysteria2', server: hp[1], server_port: int(hp[2]), password: auth,
		tls: { enabled: true, server_name: g(/\n\s+sni:\s*(\S+)/) ?? hp[1] } };
	if (g(/\n\s+insecure:\s*(\S+)/) == 'true') o.tls.insecure = true;
	const op = g(/\n\s+password:\s*(.+)/);
	if (match(text, /\n\s+type:\s*salamander/) && op) o.obfs = { type: 'salamander', password: op };
	return { name, kind: 'hy2', from, outbound: o };
}

function exit_from(dir, name, transport, cfgname, skipped) {
	let r = null;
	if (transport == 'awg') {
		let f = cfgname ? 'configs/' + replace(cfgname, /\.conf$/, '') + '.conf' : 'awg.conf';
		let t = rd(dir, f);
		if (!t && !cfgname) { f = 'awg0.conf'; t = rd(dir, f); }
		r = t ? wg_exit(name, t, f) : { error: f + ' missing' };
	}
	else if (transport == 'xray') {
		const f = cfgname ? 'xray-configs/' + replace(cfgname, /\.json$/, '') + '.json' : 'xray.json';
		const t = rd(dir, f);
		r = t ? xray_exit(name, t, f) : { error: f + ' missing' };
	}
	else if (transport == 'hy2') {
		const f = cfgname ? 'hy2-configs/' + replace(cfgname, /\.yaml$/, '') + '.yaml' : 'hysteria.yaml';
		const t = rd(dir, f);
		r = t ? hy2_exit(name, t, f) : { error: f + ' missing' };
	}
	else r = { error: 'transport ' + transport + ' is not carried over (' + (transport == 'masque' ? 'WARP-MASQUE not in v1' : 'no tunnel config') + ')' };
	if (r.error) { push(skipped, { what: 'exit ' + name, why: r.error }); return null; }
	return r;
}

function classify_member(m, dst, doms) {
	m = lc(trim(m));
	if (match(m, RE_V4) || match(m, RE_V6)) push(dst, m);
	else if (match(m, RE_DOM)) push(doms, m);
	else return false;
	return true;
}

// --- big lists (stock lists-lib.sh registry, iplist-update.sh legacy config) ---------------
const OPENCCK = 'https://iplist.opencck.org/?format=text&data=cidr4';
const LIST_CATS = {
	'tunnel-cidr': { policy: 'vpn', kind: 'cidr' },
	'tunnel-domains': { policy: 'vpn', kind: 'domain' },
	'bypass-ip': { policy: 'direct', kind: 'cidr' },
};

// stock conf files are KEY=value / KEY="value" (read, never sourced)
function conf_get(text, key) {
	for (let l in split(text ?? '', '\n')) {
		const m = match(trim(l), regexp('^' + key + '=(.*)$'));
		if (m) return replace(m[1], /^["']|["']$/g, '');
	}
	return null;
}

function plan_lists(dir, skipped, have_vpn, full_tunnel) {
	const out = [];
	for (let cat, t in LIST_CATS) {
		const reg = tsv(dir, 'lists/' + cat + '/sources.tsv');
		if (!length(reg)) continue;
		const urls = [], texts = [];
		for (let r in reg) {
			// id type enabled format count ts label value
			if (r[2] != '1') { push(skipped, { what: sprintf('list %s source %s', cat, r[6] ?? r[0]), why: 'switched off in stock' }); continue; }
			if (r[1] == 'url' && match(r[7] ?? '', /^https?:\/\//)) push(urls, r[7]);
			else if (r[1] == 'file' || r[1] == 'text') {
				const b = rd(dir, 'lists/' + cat + '/blob/' + r[0]);
				if (b) push(texts, b); else push(skipped, { what: sprintf('list %s source %s', cat, r[6] ?? r[0]), why: 'its file is not in the backup' });
			}
		}
		if (length(urls) || length(texts))
			push(out, { name: 'l_' + replace(cat, '-', '_'), policy: t.policy, kind: t.kind, urls, text: length(texts) ? join('\n', texts) : null, from: 'lists/' + cat });
	}
	for (let c in [ 'adblock', 'ipblock', 'zapret-cidr', 'zapret-dom' ])
		if (fs.access(dir + '/lists/' + c)) push(skipped, { what: 'lists/' + c, why: 'blocking/desync lists are not part of Detour for OpenWrt' });

	// no registry for tunnel-cidr: the legacy iplist.conf / iplist.custom, or the stock default (opencck)
	if (!length(filter(out, (l) => l.name == 'l_tunnel_cidr')) && !full_tunnel) {
		const c = rd(dir, 'iplist.conf');
		let url = conf_get(c, 'IPLIST_URL');
		const sites = conf_get(c, 'IPLIST_SITES'), base = conf_get(c, 'IPLIST_BASE') ?? OPENCCK;
		const mode = conf_get(c, 'IPLIST_CUSTOM_MODE');
		if (!url && sites) { url = base; for (let s in split(trim(sites), /\s+/)) url += '&site=' + s; }
		const custom = rd(dir, 'iplist.custom');
		const l = { name: 'l_tunnel_cidr', policy: 'vpn', kind: 'cidr', urls: [], text: null, from: c ? 'iplist.conf' : 'stock default list' };
		if (mode != 'only') push(l.urls, url ?? base);
		if (custom && (mode == 'only' || mode == 'merge')) l.text = custom;
		push(out, l);
	}
	if (!have_vpn) {
		for (let l in out) if (l.policy == 'vpn') push(skipped, { what: 'list ' + l.name, why: 'the main policy could not be carried over' });
		return filter(out, (l) => l.policy != 'vpn');
	}
	return out;
}

export function plan(dir) {
	const skipped = [], exits = [], policies = [];
	const direct = { dst: [], device: [], domain: [] };

	// devices: stock keys rules by LAN IP, OpenWrt policies by MAC (via the DHCP reservations)
	const ip2mac = {}, names = {};
	for (let r in tsv(dir, '.dhcp-static')) if (match(r[0] ?? '', RE_MAC)) ip2mac[r[1]] = lc(r[0]);
	for (let r in tsv(dir, '.dev-names')) if (match(r[0] ?? '', RE_MAC)) names[lc(r[0])] = r[1];
	const mac_of = function(ip, why) {
		if (ip2mac[ip]) return ip2mac[ip];
		push(skipped, { what: 'device ' + ip, why: why + ': no DHCP reservation for this IP, MAC unknown' });
		return null;
	};

	// exits: main + extra slots (s2..s7)
	const transport = word(dir, '.transport') ?? 'awg';
	const active = { awg: word(dir, '.active'), xray: word(dir, '.xray-active'), hy2: word(dir, '.hy2-active') }[transport];
	const main = exit_from(dir, 'main', transport, active, skipped);
	if (main) { main.id = 1; push(exits, main); }
	const slot_pol = {};
	for (let r in tsv(dir, '.slots')) {
		const id = int(r[0]);
		if (!(id >= 2 && id <= 7)) continue;
		if (r[5] == 'off') { push(skipped, { what: 'extra exit s' + id, why: 'switched off in stock' }); continue; }
		const e = exit_from(dir, 's' + id, r[2], (r[3] == '-') ? null : r[3], skipped);
		if (!e) continue;
		e.id = id;
		e.label = b64dec(r[1] ?? '') ?? ('s' + id);
		push(exits, e);
		const ex = [ 's' + id ];
		if ((r[4] ?? 'main') == 'main' && main) push(ex, 'main');
		else push(skipped, { what: 'extra exit s' + id + ' fallback', why: '"direct" fallback is fail-open in stock; here the policy is fail-closed' });
		slot_pol[id] = { name: 's' + id, id, exits: ex, dst: [], domain: [], device: [], label: e.label };
	}

	const vpn = { name: 'vpn', id: 1, exits: main ? [ 'main' ] : [], dst: [], domain: [], device: [], label: 'VPN' };
	if (word(dir, '.full-tunnel') == '1') push(vpn.dst, '0.0.0.0/0');
	for (let l in lines(dir, '.vpn-dst')) classify_member(l, vpn.dst, vpn.domain) || push(skipped, { what: '.vpn-dst ' + l, why: 'not an address' });
	for (let l in lines(dir, '.bypass-dst')) classify_member(l, direct.dst, direct.domain) || push(skipped, { what: '.bypass-dst ' + l, why: 'not an address' });
	for (let l in lines(dir, '.detour-custom.conf')) {
		const m = match(l, /^ipset=\/(.+)\/(detour_list|detour_bypass)$/);
		if (!m) continue;
		for (let d in split(m[1], '/')) push((m[2] == 'detour_list') ? vpn.domain : direct.domain, lc(d));
	}
	for (let l in lines(dir, '.fullvpn-ips')) {
		const f = split(l, '\t');
		const mac = mac_of(f[0], 'whole device via VPN');
		if (!mac) continue;
		const sm = match(f[1] ?? '', /^s([2-7])$/);
		if (sm && slot_pol[int(sm[1])]) push(slot_pol[int(sm[1])].device, mac);
		else push(vpn.device, mac);
	}
	for (let l in lines(dir, '.bypass-ips')) {
		const mac = mac_of(l, 'device past VPN');
		if (mac) push(direct.device, mac);
	}
	// rule groups
	for (let r in tsv(dir, 'groups/groups.tsv')) {
		const gid = r[0], en = r[1], gdir = r[2], gslot = r[3], gname = r[4], gsrc = r[5];
		if (en != '1') continue;
		if (length(gsrc ?? '')) { push(skipped, { what: 'group ' + gname, why: 'device-bound group (src) - per-device rules are not carried over yet' }); continue; }
		const mem = lines(dir, 'groups/' + gid + '.list');
		let tdst, tdom;
		if (gdir == 'bypass') { tdst = direct.dst; tdom = direct.domain; }
		else if (gdir == 'vpn') {
			const p = (int(gslot) >= 2 && slot_pol[int(gslot)]) ? slot_pol[int(gslot)] : vpn;
			tdst = p.dst; tdom = p.domain;
		}
		else { push(skipped, { what: 'group ' + gname, why: 'direction ' + gdir + ' not supported' }); continue; }
		for (let m in mem) classify_member(m, tdst, tdom) || push(skipped, { what: 'group ' + gname + ' member ' + m, why: 'not an address/domain' });
	}
	if (length(vpn.exits)) push(policies, vpn);
	else if (length(vpn.dst) + length(vpn.domain) + length(vpn.device)) push(skipped, { what: 'main policy', why: 'its exit could not be carried over' });
	for (let id, p in slot_pol) push(policies, p);

	// notifications
	let notify = null;
	const tg = rd(dir, 'notify-tg.conf');
	if (tg) {
		const g = (k) => { const m = match(tg, regexp('(^|\\n)' + k + '=["\']?([^"\'\\n]*)')); return m ? m[2] : null; };
		if (g('TG_TOKEN') && g('TG_CHAT'))
			notify = { tg_token: g('TG_TOKEN'), tg_chat: g('TG_CHAT'), tg_api: g('TG_API'), enabled: rd(dir, '.notify-off') ? '0' : '1' };
	}

	// devices with reservations -> OpenWrt DHCP hosts (keeps the MAC <-> IP of the policies)
	const hosts = [];
	for (let ip, mac in ip2mac) push(hosts, { mac, ip, name: names[mac] });

	// what is deliberately not carried over
	const not = {
		'.panel-pass': 'panel password: LuCI uses the router root password',
		'.totp': '2FA secret: set up luci-plugin-2fa again (new QR code)',
		'server': 'home access server: set it up again (new keys)',
		'sched': 'access schedules: use firewall rules with a time window',
		'.zapret-on': 'zapret: install the zapret package and choose a strategy',
		'.subs': 'subscriptions: not supported yet',
		'.port-rules': 'port rules: not supported yet',
		'geo/actions.tsv': 'geo categories: add their sources as lists',
		'.doh-on': 'encrypted DNS: set "Router DNS" in Detour settings',
		'.warp-reg': 'WARP registration: register WARP again from Detour (new device)',
	};
	for (let f, why in not) if (fs.access(dir + '/' + f)) push(skipped, { what: f, why });

	const lists = plan_lists(dir, skipped, length(vpn.exits) > 0, word(dir, '.full-tunnel') == '1');
	return { exits, policies, direct, notify, hosts, skipped, lists };
}

function uniq(l) { const o = []; for (let x in l) if (index(o, x) < 0) push(o, x); return o; }

function zone_for(c, iface) {
	let zone = null;
	c.foreach('firewall', 'zone', function(z) { if (z.name == 'vpn' || z.name == 'detour') zone = z['.name']; });
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
	let nets = c.get('firewall', zone, 'network');
	nets = (type(nets) == 'array') ? nets : (nets ? split(nets, /\s+/) : []);
	if (index(nets, iface) < 0) { push(nets, iface); c.set('firewall', zone, 'network', nets); }
}

// prefix: names of the created interfaces/exits get it, so an import never clashes with existing ones
export function apply(p, prefix) {
	prefix ??= 'st_';
	const c = cursor();
	const done = [];
	fs.mkdir(PERSIST); fs.mkdir(PERSIST + '/engines');
	const used = {};
	c.foreach('detour', 'exit', (s) => { used[int(s.id)] = s['.name']; });
	const idmap = {};
	for (let e in p.exits) {
		const n = prefix + e.name;
		let id = e.id;
		if (used[id] && used[id] != n) { for (id = 1; id <= 250 && used[id]; id++); }
		used[id] = n; idmap[e.name] = n;
		const iface = (e.kind == 'wg' || e.kind == 'awg') ? n : null;
		if (iface) {
			c.set('network', n, 'interface');
			c.set('network', n, 'proto', e.kind == 'awg' ? 'amneziawg' : 'wireguard');
			c.set('network', n, 'private_key', e.net.private_key);
			c.set('network', n, 'addresses', e.net.addresses);
			c.set('network', n, 'mtu', e.net.mtu);
			c.set('network', n, 'fwmark', sprintf('0x%x', M_UNDERLAY));
			if (e.net.awg)   // names as in amneziawg-tools 3.1 (Quarx2k feed): awg_jc .. awg_i5
				for (let k in AWG_KEYS) if (e.net.awg[k] != null) c.set('network', n, 'awg_' + lc(k), e.net.awg[k]);
			// a repeated import must not stack peers
			const old = [];
			for (let t in [ 'wireguard_' + n, 'amneziawg_' + n ]) c.foreach('network', t, (s) => push(old, s['.name']));
			for (let s in old) c.delete('network', s);
			const ps = c.add('network', (e.kind == 'awg' ? 'amneziawg_' : 'wireguard_') + n);
			for (let k, v in e.peer) if (v != null) c.set('network', ps, k, v);
			c.set('network', ps, 'allowed_ips', [ '0.0.0.0/0' ]);
			c.set('network', ps, 'route_allowed_ips', '0');
			zone_for(c, n);
		}
		else {
			const dev = substr(n, 0, 11) + 'tun';
			const f = sprintf('%s/engines/%s.json', PERSIST, n);
			fs.writefile(f, ''); fs.chmod(f, 0600);
			fs.writefile(f, sprintf('%.J\n', e.outbound));
			c.set('detour', n + '_eng', 'engine');
			c.set('detour', n + '_eng', 'type', e.kind == 'xray' ? 'xray' : 'singbox');
			c.set('detour', n + '_eng', 'device', dev);
			c.set('detour', n + '_eng', 'outbound', f);
			c.set('network', n, 'interface');
			c.set('network', n, 'proto', 'none');
			c.set('network', n, 'device', dev);
			zone_for(c, n);
		}
		c.set('detour', n, 'exit');
		c.set('detour', n, 'id', '' + id);
		c.set('detour', n, 'iface', n);
		if (!iface) c.set('detour', n, 'device', substr(n, 0, 11) + 'tun');
		c.set('detour', n, 'label', e.label ?? ('stock ' + e.name));
		c.set('detour', n, 'probe', 'https://1.1.1.1/cdn-cgi/trace');
		push(done, sprintf('exit %s (%s from %s, id %d)', n, e.kind, e.from, id));
	}
	const pused = {};
	c.foreach('detour', 'policy', (s) => { pused[int(s.id)] = s['.name']; });
	for (let pol in p.policies) {
		const n = prefix + 'p_' + pol.name;   // exits and policies share the "detour" namespace
		let id = pol.id;
		if (pused[id] && pused[id] != n) { for (id = 1; id <= 250 && pused[id]; id++); }
		pused[id] = n;
		c.set('detour', n, 'policy');
		c.set('detour', n, 'id', '' + id);
		c.set('detour', n, 'label', pol.label);
		c.set('detour', n, 'exit', map(pol.exits, (x) => idmap[x]));
		if (length(pol.dst)) c.set('detour', n, 'dst', uniq(pol.dst));
		if (length(pol.domain)) c.set('detour', n, 'domain', uniq(pol.domain));
		if (length(pol.device)) c.set('detour', n, 'device', uniq(pol.device));
		push(done, sprintf('policy %s: %d addresses, %d domains, %d devices', n, length(uniq(pol.dst)), length(uniq(pol.domain)), length(uniq(pol.device))));
	}
	if (!c.get('detour', 'direct')) c.set('detour', 'direct', 'direct');
	for (let k in [ 'dst', 'device', 'domain' ]) {
		if (!length(p.direct[k])) continue;
		let cur = c.get('detour', 'direct', k);
		cur = (type(cur) == 'array') ? cur : (cur ? [ cur ] : []);
		c.set('detour', 'direct', k, uniq([ ...cur, ...p.direct[k] ]));
	}
	push(done, sprintf('always direct: %d addresses, %d devices, %d domains', length(p.direct.dst), length(p.direct.device), length(p.direct.domain)));
	for (let l in p.lists ?? []) {
		const n = prefix + l.name;
		c.set('detour', n, 'list');
		c.set('detour', n, 'policy', (l.policy == 'direct') ? 'direct' : prefix + 'p_' + l.policy);
		c.set('detour', n, 'kind', l.kind);
		if (length(l.urls)) c.set('detour', n, 'url', l.urls); else c.delete('detour', n, 'url');
		if (l.text) {
			fs.mkdir(PERSIST + '/lists');
			const f = sprintf('%s/lists/%s.txt', PERSIST, n);
			fs.writefile(f, l.text + '\n');
			c.set('detour', n, 'file', f);
		}
		else c.delete('detour', n, 'file');
		push(done, sprintf('list %s -> %s: %d URL(s)%s (from %s)', n, c.get('detour', n, 'policy'), length(l.urls), l.text ? ' + local entries' : '', l.from));
	}
	if (p.notify) {
		c.set('detour', 'notify', 'notify');
		for (let k, v in p.notify) if (v != null) c.set('detour', 'notify', k, v);
		push(done, 'Telegram notifications');
	}
	let nh = 0;
	for (let h in p.hosts) {
		let exists = false;
		c.foreach('dhcp', 'host', (s) => { if (lc(s.mac ?? '') == h.mac) exists = true; });
		if (exists) continue;
		const s = c.add('dhcp', 'host');
		c.set('dhcp', s, 'mac', h.mac);
		c.set('dhcp', s, 'ip', h.ip);
		if (h.name && match(h.name, /^[A-Za-z0-9-]{1,63}$/)) c.set('dhcp', s, 'name', h.name);
		nh++;
	}
	if (nh) push(done, sprintf('%d DHCP reservations', nh));
	c.commit('network'); c.commit('firewall'); c.commit('dhcp'); c.commit('detour');
	return done;
}

// archive -> temp dir (the stock archive is plain files with relative paths; refuse anything else)
export function unpack(path) {
	if (fs.stat(path)?.type == 'directory') return { dir: path };
	const d = '/tmp/detour/import';
	run('rm -rf ' + d); fs.mkdir('/tmp/detour'); fs.mkdir(d);
	const list = run(sprintf('tar -tzf %s', shq(path)));
	if (list.code != 0) return { error: 'not a tar.gz archive' };
	for (let l in split(list.out, '\n'))
		if (match(l, /^\//) || match(l, /(^|\/)\.\.(\/|$)/)) return { error: 'unsafe path in the archive: ' + l };
	const r = run(sprintf('tar -xzf %s -C %s', shq(path), d));
	if (r.code != 0) return { error: 'cannot unpack: ' + r.out };
	if (trim(run('find ' + d + ' -type l | head -n1').out) != '') return { error: 'the archive contains links - refusing' };
	return { dir: d };
}
