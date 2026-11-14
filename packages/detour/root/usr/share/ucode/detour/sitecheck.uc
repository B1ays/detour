// "Check a site": where an address goes and why (which rule wins, which also matched and lost), and does it
// open directly and through the exit (stock sitecheck.sh).
// explain() follows the order of the nft "classify" chain: local addresses, "never via VPN" (addresses, device,
// domains, lists), then the policies in their order - device, addresses, domains (the dnsmasq-filled set),
// address lists, ports. For a name it asks the router's own dnsmasq first (that also fills the domain sets, as
// a device's query would) and then asks nft whether the address is in each set: the real answer, not a guess.
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, shq, RUN, PRIVATE4, is_private6 } from 'detour.core';

const T = 'inet detour';
const RE_HOST = /^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)+[A-Za-z0-9-]{2,63}$/;
const RE_IP4 = /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/;

// "https://Site.example/path" / "site.example:8443" / "1.2.3.4" -> { host, ip, port, url } or { error }
export function target(q) {
	q = trim(q ?? '');
	let url = q;
	if (!match(url, /^https?:\/\//)) url = 'https://' + url;
	const m = match(url, /^(https?):\/\/([^\/:?#]+)(:([0-9]{1,5}))?([\/?#].*)?$/);
	if (!m) return { error: 'bad target' };
	const host = lc(m[2]);
	const ip = match(host, RE_IP4) ? host : null;
	if (!ip && !match(host, RE_HOST)) return { error: 'bad target' };
	if (!match(url, /^https?:\/\/[A-Za-z0-9._~:\/?#@!$&()*+,;=%-]+$/)) return { error: 'bad target' };
	const port = m[4] ? int(m[4]) : (m[1] == 'http' ? 80 : 443);
	return { host, ip, port, url: m[1] + '://' + m[2] + (m[3] ?? '') + (m[5] ?? '/') };
}

function ip2n(a) { const m = match(a, RE_IP4); return m ? ((int(m[1]) << 24) | (int(m[2]) << 16) | (int(m[3]) << 8) | int(m[4])) : null; }
export function in_cidr(ip, cidr) {
	const p = split(cidr, '/'), n = ip2n(ip), b = ip2n(p[0]);
	if (n == null || b == null) return false;
	const len = length(p) > 1 ? int(p[1]) : 32;
	if (len == 0) return true;
	const mask = (0xffffffff << (32 - len)) & 0xffffffff;
	return (n & mask) == (b & mask);
}

// the router's dnsmasq (fills the domain sets on the way); IPv4 only, up to 4
function resolve(host) {
	const out = [];
	for (let l in split(run(sprintf('nslookup %s 127.0.0.1', shq(host))).out, '\n')) {
		const m = match(l, /^Address:?[ \t]+([0-9.]+)[ \t]*$/);
		if (m && m[1] != '127.0.0.1' && index(out, m[1]) < 0 && length(out) < 4) push(out, m[1]);
	}
	return out;
}

function in_set(set, ip) { return run(sprintf('nft get element %s %s { %s }', T, set, ip)).code == 0; }

// the name and its parents: a.b.example.org -> [ a.b.example.org, b.example.org, example.org, org ]
function suffixes(host) {
	const p = split(host, '.'), out = [];
	for (let i = 0; i < length(p); i++) push(out, join('.', slice(p, i)));
	return out;
}

// which big list of a target holds the name (domain lists) or the address (address lists)
function lists_of(tgt, kind, host, ip) {
	const out = [];
	const c = cursor();
	c.foreach('detour', 'list', function(s) {
		if (s.enabled == '0' || (s.policy ?? '') != tgt) return;
		const f = sprintf('%s/lists/%s.data', RUN, s['.name']);
		const k = trim(fs.readfile(sprintf('%s/lists/%s.kind', RUN, s['.name'])) ?? '');
		if (!fs.access(f) || (k && k != kind)) return;
		let hit = false;
		if (kind == 'domain' && host) {
			const args = join(' ', map(suffixes(host), (x) => '-e ' + shq(x)));
			hit = run(sprintf('grep -Fxq %s %s', args, shq(f))).code == 0;
		}
		else if (kind == 'cidr' && ip) {
			const fh = fs.open(f);
			let l;
			while (!hit && (l = fh.read('line')) != null && length(l)) if (in_cidr(ip, trim(l))) hit = true;
			fh.close();
		}
		if (hit) push(out, { list: s['.name'], label: s.label });
	});
	return out;
}

function dom_hit(doms, host) {
	if (!host) return null;
	for (let s in suffixes(host)) if (index(doms, s) >= 0) return s;
	return null;
}

// cfg: core.load(); state: { active: { pid: exit name }, direct: { policy: true } }
export function explain(cfg, state, q, mac) {
	const t = target(q);
	if (t.error) return t;
	mac = length(mac ?? '') ? lc(mac) : null;
	const ips = t.ip ? [ t.ip ] : resolve(t.host);
	const host = t.ip ? null : t.host;
	const m = [];      // matches in the order nft checks them
	const add = (o) => push(m, o);
	for (let ip in ips) {
		// local and private addresses, the same as nft bypass4 / bypass6
		if (index(ip, ':') >= 0 ? is_private6(ip) : length(filter(PRIVATE4, (c) => in_cidr(ip, c)))) add({ to: 'direct', why: 'local', ip });
	}
	for (let p in cfg.policies) {
		if (!p.enabled) continue;
		const P = { to: 'policy', policy: p.name, label: p.label, block: p.block, direct: p.direct };
		if (mac && index(p.devices, mac) >= 0) add({ ...P, why: 'device', value: mac });
		for (let ip in ips) { let hit = null; for (let c in p.dst4) if (in_cidr(ip, c)) hit = c; if (hit) { add({ ...P, why: 'address', value: hit, ip }); break; } }
		const ph = dom_hit(p.domains, host);
		if (ph) add({ ...P, why: 'domain', value: ph });
		else if (host) {
			// a domain list: the set (filled by dnsmasq just now) or, for "Block", the list itself (no set)
			const l = lists_of(p.name, 'domain', host);
			let inset = false;
			for (let ip in ips) if (in_set(sprintf('dom4_p%d', p.id), ip)) inset = true;
			if (length(l) || inset) add({ ...P, why: 'domain_list', lists: l });
		}
		for (let ip in ips) if (in_set(sprintf('lst4_p%d', p.id), ip)) { add({ ...P, why: 'address_list', lists: lists_of(p.name, 'cidr', null, ip), ip }); break; }
		for (let pr in [ 'tcp', 'udp' ])
			for (let r in p.ports?.[pr] ?? []) {
				const a = split(r, '-'), lo = int(a[0]), hi = int(a[1] ?? a[0]);
				if (t.port >= lo && t.port <= hi) { add({ ...P, why: 'port', value: pr + '/' + r }); break; }
			}
	}
	// a name that resolves to nothing: dnsmasq answered "no such name" - "Block" does that to its domains
	const win = length(m) ? m[0] : null;
	let goes;
	if (!win || win.to == 'direct') goes = { to: 'direct' };
	else if (win.direct) goes = { to: 'direct', policy: win.policy, label: win.label };   // a "Directly" policy
	else if (win.block) goes = { to: 'block', policy: win.policy, label: win.label };
	else if (state.direct?.[win.policy]) goes = { to: 'direct_down', policy: win.policy, label: win.label };
	else goes = { to: 'exit', policy: win.policy, label: win.label, exit: state.active?.[win.policy] };
	return { host: t.host, ip: t.ip, port: t.port, url: t.url, ips, goes, matches: m };
}

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';
// the stubs of providers and of the registry: a redirect there is a block, not "the site moved"
const STUB_RE = /warning\.rt\.ru|blocked|blocklist|zapret|eais\.rkn|rkn\.gov\.ru|block\.mts|lawfilter|fz139|nap\.rkn/;

// one path of the check: the command line (curl writes "code|connect|appconnect|first byte|size|ip|redirect")
export function probe_cmd(url, dev, bin, f) {
	return sprintf("%s -s -o /dev/null -A %s -H 'Accept: text/html,*/*' --connect-timeout 7 -m 12 --interface %s -w '%%{http_code}|%%{time_connect}|%%{time_appconnect}|%%{time_starttransfer}|%%{size_download}|%%{remote_ip}|%%{redirect_url}' %s > %s 2>/dev/null; echo \"|$?\" >> %s",
		bin ?? 'curl', shq(UA), shq(dev), shq(url), f, f);
}

// what one path saw: ok, http_block (403/451), stub (a provider's page), http_err, dns, refused, silent (no
// answer), sni (connected, TLS never started - cut by the name), freeze (started, then stopped), reset, tls, fail
export function probe_read(f) {
	const w = split(trim(fs.readfile(f) ?? ''), '|');
	fs.unlink(f);
	const code = int(w[0] ?? 0), tc = +(w[1] ?? 0), ta = +(w[2] ?? 0), tf = +(w[3] ?? 0), sz = int(w[4] ?? 0);
	const rc = int(w[length(w) - 1] ?? -1), redir = w[6] ?? '';
	let st = 'fail';
	if (rc == 0 || (rc == 28 && code && sz > 60000)) {
		if (code == 403 || code == 451) st = 'http_block';
		else if (code >= 300 && code < 400) st = match(redir, STUB_RE) ? 'stub' : 'ok';
		else if ((code >= 100 && code < 300) || index([ 401, 404, 405 ], code) >= 0) st = 'ok';
		else st = 'http_err';
	}
	else if (rc == 6) st = 'dns';
	else if (rc == 7) st = 'refused';
	else if (rc == 28) st = (tc <= 0) ? 'silent' : ((ta > 0) ? 'freeze' : 'sni');
	else if (rc == 35 || rc == 56 || rc == 52) st = (ta > 0) ? 'freeze' : 'reset';
	else if (index([ 51, 58, 59, 60, 77, 80, 83, 90, 91 ], rc) >= 0) st = 'tls';
	return { st, code, ms: int(tf * 1000), ip: w[5] ?? '', rc };
}

export function verdict(d, v) {
	if (d.st == 'ok') return 'direct_ok';
	if (!v) return 'no_vpn';
	if (v.st == 'ok') return (d.st == 'http_block') ? 'geo' : 'need_vpn';
	if (d.st == 'http_block' && v.st == 'http_block') return 'unclear';   // both 403: the site refuses robots
	return 'both_bad';
}
