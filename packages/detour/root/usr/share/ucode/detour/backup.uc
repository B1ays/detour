// Backup and restore of Detour's own settings (LuCI "Add" -> "Backup", CLI "detour backup|restore").
//
// What is Detour's: /etc/config/detour, the files in /etc/detour (engines' outbounds, WARP registrations, the
// panel tunnel's key, list snapshots and local parts, pins, traffic history), the netifd interfaces of the
// exits with their WireGuard/AmneziaWG peers, the exits' membership in the VPN firewall zone, and the DHCP
// reservations / names of the devices (the policies and the Devices page name devices by MAC).
// Never whole network/firewall/dhcp files: a restore must not touch LAN, WAN or anything else of the router.
//
// The file is always encrypted (openssl AES-256-CBC, PBKDF2): it holds private keys, the Telegram token and the
// subscription addresses. Inside: a tar.gz with manifest.json, detour.uci, network.json, dhcp.json, files/.
//
// A restore replaces Detour's settings with the backup's (exits, policies, lists... of the router now go away),
// after saving the current ones into BEFORE (encrypted with the same password) - so it can be undone.
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, shq, log, PERSIST, VERSION } from 'detour.core';
import { ensure_zone } from 'detour.warp';

export const FORMAT = 'detour-backup';
export const FORMAT_V = 1;
export const SCHEMA = 1;                            // detour.main.schema this version writes (etc/config/detour)
// the settings before a restore: on flash, so it survives a reboot (a restore that broke the network is often
// followed by one); never part of a backup itself
export const BEFORE = PERSIST + '/before-restore.bin';
const WORK = '/tmp/detour/backup';
// files of /etc/detour that are not settings: derived from the live ruleset, this router's 2FA state, a cache
const SKIP_FILES = [ 'ruleset.good', 'dom.save', 'unauthenticated.json.orig', 'v2fly-names.txt', 'before-restore.bin' ];
const SUMS = 'sums.sha256';                         // the checksum of every file inside
const MAX_UNPACKED = 64 * 1024 * 1024;
const RE_NAME = /^[A-Za-z0-9_]{1,15}$/;
const DHCP_OPTS = [ 'mac', 'ip', 'name', 'leasetime', 'duid', 'hostid', 'dns', 'tag' ];

// dhcp host 'mac' is an option or a list (LuCI writes 'list mac'): always one space-separated string here
function mac_str(v) { return (type(v) == 'array') ? join(' ', v) : v; }

function opts_of(s) {
	const o = {};
	for (let k, v in s) if (substr(k, 0, 1) != '.') o[k] = v;
	return o;
}

function exit_ifaces(c) {
	const l = [];
	c.foreach('detour', 'exit', (s) => push(l, s.iface ?? s['.name']));
	return l;
}

// the interface sections of the exits and their peers: [{ name, type, anon, opts }]
function net_sections(c) {
	const out = [];
	for (let i in exit_ifaces(c)) {
		const s = c.get_all('network', i);
		if (!s) continue;
		push(out, { name: i, type: s['.type'], anon: false, opts: opts_of(s) });
		for (let t in [ 'wireguard_' + i, 'amneziawg_' + i ])
			c.foreach('network', t, (p) => push(out, { name: p['.name'], type: t, anon: !!p['.anonymous'], opts: opts_of(p) }));
	}
	return out;
}

function pw_ok(pwfile) {
	const p = fs.readfile(pwfile ?? '');
	return p != null && length(p) >= 8;
}

function enc(src, dst, pwfile) {
	return run(sprintf('openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass file:%s -in %s -out %s', shq(pwfile), shq(src), shq(dst)));
}
function dec(src, dst, pwfile) {
	return run(sprintf('openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:%s -in %s -out %s', shq(pwfile), shq(src), shq(dst)));
}

// out: the encrypted file to write; pwfile: a file holding the password (8+ characters)
export function create(out, pwfile) {
	if (!pw_ok(pwfile)) return { error: 'the password must be at least 8 characters' };
	const d = WORK + '/new';
	run(sprintf('rm -rf %s; mkdir -p %s/files', shq(d), shq(d)));
	run('chmod 700 ' + WORK);
	const c = cursor();
	const m = c.get_all('detour', 'main') ?? {};
	let host = null;
	c.foreach('system', 'system', (s) => { host ??= s.hostname; });
	const r = run(sprintf('cp /etc/config/detour %s/detour.uci && cp -a %s/. %s/files/ 2>/dev/null; cd %s/files && rm -rf %s',
		shq(d), PERSIST, shq(d), shq(d), join(' ', SKIP_FILES)));
	if (!fs.access(d + '/detour.uci')) return { error: 'cannot read /etc/config/detour: ' + r.out };
	fs.writefile(d + '/network.json', sprintf('%.J\n', net_sections(c)));
	const hosts = [];
	c.foreach('dhcp', 'host', function(s) {
		if (!s.mac) return;
		const o = {};
		for (let k in DHCP_OPTS) if (s[k] != null) o[k] = s[k];
		o.mac = mac_str(o.mac);
		push(hosts, o);
	});
	fs.writefile(d + '/dhcp.json', sprintf('%.J\n', hosts));
	const count = {};
	for (let t in [ 'exit', 'policy', 'list', 'subscription' ]) { count[t] = 0; c.foreach('detour', t, () => { count[t]++; }); }
	const man = { format: FORMAT, format_v: FORMAT_V, version: VERSION, schema: int(m.schema ?? 0), created: time(), host, count };
	fs.writefile(d + '/manifest.json', sprintf('%.J\n', man));
	const s = run(sprintf('cd %s && find . -type f ! -name %s | sort | xargs sha256sum > %s', shq(d), SUMS, SUMS));
	if (s.code != 0) { run('rm -rf ' + shq(d)); return { error: 'cannot checksum: ' + s.out }; }
	const t = run(sprintf('tar -czf %s/new.tgz -C %s .', WORK, shq(d)));
	run('rm -rf ' + shq(d));
	if (t.code != 0) return { error: 'cannot pack: ' + t.out };
	const e = enc(WORK + '/new.tgz', out + '.tmp', pwfile);
	fs.unlink(WORK + '/new.tgz');
	if (e.code != 0) { fs.unlink(out + '.tmp'); return { error: 'cannot encrypt: ' + e.out }; }
	fs.chmod(out + '.tmp', 0600);
	fs.rename(out + '.tmp', out);
	return { file: out, size: fs.stat(out)?.size, manifest: man };
}

// the decrypted contents never stay in /tmp longer than one command
export function cleanup() { run('rm -rf ' + WORK); }

function read_json_file(p) { try { return json(fs.readfile(p) ?? 'null'); } catch (e) { return null; } }

// encrypted file -> checked contents in WORK/x: { dir, man, net, hosts } or { error }
export function open(path, pwfile) {
	if (!fs.access(path)) return { error: 'no backup file' };
	if (!pw_ok(pwfile)) return { error: 'the password must be at least 8 characters' };
	if (substr(fs.readfile(path, 8) ?? '', 0, 8) != 'Salted__') return { error: 'not a Detour backup (or not encrypted)' };
	run(sprintf('rm -rf %s/x %s/in.tgz; mkdir -p %s/x; chmod 700 %s', WORK, WORK, WORK, WORK));
	const tgz = WORK + '/in.tgz';
	if (dec(path, tgz, pwfile).code != 0) { fs.unlink(tgz); return { error: 'wrong password or a damaged file' }; }
	const list = run(sprintf('tar -tzvf %s', shq(tgz)));
	if (list.code != 0) { fs.unlink(tgz); return { error: 'damaged archive' }; }
	let total = 0;
	for (let l in split(trim(list.out), '\n')) {
		const f = split(trim(l), /\s+/);
		// busybox: mode owner size date time name
		if (length(f) < 6) continue;
		const kind = substr(f[0], 0, 1), name = join(' ', slice(f, 5));
		if (kind != '-' && kind != 'd') { fs.unlink(tgz); return { error: 'the archive contains links or special files - refusing' }; }
		if (match(name, /^\//) || match(name, /(^|\/)\.\.(\/|$)/)) { fs.unlink(tgz); return { error: 'unsafe path in the archive: ' + name }; }
		total += int(f[2]);
	}
	if (total > MAX_UNPACKED) { fs.unlink(tgz); return { error: 'the archive is too big' }; }
	const x = WORK + '/x';
	const r = run(sprintf('tar -xzf %s -C %s', shq(tgz), x));
	fs.unlink(tgz);
	if (r.code != 0) return { error: 'cannot unpack: ' + r.out };
	if (trim(run(sprintf('find %s ! -type f ! -type d | head -n1', x)).out) != '') return { error: 'the archive contains links or special files - refusing' };
	// every file as it was written (a damaged file can still decrypt and unpack); older backups have no sums
	if (fs.access(x + '/' + SUMS)) {
		const listed = length(filter(split(trim(fs.readfile(x + '/' + SUMS) ?? ''), '\n'), (l) => length(l)));
		const have = int(trim(run(sprintf('cd %s && find . -type f ! -name %s | wc -l', x, SUMS)).out));
		if (run(sprintf('cd %s && sha256sum -c -s %s', x, SUMS)).code != 0 || listed != have)
			return { error: 'damaged backup: the checksums do not match' };
	}
	const man = read_json_file(x + '/manifest.json');
	if (man?.format != FORMAT) return { error: 'not a Detour backup' };
	if (int(man.format_v) > FORMAT_V || int(man.schema) > SCHEMA)
		return { error: sprintf('the backup is from a newer Detour (%s) - update Detour first', man.version ?? '?') };
	// the config must parse and be Detour's
	run(sprintf('mkdir -p %s/c && cp %s/detour.uci %s/c/detour', x, x, x));
	const cc = cursor(x + '/c');
	if (!cc.get('detour', 'main')) return { error: 'the backup has no valid Detour config' };
	const exits = {};
	cc.foreach('detour', 'exit', (s) => { exits[s.iface ?? s['.name']] = s['.name']; });
	const net = read_json_file(x + '/network.json') ?? [];
	const hosts = read_json_file(x + '/dhcp.json') ?? [];
	if (type(net) != 'array' || type(hosts) != 'array') return { error: 'damaged backup (network/dhcp)' };
	for (let s in net) {
		const own = (s.type == 'interface') ? s.name : replace(s.type ?? '', /^(wireguard|amneziawg)_/, '');
		if (type(s.opts) != 'object' || !match(s.name ?? '', /^[A-Za-z0-9_]+$/) || !exits[own] ||
		    (s.type != 'interface' && !match(s.type, /^(wireguard|amneziawg)_/)) ||
		    (s.type == 'interface' && index([ 'wireguard', 'amneziawg', 'none' ], s.opts.proto) < 0))
			return { error: 'the backup has a network section that is not an exit\'s: ' + (s.name ?? '?') };
	}
	for (let h in hosts) {
		if (type(h) == 'object') h.mac = mac_str(h.mac);   // backups made before the fix hold a list
		if (type(h) != 'object' || !match(h.mac ?? '', /^[0-9A-Fa-f:\s-]+$/)) return { error: 'damaged backup (dhcp)' };
	}
	return { dir: x, man, net, hosts, cfg: cc };
}

function labels(c, t) {
	const l = [];
	c.foreach('detour', t, (s) => push(l, s.label ?? s['.name']));
	return l;
}

// a network section of the backup whose name the router uses for something else than an exit
function conflicts(c, net) {
	const mine = {};
	for (let i in exit_ifaces(c)) {
		mine[i] = true;
		for (let t in [ 'wireguard_' + i, 'amneziawg_' + i ]) c.foreach('network', t, (p) => { mine[p['.name']] = true; });
	}
	const out = [];
	for (let s in net) if (!s.anon && !mine[s.name] && c.get('network', s.name)) push(out, s.name);
	return out;
}

function day_total(d) {
	let t = 0;
	for (let k, v in d?.d ?? {}) t += (v[0] ?? 0) + (v[1] ?? 0);
	return t;
}

// traffic history, day by day: a day the router has no record of comes from the backup (a new router keeps the
// history of the old one); a day both have keeps the fuller record (the router's own is newer on the same
// router). The daemon flushed its month to flash before the job and reloads it afterwards (traffic.reset).
function merge_traffic(dir) {
	fs.mkdir(PERSIST + '/traffic');
	for (let f in fs.glob(dir + '/*.json') ?? []) {
		const name = replace(f, /^.*\//, '');
		if (!match(name, /^[0-9]{4}-[0-9]{2}\.json$/)) continue;
		const b = read_json_file(f), t = PERSIST + '/traffic/' + name;
		if (type(b) != 'object') continue;
		const r = read_json_file(t) ?? {};
		for (let day, v in b)
			if (match(day, /^[0-9]{2}$/) && type(v) == 'object' && day_total(v) > day_total(r[day])) r[day] = v;
		fs.writefile(t + '.tmp', sprintf('%J', r));
		fs.rename(t + '.tmp', t);
	}
}

// what the target router does not have for the backup's exits (after a reflash: packages to install again)
function missing_engines(o) {
	const need = {};
	o.cfg.foreach('detour', 'engine', (s) => { need[(s.type ?? 'singbox') == 'xray' ? 'xray-core' : 'sing-box'] = true; });
	for (let s in o.net) if (s.opts?.proto == 'amneziawg') need['amneziawg'] = true;
	const have = { 'sing-box': fs.access('/usr/bin/sing-box'), 'xray-core': fs.access('/usr/bin/xray'),
		'amneziawg': fs.access('/lib/netifd/proto/amneziawg.sh') };
	return filter(sort(keys(need)), (k) => !have[k]);
}

// what a restore would do, without secrets
export function preview(o) {
	const c = cursor(), b = o.cfg;
	const notify = b.get_all('detour', 'notify');
	const files = map(fs.glob(o.dir + '/files/traffic/*.json') ?? [], (f) => replace(f, /^.*\/|\.json$/g, ''));
	return {
		manifest: o.man,
		backup: {
			exits: labels(b, 'exit'), policies: labels(b, 'policy'), lists: labels(b, 'list'),
			subscriptions: length(labels(b, 'subscription')),
			notify: notify && (notify.tg_chat || notify.tg_token) ? 'Telegram' : null,
			devices: length(o.hosts), traffic_months: sort(files),
			panel_tunnel_key: !!fs.access(o.dir + '/files/sshtun/id_ed25519'),
			warp: length(fs.glob(o.dir + '/files/warp/*.json') ?? []),
		},
		replaced: { exits: labels(c, 'exit'), policies: labels(c, 'policy'), lists: labels(c, 'list') },
		conflicts: conflicts(c, o.net),
		missing: missing_engines(o),
	};
}

function migrate(c) {
	// what post-upgrade does for an older config
	if (int(c.get('detour', 'main', 'schema') ?? 0) < SCHEMA) c.set('detour', 'main', 'schema', '' + SCHEMA);
	const ev = c.get('detour', 'notify', 'event');
	if (ev && c.get('detour', 'notify', 'ev_rev') != '2') {
		const l = (type(ev) == 'array') ? ev : [ ev ];
		for (let e in [ 'boot', 'wan', 'list_fail', 'sub_fail', 'sub_expire' ]) if (index(l, e) < 0) push(l, e);
		c.set('detour', 'notify', 'event', l);
		c.set('detour', 'notify', 'ev_rev', '2');
	}
}

// o: from open(); the current settings are saved to BEFORE first
export function apply(o, pwfile) {
	const c0 = cursor();
	const cf = conflicts(c0, o.net);
	if (length(cf)) return { error: 'the router already has network interfaces with these names (not Detour\'s): ' + join(', ', cf) };
	// keep the backup's contents away from WORK/x: create() below uses WORK
	const src = WORK + '/apply';
	run(sprintf('rm -rf %s; mv %s %s', src, o.dir, src));
	const b = create(BEFORE, pwfile);
	if (b.error) return { error: 'cannot save the current settings first: ' + b.error };

	// 1. the current exits' interfaces, peers and zone membership go
	const c = cursor();
	const old = exit_ifaces(c);
	for (let i in old) {
		const peers = [];
		for (let t in [ 'wireguard_' + i, 'amneziawg_' + i ]) c.foreach('network', t, (p) => push(peers, p['.name']));
		for (let p in peers) c.delete('network', p);
		if (c.get('network', i)) c.delete('network', i);
		c.foreach('firewall', 'zone', function(z) {
			const nets = (type(z.network) == 'array') ? z.network : (z.network ? split(z.network, /\s+/) : []);
			if (index(nets, i) >= 0) c.set('firewall', z['.name'], 'network', filter(nets, (x) => x != i));
		});
	}
	// 2. the backup's interfaces and peers, in the VPN zone. What the router still has under those names goes
	// first: options of a section written over would stay, and a peer left behind would become a second one
	// (conflicts() made sure these names are no one else's)
	for (let s in o.net) {
		if (s.type != 'interface') continue;
		const stale = [];
		for (let t in [ 'wireguard_' + s.name, 'amneziawg_' + s.name ]) c.foreach('network', t, (p) => push(stale, p['.name']));
		for (let p in stale) c.delete('network', p);
		if (c.get('network', s.name)) c.delete('network', s.name);
	}
	for (let s in o.net) {
		const n = s.anon ? c.add('network', s.type) : s.name;
		if (!s.anon) c.set('network', n, s.type);
		for (let k, v in s.opts) c.set('network', n, k, v);
		if (s.type == 'interface') ensure_zone(c, s.name);
	}
	// 3. devices: reservations / names the router does not have yet (by MAC); the router's own stay as they are
	const have = {};
	c.foreach('dhcp', 'host', function(h) {
		for (let m in split(lc(mac_str(h.mac) ?? ''), /\s+/)) if (length(m)) have[m] = true;
	});
	let nh = 0;
	for (let h in o.hosts) {
		const macs = split(lc(h.mac), /\s+/);
		if (length(filter(macs, (m) => have[m]))) continue;
		const n = c.add('dhcp', 'host');
		for (let k in DHCP_OPTS) if (h[k] != null) c.set('dhcp', n, k, h[k]);
		nh++;
	}
	c.commit('network'); c.commit('firewall'); c.commit('dhcp');

	// 4. files: everything of /etc/detour but the derived ones and the traffic history is replaced
	const keep = join(' ', map([ ...SKIP_FILES, 'traffic' ], (f) => '! -name ' + shq(f)));
	run(sprintf('mkdir -p %s; find %s -mindepth 1 -maxdepth 1 %s -exec rm -rf {} +', PERSIST, PERSIST, keep));
	run(sprintf('rm -f %s/ruleset.good %s/dom.save', PERSIST, PERSIST));   // they describe the old rules
	run(sprintf('cd %s/files && for f in * .[!.]*; do [ -e "$f" ] && [ "$f" != traffic ] && cp -a "$f" %s/; done', src, PERSIST));
	merge_traffic(src + '/files/traffic');
	run(sprintf('chown -R dtssh %s/sshtun 2>/dev/null; chmod -R go-rwx %s/sshtun %s/engines %s/warp 2>/dev/null', PERSIST, PERSIST, PERSIST, PERSIST));

	// 5. the config itself, migrated to this version; the LAN bridge is this router's, not the backup's
	const lan_dev = cursor().get('detour', 'main', 'lan_dev');
	fs.writefile('/etc/config/detour.new', fs.readfile(src + '/detour.uci'));
	fs.rename('/etc/config/detour.new', '/etc/config/detour');
	const ce = cursor();
	migrate(ce);
	if (lan_dev != null) ce.set('detour', 'main', 'lan_dev', lan_dev); else ce.delete('detour', 'main', 'lan_dev');
	ce.commit('detour');
	run('rm -rf ' + src);

	// the lists in RAM are the old ones (a list of the same name may have other sources): the daemon's reload
	// loads the backup's from the snapshots, or downloads them (lists-update --missing)
	run('rm -f /tmp/detour/lists/*.data /tmp/detour/lists/*.kind /tmp/detour/lists/*.status');

	// 6. bring it up: interfaces, firewall, the service's engines (the daemon reloads itself after the job)
	run('/etc/init.d/network reload; fw4 -q reload; /etc/init.d/detour reload');
	log(sprintf('settings restored from a backup of %s (%s); the previous ones are in %s', o.man.host ?? '?',
		o.man.created ? sprintf('%d', o.man.created) : '?', BEFORE));
	const n = o.man.count ?? {};
	return { restored: { exits: n.exit ?? 0, policies: n.policy ?? 0, lists: n.list ?? 0, subscriptions: n.subscription ?? 0, devices: nh },
		before: BEFORE };
}
