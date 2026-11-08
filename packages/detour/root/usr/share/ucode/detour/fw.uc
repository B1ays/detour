// Bring the routing core up/down without the daemon (early boot, uninstall, CLI).
'use strict';

import * as fs from 'fs';
import * as core from 'detour.core';
import * as nft from 'detour.nft';
import * as net from 'detour.net';
import * as dns from 'detour.dns';
import * as auth from 'detour.auth';
import { cursor } from 'uci';

const ACTIVE = core.RUN + '/active.json';
const PINS = core.PERSIST + '/pins.json';
const DOMSAVE = core.PERSIST + '/dom.save';

export function pins() { return core.read_json(PINS) ?? {}; }
export function save_pins(p) { fs.mkdir(core.PERSIST); core.write_json(PINS, p); }

// policy id -> exit id. Kept across reloads; first boot: pinned exit, else the first exit.
export function active_map(cfg) {
	const saved = core.read_json(ACTIVE) ?? {};
	const pn = pins();
	const out = {};
	for (let p in cfg.policies) {
		let eid = null;
		const s = saved['' + p.id];
		for (let n in p.exits) if (cfg.by_name[n].id == s) eid = s;
		if (!eid && pn[p.name] && index(p.exits, pn[p.name]) >= 0) eid = cfg.by_name[pn[p.name]].id;
		if (!eid) eid = cfg.by_name[p.exits[0]].id;
		out['' + p.id] = eid;
	}
	return out;
}

export function save_active(m) { fs.mkdir(core.RUN); core.write_json(ACTIVE, m); }

// system users whose traffic always goes direct (never classified): the DNS fallback resolver and
// the direct attempt of notifications ("VPN is down" must not run into the dead tunnel), the panel tunnel
export function skip_uid(cfg) {
	const out = [];
	if ((cfg.main.dns == 'tunnel' || cfg.main.dns == 'encrypted') && core.uid_of('dnsproxy') != null) push(out, core.uid_of('dnsproxy'));
	if (core.uid_of('dtnotify') != null) push(out, core.uid_of('dtnotify'));
	if (core.uid_of('dtssh') != null) push(out, core.uid_of('dtssh'));   // the panel tunnel to a VPS (sshtun)
	return out;
}

// full (re)apply; returns { ok, errors[], dns_restart }
export function apply(cfg, active) {
	dns.prepare(cfg);
	active ??= active_map(cfg);
	const text = nft.render(cfg, active, { skip_uid: skip_uid(cfg), stale: nft.stale(cfg) });
	const r = nft.apply(text);
	const errors = [ ...cfg.errors ];
	if (r.code != 0) push(errors, 'nft: ' + trim(r.out));
	if (cfg.main.dns == 'tunnel' && !fs.access('/usr/bin/dnsproxy'))
		push(errors, 'router DNS through the tunnel: dnsproxy is not installed - when the exits of the DNS policy fail, the router falls back to the provider DNS, unencrypted');
	if (cfg.main.dns == 'encrypted' && !fs.access('/usr/bin/dnsproxy'))
		push(errors, 'encrypted router DNS: dnsproxy is not installed - the router uses the provider DNS, unencrypted');
	net.sync_rules(cfg);
	net.discard6(true);
	for (let e in cfg.exits) (e.enabled ? net.ensure_route(e) : net.drop_route(e));
	save_active(active);

	let restart = dns.write_conf(cfg);
	if (cfg.main.dns == 'tunnel') {
		dns.write_servers(cfg, 'tunnel');
		if (dns.ensure_uci(true)) restart = true;
	}
	else if (cfg.main.dns == 'encrypted') {
		// the router always resolves through dnsproxy (the encrypted resolvers), directly - the daemon
		// does not switch anything in this mode
		dns.write_servers(cfg, 'encrypted');
		if (dns.ensure_uci(true)) restart = true;
	}
	else if (dns.ensure_uci(false)) restart = true;
	return { ok: r.code == 0, errors, dns_restart: restart };
}

export function has_lists() {
	let n = 0;
	cursor().foreach('detour', 'list', () => { n++; });
	return n > 0;
}

// early boot (START before dnsmasq): table + sets exist before dnsmasq starts filling them
export function start() {
	const cfg = core.load();
	if (!cfg.main.enabled) return { ok: true, errors: [ 'disabled' ] };
	const res = apply(cfg);
	if (res.ok) nft.restore_dom(DOMSAVE);
	// big lists: from RAM or the flash snapshot, no downloads (boot: before dnsmasq and WAN)
	if (res.ok && has_lists()) core.run('/usr/libexec/detour/lists-update --restore');
	// at boot dnsmasq starts after us and reads the files itself; later (install, upgrade) it must restart
	if (res.dns_restart && core.run('pidof dnsmasq').code == 0) dns.restart();
	for (let e in res.errors) core.log('fw: ' + e);
	return res;
}

export function stop(keep_dom) {
	const cfg = core.load();
	if (keep_dom) { fs.mkdir(core.PERSIST); nft.save_dom(cfg, DOMSAVE); }
	nft.remove_table();
	net.remove_all();
}

// leave a stock router: no table, no rules, dnsmasq back to its own upstreams
export function purge() {
	stop(false);
	let restart = dns.remove_conf();
	if (dns.ensure_uci(false)) restart = true;
	fs.unlink(DOMSAVE);
	fs.unlink(ACTIVE);
	if (restart) dns.restart();
	auth.restore();
	auth.ssh_apply(false);
}
