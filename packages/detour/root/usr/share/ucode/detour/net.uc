// Detour routing: one table per exit (1000+N), "ip rule fwmark" per exit, permanent unreachable.
'use strict';

import * as fs from 'fs';
import { run, shq, TABLE_BASE, RULE_PRIO_BASE, UNREACH_METRIC } from 'detour.core';

export function table_of(eid) { return TABLE_BASE + eid; }

// fail-closed baseline: the table exists and is unreachable even when the exit device is gone
export function ensure_unreachable(eid) {
	return run(sprintf('ip route replace unreachable default metric %d table %d', UNREACH_METRIC, table_of(eid)));
}

export function dev_up(dev) {
	const op = fs.readfile(sprintf('/sys/class/net/%s/operstate', dev));
	const fl = fs.readfile(sprintf('/sys/class/net/%s/flags', dev));
	if (op == null) return false;
	// tun/wireguard report "unknown"; use IFF_UP
	return trim(op) == 'up' || (fl != null && (hex(trim(fl)) & 1) == 1);
}

export function ensure_route(ex) {
	ensure_unreachable(ex.id);
	if (!dev_up(ex.device)) return false;
	const r = run(sprintf('ip route replace default dev %s table %d', shq(ex.device), table_of(ex.id)));
	return r.code == 0;
}

export function drop_route(ex) {
	run(sprintf('ip route del default dev %s table %d', shq(ex.device), table_of(ex.id)));
	ensure_unreachable(ex.id);
}

function rules_now() {
	const r = run('ip rule show');
	const out = {};
	for (let l in split(r.out, '\n')) {
		const m = match(l, /^([0-9]+):.*fwmark 0x([0-9a-f]+)\/0xff0000 lookup ([0-9]+)/);
		if (m) out[int(m[1])] = { mark: hex(m[2]), table: int(m[3]) };
	}
	return out;
}

// make "ip rule" match the exits exactly (adds missing, removes ours that are no longer configured)
export function sync_rules(cfg) {
	const have = rules_now();
	const want = {};
	for (let e in cfg.exits) want[RULE_PRIO_BASE + e.id] = e.id;
	for (let prio, r in have) {
		prio = int(prio);
		if (prio > RULE_PRIO_BASE && prio <= RULE_PRIO_BASE + 250 && (!want[prio] || r.table != table_of(want[prio]) || r.mark != (want[prio] << 16)))
			run(sprintf('ip rule del priority %d', prio));
	}
	const now = rules_now();
	for (let prio, eid in want) {
		prio = int(prio);
		if (!now[prio])
			run(sprintf('ip rule add fwmark 0x%x/0xff0000 lookup %d priority %d', eid << 16, table_of(eid), prio));
	}
	for (let e in cfg.exits) ensure_unreachable(e.id);
}

// the AAAA answer for policy domains (dns.uc DISCARD6) must fail at once, also for LAN devices that
// have an IPv6 route through the router
export function discard6(on) {
	run(on ? 'ip -6 route replace unreachable 100::/64 metric 1' : 'ip -6 route del unreachable 100::/64 2>/dev/null');
}

export function remove_all() {
	const have = rules_now();
	for (let prio, r in have) {
		prio = int(prio);
		if (prio > RULE_PRIO_BASE && prio <= RULE_PRIO_BASE + 250) {
			run(sprintf('ip route flush table %d', r.table));
			run(sprintf('ip rule del priority %d', prio));
		}
	}
	discard6(false);
}

// Flows that were not classified (no policy mark) towards destinations / from devices that have just come
// under a policy. Unoffloaded, their next packet is classified anew and moves to the exit; offloaded
// (fw4 flowtable - BE7000: software for Wi-Fi and the engines' tun, PPE for wired ports) they keep going
// directly and never meet our rules again. Deleting the entry gives both cases the same outcome.
export function flush_unclassified(dsts, macs, ports) {
	let n = 0;
	for (let d in dsts) {
		const m = match(d, /^([0-9.]+)(\/([0-9]+))?$/);
		if (!m) continue;
		const len = (m[3] != null) ? int(m[3]) : 32;
		const v = (len == 0) ? 0 : ((0xffffffff << (32 - len)) & 0xffffffff);
		const mask = sprintf('%d.%d.%d.%d', (v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255);
		run(sprintf('conntrack -D -m 0/0xffff00 -d %s --mask-dst %s', m[1], mask));
		n++;
	}
	if (length(macs)) {
		const neigh = run('ip -4 neigh show').out;
		for (let l in split(neigh, '\n')) {
			const x = match(l, /^([0-9.]+) .*lladdr ([0-9a-f:]+)/);
			if (x && index(macs, x[2]) >= 0) { run(sprintf('conntrack -D -m 0/0xffff00 -s %s', x[1])); n++; }
		}
	}
	for (let pp in ports ?? []) {
		const x = match(pp, /^(tcp|udp)\/([0-9]+)$/);   // "tcp/443"; ranges are left to expire
		if (x) { run(sprintf('conntrack -D -m 0/0xffff00 -p %s --dport %s', x[1], x[2])); n++; }
	}
	return n;
}

export function flush_conntrack_exit(eid) {
	return run(sprintf('conntrack -D -m 0x%x/0xff0000', eid << 16));
}

// probe an exit: ICMP through its device, or an HTTP(S) URL bound to the device
export function probe_cmd(ex) {
	const t = ex.probe;
	if (!t) return null;
	// run through sh to silence the output (it would go to the daemon's log via procd)
	if (match(t, /^https?:\/\//))
		return [ '/bin/sh', '-c', sprintf('curl -sf -o /dev/null -m 4 --interface %s %s >/dev/null 2>&1', shq(ex.device), shq(t)) ];
	return [ '/bin/sh', '-c', sprintf('ping -q -c 1 -W 2 -I %s %s >/dev/null 2>&1', shq(ex.device), shq(t)) ];
}
