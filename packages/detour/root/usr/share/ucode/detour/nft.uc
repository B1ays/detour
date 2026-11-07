// Detour nftables: renders the "inet detour" table from the config model.
// Own table, NOT part of fw4 (survives fw4 reload). Rules are reloaded in place (flush chain);
// sets filled by dnsmasq (dom4_pN/dom6_pN) are never flushed or recreated.
'use strict';

import * as fs from 'fs';
import { hex, run, log, M_POL, M_EXIT, M_BOTH, M_SKIP, RUN } from 'detour.core';

const T = 'inet detour';

// never classified: local, private, multicast, link-local, CGNAT
const BYPASS4 = '0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3';

function elems(list, quote) {
	let out = [];
	for (let x in list) push(out, quote ? sprintf('"%s"', x) : x);
	return join(', ', out);
}

export function pol_mark(id) { return id << 8; }
export function exit_mark(id) { return id << 16; }

// names of sets/chains/maps this config needs
function wanted(cfg) {
	const sets = { direct4: 1, direct6: 1, lan_ifs: 1, bypass4: 1, exit_devs: 1, direct_dev: 1, dom_direct4: 1, lst4_direct: 1 };
	const chains = { classify: 1, prerouting: 1, output: 1, killswitch: 1, v6block: 1, dnsredir: 1, dotblock: 1 };
	for (let p in cfg.policies) {
		for (let k in [ 'dev', 'dst4', 'dst6', 'dom4', 'dom6', 'lst4' ]) sets[sprintf('%s_p%d', k, p.id)] = 1;
	}
	for (let e in cfg.exits) {
		chains[sprintf('exit%d', e.id)] = 1;
		chains[sprintf('ks%d', e.id)] = 1;
	}
	return { sets, chains };
}

// objects present in the kernel table that the config no longer has
export function stale(cfg) {
	// a dump is interrupted when the table changes meanwhile (dnsmasq fills the domain sets all the time):
	// nft fails, and a failed listing must not mean "nothing to remove" - a removed exit's chains stayed
	let j = null;
	for (let i = 0; i < 4 && j == null; i++) {
		const r = run("nft -j list table inet detour");
		if (r.code == 0) { try { j = json(r.out); } catch (e) { j = null; } }
		else if (index(r.out, 'No such file') >= 0) return { sets: [], chains: [] };   // no table yet
		if (j == null) system('sleep 0.2');
	}
	if (j == null) { log('nft: could not list the table - stale objects stay until the next reload'); return { sets: [], chains: [] }; }
	const w = wanted(cfg);
	const out = { sets: [], chains: [], maps: [] };
	for (let o in j?.nftables ?? []) {
		if (o.set && !w.sets[o.set.name]) push(out.sets, o.set.name);
		if (o.chain && !w.chains[o.chain.name]) push(out.chains, o.chain.name);
	}
	return out;
}

// active: { <policy id>: <exit id> }; opts: { skip_uid: <num|null>, stale: {sets,chains} }
export function render(cfg, active, opts) {
	opts ??= {};
	const L = [];
	const add = (s) => push(L, s);
	const to = cfg.main.dom_timeout;

	// 1. declarations (add semantics: existing objects are kept, with their elements)
	add('table inet detour {');
	add('\tset lan_ifs { type ifname; }');
	add('\tset exit_devs { type ifname; }');
	add(sprintf('\tset bypass4 { type ipv4_addr; flags interval; elements = { %s }; }', BYPASS4));
	add('\tset direct4 { type ipv4_addr; flags interval; auto-merge; }');
	add('\tset direct6 { type ipv6_addr; flags interval; auto-merge; }');
	add('\tset direct_dev { type ether_addr; }');
	add(sprintf('\tset dom_direct4 { type ipv4_addr; flags timeout; timeout %s; }', to));
	// big downloaded lists: filled by lists-update, never flushed by a rules reload
	add('\tset lst4_direct { type ipv4_addr; flags interval; auto-merge; }');
	for (let p in cfg.policies) {
		add(sprintf('\tset lst4_p%d { type ipv4_addr; flags interval; auto-merge; }', p.id));
		add(sprintf('\tset dev_p%d { type ether_addr; }', p.id));
		add(sprintf('\tset dst4_p%d { type ipv4_addr; flags interval; auto-merge; }', p.id));
		add(sprintf('\tset dst6_p%d { type ipv6_addr; flags interval; auto-merge; }', p.id));
		add(sprintf('\tset dom4_p%d { type ipv4_addr; flags timeout; timeout %s; }', p.id, to));
		add(sprintf('\tset dom6_p%d { type ipv6_addr; flags timeout; timeout %s; }', p.id, to));
	}
	add('\tmap pol2exit { type mark : verdict; }');
	for (let e in cfg.exits) {
		add(sprintf('\tchain exit%d { }', e.id));
		add(sprintf('\tchain ks%d { }', e.id));
	}
	add('\tchain classify { }');
	add('\tchain prerouting { type filter hook prerouting priority mangle - 5; policy accept; }');
	add('\tchain output { type route hook output priority mangle - 5; policy accept; }');
	add('\tchain killswitch { type filter hook postrouting priority srcnat - 10; policy accept; }');
	add('\tchain v6block { type filter hook forward priority filter - 10; policy accept; }');
	add('\tchain dnsredir { type nat hook prerouting priority dstnat - 5; policy accept; }');
	add('\tchain dotblock { type filter hook forward priority filter - 11; policy accept; }');
	add('}');

	// 2. flush rules and static data (dom* sets are left alone)
	const chains = [ 'classify', 'prerouting', 'output', 'killswitch', 'v6block', 'dnsredir', 'dotblock' ];
	for (let e in cfg.exits) { push(chains, sprintf('exit%d', e.id)); push(chains, sprintf('ks%d', e.id)); }
	for (let ch in chains) add(sprintf('flush chain %s %s', T, ch));
	add(sprintf('flush map %s pol2exit', T));
	for (let s in [ 'lan_ifs', 'exit_devs', 'direct4', 'direct6', 'direct_dev' ]) add(sprintf('flush set %s %s', T, s));
	for (let p in cfg.policies)
		for (let k in [ 'dev', 'dst4', 'dst6' ]) add(sprintf('flush set %s %s_p%d', T, k, p.id));

	// 3. remove what the config no longer has (rules referencing them were flushed above)
	for (let ch in opts.stale?.chains ?? []) { add(sprintf('flush chain %s %s', T, ch)); }
	for (let ch in opts.stale?.chains ?? []) add(sprintf('delete chain %s %s', T, ch));
	for (let s in opts.stale?.sets ?? []) add(sprintf('delete set %s %s', T, s));

	// 4. static elements
	if (length(cfg.main.lan)) add(sprintf('add element %s lan_ifs { %s }', T, elems(cfg.main.lan, true)));
	if (length(cfg.exits)) {
		let devs = [];
		for (let e in cfg.exits) if (index(devs, e.device) < 0) push(devs, e.device);
		add(sprintf('add element %s exit_devs { %s }', T, elems(devs, true)));
	}
	if (length(cfg.direct4)) add(sprintf('add element %s direct4 { %s }', T, elems(cfg.direct4)));
	if (length(cfg.direct6)) add(sprintf('add element %s direct6 { %s }', T, elems(cfg.direct6)));
	if (length(cfg.direct_dev)) add(sprintf('add element %s direct_dev { %s }', T, elems(cfg.direct_dev)));
	for (let p in cfg.policies) {
		if (!p.enabled) continue;
		if (length(p.devices)) add(sprintf('add element %s dev_p%d { %s }', T, p.id, elems(p.devices)));
		if (length(p.dst4)) add(sprintf('add element %s dst4_p%d { %s }', T, p.id, elems(p.dst4)));
		if (length(p.dst6)) add(sprintf('add element %s dst6_p%d { %s }', T, p.id, elems(p.dst6)));
	}

	// 5. exit chains: set the exit id, keep everything else
	for (let e in cfg.exits)
		add(sprintf('add rule %s exit%d meta mark set meta mark & %s | %s', T, e.id, hex(~M_EXIT & 0xffffffff), hex(exit_mark(e.id))));

	// 6. policy -> exit (atomic switch = replace one element)
	for (let p in cfg.policies) {
		if (!p.enabled) continue;
		const eid = active?.[p.id];
		if (eid) add(sprintf('add element %s pol2exit { %s : jump exit%d }', T, hex(pol_mark(p.id)), eid));
	}

	// 7. classify: first match wins, policies in config order
	add(sprintf('add rule %s classify ip daddr @bypass4 return', T));
	add(sprintf('add rule %s classify ip daddr @direct4 return', T));
	add(sprintf('add rule %s classify ip6 daddr @direct6 return', T));
	add(sprintf('add rule %s classify ether saddr @direct_dev return comment "device never via VPN"', T));
	add(sprintf('add rule %s classify ip daddr @dom_direct4 return comment "domain never via VPN"', T));
	add(sprintf('add rule %s classify ip daddr @lst4_direct return comment "list: never via VPN"', T));
	const setp = (id) => sprintf('meta mark set meta mark & %s | %s return', hex(~M_POL & 0xffffffff), hex(pol_mark(id)));
	for (let p in cfg.policies) {
		if (!p.enabled) continue;
		add(sprintf('add rule %s classify ether saddr @dev_p%d %s', T, p.id, setp(p.id)));
		add(sprintf('add rule %s classify ip daddr @dst4_p%d %s', T, p.id, setp(p.id)));
		add(sprintf('add rule %s classify ip daddr @dom4_p%d %s', T, p.id, setp(p.id)));
		add(sprintf('add rule %s classify ip daddr @lst4_p%d %s', T, p.id, setp(p.id)));
	}

	// 8. LAN ingress: established flows keep their decision (ct mark pins policy+exit)
	add(sprintf('add rule %s prerouting iifname != @lan_ifs return', T));
	add(sprintf('add rule %s prerouting ct mark & %s != 0 meta mark set ct mark & %s return', T, hex(M_BOTH), hex(M_BOTH)));
	add(sprintf('add rule %s prerouting meta nfproto ipv4 jump classify', T));
	add(sprintf('add rule %s prerouting meta mark & %s != 0 meta mark & %s vmap @pol2exit', T, hex(M_POL), hex(M_POL)));
	add(sprintf('add rule %s prerouting meta mark & %s != 0 ct mark set meta mark & %s', T, hex(M_BOTH), hex(M_BOTH)));

	// 9. router's own traffic (type route: routing is redone after the mark change)
	add(sprintf('add rule %s output meta mark & %s != 0 return comment "underlay 0x10000000 + nfqws 0x40000000"', T, hex(M_SKIP)));
	for (let u in opts.skip_uid ?? [])
		add(sprintf('add rule %s output meta skuid %d return comment "always direct (DNS fallback, notifications)"', T, u));
	// sockets bound to an exit device (health probes, notifications via a tunnel) already chose their path
	add(sprintf('add rule %s output oifname @exit_devs return comment "bound to an exit device"', T));
	add(sprintf('add rule %s output meta mark & %s != 0 return', T, hex(M_BOTH)));
	add(sprintf('add rule %s output meta nfproto ipv4 jump classify', T));
	add(sprintf('add rule %s output meta mark & %s != 0 meta mark & %s vmap @pol2exit', T, hex(M_POL), hex(M_POL)));

	// 10. kill-switch in POSTROUTING (in OUTPUT oifname is the pre-reroute device)
	for (let e in cfg.exits)
		add(sprintf('add rule %s ks%d oifname != "%s" counter drop comment "leak blocked (%s)"', T, e.id, e.device, e.name));
	add(sprintf('add rule %s killswitch meta mark & %s == 0 return', T, hex(M_EXIT)));
	if (length(cfg.exits)) {
		let vm = [];
		for (let e in cfg.exits) push(vm, sprintf('%s : goto ks%d', hex(exit_mark(e.id)), e.id));
		add(sprintf('add rule %s killswitch meta mark & %s vmap { %s }', T, hex(M_EXIT), join(', ', vm)));
	}
	add(sprintf('add rule %s killswitch counter drop comment "unknown exit id"', T));

	// 11. IPv6 (first version: no tunnelling) - reject v6 from devices / to addresses under a policy
	for (let p in cfg.policies) {
		if (!p.enabled) continue;
		add(sprintf('add rule %s v6block iifname @lan_ifs meta nfproto ipv6 ether saddr @dev_p%d counter reject', T, p.id));
		add(sprintf('add rule %s v6block iifname @lan_ifs ip6 daddr @dst6_p%d counter reject', T, p.id));
		add(sprintf('add rule %s v6block iifname @lan_ifs ip6 daddr @dom6_p%d counter reject', T, p.id));
	}

	// 12. DNS of LAN devices goes to the router (domain policies need it): redirect :53, block DoT/DoQ :853
	if (cfg.main.force_dns) {
		add(sprintf('add rule %s dnsredir iifname != @lan_ifs return', T));
		add(sprintf('add rule %s dnsredir fib daddr type local return', T));
		add(sprintf('add rule %s dnsredir meta l4proto { tcp, udp } th dport 53 counter redirect to :53 comment "LAN DNS -> router"', T));
		add(sprintf('add rule %s dotblock iifname @lan_ifs meta l4proto { tcp, udp } th dport 853 counter reject comment "DoT/DoQ bypasses domain policies"', T));
	}
	return join('\n', L) + '\n';
}

export function apply(text) {
	fs.mkdir(RUN);
	const f = RUN + '/ruleset.nft';
	fs.writefile(f, text);
	return run('nft -f ' + f);
}

// switch one policy to another exit: one atomic element replace
export function set_policy_exit(pid, eid) {
	const f = RUN + '/switch.nft';
	fs.writefile(f, sprintf('delete element %s pol2exit { %s }\nadd element %s pol2exit { %s : jump exit%d }\n',
		T, hex(pol_mark(pid)), T, hex(pol_mark(pid)), eid));
	let r = run('nft -f ' + f);
	if (r.code != 0) {   // element did not exist yet
		fs.writefile(f, sprintf('add element %s pol2exit { %s : jump exit%d }\n', T, hex(pol_mark(pid)), eid));
		r = run('nft -f ' + f);
	}
	return r;
}

export function counter_drops(eid) {
	const r = run(sprintf('nft list chain %s ks%d', T, eid));
	const m = match(r.out, /packets ([0-9]+)/);
	return m ? int(m[1]) : 0;
}

export function remove_table() {
	return run('nft delete table inet detour');
}

// --- dnsmasq-filled sets survive reboot: save with the remaining timeout, restore before dnsmasq
export function save_dom(cfg, file) {
	let out = [];
	for (let p in cfg.policies) {
		for (let k in [ 'dom4', 'dom6' ]) {
			const r = run(sprintf('nft list set %s %s_p%d', T, k, p.id));
			if (r.code != 0) continue;
			const re = (k == 'dom4')
				? /([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) expires ([0-9dhms]+)/g
				: /([0-9a-f:]+:[0-9a-f:]*) expires ([0-9dhms]+)/g;
			let el = [];
			for (let m in match(r.out, re)) push(el, sprintf('%s timeout %s', m[1], m[2]));
			if (length(el)) push(out, sprintf('add element %s %s_p%d { %s }', T, k, p.id, join(', ', el)));
		}
	}
	fs.writefile(file + '.tmp', join('\n', out) + '\n');
	fs.rename(file + '.tmp', file);
	return length(out);
}

export function restore_dom(file) {
	if (!fs.access(file)) return { code: 0, out: 'nothing saved' };
	return run('nft -f ' + file);
}
