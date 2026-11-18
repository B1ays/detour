// Detour nftables: renders the "inet detour" table from the config model.
// Own table, NOT part of fw4 (survives fw4 reload). Rules are reloaded in place (flush chain);
// sets filled by dnsmasq (dom4_pN/dom6_pN) are never flushed or recreated.
'use strict';

import * as fs from 'fs';
import { hex, run, log, M_SKIP, RUN, PRIVATE4, PRIVATE6, pol_mark as core_pol_mark } from 'detour.core';

const T = 'inet detour';

function elems(list, quote) {
	let out = [];
	for (let x in list) push(out, quote ? sprintf('"%s"', x) : x);
	return join(', ', out);
}


// names of sets/chains/maps this config needs
function wanted(cfg) {
	const sets = { lan_ifs: 1, bypass4: 1, bypass6: 1, exit_devs: 1 };
	const chains = { classify: 1, prerouting: 1, output: 1, killswitch: 1, v6block: 1, dnsredir: 1, dotblock: 1, blockrej: 1, podirect: 1 };
	for (let p in cfg.policies) {
		for (let k in [ 'dev', 'dst4', 'dst6', 'dom4', 'dom6', 'lst4', 'lst6', 'src4', 'src6', 'ifs' ]) sets[sprintf('%s_p%d', k, p.id)] = 1;
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
		// -t: names only, no set elements - the big lists would be listed whole on every reload for nothing
		const r = run("nft -j -t list table inet detour");
		if (r.code == 0) { try { j = json(r.out); } catch (e) { j = null; } }
		else if (index(r.out, 'No such file') >= 0) return { sets: [], chains: [] };   // no table yet
		if (j == null) system('sleep 0.2 2>/dev/null || sleep 1');   // a busybox without fractions (Beam WRT): 1 s
	}
	if (j == null) { log('nft: could not list the table - stale objects stay until the next reload'); return { sets: [], chains: [] }; }
	const w = wanted(cfg);
	const out = { sets: [], chains: [], maps: [] };
	for (let o in j?.nftables ?? []) {
		if (o.set && !w.sets[o.set.name]) push(out.sets, o.set.name);
		if (o.chain && !w.chains[o.chain.name]) push(out.chains, o.chain.name);
	}
	return out;
};

// active: { <policy id>: <exit id> }; opts: { skip_uid: <num|null>, stale: {sets,chains} }
export function render(cfg, active, opts) {
	opts ??= {};
	const L = [];
	const add = (s) => push(L, s);
	const to = cfg.main.dom_timeout;
	// the fwmark layout (main.fw_mask): policy byte, exit byte, the "decided: directly" value
	const K = cfg.main.marks;
	const pol_mark = (id) => id << K.shift, exit_mark = (id) => id << (K.shift + 8);

	// 1. declarations (add semantics: existing objects are kept, with their elements)
	add('table inet detour {');
	add('\tset lan_ifs { type ifname; }');
	add('\tset exit_devs { type ifname; }');
	add(sprintf('\tset bypass4 { type ipv4_addr; flags interval; elements = { %s }; }', join(', ', PRIVATE4)));
	add(sprintf('\tset bypass6 { type ipv6_addr; flags interval; elements = { %s }; }', join(', ', PRIVATE6)));
	for (let p in cfg.policies) {
		// big downloaded lists: filled by lists-update, never flushed by a rules reload
		add(sprintf('\tset lst4_p%d { type ipv4_addr; flags interval; auto-merge; }', p.id));
		add(sprintf('\tset lst6_p%d { type ipv6_addr; flags interval; auto-merge; }', p.id));
		add(sprintf('\tset dev_p%d { type ether_addr; }', p.id));
		add(sprintf('\tset src4_p%d { type ipv4_addr; flags interval; auto-merge; }', p.id));
		add(sprintf('\tset src6_p%d { type ipv6_addr; flags interval; auto-merge; }', p.id));
		add(sprintf('\tset ifs_p%d { type ifname; }', p.id));
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
	add('\tchain blockrej { }');
	add('\tchain podirect { }');
	add('\tchain prerouting { type filter hook prerouting priority mangle - 5; policy accept; }');
	add('\tchain output { type route hook output priority mangle - 5; policy accept; }');
	add('\tchain killswitch { type filter hook postrouting priority srcnat - 10; policy accept; }');
	add('\tchain v6block { type filter hook forward priority filter - 10; policy accept; }');
	add('\tchain dnsredir { type nat hook prerouting priority dstnat - 5; policy accept; }');
	add('\tchain dotblock { type filter hook forward priority filter - 11; policy accept; }');
	add('}');

	// 2. flush rules and static data (dom* sets are left alone)
	const chains = [ 'classify', 'prerouting', 'output', 'killswitch', 'v6block', 'dnsredir', 'dotblock', 'blockrej', 'podirect' ];
	for (let e in cfg.exits) { push(chains, sprintf('exit%d', e.id)); push(chains, sprintf('ks%d', e.id)); }
	for (let ch in chains) add(sprintf('flush chain %s %s', T, ch));
	add(sprintf('flush map %s pol2exit', T));
	for (let s in [ 'lan_ifs', 'exit_devs' ]) add(sprintf('flush set %s %s', T, s));
	for (let p in cfg.policies)
		for (let k in [ 'dev', 'dst4', 'dst6', 'src4', 'src6', 'ifs' ]) add(sprintf('flush set %s %s_p%d', T, k, p.id));

	// 3. remove what the config no longer has (rules referencing them were flushed above)
	for (let ch in opts.stale?.chains ?? []) { add(sprintf('flush chain %s %s', T, ch)); }
	for (let ch in opts.stale?.chains ?? []) add(sprintf('delete chain %s %s', T, ch));
	for (let s in opts.stale?.sets ?? []) add(sprintf('delete set %s %s', T, s));

	// 4. static elements
	// the home networks: main.lan_dev and the networks policies name (a guest network is "home" for its policy)
	const lan = [ ...cfg.main.lan ];
	for (let p in cfg.policies) if (p.enabled) for (let d in p.ifdevs ?? []) if (index(lan, d) < 0) push(lan, d);
	if (length(lan)) add(sprintf('add element %s lan_ifs { %s }', T, elems(lan, true)));
	if (length(cfg.exits)) {
		let devs = [];
		for (let e in cfg.exits) if (index(devs, e.device) < 0) push(devs, e.device);
		add(sprintf('add element %s exit_devs { %s }', T, elems(devs, true)));
	}
	for (let p in cfg.policies) {
		if (!p.enabled) continue;
		if (length(p.devices)) add(sprintf('add element %s dev_p%d { %s }', T, p.id, elems(p.devices)));
		if (length(p.dst4)) add(sprintf('add element %s dst4_p%d { %s }', T, p.id, elems(p.dst4)));
		if (length(p.dst6)) add(sprintf('add element %s dst6_p%d { %s }', T, p.id, elems(p.dst6)));
		if (length(p.src4)) add(sprintf('add element %s src4_p%d { %s }', T, p.id, elems(p.src4)));
		if (length(p.src6)) add(sprintf('add element %s src6_p%d { %s }', T, p.id, elems(p.src6)));
		if (length(p.ifdevs)) add(sprintf('add element %s ifs_p%d { %s }', T, p.id, elems(p.ifdevs, true)));
	}

	// 5. exit chains: set the exit id, keep everything else
	for (let e in cfg.exits)
		add(sprintf('add rule %s exit%d meta mark set meta mark & %s | %s', T, e.id, hex(~K.exit & 0xffffffff), hex(exit_mark(e.id))));

	// 6. policy -> exit (atomic switch = replace one element)
	for (let p in cfg.policies) {
		if (!p.enabled || p.direct) continue;   // "Directly": no mark, never reaches pol2exit
		const eid = active?.[p.id];
		// "Block": refused at once, so apps do not wait for a timeout
		if (p.block) add(sprintf('add element %s pol2exit { %s : jump blockrej }', T, hex(pol_mark(p.id))));
		// no exit at all (its last one was removed): what the policy covers is blocked, never sent directly
		else if (!length(p.exits)) add(sprintf('add element %s pol2exit { %s : drop }', T, hex(pol_mark(p.id))));
		else if (eid) add(sprintf('add element %s pol2exit { %s : jump exit%d }', T, hex(pol_mark(p.id)), eid));
	}

	// the "Block" target: TCP gets a reset, the rest "administratively prohibited"
	add(sprintf('add rule %s blockrej counter meta l4proto tcp reject with tcp reset', T));
	add(sprintf('add rule %s blockrej reject with icmpx type admin-prohibited', T));
	// on_down 'direct' (set_policy_direct): the flow is pinned with the policy mark alone (no exit), so it stays
	// direct while it lasts and the daemon can drop exactly these flows when an exit is back
	add(sprintf('add rule %s podirect ct mark set meta mark & %s accept', T, hex(K.both)));

	// 7. classify: first match wins, policies in config order
	add(sprintf('add rule %s classify ip daddr @bypass4 return', T));
	const setp = (id) => sprintf('meta mark set meta mark & %s | %s return', hex(~K.pol & 0xffffffff), hex(pol_mark(id)));
	for (let p in cfg.policies) {
		if (!p.enabled) continue;
		// "Directly": what matches leaves unmarked - the policies below it never see it
		const v = p.direct ? sprintf('return comment "%s: directly"', p.name) : setp(p.id);
		add(sprintf('add rule %s classify ether saddr @dev_p%d %s', T, p.id, v));
		// by the source: only what came in from a home network (the router's own answers carry its LAN address)
		add(sprintf('add rule %s classify iifname @ifs_p%d %s', T, p.id, v));
		add(sprintf('add rule %s classify iifname @lan_ifs ip saddr @src4_p%d %s', T, p.id, v));
		add(sprintf('add rule %s classify ip daddr @dst4_p%d %s', T, p.id, v));
		add(sprintf('add rule %s classify ip daddr @dom4_p%d %s', T, p.id, v));
		add(sprintf('add rule %s classify ip daddr @lst4_p%d %s', T, p.id, v));
		for (let pr in [ 'tcp', 'udp' ])
			if (length(p.ports?.[pr]))
				add(sprintf('add rule %s classify meta l4proto %s th dport { %s } %s', T, pr, join(', ', p.ports[pr]), v));
	}

	// 8. LAN ingress: a flow is classified once - its first packet; the decision lives in the ct mark (policy +
	// exit, or "directly"), every later packet only reads it back. (Two run-time values cannot be combined in one
	// nft expression on older kernels: the policy+exit mark replaces the ct mark as before; "directly", a constant,
	// keeps the other bits.)
	const keep = hex(~K.both & 0xffffffff);
	add(sprintf('add rule %s prerouting iifname != @lan_ifs return', T));
	add(sprintf('add rule %s prerouting ct mark & %s == %s return comment "decided: directly"', T, hex(K.both), hex(K.direct)));
	add(sprintf('add rule %s prerouting ct mark & %s != 0 meta mark set ct mark & %s return', T, hex(K.both), hex(K.both)));
	// answers of LAN devices to connections that came from outside (port forwards) are not new flows: they
	// go back the way the connection came, whatever policy the device is under
	add(sprintf('add rule %s prerouting ct direction reply return', T));
	add(sprintf('add rule %s prerouting meta nfproto ipv4 jump classify', T));
	add(sprintf('add rule %s prerouting meta mark & %s != 0 meta mark & %s vmap @pol2exit', T, hex(K.pol), hex(K.pol)));
	add(sprintf('add rule %s prerouting meta mark & %s != 0 ct mark set meta mark & %s', T, hex(K.both), hex(K.both)));
	// no policy took it (or a "Directly" one did): remembered, so the rest of the flow skips classify
	add(sprintf('add rule %s prerouting meta nfproto ipv4 meta mark & %s == 0 ct mark set ct mark & %s | %s', T, hex(K.both), keep, hex(K.direct)));

	// 9. router's own traffic (type route: routing is redone after the mark change)
	add(sprintf('add rule %s output meta mark & %s != 0 return comment "underlay 0x10000000 + nfqws 0x40000000"', T, hex(M_SKIP)));
	for (let u in opts.skip_uid ?? [])
		add(sprintf('add rule %s output meta skuid %d return comment "always direct (DNS fallback, notifications, bypass_user)"', T, u));
	// sockets bound to an exit device (health probes, notifications via a tunnel) already chose their path
	add(sprintf('add rule %s output oifname @exit_devs return comment "bound to an exit device"', T));
	add(sprintf('add rule %s output meta mark & %s != 0 return', T, hex(K.both)));
	add(sprintf('add rule %s output meta nfproto ipv4 jump classify', T));
	add(sprintf('add rule %s output meta mark & %s != 0 meta mark & %s vmap @pol2exit', T, hex(K.pol), hex(K.pol)));

	// 10. kill-switch in POSTROUTING (in OUTPUT oifname is the pre-reroute device)
	for (let e in cfg.exits)
		add(sprintf('add rule %s ks%d oifname != "%s" counter drop comment "leak blocked (%s)"', T, e.id, e.device, e.name));
	add(sprintf('add rule %s killswitch meta mark & %s == 0 return', T, hex(K.exit)));
	if (length(cfg.exits)) {
		let vm = [];
		for (let e in cfg.exits) push(vm, sprintf('%s : goto ks%d', hex(exit_mark(e.id)), e.id));
		add(sprintf('add rule %s killswitch meta mark & %s vmap { %s }', T, hex(K.exit), join(', ', vm)));
	}
	add(sprintf('add rule %s killswitch counter drop comment "unknown exit id"', T));

	// 11. IPv6 (first version: no tunnelling) - reject v6 from devices / to addresses under a policy
	// "full tunnel" refuses all IPv6 where the policy taking all IPv4 stands: a "Directly" policy above it keeps
	// its IPv6 (its returns come first); set by hand with no such policy, at the end, after every policy
	let full = cfg.main.ipv6_block;
	const full_rule = sprintf('add rule %s v6block iifname @lan_ifs meta nfproto ipv6 counter reject comment "full tunnel: no IPv6 past it"', T);
	// a flow that got through when it began stays (only new ones are refused); local and private ones are never refused
	add(sprintf('add rule %s v6block ct state established,related return', T));
	add(sprintf('add rule %s v6block ip6 daddr @bypass6 return', T));
	for (let p in cfg.policies) {
		if (!p.enabled) continue;
		if (full && !p.direct && length(filter(p.dst4, (a) => match(a, /\/0$/)))) { add(full_rule); full = false; }
		// the policy refuses all IPv6 from its place in the order (main.ipv6_block for one policy)
		if (p.ipv6_block) add(sprintf('add rule %s v6block iifname @lan_ifs meta nfproto ipv6 counter reject comment "%s: no IPv6"', T, p.name));
		// "Directly" is not tunnelled: its IPv6 goes as it is, and a policy below it must not refuse it (the same
		// order as classify)
		if (p.direct) {
			add(sprintf('add rule %s v6block iifname @lan_ifs meta nfproto ipv6 ether saddr @dev_p%d return', T, p.id));
			add(sprintf('add rule %s v6block iifname @ifs_p%d meta nfproto ipv6 return', T, p.id));
			add(sprintf('add rule %s v6block iifname @lan_ifs ip6 saddr @src6_p%d return', T, p.id));
			add(sprintf('add rule %s v6block iifname @lan_ifs ip6 daddr @dst6_p%d return', T, p.id));
			add(sprintf('add rule %s v6block iifname @lan_ifs ip6 daddr @lst6_p%d return', T, p.id));
			for (let pr in [ 'tcp', 'udp' ])
				if (length(p.ports?.[pr]))
					add(sprintf('add rule %s v6block iifname @lan_ifs meta nfproto ipv6 meta l4proto %s th dport { %s } return', T, pr, join(', ', p.ports[pr])));
			continue;
		}
		add(sprintf('add rule %s v6block iifname @lan_ifs meta nfproto ipv6 ether saddr @dev_p%d counter reject', T, p.id));
		add(sprintf('add rule %s v6block iifname @ifs_p%d meta nfproto ipv6 counter reject', T, p.id));
		add(sprintf('add rule %s v6block iifname @lan_ifs ip6 saddr @src6_p%d counter reject', T, p.id));
		add(sprintf('add rule %s v6block iifname @lan_ifs ip6 daddr @dst6_p%d counter reject', T, p.id));
		add(sprintf('add rule %s v6block iifname @lan_ifs ip6 daddr @dom6_p%d counter reject', T, p.id));
		add(sprintf('add rule %s v6block iifname @lan_ifs ip6 daddr @lst6_p%d counter reject', T, p.id));
		for (let pr in [ 'tcp', 'udp' ])
			if (length(p.ports?.[pr]))
				add(sprintf('add rule %s v6block iifname @lan_ifs meta nfproto ipv6 meta l4proto %s th dport { %s } counter reject', T, pr, join(', ', p.ports[pr])));
	}
	if (full) add(full_rule);

	// 12. DNS of LAN devices goes to the router (domain policies need it): redirect :53, block DoT/DoQ :853
	if (cfg.main.force_dns) {
		add(sprintf('add rule %s dnsredir iifname != @lan_ifs return', T));
		add(sprintf('add rule %s dnsredir fib daddr type local return', T));
		add(sprintf('add rule %s dnsredir meta l4proto { tcp, udp } th dport 53 counter redirect to :53 comment "LAN DNS -> router"', T));
		add(sprintf('add rule %s dotblock ct state established,related return', T));
		add(sprintf('add rule %s dotblock iifname @lan_ifs meta l4proto { tcp, udp } th dport 853 counter reject comment "DoT/DoQ bypasses domain policies"', T));
	}
	return join('\n', L) + '\n';
};

export function apply(text) {
	fs.mkdir(RUN);
	const f = RUN + '/ruleset.nft';
	fs.writefile(f, text);
	return run('nft -f ' + f);
};

// switch one policy to another exit: one atomic element replace
export function set_policy_exit(pid, eid) {
	const pol_mark = core_pol_mark;
	const f = RUN + '/switch.nft';
	fs.writefile(f, sprintf('delete element %s pol2exit { %s }\nadd element %s pol2exit { %s : jump exit%d }\n',
		T, hex(pol_mark(pid)), T, hex(pol_mark(pid)), eid));
	let r = run('nft -f ' + f);
	if (r.code != 0) {   // element did not exist yet
		fs.writefile(f, sprintf('add element %s pol2exit { %s : jump exit%d }\n', T, hex(pol_mark(pid)), eid));
		r = run('nft -f ' + f);
	}
	return r;
};

// a policy whose exits are all down and which may then go directly (on_down 'direct'): its packets keep their
// policy mark (so they are known as its traffic) but take no exit - the main table, the provider's line.
// podirect pins the flow (ct mark = policy, exit 0); conntrack -D -m <policy mark>/0xffff00 drops these flows
export function set_policy_direct(pid) {
	const pol_mark = core_pol_mark;
	const f = RUN + '/switch.nft';
	fs.writefile(f, sprintf('delete element %s pol2exit { %s }\nadd element %s pol2exit { %s : jump podirect }\n',
		T, hex(pol_mark(pid)), T, hex(pol_mark(pid))));
	let r = run('nft -f ' + f);
	if (r.code != 0) {
		fs.writefile(f, sprintf('add element %s pol2exit { %s : jump podirect }\n', T, hex(pol_mark(pid))));
		r = run('nft -f ' + f);
	}
	return r;
};

// how many packets the "Block" target refused
export function counter_blocked() {
	const m = match(run(sprintf('nft list chain %s blockrej', T)).out, /packets ([0-9]+)/);
	return m ? int(m[1]) : 0;
};

export function counter_drops(eid) {
	const r = run(sprintf('nft list chain %s ks%d', T, eid));
	const m = match(r.out, /packets ([0-9]+)/);
	return m ? int(m[1]) : 0;
};

export function remove_table() {
	return run('nft delete table inet detour');
};

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
};

export function restore_dom(file) {
	if (!fs.access(file)) return { code: 0, out: 'nothing saved' };
	return run('nft -f ' + file);
};
