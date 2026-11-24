// The local SOCKS5 proxy (config socks 'socks'): for the apps and devices of the home network that take a proxy.
// It listens on the IPv4 addresses of the home networks (main.lan_dev) only, never on the WAN. It runs as the system
// user "dtsocks", so its connections are the router's own and the nft output chain knows them by that user
// (nft.uc): by the policies, as any device (destinations, sites, lists, ports - not MACs or sources: those are
// the router's), or all through one policy, with its exits, failover and kill-switch. The engine is sing-box, else
// Xray; its config (with the login) is a file of mode 600 owned by the user - never a command line. Names are
// resolved by the router's dnsmasq (the domain policies fill their sets from those answers), IPv4 only: the
// policies and the kill-switch are IPv4, and a policy domain answers AAAA 100::.
'use strict';

import * as fs from 'fs';
import { RUN, run } from 'detour.core';

export const USER = 'dtsocks';
export const CONF = RUN + '/socks.json';
const BIN = { singbox: '/usr/bin/sing-box', xray: '/usr/bin/xray' };

// sing-box, else Xray; null when neither is installed
export function engine() {
	for (let t in [ 'singbox', 'xray' ]) if (fs.access(BIN[t], 'x')) return t;
	return null;
};

// the IPv4 addresses of the home networks, now
export function addrs(cfg) {
	const out = [];
	for (let d in cfg.main.lan) {
		const r = run(sprintf("ip -4 -o addr show dev '%s' 2>/dev/null", d));
		for (let l in split(r.out ?? '', '\n')) {
			const m = match(l, /inet ([0-9.]+)\//);
			if (m && index(out, m[1]) < 0) push(out, m[1]);
		}
	}
	return out;
};

function config(t, s, listen) {
	if (t == 'singbox')
		return {
			// "fatal": an error of a connection names the login and the password a client tried (in the system log)
			log: { level: 'fatal' },
			dns: { servers: [ { type: 'local', tag: 'local' } ] },
			inbounds: map(listen, (a, i) => {
				const x = { type: 'socks', tag: sprintf('socks%d', i), listen: a, listen_port: s.port };
				if (s.user) x.users = [ { username: s.user, password: s.pass } ];
				return x;
			}),
			outbounds: [ { type: 'direct', tag: 'direct', domain_resolver: { server: 'local', strategy: 'ipv4_only' } } ],
			route: { final: 'direct', default_domain_resolver: { server: 'local', strategy: 'ipv4_only' } }
		};
	return {
		// nothing: what a client tried as a login is not written down
		log: { loglevel: 'none', access: 'none' },
		// "localhost": the system's resolver, the router's dnsmasq
		dns: { servers: [ 'localhost' ], queryStrategy: 'UseIPv4' },
		inbounds: map(listen, (a, i) => {
			const st = { auth: s.user ? 'password' : 'noauth', udp: true, ip: a };
			if (s.user) st.accounts = [ { user: s.user, pass: s.pass } ];
			return { tag: sprintf('socks%d', i), listen: a, port: s.port, protocol: 'socks', settings: st };
		}),
		outbounds: [ { tag: 'direct', protocol: 'freedom', settings: { domainStrategy: 'UseIPv4' } } ]
	};
}

// the config written for the init script: { bin, args } | { error } | null (switched off)
export function prepare(cfg) {
	const s = cfg.socks;
	fs.unlink(CONF);
	if (!s?.enabled) return null;
	const t = engine();
	if (!t) return { error: 'socks: neither sing-box nor xray is installed' };
	const listen = addrs(cfg);
	if (!length(listen)) return { error: 'socks: the home networks have no IPv4 address' };
	fs.mkdir(RUN);
	fs.writefile(CONF, '');
	fs.chmod(CONF, 0600);
	fs.writefile(CONF, sprintf('%.J\n', config(t, s, listen)));
	system(sprintf("chown %s: '%s' 2>/dev/null", USER, CONF));
	return { bin: BIN[t], args: 'run -c ' + CONF, engine: t, listen };
};

// what LuCI shows: where to point an app, without the login
export function info(cfg) {
	const s = cfg.socks;
	return { enabled: !!s?.enabled, port: s?.port, auth: !!s?.user, policy: s?.policy, engine: engine(),
		addrs: s?.enabled ? addrs(cfg) : [] };
};
