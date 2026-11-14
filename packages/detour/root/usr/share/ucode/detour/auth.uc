// A-8: with LuCI 2FA enabled, "session.login" over HTTP /ubus would let a password alone in
// (rpcd grants it to unauthenticated callers). LuCI itself logs in over local ubus as root and is
// not affected. The file belongs to rpcd and comes back on rpcd upgrades, so this is re-checked
// periodically, not only at install time.
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, log, PERSIST, lan_zones } from 'detour.core';

export const ACL = '/usr/share/rpcd/acl.d/unauthenticated.json';
const BACKUP = PERSIST + '/unauthenticated.json.orig';
const MARK = 'Detour: no session.login over HTTP (2FA)';

const FIXED = {
	unauthenticated: {
		description: 'Access controls for unauthenticated requests (' + MARK + ')',
		read: { ubus: { session: [ 'access' ] } }
	}
};
const STOCK = {
	unauthenticated: {
		description: 'Access controls for unauthenticated requests',
		read: { ubus: { session: [ 'access', 'login' ] } }
	}
};

export function twofa_enabled() {
	const c = cursor();
	if (c.get('luci_plugins', 'global', 'enabled') != '1') return false;
	if (c.get('luci_plugins', 'global', 'auth_login_enabled') != '1') return false;
	let on = false;
	c.foreach('luci_plugins', 'auth_login', function(s) {
		if (s.enabled == '1') on = true;
	});
	return on;
}

function grants_login() {
	const s = fs.readfile(ACL);
	if (!s) return false;
	let j;
	try { j = json(s); } catch (e) { return true; }
	const l = j?.unauthenticated?.read?.ubus?.session ?? [];
	return index(l, 'login') >= 0 || index(l, '*') >= 0;
}

function ours() {
	return index(fs.readfile(ACL) ?? '', MARK) >= 0;
}

function reload_rpcd() {
	run('killall -HUP rpcd');   // keeps existing sessions
}

export function restore() {
	if (!ours()) return false;
	const b = fs.readfile(BACKUP);
	fs.writefile(ACL, (b && length(b)) ? b : sprintf('%.J\n', STOCK));
	fs.unlink(BACKUP);
	reload_rpcd();
	return true;
}

// --- A-9: with 2FA on, SSH password login only from LAN networks; elsewhere keys only.
// Specific and wildcard listeners on one port do not mix (whoever binds second gets EADDRINUSE,
// including the v6 address of the LAN), so every instance is bound to a network: password ones
// for the networks of the home zones (core.lan_zones), keys-only ones for all other networks; the stock wildcard
// instances are disabled meanwhile. Everything is undone when 2FA is off.
const PW_PREFIX = 'detour_pw_', KEY_PREFIX = 'detour_key_';

function lan_networks() {
	const c = cursor();
	const zones = lan_zones();
	let nets = [];
	c.foreach('firewall', 'zone', function(z) {
		if (index(zones, z.name) >= 0) {
			const n = z.network;
			for (let x in ((type(n) == 'array') ? n : split(n ?? (z.name == 'lan' ? 'lan' : ''), /\s+/)))
				if (index(nets, x) < 0) push(nets, x);
		}
	});
	return filter(nets, (x) => length(x));
}

function other_networks(lan) {
	const c = cursor();
	const out = [];
	c.foreach('network', 'interface', function(s) {
		const n = s['.name'];
		if (n != 'loopback' && index(lan, n) < 0) push(out, n);
	});
	return out;
}

export function root_keys() {
	let n = 0;
	for (let l in split(fs.readfile('/etc/dropbear/authorized_keys') ?? '', '
'))
		if (match(l, /^(ssh-|ecdsa-|sk-)/)) n++;
	return n;
}

function sname(prefix, net) { return prefix + replace(net, /[^A-Za-z0-9_]/g, '_'); }

// returns true when dropbear config changed (and dropbear was restarted)
export function ssh_apply(on) {
	const c = cursor();
	let changed = false, port = '22';
	const have = {};
	c.foreach('dropbear', 'dropbear', function(s) {
		const n = s['.name'];
		if (index(n, PW_PREFIX) == 0 || index(n, KEY_PREFIX) == 0) { have[n] = true; return; }
		if (on) {
			if (s.Interface) return;          // already bound to a network by the user: leave it
			port = s.Port ?? '22';
			if (s.enable != '0') {
				c.set('dropbear', n, 'detour_disabled', '1');
				c.set('dropbear', n, 'enable', '0');
				changed = true;
			}
		}
		else if (s.detour_disabled == '1') {
			c.set('dropbear', n, 'enable', '1');
			c.delete('dropbear', n, 'detour_disabled');
			changed = true;
		}
	});
	const want = {};
	if (on) {
		const lan = lan_networks();
		for (let net in lan) want[sname(PW_PREFIX, net)] = { net, pw: 'on' };
		for (let net in other_networks(lan)) want[sname(KEY_PREFIX, net)] = { net, pw: 'off' };
	}
	for (let n, w in want) {
		if (have[n]) { delete have[n]; continue; }
		c.set('dropbear', n, 'dropbear');
		c.set('dropbear', n, 'enable', '1');
		c.set('dropbear', n, 'Interface', w.net);
		c.set('dropbear', n, 'Port', port);
		c.set('dropbear', n, 'PasswordAuth', w.pw);
		c.set('dropbear', n, 'RootPasswordAuth', w.pw);
		changed = true;
	}
	for (let n in keys(have)) { c.delete('dropbear', n); changed = true; }
	if (changed) {
		c.commit('dropbear');
		// detached: restarting dropbear may end the SSH session this runs from
		system('(sleep 1; /etc/init.d/dropbear restart) </dev/null >/dev/null 2>&1 &');
		log(on ? 'SSH: password login only from LAN networks, keys elsewhere (2FA is on)' : 'SSH: stock dropbear settings restored');
	}
	return changed;
}

// returns 'closed' | 'reopened' (we closed it again) | 'restored' | 'ok'
export function guard() {
	ssh_apply(twofa_enabled() && cursor().get('detour', 'main', 'ssh_guard') != '0');
	if (twofa_enabled()) {
		if (!grants_login()) return 'ok';
		fs.mkdir(PERSIST);
		if (!ours() && !fs.access(BACKUP)) fs.writefile(BACKUP, fs.readfile(ACL) ?? '');
		fs.writefile(ACL, sprintf('%.J\n', FIXED));
		reload_rpcd();
		log('2FA is on: closed session.login over HTTP /ubus');
		return 'closed';
	}
	if (ours()) {
		restore();
		log('2FA is off: session.login over /ubus restored');
		return 'restored';
	}
	return 'ok';
}

export function status() {
	let ssh_guard = false;
	cursor().foreach('dropbear', 'dropbear', function(x) { if (index(x['.name'], PW_PREFIX) == 0 || index(x['.name'], KEY_PREFIX) == 0) ssh_guard = true; });
	return { twofa: twofa_enabled(), http_login_open: grants_login(), managed: ours(), ssh_lan_password_only: ssh_guard, root_keys: root_keys() };
}
