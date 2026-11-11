// LuCI "Devices": the devices of the home networks - DHCP leases, fixed addresses, neighbours - with their
// state (online, Wi-Fi with its signal or wired). Where each device goes is read by the page from the config.
'use strict';

import * as fs from 'fs';
import * as core from 'detour.core';
import * as traffic from 'detour.traffic';
import { cursor } from 'uci';

const RE_MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;

function dev(o, mac) {
	mac = lc(mac ?? '');
	if (!match(mac, RE_MAC)) return null;
	return o[mac] ??= { mac, name: null, hostname: null, ips: [], online: false, wifi: null, fixed: false, lease: false };
}
function add_ip(d, ip) { if (d && ip && index(d.ips, ip) < 0) push(d.ips, ip); }

// Wi-Fi clients: every AP interface's stations (iw; iwinfo when there is no iw)
function wifi(o) {
	const iw = fs.access('/usr/sbin/iw') || fs.access('/sbin/iw');
	if (iw) {
		let ifc = null, ssid = {}, aps = [];
		for (let l in split(core.run('iw dev').out, '\n')) {
			let m = match(l, /Interface ([^ ]+)/); if (m) ifc = m[1];
			m = match(l, /ssid (.+)$/); if (m && ifc) ssid[ifc] = trim(m[1]);
			if (match(l, /type AP/) && ifc) push(aps, ifc);
		}
		for (let a in aps) {
			let d = null;
			for (let l in split(core.run('iw dev ' + core.shq(a) + ' station dump').out, '\n')) {
				let m = match(l, /^Station ([0-9a-fA-F:]+)/);
				if (m) { d = dev(o, m[1]); if (d) d.wifi = { iface: a, ssid: ssid[a] }; continue; }
				if (!d) continue;
				// an MLO client (several links) reports "signal: 0" for the whole: then its average
				m = match(l, /^\s*signal:\s*(-?[0-9]+)/); if (m && int(m[1]) != 0) d.wifi.signal = int(m[1]);
				m = match(l, /^\s*signal avg:\s*(-?[0-9]+)/); if (m && !d.wifi.signal) d.wifi.signal = int(m[1]);
				m = match(l, /^\s*connected time:\s*([0-9]+)/); if (m) d.wifi.connected = int(m[1]);
			}
		}
		return;
	}
	if (!fs.access('/usr/bin/iwinfo')) return;
	for (let l in split(core.run('ls /sys/class/net').out, '\n')) {
		if (!length(l) || !fs.access('/sys/class/net/' + l + '/phy80211')) continue;
		for (let s in split(core.run('iwinfo ' + core.shq(l) + ' assoclist').out, '\n')) {
			const m = match(s, /^([0-9A-Fa-f:]{17})\s+(-?[0-9]+) dBm/);
			if (m) { const d = dev(o, m[1]); if (d) d.wifi = { iface: l, signal: int(m[2]) }; }
		}
	}
}

export function list() {
	const o = {};
	const c = cursor();
	// fixed addresses (and names) in /etc/config/dhcp
	c.foreach('dhcp', 'host', function(s) {
		for (let m in (type(s.mac) == 'array' ? s.mac : split(s.mac ?? '', ' '))) {
			const d = dev(o, m);
			if (!d) continue;
			d.fixed = true;
			if (s.name) d.name = s.name;
			if (s.ip && s.ip != 'ignore') add_ip(d, s.ip);
		}
	});
	// DHCP leases: "expiry mac ip hostname clientid"
	let lf = null;
	c.foreach('dhcp', 'dnsmasq', (s) => { lf ??= s.leasefile; });
	for (let l in split(fs.readfile(lf ?? '/tmp/dhcp.leases') ?? '', '\n')) {
		const p = split(l, ' ');
		const d = dev(o, p[1]);
		if (!d) continue;
		d.lease = true;
		add_ip(d, p[2]);
		if (p[3] && p[3] != '*') d.hostname = p[3];
	}
	// neighbours on the home networks: addresses and "online"
	const home = traffic.home_devs() ?? {};
	const stale = [];
	for (let l in split(core.run('ip neigh show').out, '\n')) {
		const m = match(trim(l), /^([^ ]+) dev ([^ ]+) lladdr ([0-9a-fA-F:]+).* ([A-Z]+)$/);
		if (!m || !home[m[2]] || match(m[1], /^fe80:/)) continue;
		const d = dev(o, m[3]);
		if (!d) continue;
		add_ip(d, m[1]);
		if (index([ 'REACHABLE', 'DELAY', 'PROBE' ], m[4]) >= 0) d.online = true;
		// quiet for half a minute = STALE, which says nothing: one ping now (in the background) and the kernel
		// knows by the page's next look whether the device is there
		else if (m[4] == 'STALE' && match(m[1], /^[0-9.]+$/) && length(stale) < 64) push(stale, m[1]);
	}
	if (length(stale)) core.run('for a in ' + join(' ', stale) + '; do ping -c1 -W1 $a >/dev/null 2>&1 & done');
	wifi(o);
	for (let mac, d in o) if (d.wifi) d.online = true;
	// IPv4 first
	for (let mac, d in o) d.ips = sort(d.ips, (a, b) => (index(a, ':') >= 0) - (index(b, ':') >= 0));
	// the router's own interfaces are not devices
	for (let n in fs.lsdir('/sys/class/net') ?? []) delete o[lc(trim(fs.readfile('/sys/class/net/' + n + '/address') ?? ''))];
	return { devices: values(o) };
}
