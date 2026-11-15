// Traffic by device and by exit, per day (LuCI "Traffic").
//
// Devices: nlbwmon (conntrack accounting: accelerated flows are counted too, whatever the interfaces are;
// rx = download of the device). Exits: the counters of their own devices (the tunnels Detour sets up).
// Through VPN = the exits' download, minus what an exit carries for another one riding through it.
// Directly = all devices minus through VPN (approximate: the router's own downloads through a tunnel count as VPN).
//
// Every tick (5 min) adds the growth of each counter to today. A counter that went down was reset
// (nlbwmon restarted or began its next period, a tunnel came up again): its new value is all growth.
// A month is one file: in RAM every tick, on flash every 30 min, when the month ends and when the daemon stops.
'use strict';

import * as fs from 'fs';
import * as core from 'detour.core';
import { cursor } from 'uci';

const RAMDIR = core.RUN + '/traffic';
const DISK = core.PERSIST + '/traffic';
const STATE = RAMDIR + '/last.json';
const KEEP_MONTHS = 13;

let month = null;     // 'YYYY-MM' of the loaded month
let data = null;      // { 'DD': { d: { mac: [rx, tx] }, x: { exit: [rx, tx] }, v: [rx, tx] } }
let saved_at = 0;
let src = { nlbwmon: false, running: false, hw_offload: false };

function pad(n) { return (n < 10 ? '0' : '') + n; }
function ymd(t) { const l = localtime(t); return [ sprintf('%d-%s', l.year, pad(l.mon)), pad(l.mday) ]; }

function load_month(m) {
	return core.read_json(RAMDIR + '/' + m + '.json') ?? core.read_json(DISK + '/' + m + '.json') ?? {};
}

function save_disk() {
	if (!month) return;
	fs.mkdir(core.PERSIST); fs.mkdir(DISK);
	core.write_json(DISK + '/' + month + '.json', data);
	saved_at = time();
	// months older than a year and a month are dropped
	const files = sort(fs.glob(DISK + '/*.json') ?? []);
	while (length(files) > KEEP_MONTHS) fs.unlink(shift(files));
}

// the router's own addresses are not devices: its interfaces (WAN in a private network, tunnels) show up in
// nlbwmon too, as nlbwmon counts every private network as local by default
function own_macs() {
	const out = { '00:00:00:00:00:00': true };
	for (let d in fs.lsdir('/sys/class/net') ?? []) {
		const a = trim(fs.readfile('/sys/class/net/' + d + '/address') ?? '');
		if (length(a)) out[lc(a)] = true;
	}
	return out;
}

// the home networks: those the router hands out addresses in (DHCP), whatever their names and devices.
// A host met on another device (a VPN server in a private network, a modem) is not one of the devices.
// netifd's view of the interfaces, asked with a short timeout: while it brings tunnels up it can take seconds to
// answer (7 s measured on the lab), and the daemon waits on every call - nothing else is served meanwhile
export function netifd_dump() {
	try { return json(core.run('ubus -t 2 call network.interface dump').out); } catch (e) { return null; }
};

let home_cache = null, home_at = 0;
export function home_devs() {
	if (home_cache && time() - home_at < 60) return home_cache;
	const nets = {};
	cursor().foreach('dhcp', 'dhcp', (s) => { if (s.interface && s.ignore != '1') nets[s.interface] = true; });
	const out = {};
	for (let i in netifd_dump()?.interface ?? [])
		if (nets[i.interface]) for (let d in [ i.l3_device, i.device ]) if (d) out[d] = true;
	// netifd busy may not answer: the devices as configured, if they exist (not cached - netifd is asked again)
	if (!length(out)) {
		for (let n in nets) {
			let d = cursor().get('network', n, 'device');
			if (type(d) == 'array') d = d[0];
			if (d && fs.access('/sys/class/net/' + d)) out[d] = true;
		}
		return length(out) ? out : null;
	}
	home_cache = out; home_at = time();
	return out;
};

// mac -> is it in a home network; remembered, as a device offline now has no neighbour entry
function classify(known) {
	const home = home_devs();
	if (!home) return known;
	for (let l in split(core.run('ip neigh show').out, '\n')) {
		const m = match(l, / dev ([^ ]+) lladdr ([0-9a-fA-F:]+)/);
		if (m) known[lc(m[2])] = !!home[m[1]];
	}
	return known;
}

function nlbw() {
	src.nlbwmon = !!fs.access('/usr/sbin/nlbw');
	if (!src.nlbwmon) { src.running = false; return null; }
	const r = core.run('nlbw -c json -g mac');
	let j = null;
	try { j = json(r.out); } catch (e) { }
	src.running = r.code == 0 && type(j?.data) == 'array';
	if (!src.running) return null;
	const col = {};
	for (let i, c in j.columns) col[c] = i;
	const own = own_macs(), out = {};
	for (let row in j.data) {
		const mac = lc(row[col.mac] ?? '');
		if (!length(mac) || own[mac]) continue;
		out[mac] = [ +(row[col.rx_bytes] ?? 0), +(row[col.tx_bytes] ?? 0) ];
	}
	return out;
}

function dev_bytes(dev) {
	const b = (k) => fs.readfile(sprintf('/sys/class/net/%s/statistics/%s_bytes', dev, k));
	const rx = b('rx');
	return rx == null ? null : [ +rx, +(b('tx') ?? 0) ];
}

function grow(cur, last) { return cur >= (last ?? 0) ? cur - (last ?? 0) : cur; }
function add(o, k, rx, tx) { const v = (o[k] ??= [ 0, 0 ]); v[0] += rx; v[1] += tx; }

// one step: cfg = core.load() (exits: name, device, enabled; via from the engine section)
export function tick(cfg, via_of) {
	fs.mkdir(core.RUN); fs.mkdir(RAMDIR);
	if (trim(fs.readfile('/proc/sys/net/netfilter/nf_conntrack_acct') ?? '1') == '0')
		fs.writefile('/proc/sys/net/netfilter/nf_conntrack_acct', '1');
	const now = time();
	const md = ymd(now), m = md[0], day = md[1];   // no destructuring: older ucode (Beam WRT) lacks it
	if (month != m) {
		if (month) save_disk();   // the month that ended goes to flash whole
		month = m; data = load_month(m);
	}
	const last = core.read_json(STATE);
	const cur = { d: nlbw(), x: {}, home: classify(last?.home ?? {}) };
	// counted: a home device, or one never met as a neighbour (unknown is counted rather than lost)
	for (let mac in keys(cur.d ?? {})) if (cur.home[mac] === false) delete cur.d[mac];
	for (let e in cfg.exits) {
		const b = dev_bytes(e.device);
		if (b) cur.x[e.name] = [ e.device, ...b ];
	}
	src.hw_offload = int(trim(core.run('grep -c HW_OFFLOAD /proc/net/nf_conntrack 2>/dev/null').out) || 0) > 0;
	// the first step after start only takes the starting point
	if (last) {
		const today = (data[day] ??= { d: {}, x: {}, v: [ 0, 0 ] });
		for (let mac, v in cur.d ?? {}) {
			const l = last.d?.[mac];
			const rx = grow(v[0], l?.[0]), tx = grow(v[1], l?.[1]);
			if (rx || tx) add(today.d, mac, rx, tx);
		}
		let vrx = 0, vtx = 0;   // through VPN this step
		for (let name, v in cur.x) {
			const l = last.x?.[name];
			// a different device under the same name: a new tunnel, its counter starts anew
			const same = l && l[0] == v[0];
			const rx = grow(v[1], same ? l[1] : 0), tx = grow(v[2], same ? l[2] : 0);
			if (!same && l == null) continue;   // an exit seen for the first time: starting point only
			if (rx || tx) add(today.x, name, rx, tx);
			// an exit riding through another one is in that one's counter as well: counted once, there
			const carrier = via_of(name);
			if (carrier && cur.x[carrier]) continue;
			vrx += rx; vtx += tx;
		}
		today.v[0] += vrx;
		today.v[1] += vtx;
	}
	core.write_json(STATE, { d: cur.d ?? last?.d ?? {}, x: cur.x, home: cur.home, at: now });
	core.write_json(RAMDIR + '/' + m + '.json', data);
	if (now - saved_at >= 1800 || !fs.access(DISK + '/' + m + '.json')) save_disk();
};

// the daemon stops (reboot, upgrade): today so far goes to flash
export function flush() { if (month && data) save_disk(); };

// the history on flash was replaced (a restore from a backup): what is in memory is dropped, the next step loads
// the month from flash again (the step's counters stay: growth goes on from where it was)
export function reset() {
	month = null; data = null; saved_at = 0;
	for (let f in fs.glob(RAMDIR + '/[0-9]*.json') ?? []) fs.unlink(f);
};

function days_back(n) {
	const out = [];
	const now = time();
	for (let i = n - 1; i >= 0; i--) push(out, ymd(now - i * 86400));
	return out;
}

// period: day | days3 | week | month | year
export function report(period) {
	const files = {};
	const get = (m) => (m == month && data) ? data : (files[m] ??= load_month(m));
	const bars = [], devices = {}, exits = {};
	const total = [ 0, 0 ], vpn = [ 0, 0 ];
	const take = (d, bar) => {
		if (!d) return;
		for (let mac, v in d.d ?? {}) { add(devices, mac, v[0], v[1]); bar.rx += v[0]; bar.tx += v[1]; }
		for (let n, v in d.x ?? {}) add(exits, n, v[0], v[1]);
		bar.vrx += d.v?.[0] ?? 0; bar.vtx += d.v?.[1] ?? 0;
	};
	if (period == 'year') {
		const l = localtime(time());
		for (let i = 11; i >= 0; i--) {
			let y = l.year, mo = l.mon - i;
			while (mo < 1) { mo += 12; y--; }
			const m = sprintf('%d-%s', y, pad(mo));
			const bar = { label: m, rx: 0, tx: 0, vrx: 0, vtx: 0 };
			for (let dd, d in get(m)) take(d, bar);
			push(bars, bar);
		}
	}
	else {
		for (let x in days_back({ day: 1, days3: 3, week: 7 }[period] ?? 30)) {
			const bar = { label: x[0] + '-' + x[1], rx: 0, tx: 0, vrx: 0, vtx: 0 };
			take(get(x[0])[x[1]], bar);
			push(bars, bar);
		}
	}
	for (let b in bars) { total[0] += b.rx; total[1] += b.tx; vpn[0] += b.vrx; vpn[1] += b.vtx; }
	// the earliest day there is data for: "since" when the period reaches further back
	let since = null;
	for (let f in sort(fs.glob(DISK + '/*.json') ?? [])) {
		const m = substr(f, length(DISK) + 1, 7);
		const ds = sort(keys(get(m)));
		if (length(ds)) { since = m + '-' + ds[0]; break; }
	}
	if (!since && month && data && length(keys(data))) since = month + '-' + sort(keys(data))[0];
	const min0 = (a, b) => a > b ? a - b : 0;
	return {
		period, since, source: src, bars,
		devices: map(sort(keys(devices), (a, b) => (devices[b][0] + devices[b][1]) - (devices[a][0] + devices[a][1])), (k) => ({ mac: k, rx: devices[k][0], tx: devices[k][1] })),
		exits: map(keys(exits), (k) => ({ name: k, rx: exits[k][0], tx: exits[k][1] })),
		total: { rx: total[0], tx: total[1] },
		vpn: { rx: vpn[0] < total[0] ? vpn[0] : total[0], tx: vpn[1] < total[1] ? vpn[1] : total[1] },
		direct: { rx: min0(total[0], vpn[0]), tx: min0(total[1], vpn[1]) },
	};
};
