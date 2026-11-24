'use strict';
'require baseclass';
'require uci';
'require detour.msg as msg';

// What the Policies list and a policy's own page share: the checks of what a policy may hold (the same as the
// router's, core.uc is_v4 / is_v6 and the port range: what passes here is applied there), the devices of the
// home network by name, a policy's summary and what it is doing right now (from the daemon's status).

const RE_MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i;
// a domain with a dot; the zone may be punycode (.xn--p1ai is .рф)
const RE_DOM = /^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?\.([a-z]{2,}|xn--[a-z0-9-]*[a-z0-9])$/i;

function arr(v) { return Array.isArray(v) ? v : (v ? String(v).split(/\s+/) : []); }
function isV4(a) {
	const m = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})(\/(0|[1-9]\d?))?$/.exec(a);
	if (!m) return false;
	for (let i = 1; i <= 4; i++) if (+m[i] > 255) return false;
	return m[6] == null || +m[6] <= 32;
}
function isV6(a) {
	const m = /^([0-9a-f:]+)(\/(0|[1-9]\d{0,2}))?$/i.exec(a);
	if (!m || m[1].indexOf(':') < 0 || (m[3] != null && +m[3] > 128)) return false;
	const halves = m[1].split('::');
	if (halves.length > 2) return false;
	let n = 0;
	for (const h of halves) {
		if (h == '') continue;
		for (const g of h.split(':')) { if (!/^[0-9a-f]{1,4}$/i.test(g)) return false; n++; }
	}
	return halves.length == 2 ? n <= 7 : n == 8;
}
function isPort(x) {
	const m = /^(tcp\/|udp\/)?(\d{1,5})(-(\d{1,5}))?$/i.exec(x);
	if (!m) return false;
	const lo = +m[2], hi = m[4] != null ? +m[4] : lo;
	return lo >= 1 && hi <= 65535 && hi >= lo;
}
// сайт.рф -> xn--80aswg.xn--p1ai (dnsmasq and the lists take the ASCII form); plain ASCII is only lower-cased
function asciiDomain(x) {
	x = x.toLowerCase();
	if (!/[^\x00-\x7f]/.test(x)) return x;
	try { return new URL('http://' + x).hostname; } catch (e) { return x; }
}

return baseclass.extend({
	RE_MAC: RE_MAC, RE_DOM: RE_DOM, arr: arr, isV4: isV4, isV6: isV6, isPort: isPort, asciiDomain: asciiDomain,
	isAddr: function(a) { return isV4(a) || isV6(a); },
	isDomain: function(d) { return RE_DOM.test(d); },

	// the devices of the home network from DHCP leases and reserved addresses (getHostHints also knows the router's
	// tunnel and WAN neighbours), named from the lease, the reservation or the hints: MAC (upper case) -> { name, ipaddrs }
	homeDevices: function(hints, leases) {
		const lan = {};
		const put = function(mac, name, ip) {
			if (!mac || !RE_MAC.test(mac)) return;
			const k = mac.toUpperCase(), h = lan[k] || (lan[k] = { name: null, ipaddrs: [] });
			if (name && !h.name) h.name = name;
			if (ip && h.ipaddrs.indexOf(ip) < 0) h.ipaddrs.push(ip);
		};
		((leases || {}).dhcp_leases || []).forEach(function(l) { put(l.macaddr, l.hostname, l.ipaddr); });
		uci.sections('dhcp', 'host').forEach(function(h) { arr(h.mac).forEach(function(m) { put(m, h.name, h.ip); }); });
		Object.keys(lan).forEach(function(k) { const h = (hints || {})[k] || {}; if (!lan[k].name && h.name) lan[k].name = h.name; });
		return lan;
	},

	deviceName: function(mac, devs) {
		const h = devs[mac.toUpperCase()] || devs[mac.toLowerCase()] || {};
		const ip = (h.ipaddrs || h.ipv4 || [])[0];
		return (h.name ? h.name + ' ' : '') + '(' + (ip ? ip + ', ' : '') + mac.toLowerCase() + ')';
	},

	exitLabel: function(n) { return uci.get('detour', n, 'label') || n; },

	typeText: function(kind) { return { vpn: _('VPN'), direct: _('Directly'), block: _('Blocks') }[kind] || _('VPN'); },

	// the lists that belong to a policy (all of them, on or off)
	listsOf: function(name) { return uci.sections('detour', 'list').filter(function(l) { return l.policy == name; }); },

	// what a policy holds, in a line: through which exits, how many sites, addresses, devices, lists
	summary: function(p) {
		const self = this, kind = msg.policyKind(p), parts = [];
		if (kind == 'vpn') {
			const ex = arr(p.exit);
			parts.push(ex.length ? _('through %s').format(ex.map(function(e) { return self.exitLabel(e); }).join(' → ')) : _('no exit'));
		}
		const what = [];
		let c;
		if ((c = arr(p.domain).length)) what.push(N_(c, '%d site', '%d sites').format(c));
		if ((c = arr(p.dst).length)) what.push(N_(c, '%d address', '%d addresses').format(c));
		if ((c = arr(p.device).length)) what.push(N_(c, '%d device', '%d devices').format(c));
		if ((c = arr(p.network).length)) what.push(N_(c, '%d network', '%d networks').format(c));
		if ((c = arr(p.src).length)) what.push(N_(c, '%d device by address', '%d devices by address').format(c));
		if ((c = arr(p.port).length)) what.push(N_(c, '%d port', '%d ports').format(c));
		const lists = this.listsOf(p['.name']).length;
		if (lists) what.push(N_(lists, '%d list', '%d lists').format(lists));
		if (what.length) parts.push(what.join(', '));
		else if (kind != 'vpn') parts.push(_('nothing yet'));
		return parts.join(' · ');
	},

	// what the policy is doing now, from the daemon's status: { text, tone: 'ok' | 'warn' | 'bad' } or null
	// (switched off, or not applied yet: the daemon does not know it)
	live: function(p, st, listSt) {
		if (p.enabled == '0') return null;
		const self = this, name = p['.name'], kind = msg.policyKind(p), parts = [];
		let tone = '';
		const lv = ((st || {}).policies || []).filter(function(x) { return x.name == name; })[0];
		if (kind == 'vpn' && lv) {
			const exits = arr(p.exit), ex = {};
			((st || {}).exits || []).forEach(function(e) { ex[e.name] = e; });
			if (!exits.length) { parts.push(_('No exit: its traffic is blocked')); tone = 'bad'; }
			else if (!exits.some(function(n) { return ex[n] && ex[n].healthy; })) {
				parts.push(lv.direct ? _('No exit works: its traffic goes directly') : _('No exit works: its traffic is blocked'));
				tone = 'bad';
			}
			else if (lv.active) { parts.push(lv.pinned == lv.active ? _('Now through %s (pinned)').format(self.exitLabel(lv.active)) : _('Now through %s').format(self.exitLabel(lv.active))); tone = 'ok'; }
		}
		const failed = this.listsOf(name).filter(function(l) { const s = (listSt || {})[l['.name']]; return l.enabled != '0' && s && !s.ok; });
		if (failed.length) {
			parts.push(failed.length == 1 ? _('the list «%s» did not update').format(msg.listTitle(failed[0])) : N_(failed.length, '%d list did not update', '%d lists did not update').format(failed.length));
			if (tone != 'bad') tone = 'warn';
		}
		if (!parts.length) return null;
		const t = parts.join(' · ');
		return { text: t.charAt(0).toUpperCase() + t.slice(1), tone: tone };
	}
});
