'use strict';
'require view';
'require rpc';
'require poll';
'require dom';
'require uci';
'require detour.chart as chart';
'require detour.pkg as pkg';

// Text from the router (names of exits and servers come from subscriptions and links) never becomes HTML:
// LuCI's E() puts a string child in with innerHTML, here it always goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

// "Traffic": how much each device and each exit moved today, this week, month, year.
// Devices: nlbwmon (counts accelerated flows too). Exits: their tunnels' counters. Directly = devices minus VPN.

const callTraffic = rpc.declare({ object: 'detour', method: 'traffic', params: [ 'period' ] });
const callHints = rpc.declare({ object: 'luci-rpc', method: 'getHostHints', expect: { '': {} } });

const PERIODS = [ [ 'day', _('Today') ], [ 'days3', _('3 days') ], [ 'week', _('7 days') ], [ 'month', _('30 days') ], [ 'year', _('12 months') ] ];

function css() { return E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') }); }
function td(title, content) { return E('td', { 'class': 'td', 'data-title': title }, content); }
function size(b) { return '%1024.2mB'.format(b || 0); }
function pct(a, b) { return b > 0 ? Math.round(a * 100 / b) + '%' : '—'; }

function barLabel(l, period) {
	const p = l.split('-').map(Number);
	if (period == 'year') return new Date(p[0], p[1] - 1, 1).toLocaleDateString(undefined, { month: 'short' });
	return String(p[2]);
}
function longLabel(l, period) {
	const p = l.split('-').map(Number);
	if (period == 'year') return new Date(p[0], p[1] - 1, 1).toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
	return new Date(p[0], p[1] - 1, p[2]).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'long' });
}

return view.extend({
	period: 'day',

	load: function() {
		return Promise.all([ callTraffic(this.period).catch(function() { return null; }), callHints().catch(function() { return {}; }), uci.load('detour') ]);
	},

	devName: function(mac) {
		const h = this.hints[mac.toUpperCase()] || this.hints[mac] || {};
		return h.name || null;
	},
	devIp: function(mac) {
		const h = this.hints[mac.toUpperCase()] || this.hints[mac] || {};
		return (h.ipaddrs || [])[0] || (h.ip6addrs || [])[0] || '';
	},
	exitName: function(n) { return uci.get('detour', n, 'label') || n; },

	notes: function(r) {
		const out = [];
		const s = r.source || {};
		if (!s.nlbwmon) out.push(pkg.offer('nlbwmon', _('nlbwmon is not installed: devices are not counted.')));
		else if (!s.running) out.push(E('div', { 'class': 'alert-message warning' }, _('nlbwmon is not running: devices are not counted now (System → Startup: nlbwmon).')));
		if (s.hw_offload) out.push(E('div', { 'class': 'alert-message notice' }, _('Hardware flow offloading works on this router: some traffic may bypass the counting, the numbers by device can be too low.')));
		if (r.since) {
			const first = r.bars.length ? r.bars[0].label : null;
			if (first && (this.period == 'year' ? r.since.substr(0, 7) > first : r.since > first))
				out.push(E('div', { 'class': 'detour-muted' }, _('Counted since %s.').format(new Date(r.since.replace(/-/g, '/')).toLocaleDateString())));
		}
		else out.push(E('div', { 'class': 'detour-muted' }, _('Nothing counted yet: the first numbers appear within 5 minutes.')));
		return out;
	},

	// the card: downloads by day (by month for a year) - all of it and through VPN, the totals of the period below
	card: function() {
		const self = this;
		this.cNow = E('div', { 'class': 'detour-chart-now' });
		this.cSub = E('div', { 'class': 'detour-chart-sub' });
		this.cFoot = E('div', { 'class': 'detour-chart-foot' });
		this.chart = chart.create(function() { if (self.data) self.drawChart(self.data); });
		this.cardEl = E('div', { 'class': 'detour-chart-card' }, [
			E('div', { 'class': 'detour-chart-head' }, [ E('div', {}, [ E('div', { 'class': 'detour-chart-title' }, _('Downloaded')), this.cSub ]), this.cNow ]),
			this.chart.el, this.cFoot ]);
		return this.cardEl;
	},

	drawChart: function(r) {
		const period = this.period, bars = r.bars, t = r.total, v = r.vpn, d = r.direct;
		const stat = function(label, value, note) {
			return E('div', { 'class': 'detour-chart-stat' }, [ E('div', { 'class': 'detour-chart-label' }, label), E('div', { 'class': 'detour-chart-value' }, value),
				note ? E('div', { 'class': 'detour-chart-note' }, note) : '' ]);
		};
		dom.content(this.cFoot, [
			stat(_('Downloaded'), size(t.rx)),
			stat(_('Uploaded'), size(t.tx)),
			stat(_('Through VPN'), size(v.rx), pct(v.rx, t.rx)),
			stat(_('Directly'), size(d.rx), pct(d.rx, t.rx)) ]);
		this.cSub.textContent = (PERIODS.find(function(p) { return p[0] == period; }) || [ '', '' ])[1] + (bars.length > 1 ? ' · ' + (period == 'year' ? _('by month') : _('by day')) : '');
		const all = bars.map(function(b) { return b.rx; }), vpn = bars.map(function(b) { return Math.min(b.vrx, b.rx); });
		const hv = this.chart.hover != null ? this.chart.hover : bars.length - 1;
		const pill = function(cls, label, value) { return E('span', {}, [ E('span', { 'class': 'detour-c-' + cls }, '● '), label + ' ', E('strong', {}, value) ]); };
		dom.content(this.cNow, bars.length && bars.length > 1 ? [ E('span', { 'class': 'detour-muted' }, longLabel(bars[hv].label, period)),
			pill('mute', _('All the traffic'), size(all[hv])), pill('acc', _('Through VPN'), size(vpn[hv])) ] : []);
		chart.draw(this.chart, {
			n: bars.length, fmt: size, minTop: 1048576, binary: true,
			empty: _('Today is a single point: the chart starts with the 3 days period.'),
			labels: bars.map(function(b) { return barLabel(b.label, period); }),
			series: [ { cls: 'mute', vals: all }, { cls: 'acc', vals: vpn } ],
			tip: function(i) {
				return [ E('div', { 'class': 'detour-muted' }, longLabel(bars[i].label, period)),
					E('div', {}, [ E('span', { 'class': 'detour-c-mute' }, '● '), _('All the traffic') + ': ' + size(all[i]) ]),
					E('div', {}, [ E('span', { 'class': 'detour-c-acc' }, '● '), _('Through VPN') + ': ' + size(vpn[i]) ]),
					E('div', {}, [ E('span', { 'class': 'detour-muted' }, '○ '), _('Directly') + ': ' + size(all[i] - vpn[i]) ]) ];
			}
		});
	},

	devices: function(r) {
		const self = this;
		if (!r.devices.length) return E('p', { 'class': 'detour-muted' }, _('No device traffic in this period.'));
		const top = r.devices[0].rx || 1;
		const rows = [ E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, _('Device')), E('th', { 'class': 'th' }, _('Downloaded')), E('th', { 'class': 'th' }, _('Uploaded')), E('th', { 'class': 'th' }, _('Share of the traffic'))
		]) ];
		r.devices.forEach(function(d) {
			const name = self.devName(d.mac), ip = self.devIp(d.mac);
			rows.push(E('tr', { 'class': 'tr' }, [
				td(_('Device'), [ E('strong', {}, name || ip || d.mac), E('br'), E('span', { 'class': 'detour-muted' }, name ? [ ip, ip ? ' · ' : '', d.mac ].join('') : (ip ? d.mac : '')) ]),
				td(_('Downloaded'), size(d.rx)),
				td(_('Uploaded'), size(d.tx)),
				td(_('Share of the traffic'), E('div', { 'class': 'detour-share', 'title': pct(d.rx, r.total.rx) }, E('div', { 'style': 'width:' + (d.rx * 100 / top) + '%' })))
			]));
		});
		return E('table', { 'class': 'table' }, rows);
	},

	exits: function(r) {
		const self = this;
		const list = r.exits.filter(function(x) { return x.rx || x.tx; }).sort(function(a, b) { return b.rx - a.rx; });
		if (!list.length) return E('p', { 'class': 'detour-muted' }, _('Nothing went through the exits in this period.'));
		const rows = [ E('tr', { 'class': 'tr table-titles' }, [ E('th', { 'class': 'th' }, _('Exit')), E('th', { 'class': 'th' }, _('Downloaded')), E('th', { 'class': 'th' }, _('Uploaded')) ]) ];
		list.forEach(function(x) {
			const via = uci.get('detour', x.name + '_eng', 'via');
			rows.push(E('tr', { 'class': 'tr' }, [
				td(_('Exit'), [ self.exitName(x.name), via ? E('span', { 'class': 'detour-muted' }, ' ' + _('(rides through «%s»: counted there too)').format(self.exitName(via))) : '' ]),
				td(_('Downloaded'), size(x.rx)),
				td(_('Uploaded'), size(x.tx))
			]));
		});
		return [ E('table', { 'class': 'table' }, rows),
			E('p', { 'class': 'detour-muted' }, _('Through VPN and directly are counted from the tunnels: the router\'s own checks and downloads through a tunnel count as VPN, so the split is approximate.')) ];
	},

	body: function(r) {
		if (!r) return E('div', { 'class': 'alert-message warning' }, _('The Detour service is not running.'));
		const self = this;
		this.data = r;
		// drawn once the card is in the page (its width sets the picture's)
		window.requestAnimationFrame(function() { if (self.data === r) self.drawChart(r); });
		return E('div', {}, [
			E('div', { 'class': 'cbi-section' }, [ this.cardEl || this.card(), E('div', { 'class': 'detour-node' }, E('div', { 'class': 'detour-result' }, this.notes(r))) ]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('By device')), this.devices(r) ]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('By exit')) ].concat(this.exits(r)))
		]);
	},

	show: function(period) {
		const self = this;
		if (period != this.period && this.chart) this.chart.hover = null;
		this.period = period;
		document.querySelectorAll('.detour-period .btn').forEach(function(b) { b.classList.toggle('cbi-button-action', b.getAttribute('data-period') == period); });
		return callTraffic(period).then(function(r) { dom.content(document.getElementById('detour-traffic'), self.body(r)); });
	},

	render: function(data) {
		const self = this;
		this.hints = data[1] || {};
		const tabs = E('div', { 'class': 'detour-period' }, PERIODS.map(function(p) {
			return E('button', { 'class': 'btn' + (p[0] == self.period ? ' cbi-button-action' : ''), 'data-period': p[0], 'click': function() { return self.show(p[0]); } }, p[1]);
		}));
		poll.add(function() { return self.show(self.period); }, 60);
		return E('div', {}, [
			css(),
			E('h2', {}, _('Traffic')),
			E('div', { 'class': 'cbi-map-descr' }, _('How much each device downloaded and uploaded, and how much of it went through the VPN. Counted every 5 minutes; kept for a year.')),
			tabs,
			E('div', { 'id': 'detour-traffic' }, this.body(data[0]))
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
