'use strict';
'require baseclass';
'require rpc';
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

// Traffic statistics (detourd "traffic"): how much moved today, in 3 / 7 / 30 days, in 12 months - all of it,
// through VPN and directly, by exit and by device. Devices: nlbwmon (counts accelerated flows too). Exits: their
// tunnels' counters. Directly = devices minus VPN. The Overview shows the chart and the exits, the Devices page
// each device's downloaded and uploaded.

const callTraffic = rpc.declare({ object: 'detour', method: 'traffic', params: [ 'period' ] });

const PERIODS = [ [ 'day', _('Today') ], [ 'days3', _('3 days') ], [ 'week', _('7 days') ], [ 'month', _('30 days') ], [ 'year', _('12 months') ] ];

function td(title, content) { return E('td', { 'class': 'td', 'data-title': title }, content); }
function size(b) { return '%1024.2mB'.format(b || 0); }
function pct(a, b) { return b > 0 ? Math.round(a * 100 / b) + '%' : '—'; }
function exitName(n) { return uci.get('detour', n, 'label') || n; }

// a bar: { label: 'YYYY-MM' (a year by month) or 'YYYY-MM-DD', h: its first hour, span: its hours } (the hours of
// a day: the daemon keeps them since this version; a bar without h is a whole day)
function hh(h) { return (h < 10 ? '0' : '') + h + ':00'; }
function barLabel(b, period) {
	const p = b.label.split('-').map(Number);
	if (period == 'year') return new Date(p[0], p[1] - 1, 1).toLocaleDateString(undefined, { month: 'short' });
	if (b.h == null) return String(p[2]);
	// the first bar of a day names the day, the others their hour
	if (b.h == 0 && period != 'day') return new Date(p[0], p[1] - 1, p[2]).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
	return hh(b.h);
}
function longLabel(b, period) {
	const p = b.label.split('-').map(Number);
	if (period == 'year') return new Date(p[0], p[1] - 1, 1).toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
	const day = new Date(p[0], p[1] - 1, p[2]).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'long' });
	return b.h == null ? day : day + ', ' + hh(b.h) + '–' + hh((b.h + (b.span || 1)) % 24);
}
function byText(bars, period) {
	if (period == 'year') return _('by month');
	const b = bars[0] || {};
	if (b.h == null) return _('by day');
	return b.span == 4 ? _('by 4 hours') : b.span == 6 ? _('by 6 hours') : _('by hour');
}

return baseclass.extend({
	periods: PERIODS,
	fetch: function(period) { return callTraffic(period).catch(function() { return null; }); },
	size: size,
	periodLabel: function(period) { return (PERIODS.find(function(p) { return p[0] == period; }) || [ '', '' ])[1]; },

	// the period buttons (Today ... 12 months); onPick(period)
	periodTabs: function(current, onPick) {
		const box = E('div', { 'class': 'detour-period' });
		PERIODS.forEach(function(p) {
			box.appendChild(E('button', { 'class': 'btn' + (p[0] == current ? ' cbi-button-action' : ''), 'data-period': p[0], 'click': function() {
				box.querySelectorAll('.btn').forEach(function(b) { b.classList.toggle('cbi-button-action', b.getAttribute('data-period') == p[0]); });
				return onPick(p[0]);
			} }, p[1]));
		});
		return box;
	},

	// the notes about the counting: nlbwmon missing or stopped, offloading, since when
	notes: function(r, period) {
		const out = [];
		const s = r.source || {};
		if (!s.nlbwmon) out.push(pkg.offer('nlbwmon', _('nlbwmon is not installed: devices are not counted.')));
		else if (s.hung) out.push(E('div', { 'class': 'alert-message warning' }, (s.restarted
			? _('nlbwmon is running but does not answer: devices are not counted now. Detour restarted it at %s and restarts it again after 10 minutes of silence.').format(new Date(s.restarted * 1000).toLocaleTimeString())
			: _('nlbwmon is running but does not answer: devices are not counted now. Detour restarts it by itself after 10 minutes of silence.'))));
		else if (!s.running) out.push(E('div', { 'class': 'alert-message warning' }, _('nlbwmon is not running: devices are not counted now (System → Startup: nlbwmon).')));
		if (s.hw_offload) out.push(E('div', { 'class': 'alert-message notice' }, _('Hardware flow offloading works on this router: some traffic may bypass the counting, the numbers by device can be too low.')));
		if (r.since) {
			const first = r.bars.length ? r.bars[0].label : null;
			if (first && (period == 'year' ? r.since.substr(0, 7) > first : r.since > first))
				out.push(E('div', { 'class': 'detour-muted' }, _('Counted since %s.').format(new Date(r.since.replace(/-/g, '/')).toLocaleDateString())));
		}
		else out.push(E('div', { 'class': 'detour-muted' }, _('Nothing counted yet: the first numbers appear within 5 minutes.')));
		return out;
	},

	// the statistics chart: downloads by day (by month for a year) - all of it and through VPN, the totals below.
	// -> { el, notes, set(r, period), draw() }; drawn when it is in the page (its width sets the picture's)
	statsChart: function() {
		const self = this;
		const o = { data: null, period: 'day' };
		const cNow = E('div', { 'class': 'detour-chart-now' }), cSub = E('div', { 'class': 'detour-chart-sub' }), cFoot = E('div', { 'class': 'detour-chart-foot' });
		const ch = chart.create(function() { o.draw(); });
		o.notes = E('div', { 'class': 'detour-result' });
		o.el = E('div', { 'class': 'detour-chart-card' }, [
			E('div', { 'class': 'detour-chart-head' }, [ E('div', {}, [ E('div', { 'class': 'detour-chart-title' }, _('Downloaded')), cSub ]), cNow ]),
			ch.el, cFoot ]);
		o.set = function(r, period) {
			if (period != o.period) ch.hover = null;
			o.data = r; o.period = period;
			dom.content(o.notes, r ? self.notes(r, period) : E('div', { 'class': 'alert-message warning' }, _('The Detour service is not running.')));
			o.draw();
		};
		o.draw = function() {
			const r = o.data, period = o.period;
			if (!r || !o.el.offsetParent) return;
			const bars = r.bars, t = r.total, v = r.vpn, d = r.direct;
			const stat = function(label, value, note) {
				return E('div', { 'class': 'detour-chart-stat' }, [ E('div', { 'class': 'detour-chart-label' }, label), E('div', { 'class': 'detour-chart-value' }, value),
					note ? E('div', { 'class': 'detour-chart-note' }, note) : '' ]);
			};
			dom.content(cFoot, [ stat(_('Downloaded'), size(t.rx)), stat(_('Uploaded'), size(t.tx)), stat(_('Through VPN'), size(v.rx), pct(v.rx, t.rx)), stat(_('Directly'), size(d.rx), pct(d.rx, t.rx)) ]);
			cSub.textContent = self.periodLabel(period) + (bars.length > 1 ? ' · ' + byText(bars, period) : '');
			const all = bars.map(function(b) { return b.rx; }), vpn = bars.map(function(b) { return Math.min(b.vrx, b.rx); });
			const hv = ch.hover != null ? ch.hover : bars.length - 1;
			const pill = function(cls, label, value) { return E('span', {}, [ E('span', { 'class': 'detour-c-' + cls }, '● '), label + ' ', E('strong', {}, value) ]); };
			dom.content(cNow, bars.length > 1 ? [ E('span', { 'class': 'detour-muted' }, longLabel(bars[hv], period)),
				pill('mute', _('All the traffic'), size(all[hv])), pill('acc', _('Through VPN'), size(vpn[hv])) ] : []);
			chart.draw(ch, {
				n: bars.length, fmt: size, minTop: 1048576, binary: true,
				empty: _('The day has just begun: the chart starts with its second hour.'),
				labels: bars.map(function(b) { return barLabel(b, period); }),
				series: [ { cls: 'mute', vals: all }, { cls: 'acc', vals: vpn } ],
				tip: function(i) {
					return [ E('div', { 'class': 'detour-muted' }, longLabel(bars[i], period)),
						E('div', {}, [ E('span', { 'class': 'detour-c-mute' }, '● '), _('All the traffic') + ': ' + size(all[i]) ]),
						E('div', {}, [ E('span', { 'class': 'detour-c-acc' }, '● '), _('Through VPN') + ': ' + size(vpn[i]) ]),
						E('div', {}, [ E('span', { 'class': 'detour-muted' }, '○ '), _('Directly') + ': ' + size(all[i] - vpn[i]) ]) ];
				}
			});
		};
		return o;
	},

	// "By exit": what went through each exit in the period
	exits: function(r) {
		if (!r) return E('p', { 'class': 'detour-muted' }, _('The Detour service is not running.'));
		const list = r.exits.filter(function(x) { return x.rx || x.tx; }).sort(function(a, b) { return b.rx - a.rx; });
		if (!list.length) return E('p', { 'class': 'detour-muted' }, _('Nothing went through the exits in this period.'));
		const rows = [ E('tr', { 'class': 'tr table-titles' }, [ E('th', { 'class': 'th' }, _('Exit')), E('th', { 'class': 'th' }, _('Downloaded')), E('th', { 'class': 'th' }, _('Uploaded')) ]) ];
		list.forEach(function(x) {
			const via = uci.get('detour', x.name + '_eng', 'via');
			rows.push(E('tr', { 'class': 'tr' }, [
				td(_('Exit'), [ exitName(x.name), via ? E('span', { 'class': 'detour-muted' }, ' ' + _('(rides through «%s»: counted there too)').format(exitName(via))) : '' ]),
				td(_('Downloaded'), size(x.rx)),
				td(_('Uploaded'), size(x.tx))
			]));
		});
		return E('div', {}, [ E('table', { 'class': 'table' }, rows),
			E('p', { 'class': 'detour-muted' }, _('Through VPN and directly are counted from the tunnels: the router\'s own checks and downloads through a tunnel count as VPN, so the split is approximate.')) ]);
	}
});
