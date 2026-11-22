'use strict';
'require view';
'require detour.load as pdata';
'require rpc';
'require ui';
'require poll';
'require dom';
'require uci';
'require detour.msg as msg';
'require detour.chart as chart';
'require detour.trafficui as trafficui';

// Text from the router (names of exits and servers come from subscriptions and links) never becomes HTML:
// LuCI's E() puts a string child in with innerHTML, here it always goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

const callStatus = rpc.declare({ object: 'detour', method: 'status' });
const callRates = rpc.declare({ object: 'detour', method: 'rates' });

const RATE_EVERY = 3;          // s between two readings of the counters
const RATE_POINTS = 100;       // 100 x 3 s = 5 min

// bytes in LuCI's own units (as on the Traffic page)
function bytes(b) { return '%1024.2mB'.format(b || 0); }

// a total under a chart, and a value in its head
function chartStat(label, value) { return E('div', { 'class': 'detour-chart-stat' }, [ E('div', { 'class': 'detour-chart-label' }, label), E('div', { 'class': 'detour-chart-value' }, value) ]); }
function chartPill(cls, arrow, label, value) {
	return E('span', {}, [ E('span', { 'class': 'detour-c-' + cls }, arrow + ' '), label + ' ', E('strong', {}, value) ]);
}

// a country code -> its flag (regional indicator letters); nothing for anything else
function flag(cc) {
	if (!/^[A-Z]{2}$/.test(cc || '') || cc == 'XX' || cc == 'T1') return '';
	return String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65) + ' ';
}
function mbit(bps) { return bps >= 1e6 ? (bps / 1e6).toFixed(bps >= 1e8 ? 0 : 1) + ' ' + _('Mbit/s') : Math.round(bps / 1e3) + ' ' + _('kbit/s'); }

function badge(ok, yes, no) {
	return E('span', { 'class': 'detour-badge ' + (ok ? 'ok' : 'bad') }, ok ? yes : no);
}

// a table cell with its column title: narrow layouts (Argon < 1153 px) hide the title row and show this
function td(title, content) {
	return E('td', { 'class': 'td', 'data-title': title }, content);
}

function css() {
	return E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') });
}

function fmtTime(ts) {
	if (!ts) return '-';
	return new Date(ts * 1000).toLocaleString();
}

return view.extend({
	load: function() {
		return pdata.all({ status: callStatus().catch(function() { return null; }), cfg: L.resolveDefault(uci.load('detour'), null) }).then(function(r) { return r.status; });
	},

	// names people gave to exits and policies (internal names otherwise)
	labels: function() {
		const out = {};
		[ 'exit', 'policy' ].forEach(function(t) { uci.sections('detour', t).forEach(function(s) { out[s['.name']] = s.label || s['.name']; }); });
		return out;
	},
	lab: function(n) { return (this.labels()[n]) || n; },

	// "VPN is on": main.enabled. Off = Detour takes everything down and all traffic goes directly - not blocked
	vpnSwitch: function(on) {
		const box = E('input', { 'type': 'checkbox', 'checked': on ? '' : null });
		box.addEventListener('change', function() {
			if (!box.checked) {
				const t = _('Switch the VPN off?\n\nAll traffic will go directly through your provider - also the sites, devices and lists of your policies. Nothing is blocked while it is off: the kill-switch is off too.');
				if (!confirm(t)) { box.checked = true; return; }
			}
			uci.set('detour', 'main', 'enabled', box.checked ? '1' : '0');
			return uci.save().then(function() { return ui.changes.apply(); });
		});
		return E('div', { 'class': 'detour-vpn-switch' }, [
			E('label', { 'class': 'detour-switch' }, [ box, E('span', { 'class': 'detour-switch-slider' }), E('strong', {}, on ? _('VPN is on') : _('VPN is off')) ]),
			E('div', { 'class': 'detour-muted' }, on ? _('Traffic goes by your policies: through the exits, blocked when they are down.') : _('Everything goes directly through your provider: no policy, no exit, no blocking.'))
		]);
	},

	// the outside address: directly and through the exit each policy uses now
	renderIp: function(st) {
		const self = this;
		const x = st.extip || {};
		const one = function(r) {
			if (!r) return E('em', {}, _('checking…'));
			if (r.error || !r.ip) return E('span', { 'class': 'detour-muted' }, _('no answer'));
			return E('span', { 'title': r.colo ? _('Cloudflare point: %s').format(r.colo) : null }, [ flag(r.loc), E('strong', {}, r.ip), r.loc ? ' (' + r.loc + ')' : '' ]);
		};
		const rows = [ E('div', {}, [ _('Directly:') + ' ', one(x.direct) ]) ];
		const seen = {};
		(st.policies || []).forEach(function(p) {
			if (!p.enabled || p.block || !p.active || seen[p.active]) return;
			seen[p.active] = true;
			rows.push(E('div', {}, [ _('Through «%s»:').format(self.lab(p.active)) + ' ', one((x.exits || {})[p.active]) ]));
		});
		return E('div', { 'id': 'detour-ip', 'class': 'detour-ip' }, rows);
	},

	// the speed of the last 5 minutes of one source (all the traffic, or an exit): download and upload as two
	// smooth curves (detour.chart), the speed now in the head, the totals of its counters and the window average below
	rateBox: function() {
		const self = this;
		this.hist = [];       // [ { t (router uptime, ms), at (browser clock), wan: [rx, tx], exits: { name: [rx, tx] } } ] - bits per second
		this.last = null;     // the last answer: the counters (bytes) for the totals
		this.src = '';        // '' all the traffic (the provider's line), else an exit's name
		this.srcSel = E('select', { 'class': 'cbi-input-select', 'change': function() { self.src = self.srcSel.value; self.drawRates(); } },
			[ E('option', { 'value': '' }, _('All the traffic')) ]);
		this.rateNow = E('div', { 'class': 'detour-chart-now' });
		this.rateSub = E('div', { 'class': 'detour-chart-sub' }, _('the last 5 minutes, every %d s').format(RATE_EVERY));
		this.rateFoot = E('div', { 'class': 'detour-chart-foot' });
		this.chart = chart.create(function() { self.drawRates(); });
		return E('div', { 'class': 'detour-chart-card' }, [
			E('div', { 'class': 'detour-chart-head' }, [
				E('div', {}, [ E('div', { 'class': 'detour-chart-title' }, _('Speed')), this.rateSub ]),
				this.rateNow ]),
			E('div', { 'class': 'detour-chart-bar' }, this.srcSel),
			this.chart.el, this.rateFoot ]);
	},

	pollRates: function() {
		const self = this;
		return callRates().then(function(r) {
			if (!r || !r.t) return;
			if (self.last && r.t > self.last.t) {
				const dt = (r.t - self.last.t) / 1000;
				const d = function(a, b) { return (a && b && a[0] >= b[0] && a[1] >= b[1]) ? [ (a[0] - b[0]) * 8 / dt, (a[1] - b[1]) * 8 / dt ] : null; };
				const p = { t: r.t, at: Date.now(), wan: r.wan && self.last.wan ? d([ r.wan.rx, r.wan.tx ], [ self.last.wan.rx, self.last.wan.tx ]) : null, exits: {} };
				for (const n in r.exits) { const v = d(r.exits[n], (self.last.exits || {})[n]); if (v) p.exits[n] = v; }
				self.hist.push(p);
				if (self.hist.length > RATE_POINTS) { self.hist.shift(); if (self.chart.hover != null) self.chart.hover = Math.max(0, self.chart.hover - 1); }
			}
			self.last = r;
			self.drawRates();
		});
	},

	// the exits seen in the counters, in the select (kept as they come and go)
	rateSources: function() {
		const sel = this.srcSel, have = {};
		Array.prototype.forEach.call(sel.options, function(o) { have[o.value] = o; });
		const names = Object.keys((this.last && this.last.exits) || {}).sort();
		names.forEach(function(n) { if (!have[n]) sel.appendChild(E('option', { 'value': n }, _('Exit «%s»').format(this.lab(n)))); }, this);
		Array.prototype.slice.call(sel.options).forEach(function(o) { if (o.value && names.indexOf(o.value) < 0) o.remove(); });
		this.src = sel.value;
	},

	drawRates: function() {
		// hidden (the statistics are shown): the readings go on, the picture waits
		if (!this.chart.el.offsetParent) return;
		const self = this, h = this.hist, src = this.src;
		this.rateSources();
		const vals = h.map(function(p) { return src ? (p.exits[src] || null) : p.wan; });
		// the totals: the counters of the source, since its interface came up
		const cnt = this.last ? (src ? (this.last.exits || {})[src] : (this.last.wan ? [ this.last.wan.rx, this.last.wan.tx ] : null)) : null;
		const seen = vals.filter(function(v) { return v; });
		const avg = function(k) { return seen.reduce(function(a, v) { return a + v[k]; }, 0) / seen.length; };
		dom.content(this.rateFoot, [
			chartStat(_('Received'), cnt ? bytes(cnt[0]) : '—'),
			chartStat(_('Sent'), cnt ? bytes(cnt[1]) : '—'),
			chartStat(_('Average for the window'), seen.length ? '↓ ' + mbit(avg(0)) + '  ↑ ' + mbit(avg(1)) : '—') ]);
		const hv = this.chart.hover;
		const show = hv != null ? vals[hv] : vals[vals.length - 1];
		dom.content(this.rateNow, [ chartPill('mute', '↓', _('Downloading'), show ? mbit(show[0]) : '—'), chartPill('acc', '↑', _('Uploading'), show ? mbit(show[1]) : '—') ]);
		let max = 0;
		seen.forEach(function(v) { max = Math.max(max, v[0], v[1]); });
		if (h.length > 1) this.rateSub.textContent = _('the last 5 minutes, every %d s').format(RATE_EVERY) + ' · ' + _('peak %s').format(mbit(max));
		chart.draw(this.chart, {
			n: h.length, slots: RATE_POINTS, minTop: 1e5, fmt: mbit,
			series: [ { cls: 'mute', vals: vals.map(function(v) { return v ? v[0] : null; }) }, { cls: 'acc', vals: vals.map(function(v) { return v ? v[1] : null; }) } ],
			tip: function(i) {
				const v = vals[i];
				return [ E('div', { 'class': 'detour-muted' }, new Date(h[i].at).toLocaleTimeString()),
					E('div', {}, [ E('span', { 'class': 'detour-c-mute' }, '↓ '), v ? mbit(v[0]) : '—' ]),
					E('div', {}, [ E('span', { 'class': 'detour-c-acc' }, '↑ '), v ? mbit(v[1]) : '—' ]) ];
			}
		});
	},

	renderExits: function(st) {
		const self = this;
		const rows = [ E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, _('Exit')),
			E('th', { 'class': 'th' }, _('Device')),
			E('th', { 'class': 'th' }, _('State')),
			E('th', { 'class': 'th' }, _('Last good probe')),
			E('th', { 'class': 'th' }, _('Blocked leaks'))
		]) ];
		(st.exits || []).forEach(function(x) {
			rows.push(E('tr', { 'class': 'tr' }, [
				td(_('Exit'), self.lab(x.name)),
				td(_('Device'), x.colo ? [ x.device, ' ', E('small', { 'title': _('Cloudflare point the WARP tunnel lands on') }, '(' + x.colo + ')') ] : x.device),
				td(_('State'), !x.enabled ? _('switched off') : badge(x.healthy, _('working'), x.up ? _('not responding') : _('down'))),
				td(_('Last good probe'), x.probe ? fmtTime(x.last_ok) : _('device state only')),
				td(_('Blocked leaks'), String(x.drops || 0))
			]));
		});
		return E('table', { 'class': 'table', 'id': 'detour-exits' }, rows);
	},

	// what needs attention, under the switch: configuration errors and an open way to log in
	renderAlerts: function(st) {
		const items = [];
		if (st.auth && st.auth.twofa && st.auth.http_login_open)
			items.push(E('div', { 'class': 'alert-message warning' }, _('Two-factor login') + ': ' + _('password-only login over /ubus is open')));
		if (st.auth && st.auth.ssh_lan_password_only && !st.auth.root_keys)
			items.push(E('div', { 'class': 'alert-message warning' }, _('SSH') + ': ' + _('no SSH key for root: SSH from outside is impossible until you add one (System → Administration → SSH-Keys)')));
		const labels = this.labels();
		(st.errors || []).forEach(function(e) {
			items.push(E('div', { 'class': 'alert-message warning' }, _('Configuration') + ': ' + msg.configError(e, labels)));
		});
		return E('div', { 'id': 'detour-alerts', 'class': 'detour-lines' }, items);
	},

	// the chart in two modes: the speed now (the last 5 minutes) or the traffic statistics of a period
	chartBox: function() {
		const self = this;
		this.mode = 'speed';
		this.period = 'day';
		this.stats = trafficui.statsChart();
		const rate = this.rateBox();
		const statsPart = E('div', { 'style': 'display:none' }, [ trafficui.periodTabs(this.period, function(p) { return self.loadTraffic(p); }), this.stats.el, this.stats.notes ]);
		const modes = E('div', { 'class': 'detour-period' });
		const show = function(m) {
			self.mode = m;
			modes.querySelectorAll('.btn').forEach(function(b) { b.classList.toggle('cbi-button-action', b.getAttribute('data-mode') == m); });
			rate.style.display = m == 'speed' ? '' : 'none';
			statsPart.style.display = m == 'stats' ? '' : 'none';
			// "By exit" belongs to the statistics: shown with them only
			if (self.exitsCard) self.exitsCard.style.display = m == 'stats' ? '' : 'none';
			if (m == 'speed') self.drawRates(); else self.stats.draw();
		};
		[ [ 'speed', _('Speed') ], [ 'stats', _('Statistics') ] ].forEach(function(x) {
			modes.appendChild(E('button', { 'class': 'btn' + (x[0] == 'speed' ? ' cbi-button-action' : ''), 'data-mode': x[0], 'click': function() { show(x[0]); } }, x[1]));
		});
		this.exitsTraffic = E('div', {}, E('em', {}, _('Loading…')));
		this.exitsSub = E('div', { 'class': 'cbi-section-descr' });
		return [ modes, rate, statsPart ];
	},

	// the statistics of a period: the chart and "By exit"
	loadTraffic: function(period) {
		const self = this;
		if (period) this.period = period;
		const p = this.period;
		return trafficui.fetch(p).then(function(r) {
			if (p != self.period) return;   // a period no longer chosen (a poll that started before a click)
			self.stats.set(r, self.period);
			self.exitsSub.textContent = trafficui.periodLabel(self.period);
			dom.content(self.exitsTraffic, trafficui.exits(r));
		});
	},

	renderEvents: function(st) {
		const evl = this.labels();
		const ev = (st.events || []).slice().reverse().map(function(l) {
			const i = l.indexOf(' ');
			return fmtTime(+l.substr(0, i)) + '  ' + msg.event(l.substr(i + 1), evl);
		});
		return E('pre', { 'id': 'detour-events', 'class': 'detour-log' }, ev.length ? ev.join('\n') : _('No events yet.'));
	},

	render: function(st) {
		const self = this;
		const on = uci.get('detour', 'main', 'enabled') != '0';
		// switched off: only the switch (the daemon may still be idling until procd stops it)
		if (!st || !on)
			return E('div', {}, [ css(), E('h2', {}, _('Detour')),
				E('div', { 'class': 'cbi-section' }, [ E('div', { 'class': 'detour-node' }, [ E('div', { 'class': 'detour-result' }, this.vpnSwitch(on)) ]) ]),
				on ? E('div', { 'class': 'alert-message warning' }, _('The Detour service is not running.')) : '' ]);
		const body = E('div', {}, [
			css(),
			E('h2', {}, _('Detour')),
			E('div', { 'class': 'cbi-section' }, [ E('div', { 'class': 'detour-node' }, [ E('div', { 'class': 'detour-result detour-lines' }, [ this.vpnSwitch(on), this.renderIp(st), this.renderAlerts(st) ]) ]) ]),
			E('div', { 'class': 'cbi-section' }, this.chartBox()),
			this.exitsCard = E('div', { 'class': 'cbi-section', 'style': 'display:none' }, [ E('h3', {}, _('By exit')), this.exitsSub, this.exitsTraffic ]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('Exits')), this.renderExits(st) ]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('Events')), this.renderEvents(st) ])
		]);
		this.loadTraffic();
		poll.add(function() { return self.loadTraffic(); }, 60);
		poll.add(function() {
			return callStatus().then(function(s) {
				if (!s) return;
				dom.content(document.getElementById('detour-exits').parentNode, [ E('h3', {}, _('Exits')), self.renderExits(s) ]);
				const al = document.getElementById('detour-alerts');
				if (al) al.replaceWith(self.renderAlerts(s));
				document.getElementById('detour-events').textContent = self.renderEvents(s).textContent;
				const ip = document.getElementById('detour-ip');
				if (ip) ip.replaceWith(self.renderIp(s));
			});
		}, 5);
		this.pollRates();
		poll.add(function() { return self.pollRates(); }, RATE_EVERY);
		return body;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
