'use strict';
'require view';
'require rpc';
'require ui';
'require poll';
'require dom';
'require uci';
'require detour.msg as msg';

// Text from the router (names of exits and servers come from subscriptions and links) never becomes HTML:
// LuCI's E() puts a string child in with innerHTML, here it always goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

const callStatus = rpc.declare({ object: 'detour', method: 'status' });
const callPin = rpc.declare({ object: 'detour', method: 'pin', params: [ 'policy', 'exit' ] });
const callUnpin = rpc.declare({ object: 'detour', method: 'unpin', params: [ 'policy' ] });
const callRates = rpc.declare({ object: 'detour', method: 'rates' });

const RATE_EVERY = 3;          // s between two readings of the counters
const RATE_POINTS = 100;       // 100 x 3 s = 5 min
const COLORS = [ '#1e88e5', '#8e24aa', '#f4511e', '#00897b', '#6d4c41', '#c0ca33' ];

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
		return Promise.all([ callStatus().catch(function() { return null; }), L.resolveDefault(uci.load('detour'), null) ]).then(function(r) { return r[0]; });
	},

	// names people gave to exits and policies (internal names otherwise)
	labels: function() {
		const out = {};
		[ 'exit', 'policy' ].forEach(function(t) { uci.sections('detour', t).forEach(function(s) { out[s['.name']] = s.label || s['.name']; }); });
		return out;
	},
	lab: function(n) { return (this.labels()[n]) || n; },

	pinHandler: function(policy, sel) {
		const v = sel.value;
		const p = v ? callPin(policy, v) : callUnpin(policy);
		return p.then(function(r) {
			if (r && r.error) ui.addNotification(null, E('p', _('Error') + ': ' + r.error), 'danger');
		});
	},

	// "VPN is on": main.enabled. Off = Detour takes everything down and all traffic goes directly - not blocked
	vpnSwitch: function(on) {
		const box = E('input', { 'type': 'checkbox', 'checked': on ? '' : null });
		box.addEventListener('change', function() {
			if (!box.checked) {
				let t = _('Switch the VPN off?\n\nAll traffic will go directly through your provider - also the sites, devices and lists of your policies. Nothing is blocked while it is off: the kill-switch is off too.');
				if (uci.get('detour', 'sshtun', 'enabled') == '1')
					t += '\n\n' + _('The panel through your VPS stops too: if you are connected through it now, you lose this page.');
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

	// the speed of the last 5 minutes: the provider's line and each exit, download (or upload)
	rateBox: function() {
		const self = this;
		this.hist = [];       // [ { t, wan: [rx, tx], exits: { name: [rx, tx] } } ] - per-second rates
		this.last = null;
		this.dir = 0;         // 0 download, 1 upload
		const sel = E('select', { 'class': 'cbi-input-select', 'change': function() { self.dir = +sel.value; self.drawRates(); } }, [
			E('option', { 'value': '0' }, _('download')), E('option', { 'value': '1' }, _('upload')) ]);
		this.graph = E('div', { 'class': 'detour-graph' }, E('em', {}, _('Measuring…')));
		this.legend = E('div', { 'class': 'detour-legend' });
		return E('div', { 'class': 'detour-node' }, [ E('div', { 'class': 'detour-actions' }, [ sel, E('span', { 'class': 'detour-muted' }, _('the last 5 minutes, every %d s').format(RATE_EVERY)) ]),
			E('div', { 'class': 'detour-result' }, [ this.graph, this.legend ]) ]);
	},

	pollRates: function() {
		const self = this;
		return callRates().then(function(r) {
			if (!r || !r.t) return;
			if (self.last && r.t > self.last.t) {
				const dt = (r.t - self.last.t) / 1000;
				const d = function(a, b) { return (a && b && a[0] >= b[0] && a[1] >= b[1]) ? [ (a[0] - b[0]) * 8 / dt, (a[1] - b[1]) * 8 / dt ] : null; };
				const p = { t: r.t, wan: r.wan && self.last.wan ? d([ r.wan.rx, r.wan.tx ], [ self.last.wan.rx, self.last.wan.tx ]) : null, exits: {} };
				for (const n in r.exits) { const v = d(r.exits[n], (self.last.exits || {})[n]); if (v) p.exits[n] = v; }
				self.hist.push(p);
				if (self.hist.length > RATE_POINTS) self.hist.shift();
				self.drawRates();
			}
			self.last = r;
		});
	},

	drawRates: function() {
		const self = this, h = this.hist, k = this.dir;
		if (h.length < 2) return;
		const names = [];
		h.forEach(function(p) { for (const n in p.exits) if (names.indexOf(n) < 0) names.push(n); });
		const series = [ { name: _('Provider line (everything)'), color: '#757575', get: function(p) { return p.wan ? p.wan[k] : null; } } ]
			.concat(names.map(function(n, i) { return { name: self.lab(n), color: COLORS[i % COLORS.length], get: function(p) { return p.exits[n] ? p.exits[n][k] : null; } }; }));
		let max = 1;
		h.forEach(function(p) { series.forEach(function(s) { const v = s.get(p); if (v > max) max = v; }); });
		const W = 600, H = 160, step = W / (RATE_POINTS - 1), x0 = W - (h.length - 1) * step;
		const svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" class="detour-graph-svg">' +
			[ 0.25, 0.5, 0.75 ].map(function(f) { return '<line x1="0" x2="' + W + '" y1="' + (H * f) + '" y2="' + (H * f) + '" class="detour-grid"/>'; }).join('') +
			series.map(function(s) {
				const pts = [];
				h.forEach(function(p, i) { const v = s.get(p); if (v != null) pts.push((x0 + i * step).toFixed(1) + ',' + (H - v / max * (H - 4)).toFixed(1)); });
				return pts.length > 1 ? '<polyline fill="none" stroke="' + s.color + '" stroke-width="2" vector-effect="non-scaling-stroke" points="' + pts.join(' ') + '"/>' : '';
			}).join('') + '</svg>';
		this.graph.innerHTML = '<div class="detour-graph-max">' + mbit(max) + '</div>' + svg;
		const now = h[h.length - 1];
		dom.content(this.legend, series.map(function(s) {
			const v = s.get(now);
			return E('span', {}, [ E('span', { 'class': 'detour-dot', 'style': 'background:' + s.color }), s.name + ': ', E('strong', {}, v == null ? '—' : mbit(v)) ]);
		}));
	},

	renderPolicies: function(st) {
		const self = this;
		const rows = [ E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, _('Policy')),
			E('th', { 'class': 'th' }, _('Active exit')),
			E('th', { 'class': 'th' }, _('Exits in order')),
			E('th', { 'class': 'th' }, _('Manual choice'))
		]) ];
		(st.policies || []).forEach(function(p) {
			if (p.block || p.action == 'direct') {
				rows.push(E('tr', { 'class': 'tr' }, [
					td(_('Policy'), [ self.lab(p.name), p.enabled ? '' : ' (' + _('disabled') + ')' ]),
					td(_('Active exit'), E('strong', {}, p.block ? _('blocks') : _('directly'))),
					td(_('Exits in order'), p.block && st.blocked ? _('refused: %d').format(st.blocked) : '—'),
					td(_('Manual choice'), '')
				]));
				return;
			}
			const sel = E('select', { 'class': 'cbi-input-select' }, [ E('option', { 'value': '' }, _('Automatic')) ].concat(
				p.exits.map(function(x) { return E('option', { 'value': x, 'selected': p.pinned == x ? '' : null }, self.lab(x)); })));
			sel.addEventListener('change', ui.createHandlerFn(self, 'pinHandler', p.name, sel));
			rows.push(E('tr', { 'class': 'tr' }, [
				td(_('Policy'), [ self.lab(p.name), p.enabled ? '' : ' (' + _('disabled') + ')' ]),
				td(_('Active exit'), E('strong', {}, p.direct ? _('none - goes directly') : (p.active ? self.lab(p.active) : _('none - blocked')))),
				td(_('Exits in order'), p.exits.map(function(x) { return self.lab(x); }).join(' → ')),
				td(_('Manual choice'), sel)
			]));
		});
		return E('table', { 'class': 'table', 'id': 'detour-policies' }, rows);
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
				td(_('State'), !x.enabled ? _('disabled') : badge(x.healthy, _('working'), x.up ? _('not responding') : _('down'))),
				td(_('Last good probe'), x.probe ? fmtTime(x.last_ok) : _('device state only')),
				td(_('Blocked leaks'), String(x.drops || 0))
			]));
		});
		return E('table', { 'class': 'table', 'id': 'detour-exits' }, rows);
	},

	renderInfo: function(st) {
		const dnsText = { 'off': _('not managed'), 'tunnel': _('through the tunnel'), 'fallback': _('encrypted fallback (all exits down)'), 'encrypted': _('encrypted (DoH/DoT/DoQ)') }[st.dns] || st.dns;
		const items = [
			E('div', {}, [ E('strong', {}, _('Router DNS') + ': '), dnsText ]),
			E('div', {}, [ E('strong', {}, _('Switches') + ': '), String(st.switches), st.last_switch ? ' (' + fmtTime(st.last_switch) + ')' : '' ])
		];
		if (st.auth && st.auth.twofa)
			items.push(E('div', {}, [ E('strong', {}, _('Two-factor login') + ': '),
				st.auth.http_login_open ? badge(false, '', _('password-only login over /ubus is open')) : badge(true, _('protected'), '') ]));
		if (st.auth && st.auth.ssh_lan_password_only)
			items.push(E('div', {}, [ E('strong', {}, _('SSH') + ': '),
				_('password login only from the local network; elsewhere keys only'),
				st.auth.root_keys ? '' : E('span', { 'class': 'detour-warn' }, ' — ' + _('no SSH key for root: SSH from outside is impossible until you add one (System → Administration → SSH-Keys)')) ]));
		const labels = this.labels();
		(st.errors || []).forEach(function(e) {
			items.push(E('div', { 'class': 'alert-message warning' }, _('Configuration') + ': ' + msg.configError(e, labels)));
		});
		return E('div', { 'id': 'detour-info', 'class': 'detour-info' }, items);
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
			E('div', { 'class': 'cbi-section' }, [ E('div', { 'class': 'detour-node' }, [ E('div', { 'class': 'detour-result detour-lines' }, [ this.vpnSwitch(on), this.renderIp(st) ]) ]) ]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('Speed')), this.rateBox() ]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('Policies')), this.renderPolicies(st) ]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('Exits')), this.renderExits(st) ]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('State')), this.renderInfo(st) ]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, _('Events')), this.renderEvents(st) ])
		]);
		poll.add(function() {
			return callStatus().then(function(s) {
				if (!s) return;
				// keep an open <select> untouched while the user is choosing
				if (!document.activeElement || document.activeElement.tagName != 'SELECT')
					dom.content(document.getElementById('detour-policies').parentNode, [ E('h3', {}, _('Policies')), self.renderPolicies(s) ]);
				dom.content(document.getElementById('detour-exits').parentNode, [ E('h3', {}, _('Exits')), self.renderExits(s) ]);
				dom.content(document.getElementById('detour-info').parentNode, [ E('h3', {}, _('State')), self.renderInfo(s) ]);
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
