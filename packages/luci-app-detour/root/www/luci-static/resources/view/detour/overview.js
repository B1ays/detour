'use strict';
'require view';
'require rpc';
'require ui';
'require poll';
'require dom';

const callStatus = rpc.declare({ object: 'detour', method: 'status' });
const callPin = rpc.declare({ object: 'detour', method: 'pin', params: [ 'policy', 'exit' ] });
const callUnpin = rpc.declare({ object: 'detour', method: 'unpin', params: [ 'policy' ] });

function badge(ok, yes, no) {
	return E('span', { 'class': 'detour-badge ' + (ok ? 'ok' : 'bad') }, ok ? yes : no);
}

// a table cell with its column title: narrow layouts (Argon < 1153 px) hide the title row and show this
function td(title, content) {
	return E('td', { 'class': 'td', 'data-title': title }, content);
}

function css() {
	return E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') });
}

function fmtTime(ts) {
	if (!ts) return '-';
	return new Date(ts * 1000).toLocaleString();
}

return view.extend({
	load: function() {
		return callStatus().catch(function() { return null; });
	},

	pinHandler: function(policy, sel) {
		const v = sel.value;
		const p = v ? callPin(policy, v) : callUnpin(policy);
		return p.then(function(r) {
			if (r && r.error) ui.addNotification(null, E('p', _('Error') + ': ' + r.error), 'danger');
		});
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
			const sel = E('select', { 'class': 'cbi-input-select' }, [ E('option', { 'value': '' }, _('Automatic')) ].concat(
				p.exits.map(function(x) { return E('option', { 'value': x, 'selected': p.pinned == x ? '' : null }, x); })));
			sel.addEventListener('change', ui.createHandlerFn(self, 'pinHandler', p.name, sel));
			rows.push(E('tr', { 'class': 'tr' }, [
				td(_('Policy'), [ p.name, p.enabled ? '' : ' (' + _('disabled') + ')' ]),
				td(_('Active exit'), E('strong', {}, p.active)),
				td(_('Exits in order'), p.exits.join(' → ')),
				td(_('Manual choice'), sel)
			]));
		});
		return E('table', { 'class': 'table', 'id': 'detour-policies' }, rows);
	},

	renderExits: function(st) {
		const rows = [ E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, _('Exit')),
			E('th', { 'class': 'th' }, _('Device')),
			E('th', { 'class': 'th' }, _('State')),
			E('th', { 'class': 'th' }, _('Last good probe')),
			E('th', { 'class': 'th' }, _('Blocked leaks'))
		]) ];
		(st.exits || []).forEach(function(x) {
			rows.push(E('tr', { 'class': 'tr' }, [
				td(_('Exit'), x.name),
				td(_('Device'), x.colo ? [ x.device, ' ', E('small', { 'title': _('Cloudflare point the WARP tunnel lands on') }, '(' + x.colo + ')') ] : x.device),
				td(_('State'), !x.enabled ? _('disabled') : badge(x.healthy, _('working'), x.up ? _('not responding') : _('down'))),
				td(_('Last good probe'), x.probe ? fmtTime(x.last_ok) : _('device state only')),
				td(_('Blocked leaks'), String(x.drops || 0))
			]));
		});
		return E('table', { 'class': 'table', 'id': 'detour-exits' }, rows);
	},

	renderInfo: function(st) {
		const dnsText = { 'off': _('not managed'), 'tunnel': _('through the tunnel'), 'fallback': _('encrypted fallback (all exits down)') }[st.dns] || st.dns;
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
		(st.errors || []).forEach(function(e) {
			items.push(E('div', { 'class': 'alert-message warning' }, _('Configuration') + ': ' + e));
		});
		return E('div', { 'id': 'detour-info', 'class': 'detour-info' }, items);
	},

	renderEvents: function(st) {
		const ev = (st.events || []).slice().reverse().map(function(l) {
			const i = l.indexOf(' ');
			return fmtTime(+l.substr(0, i)) + '  ' + l.substr(i + 1);
		});
		return E('pre', { 'id': 'detour-events', 'class': 'detour-log' }, ev.length ? ev.join('\n') : _('No events yet.'));
	},

	render: function(st) {
		if (!st)
			return E('div', { 'class': 'alert-message warning' }, _('The Detour service is not running.'));
		const self = this;
		const body = E('div', {}, [
			css(),
			E('h2', {}, _('Detour')),
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
				dom.content(document.getElementById('detour-events'), self.renderEvents(s).textContent);
			});
		}, 5);
		return body;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
