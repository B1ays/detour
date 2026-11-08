'use strict';
'require view';
'require rpc';
'require ui';
'require uci';
'require dom';

// Exits and subscriptions as cards: what each exit is (protocol, server, the exit it rides), its state,
// a real check, editing of what belongs to it, removal with everything it owns. The daemon describes the
// exits (exits_info, no secrets); edits of names and of WireGuard/AmneziaWG settings are plain UCI.

const callInfo = rpc.declare({ object: 'detour', method: 'exits_info' });
const callCheck = rpc.declare({ object: 'detour', method: 'exit_check', params: [ 'name' ] });
const callRemove = rpc.declare({ object: 'detour', method: 'exit_remove', params: [ 'name' ] });
const callPick = rpc.declare({ object: 'detour', method: 'exit_pick', params: [ 'name', 'key' ] });
const callCfgGet = rpc.declare({ object: 'detour', method: 'exit_config_get', params: [ 'name' ] });
const callCfgSet = rpc.declare({ object: 'detour', method: 'exit_config_set', params: [ 'name', 'config' ] });
const callSetLink = rpc.declare({ object: 'detour', method: 'exit_set_link', params: [ 'name', 'link' ] });
const callSubUpdate = rpc.declare({ object: 'detour', method: 'sub_update', params: [ 'name' ] });
const callStatus = rpc.declare({ object: 'detour', method: 'status' });
const callReload = rpc.declare({ object: 'detour', method: 'reload' });

// AmneziaWG masking parameters (amneziawg-tools 3.1 names, network UCI options awg_*), with what they do
const AWG = [
	[ 'jc', _('Junk packets (Jc)'), _('How many random packets go before the handshake. 0 = no masking by junk.') ],
	[ 'jmin', _('Junk size from (Jmin)'), _('Smallest junk packet, bytes.') ],
	[ 'jmax', _('Junk size to (Jmax)'), _('Largest junk packet, bytes.') ],
	[ 's1', _('Handshake padding (S1)'), _('Random bytes added to the handshake start. Must match the server.') ],
	[ 's2', _('Answer padding (S2)'), _('Random bytes added to the handshake answer. Must match the server.') ],
	[ 'h1', 'H1', _('Packet type numbers (H1–H4) replace the standard WireGuard ones. Must match the server; WARP uses 1, 2, 3, 4.') ],
	[ 'h2', 'H2', '' ], [ 'h3', 'H3', '' ], [ 'h4', 'H4', '' ],
	[ 'i1', _('Imitation packet (I1)'), _('A packet that looks like another protocol (for example QUIC) sent before the handshake. For WARP Detour makes it itself.') ]
];

function busy(btn, on) { btn.disabled = on; btn.classList.toggle('spinning', on); }
function note(text, cls) { return E('div', { 'class': 'alert-message ' + (cls || 'notice') }, text); }
function fmtTime(ts) { return ts ? new Date(ts * 1000).toLocaleString() : ''; }

function stateBadge(x) {
	if (!x.enabled) return E('span', { 'class': 'detour-badge off' }, _('off'));
	if (x.healthy) return E('span', { 'class': 'detour-badge ok' }, _('working'));
	return E('span', { 'class': 'detour-badge bad' }, x.up ? _('not responding') : _('down'));
}

function kindText(x) {
	return { 'wireguard': 'WireGuard', 'amneziawg': 'AmneziaWG', 'singbox': _('proxy (sing-box)'), 'xray': _('proxy (Xray)'),
		'subscription': _('subscription') }[x.kind] || x.kind || '';
}

// "VLESS · Reality · TCP · Vision", the masking word translated
function protoText(p) { return (p || '').replace(' · masking', ' · ' + _('masking')); }

function row(title, field, descr) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, title),
		E('div', { 'class': 'cbi-value-field' }, descr ? [ field, E('div', { 'class': 'cbi-value-description' }, descr) ] : field)
	]);
}

function modal(title, body, onSave, saveText) {
	const box = E('div', { 'class': 'detour-result' });
	const save = E('button', { 'class': 'btn cbi-button-positive', 'click': function() {
		busy(save, true);
		return Promise.resolve(onSave(box)).then(function(done) { if (done) ui.hideModal(); })
			.catch(function(e) { box.replaceChildren(note(e.message || String(e), 'warning')); })
			.finally(function() { busy(save, false); });
	} }, saveText || _('Save'));
	ui.showModal(title, [ E('div', { 'class': 'detour-node' }, body), box,
		E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ', save ]) ]);
}

// staged UCI changes are applied the standard LuCI way (with its rollback on lost access)
function applyUci() { return uci.save().then(function() { return ui.changes.apply(); }); }

return view.extend({
	load: function() {
		return Promise.all([ L.resolveDefault(callInfo(), { exits: [] }), L.resolveDefault(callStatus(), {}), uci.load('detour'), uci.load('network') ]);
	},

	exitsBy: function(info) {
		const by = {};
		(info.exits || []).forEach(function(x) { by[x.name] = x; });
		return by;
	},

	// --- one exit --------------------------------------------------------------------------------
	renderExit: function(x, by) {
		const self = this;
		const result = E('div', { 'class': 'detour-check' });
		const lines = [];
		// a tunnel's protocol already names it ("AmneziaWG · masking"); a proxy says which engine runs it
		const what = (x.kind == 'wireguard' || x.kind == 'amneziawg') ? [ protoText(x.proto) || kindText(x) ] : [ kindText(x) ];
		if (x.proto && x.kind != 'wireguard' && x.kind != 'amneziawg') what.push(protoText(x.proto));
		lines.push(E('div', {}, [ E('strong', {}, what.join(' · ')) ]));
		if (x.server) lines.push(E('div', {}, _('Server: %s').format(x.server + (x.port ? ':' + x.port : ''))));
		if (x.via) lines.push(E('div', {}, _('Connects to its server through «%s»: if that exit stops, this one stops too.').format(x.via_label || x.via)));
		if (x.warp) lines.push(E('div', {}, x.colo ? _('Cloudflare WARP, point %s').format(x.colo) : _('Cloudflare WARP')));
		if (x.last_ok) lines.push(E('div', { 'class': 'detour-muted' }, _('Last successful automatic check: %s').format(fmtTime(x.last_ok))));

		const bCheck = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			busy(bCheck, true);
			result.replaceChildren(E('em', {}, _('Checking…')));
			return callCheck(x.name).then(function(r) {
				result.replaceChildren(r && r.ok
					? note(_('Works: answer in %d ms, the internet sees the address %s (%s).').format(r.ms, r.ip, r.loc + (r.colo ? ', ' + _('Cloudflare point %s').format(r.colo) : '')), 'success')
					: note((r && r.error) ? _('No answer through this exit (%s).').format(r.error) : _('No answer from the router'), 'warning'));
			}).finally(function() { busy(bCheck, false); });
		} }, _('Check'));
		const bEdit = E('button', { 'class': 'btn cbi-button-edit', 'click': function() { self.editExit(x, by); } }, _('Edit'));
		const bToggle = E('button', { 'class': 'btn', 'click': function() {
			uci.set('detour', x.name, 'enabled', x.enabled ? '0' : '1');
			return applyUci();
		} }, x.enabled ? _('Turn off') : _('Turn on'));
		const bRemove = E('button', { 'class': 'btn cbi-button-negative', 'click': function() { self.removeExit(x); } }, _('Remove'));

		return E('div', { 'class': 'detour-card' }, [
			E('div', { 'class': 'detour-card-head' }, [ E('span', { 'class': 'detour-card-title' }, x.label), ' ', stateBadge(x),
				E('span', { 'class': 'detour-muted', 'title': _('Internal name: used in the configuration and the log') }, x.name) ]),
			E('div', { 'class': 'detour-card-body' }, lines),
			result,
			E('div', { 'class': 'detour-actions detour-card-actions' }, [ bCheck, bEdit, bToggle, bRemove ])
		]);
	},

	removeExit: function(x) {
		const sub = x.kind == 'subscription';
		ui.showModal(_('Remove «%s»?').format(x.label), [
			E('p', {}, sub ? _('The subscription, its servers and the exit are removed. Policies that use only this exit are left without an exit - their traffic is blocked until you choose another one.')
				: _('The exit and everything it owns are removed (its tunnel settings, its configuration). Policies that use only this exit are left without an exit - their traffic is blocked until you choose another one.')),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
				E('button', { 'class': 'btn cbi-button-negative', 'click': function(ev) {
					busy(ev.target, true);
					return callRemove(x.name).then(function(r) {
						ui.hideModal();
						if (!r || r.error) ui.addNotification(null, E('p', (r && r.error) || _('No answer from the router')), 'danger');
						else location.reload();
					});
				} }, _('Remove'))
			])
		]);
	},

	// --- editing -------------------------------------------------------------------------------------
	editExit: function(x, by) {
		if (x.kind == 'wireguard' || x.kind == 'amneziawg') return this.editTunnel(x);
		if (x.kind == 'subscription') return this.editSub(x, by);
		return this.editProxy(x, by);
	},

	labelField: function(x) {
		return E('input', { 'class': 'cbi-input-text', 'value': x.label });
	},

	viaSelect: function(x, current, by) {
		const sel = E('select', { 'class': 'cbi-input-select' }, [ E('option', { 'value': '' }, _('directly')) ]);
		Object.keys(by).forEach(function(n) {
			const e = by[n];
			if (n == x.name || e.via == x.name || e.kind == 'subscription') return;
			sel.appendChild(E('option', { 'value': n, 'selected': n == current ? '' : null }, _('through «%s»').format(e.label)));
		});
		return sel;
	},

	editProxy: function(x, by) {
		const label = this.labelField(x);
		const via = this.viaSelect(x, x.via || '', by);
		const link = E('textarea', { 'class': 'cbi-input-textarea', 'rows': 2, 'placeholder': 'vless://… / trojan://… / ss://… / hysteria2://…' });
		const cfg = E('textarea', { 'class': 'cbi-input-textarea detour-code', 'rows': 14, 'spellcheck': 'false' }, _('Loading…'));
		let cfgOrig = null;
		callCfgGet(x.name).then(function(r) {
			cfgOrig = (r && r.config) || '';
			cfg.value = (r && r.error) ? r.error : cfgOrig;
		});
		modal(_('Exit «%s»').format(x.label), [
			row(_('Name'), label, _('Shown in policies, on the overview and in notifications.')),
			row(_('Connect to the server'), via, _('Through another exit when the provider blocks this server (for example through WARP). If that exit stops, this one stops too - nothing goes directly.')),
			row(_('Another server from a link'), link, _('Paste a link to replace the server of this exit. Policies keep using the exit.')),
			row(_('Configuration'), cfg, _('The exit\'s settings as the engine sees them (%s). For those who know the format; a wrong value stops the exit.').format(x.kind == 'xray' ? 'Xray outbound' : 'sing-box outbound'))
		], function(box) {
			const jobs = [];
			if (label.value.trim() && label.value.trim() != x.label) uci.set('detour', x.name, 'label', label.value.trim());
			if ((via.value || '') != (x.via || '')) {
				if (via.value) uci.set('detour', x.engine, 'via', via.value); else uci.unset('detour', x.engine, 'via');
			}
			if (link.value.trim()) jobs.push(function() { return callSetLink(x.name, link.value.trim()); });
			else if (cfgOrig != null && cfg.value != cfgOrig) jobs.push(function() { return callCfgSet(x.name, cfg.value); });
			let p = Promise.resolve();
			jobs.forEach(function(j) { p = p.then(j).then(function(r) { if (!r || r.error) throw new Error((r && r.error) || _('No answer from the router')); }); });
			return p.then(function() { return applyUci(); }).then(function() { return true; });
		});
	},

	editTunnel: function(x) {
		const iface = x.iface;
		const ptype = (x.kind == 'amneziawg' ? 'amneziawg_' : 'wireguard_') + iface;
		const peer = uci.sections('network', ptype)[0];
		const label = this.labelField(x);
		const host = E('input', { 'class': 'cbi-input-text', 'value': peer ? (peer.endpoint_host || '') : '' });
		const port = E('input', { 'class': 'cbi-input-text', 'value': peer ? (peer.endpoint_port || '') : '' });
		const mtu = E('input', { 'class': 'cbi-input-text', 'value': uci.get('network', iface, 'mtu') || '', 'placeholder': '1420' });
		const fields = {};
		const body = [
			row(_('Name'), label, _('Shown in policies, on the overview and in notifications.')),
			row(_('Server address'), host, x.warp ? _('A Cloudflare WARP address. Detour moves it away from a bad point (DME) by itself.') : ''),
			row(_('Server port'), port),
			row(_('MTU'), mtu, _('Packet size inside the tunnel. Lower it (1280) if some sites hang while others work.'))
		];
		if (x.kind == 'amneziawg') {
			body.push(E('h4', {}, _('Masking (AmneziaWG)')));
			body.push(E('div', { 'class': 'cbi-value-description' }, _('Makes the tunnel look unlike WireGuard so the provider does not cut it. The values must match the server (your VPN provider gives them in the config).')));
			AWG.forEach(function(a) {
				const v = uci.get('network', iface, 'awg_' + a[0]);
				fields[a[0]] = E(a[0] == 'i1' ? 'textarea' : 'input', a[0] == 'i1' ? { 'class': 'cbi-input-textarea detour-code', 'rows': 3 } : { 'class': 'cbi-input-text', 'value': v || '' }, a[0] == 'i1' ? (v || '') : null);
				body.push(row(a[1], fields[a[0]], a[2]));
			});
		}
		modal(_('Exit «%s»').format(x.label), body, function() {
			if (label.value.trim() && label.value.trim() != x.label) uci.set('detour', x.name, 'label', label.value.trim());
			if (peer) {
				if (host.value.trim()) uci.set('network', peer['.name'], 'endpoint_host', host.value.trim());
				if (/^\d+$/.test(port.value.trim())) uci.set('network', peer['.name'], 'endpoint_port', port.value.trim());
			}
			if (/^\d+$/.test(mtu.value.trim())) uci.set('network', iface, 'mtu', mtu.value.trim()); else if (!mtu.value.trim()) uci.unset('network', iface, 'mtu');
			Object.keys(fields).forEach(function(k) {
				const v = fields[k].value.trim();
				if (v) uci.set('network', iface, 'awg_' + k, v); else uci.unset('network', iface, 'awg_' + k);
			});
			return applyUci().then(function() { return true; });
		});
	},

	// --- subscriptions -------------------------------------------------------------------------------
	renderSub: function(x, by, subState) {
		const self = this;
		const st = subState[x.subscription] || {};
		const result = E('div', { 'class': 'detour-check' });
		const head = [];
		const n = (x.servers || []).length;
		head.push(E('div', {}, [ E('strong', {}, N_(n, '%d server', '%d servers').format(n)),
			st.ts ? ' · ' + _('updated %s').format(fmtTime(st.ts)) : '',
			' · ' + _('updates every %s').format(this.intervalText(x.sub_interval || 24)) ]));
		if (st.ok === false) head.push(note(_('The last update failed - the previous servers are kept.'), 'warning'));
		if (x.via) head.push(E('div', {}, _('Connects to its servers through «%s».').format(x.via_label || x.via)));

		// the servers: automatic (the group picks a working, fast one) or one of them
		const group = 'pick-' + x.name;
		const list = E('div', { 'class': 'detour-servers' });
		const radio = function(key, title, sub) {
			const r = E('input', { 'type': 'radio', 'name': group, 'value': key, 'checked': ((x.pick || '') == key) ? '' : null, 'change': function() {
				list.classList.add('spinning');
				return callPick(x.name, key).then(function(res) {
					if (!res || res.error) ui.addNotification(null, E('p', (res && res.error) || _('No answer from the router')), 'danger');
					else x.pick = key || null;
				}).finally(function() { list.classList.remove('spinning'); });
			} });
			return E('label', { 'class': 'detour-server' }, [ r, ' ', E('span', {}, [ E('strong', {}, title), sub ? E('span', { 'class': 'detour-muted' }, ' ' + sub) : '' ]) ]);
		};
		list.appendChild(radio('', _('Automatically'), _('a working, fast server is chosen and re-checked every few minutes')));
		(x.servers || []).forEach(function(s) {
			list.appendChild(radio(s.key, s.name, protoText(s.proto) + (s.server ? ' · ' + s.server + (s.port ? ':' + s.port : '') : '')));
		});
		if (x.pick && !(x.servers || []).some(function(s) { return s.key == x.pick; }))
			head.push(note(_('The chosen server is no longer in the subscription - the choice is automatic until you choose again.'), 'warning'));

		const bUpdate = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			busy(bUpdate, true);
			return callSubUpdate(x.subscription).then(function(r) {
				if (!r || r.error) ui.addNotification(null, E('p', (r && r.error) || _('No answer from the router')), 'danger');
				else location.reload();
			}).finally(function() { busy(bUpdate, false); });
		} }, _('Update now'));
		const bCheck = E('button', { 'class': 'btn', 'click': function() {
			busy(bCheck, true);
			result.replaceChildren(E('em', {}, _('Checking…')));
			return callCheck(x.name).then(function(r) {
				result.replaceChildren(r && r.ok
					? note(_('Works: answer in %d ms, the internet sees the address %s (%s).').format(r.ms, r.ip, r.loc), 'success')
					: note((r && r.error) ? _('No answer through this exit (%s).').format(r.error) : _('No answer from the router'), 'warning'));
			}).finally(function() { busy(bCheck, false); });
		} }, _('Check'));
		const bEdit = E('button', { 'class': 'btn cbi-button-edit', 'click': function() { self.editSub(x, by); } }, _('Edit'));
		const bRemove = E('button', { 'class': 'btn cbi-button-negative', 'click': function() { self.removeExit(x); } }, _('Remove'));

		return E('div', { 'class': 'detour-card' }, [
			E('div', { 'class': 'detour-card-head' }, [ E('span', { 'class': 'detour-card-title' }, x.label), ' ', stateBadge(x),
				E('span', { 'class': 'detour-muted', 'title': _('Internal name: used in the configuration and the log') }, x.name) ]),
			E('div', { 'class': 'detour-card-body' }, head),
			E('details', { 'class': 'detour-details', 'open': x.pick ? '' : null }, [ E('summary', {}, _('Servers and the choice')), list ]),
			result,
			E('div', { 'class': 'detour-actions detour-card-actions' }, [ bUpdate, bCheck, bEdit, bRemove ])
		]);
	},

	intervalText: function(h) {
		return { 6: _('6 hours'), 12: _('12 hours'), 24: _('day'), 168: _('week') }[h] || _('%d hours').format(h);
	},

	subFields: function(s, x, by) {
		const f = {
			label: E('input', { 'class': 'cbi-input-text', 'value': (s && s.label) || '' }),
			url: E('input', { 'class': 'cbi-input-password', 'type': 'password', 'value': (s && s.url) || '', 'placeholder': 'https://…' }),
			interval: E('select', { 'class': 'cbi-input-select' }, [ 6, 12, 24, 168 ].map(function(h) {
				return E('option', { 'value': String(h), 'selected': (+(s && s.interval || 24) == h) ? '' : null }, this.intervalText(h));
			}, this)),
			ua: E('input', { 'class': 'cbi-input-text', 'value': (s && s.user_agent) || '', 'placeholder': 'v2rayNG/1.10.0' }),
			hwid: E('input', { 'class': 'cbi-input-text', 'value': (s && s.hwid) || '' })
		};
		f.via = this.viaSelect(x || { name: '' }, (s && s.via) || '', by);
		f.rows = [
			row(_('Name'), f.label, _('Shown in policies, on the overview and in notifications.')),
			row(_('Subscription address'), f.url, _('The link your VPN provider gives for apps. Kept secret: shown only here, never logged.')),
			row(_('Update every'), f.interval),
			row(_('Connect to the servers'), f.via, _('Through another exit when the provider blocks these servers.')),
			row(_('Present as app (User-Agent)'), f.ua, _('Some providers give servers only to certain apps (Happ, v2rayNG…). Empty: v2rayNG.')),
			row(_('Device id (x-hwid)'), f.hwid, _('Only if your provider counts devices.'))
		];
		return f;
	},

	saveSubFields: function(name, f) {
		const set = function(k, v) { if (v) uci.set('detour', name, k, v); else uci.unset('detour', name, k); };
		set('label', f.label.value.trim());
		set('url', f.url.value.trim());
		set('interval', f.interval.value == '24' ? '' : f.interval.value);
		set('via', f.via.value);
		set('user_agent', f.ua.value.trim());
		set('hwid', f.hwid.value.trim());
	},

	editSub: function(x, by) {
		const self = this;
		const s = uci.get('detour', x.subscription) ? uci.sections('detour', 'subscription').filter(function(q) { return q['.name'] == x.subscription; })[0] : null;
		const f = this.subFields(s, x, by);
		modal(_('Subscription «%s»').format(x.label), f.rows, function() {
			if (!/^https?:\/\/\S+$/.test(f.url.value.trim())) throw new Error(_('The subscription address must start with http:// or https://'));
			self.saveSubFields(x.subscription, f);
			if (f.label.value.trim()) uci.set('detour', x.name, 'label', f.label.value.trim());
			return applyUci().then(function() { return callSubUpdate(x.subscription); }).then(function() { return true; });
		});
	},

	addSub: function(by) {
		const self = this;
		const name = E('input', { 'class': 'cbi-input-text', 'placeholder': 'provider', 'maxlength': 11 });
		const f = this.subFields(null, null, by);
		modal(_('New subscription'), [ row(_('Internal name'), name, _('Latin letters, digits and _, up to 11; used in the configuration.')) ].concat(f.rows), function() {
			const n = name.value.trim();
			if (!/^[a-z][a-z0-9_]{0,10}$/.test(n)) throw new Error(_('Internal name: a-z, 0-9, _, starts with a letter, up to 11'));
			if (uci.get('detour', n) || uci.get('network', n + '_sub')) throw new Error(_('This name is already used'));
			if (!/^https?:\/\/\S+$/.test(f.url.value.trim())) throw new Error(_('The subscription address must start with http:// or https://'));
			uci.add('detour', 'subscription', n);
			self.saveSubFields(n, f);
			return applyUci().then(function() { return callSubUpdate(n); }).then(function(r) {
				if (!r || r.error) throw new Error((r && r.error) || _('No answer from the router'));
				return true;
			});
		}, _('Add'));
	},

	render: function(data) {
		const self = this;
		const info = data[0] || { exits: [] };
		const subState = {};
		((data[1] || {}).subscriptions || []).forEach(function(s) { subState[s.name] = s; });
		const by = this.exitsBy(info);
		const plain = info.exits.filter(function(x) { return x.kind != 'subscription'; });
		const subs = info.exits.filter(function(x) { return x.kind == 'subscription'; });

		return E('div', {}, [
			E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') }),
			E('h2', {}, _('Exits')),
			E('div', { 'class': 'cbi-map-descr' }, _('An exit is a way out to the internet other than your provider: a VPN server, WARP, a proxy. Policies send chosen traffic into exits. If an exit stops, its traffic is blocked or goes to the next exit of the policy - never directly.')),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Exits')),
				E('div', { 'class': 'cbi-section-node detour-node' }, [
					plain.length ? E('div', { 'class': 'detour-cards' }, plain.map(function(x) { return self.renderExit(x, by); }))
						: E('div', { 'class': 'detour-result' }, E('em', {}, _('No exits yet.'))),
					E('div', { 'class': 'detour-actions' }, [
						E('a', { 'class': 'btn cbi-button-add', 'href': L.url('admin/services/detour/add') }, _('Add an exit…')),
						E('span', { 'class': 'detour-muted' }, _('from a link, WARP or a settings backup'))
					])
				])
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Subscriptions')),
				E('div', { 'class': 'cbi-section-descr' }, _('A subscription is an address from your VPN provider that gives the current list of its servers. All of them form one exit: it picks a working server by itself, or you choose one.')),
				E('div', { 'class': 'cbi-section-node detour-node' }, [
					subs.length ? E('div', { 'class': 'detour-cards' }, subs.map(function(x) { return self.renderSub(x, by, subState); }))
						: E('div', { 'class': 'detour-result' }, E('em', {}, _('No subscriptions yet.'))),
					E('div', { 'class': 'detour-actions' }, [ E('button', { 'class': 'btn cbi-button-add', 'click': function() { self.addSub(by); } }, _('Add subscription')) ])
				])
			])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
