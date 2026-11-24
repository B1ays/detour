'use strict';
'require view';
'require detour.load as pdata';
'require rpc';
'require ui';
'require uci';
'require dom';
'require detour.outform as outform';
'require detour.pkg as pkg';
'require detour.addexit as addexit';

// Text from the router (names of exits and servers come from subscriptions and links) never becomes HTML:
// LuCI's E() puts a string child in with innerHTML, here it always goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

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
const callSubState = rpc.declare({ object: 'detour', method: 'sub_state', params: [ 'name' ] });
const callSubCheck = rpc.declare({ object: 'detour', method: 'sub_check', params: [ 'name', 'index' ] });
const callExport = rpc.declare({ object: 'detour', method: 'exit_export', params: [ 'name' ] });
const callSpeed = rpc.declare({ object: 'detour', method: 'exit_speed', params: [ 'name', 'direct' ] });
const callSubSpeed = rpc.declare({ object: 'detour', method: 'sub_speed', params: [ 'name', 'index' ] });
const callDiag = rpc.declare({ object: 'detour', method: 'exit_diag', params: [ 'name' ] });
const callSetVia = rpc.declare({ object: 'detour', method: 'exit_set_via', params: [ 'name', 'via' ] });
const callReload = rpc.declare({ object: 'detour', method: 'reload' });
const callWake = rpc.declare({ object: 'detour', method: 'exit_wake', params: [ 'name' ] });

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
	if (!x.enabled) return E('span', { 'class': 'detour-badge off' }, _('switched off'));
	if (x.idle) return E('span', { 'class': 'detour-badge off' }, _('not in use'));
	if (x.healthy) return E('span', { 'class': 'detour-badge ok' }, _('working'));
	return E('span', { 'class': 'detour-badge bad' }, x.up ? _('not responding') : _('down'));
}

// an exit on an engine that no policy uses is not started (core.mark_idle): what the card says, and "start for a
// check" - its engine runs for 10 minutes (exit_wake), the page comes back once its device is up
function idleLine(x) {
	if (x.idle) return E('div', { 'class': 'detour-muted' }, _('Not started: no policy uses it. It starts by itself once a policy does.'));
	if (x.warm) return E('div', { 'class': 'detour-muted' }, _('Started for a check until %s.').format(new Date(x.warm * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })));
	return null;
}
function wakeButton(x) {
	const b = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
		busy(b, true);
		return callWake(x.name).then(function(r) {
			if (!r || r.error) { ui.addNotification(null, E('p', (r && r.error) || _('No answer from the router')), 'danger'); return; }
			// the engine's device comes up in a few seconds; at most 20 s of waiting
			let n = 0;
			const wait = function() {
				return L.resolveDefault(callStatus(), {}).then(function(s) {
					const e = ((s || {}).exits || []).filter(function(e) { return e.name == x.name; })[0];
					if ((e && e.up) || ++n >= 13) return location.reload();
					return new Promise(function(res) { window.setTimeout(res, 1500); }).then(wait);
				});
			};
			return wait();
		}).finally(function() { busy(b, false); });
	} }, _('Start for 10 minutes'));
	b.title = _('To check it or measure its speed before a policy uses it');
	return b;
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
		// through then(): a wrong field throws inside onSave, and the message must land in the box
		return Promise.resolve().then(function() { return onSave(box); }).then(function(done) { if (done) ui.hideModal(); })
			.catch(function(e) { box.replaceChildren(note(e.message || String(e), 'warning')); })
			.finally(function() { busy(save, false); });
	} }, saveText || _('Save'));
	ui.showModal([ title ], [ E('div', { 'class': 'detour-node' }, body), box,
		E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ', save ]) ]);
}

// staged UCI changes are applied the standard LuCI way (with its rollback on lost access)
function applyUci() { return uci.save().then(function() { return ui.changes.apply(); }); }

return view.extend({
	load: function() {
		return pdata.all({ info: L.resolveDefault(callInfo(), { exits: [] }), status: L.resolveDefault(callStatus(), {}), cfg: uci.load('detour'), network: uci.load('network') });
	},

	exitsBy: function(info) {
		const by = {};
		(info.exits || []).forEach(function(x) { by[x.name] = x; });
		return by;
	},

	// --- one exit --------------------------------------------------------------------------------
	// "Speed" of an exit or a subscription: a download through it, then directly to compare
	speedButton: function(x, result) {
		const bSpeed = E('button', { 'class': 'btn', 'click': function() {
			busy(bSpeed, true);
			result.replaceChildren(E('em', {}, _('Measuring through the exit (up to 15 s)…')));
			let viaExit = null;
			return callSpeed(x.name, false).then(function(r) {
				viaExit = r;
				result.replaceChildren(E('em', {}, _('Measuring directly, to compare…')));
				return L.resolveDefault(callSpeed(x.name, true), null);
			}).then(function(d) {
				const t = function(r) { return (r && r.ok) ? _('%s Mbit/s').format(r.mbps) : _('failed') + ((r && r.error) ? ' (' + r.error + ')' : ''); };
				result.replaceChildren(note(_('Download speed: through the exit %s, directly %s.').format(t(viaExit), t(d)), (viaExit && viaExit.ok) ? 'success' : 'warning'),
					E('div', { 'class': 'detour-muted' }, (viaExit && viaExit.host)
						? _('A download of %s MB from %s. The speed of one download, not of the whole line.').format(viaExit.mb || '?', viaExit.host)
						: _('The speed of one download, not of the whole line.')));
			}).finally(function() { busy(bSpeed, false); });
		} }, _('Speed'));
		return bSpeed;
	},

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
		if (x.last_ok && !x.idle) lines.push(E('div', { 'class': 'detour-muted' }, _('Last successful automatic check: %s').format(fmtTime(x.last_ok))));
		const il = idleLine(x);
		if (il) lines.push(il);

		const bCheck = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			busy(bCheck, true);
			result.replaceChildren(E('em', {}, _('Checking…')));
			return callCheck(x.name).then(function(r) {
				if (r && r.ok) return result.replaceChildren(note(_('Works: answer in %d ms, the internet sees the address %s (%s).').format(r.ms, r.ip, r.loc + (r.colo ? ', ' + _('Cloudflare point %s').format(r.colo) : '')), 'success'));
				const failed = note((r && r.error) ? _('No answer through this exit (%s).').format(r.error) : _('No answer from the router'), 'warning');
				result.replaceChildren(failed, E('em', {}, _('Finding out why…')));
				// why: does the server answer directly, through another exit
				return L.resolveDefault(callDiag(x.name), null).then(function(d) { result.replaceChildren(failed, self.diagNote(x, d)); });
			}).finally(function() { busy(bCheck, false); });
		} }, _('Check'));
		const bSpeed = this.speedButton(x, result);
		const bShare = E('button', { 'class': 'btn', 'click': function() { self.exportExit(x); } }, _('Share'));
		const bEdit = E('button', { 'class': 'btn', 'click': function() { self.editExit(x, by); } }, _('Edit'));
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
			E('div', { 'class': 'detour-actions detour-card-actions' }, (x.idle && x.enabled) ? [ wakeButton(x), bEdit, bShare, bToggle, bRemove ] : [ bCheck, bSpeed, bEdit, bShare, bToggle, bRemove ])
		]);
	},

	// what diag_exit found, in words; for a blocked address of a proxy exit - connect it through the exit that works
	diagNote: function(x, d) {
		if (!d) return '';
		const V = {
			blocked: _('The server\'s address seems blocked by the provider: directly it is silent, through «%s» it answers.').format(d.other_label || d.other),
			down: _('The server answers neither directly nor through another exit: it is down, or blocked everywhere.'),
			silent: _('The server does not answer. There is no other working exit to tell whether the provider blocks it.'),
			reachable: _('The server answers: the connection itself fails - wrong keys or settings, or the provider filters this protocol.'),
			dns: _('The server\'s name is not found in DNS.'),
			nodev: _('The engine did not start: its tunnel device is missing. See the router\'s log.'),
			notun: _('The engine cannot make its tunnel: the kernel module kmod-tun is missing (apk add kmod-tun).'),
			udp: _('The server works over UDP: the router cannot tell from here whether the provider blocks it.')
		};
		const items = [ E('div', {}, V[d.verdict] || '') ];
		if (d.verdict == 'blocked' && x.engine && d.other && !x.via)
			items.push(E('div', { 'class': 'detour-actions' }, [ E('button', { 'class': 'btn cbi-button-action', 'click': function(ev) {
				busy(ev.target, true);
				return callSetVia(x.name, d.other).then(function(r) {
					if (!r || r.error) ui.addNotification(null, E('p', (r && r.error) || _('No answer from the router')), 'danger');
					else location.reload();
				}).finally(function() { busy(ev.target, false); });
			} }, _('Connect through «%s»').format(d.other_label || d.other)) ]));
		return E('div', { 'class': 'alert-message notice' }, items);
	},

	// the exit as a link or a .conf, with a QR code: to set it up on a phone or a computer
	exportExit: function(x) {
		const body = E('div', {}, E('em', {}, _('Loading…')));
		ui.showModal([ _('Share «%s»').format(x.label) ], [ body,
			E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Close')) ]) ]);
		callExport(x.name).then(function(r) {
			if (!r || r.error) return body.replaceChildren(note((r && r.error) || _('No answer from the router'), 'warning'));
			// JSON from the engine comes tab-indented and wraps in a narrow box: two spaces, no wrapping
			let text = r.text;
			const json = /\.json$/.test(r.filename || '');
			if (json) try { text = JSON.stringify(JSON.parse(r.text), null, 2); } catch (e) { }
			const ta = E('textarea', { 'class': 'cbi-input-textarea detour-code' + (json ? ' detour-json' : ''), 'rows': r.link ? 4 : 14, 'readonly': '', 'spellcheck': 'false', 'wrap': json ? 'off' : 'soft' }, text);
			const url = URL.createObjectURL(new Blob([ text ], { type: 'text/plain' }));
			const kind = r.link ? _('A link for v2rayN, v2rayNG, Hiddify, NekoBox, Streisand…')
				: (/\.conf$/.test(r.filename) ? _('A config for the WireGuard or AmneziaWG app.') : _('The engine\'s settings (JSON).'));
			const items = [
				note(_('This holds the keys of the exit: whoever has it can use your server. Share it only with your own devices.'), 'warning'),
				E('div', {}, kind),
				ta,
				E('div', { 'class': 'detour-actions' }, [
					E('button', { 'class': 'btn', 'click': function(ev) {
						ta.select();
						try { navigator.clipboard.writeText(text); } catch (e) { document.execCommand('copy'); }
						ev.target.textContent = _('Copied');
					} }, _('Copy')),
					E('a', { 'class': 'btn', 'href': url, 'download': r.filename }, _('Download %s').format(r.filename))
				])
			];
			if (r.qr_svg) items.push(E('div', { 'class': 'detour-qr' }, E('img', { 'src': 'data:image/svg+xml;base64,' + btoa(r.qr_svg), 'alt': 'QR' })));
			else if (r.qr_missing) items.push(pkg.offer('qrencode', _('A QR code needs qrencode.')));
			body.replaceChildren(E('div', { 'class': 'detour-modal-body' }, items));
		});
	},

	removeExit: function(x) {
		const sub = x.kind == 'subscription';
		ui.showModal([ _('Remove «%s»?').format(x.label) ], [
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
		// the fields of the server (sing-box exits); JSON stays for what the form does not show
		const fieldsBox = E('div', {}, E('em', {}, _('Loading…')));
		let cfgOrig = null, form = null, fieldsOrig = null;
		callCfgGet(x.name).then(function(r) {
			if (!r || r.error) {
				// not read: the error is shown, never sent back as the configuration (the name and "through" still save)
				cfg.value = (r && r.error) || _('No answer from the router');
				cfg.readOnly = true;
				fieldsBox.replaceChildren(E('em', {}, _('The configuration could not be read.')));
				return;
			}
			cfgOrig = r.config || '';
			cfg.value = cfgOrig;
			let o = null;
			try { o = JSON.parse(cfgOrig); } catch (e) { }
			if (o && outform.supported(o)) {
				form = outform.build(o);
				fieldsBox.replaceChildren(form.node);
				fieldsOrig = JSON.stringify(form.read());
			}
			else fieldsBox.replaceChildren(E('div', { 'class': 'cbi-value-description' },
				x.kind == 'xray' ? _('This exit runs on Xray: its settings are edited as JSON below, or replaced by a link (it stays on Xray when Xray runs that link, else moves to sing-box).')
					: _('This kind of server is edited as JSON below.')));
		});
		modal(_('Exit «%s»').format(x.label), [
			row(_('Name'), label, _('Shown in policies, on the overview and in notifications.')),
			row(_('Connect to the server'), via, _('Through another exit when the provider blocks this server (for example through WARP). If that exit stops, this one stops too - nothing goes directly.')),
			E('h4', {}, _('Server')),
			fieldsBox,
			row(_('Another server from a link'), link, _('Paste a link to replace the server of this exit. Policies keep using the exit.')),
			E('details', { 'class': 'detour-details' }, [ E('summary', {}, _('For experts: the configuration as JSON')),
				row(_('Configuration'), cfg, _('The exit\'s settings as the engine sees them (%s). A wrong value stops the exit. Changed here, it wins over the fields above.').format(x.kind == 'xray' ? 'Xray outbound' : 'sing-box outbound')) ])
		], function(box) {
			const jobs = [];
			if (label.value.trim() && label.value.trim() != x.label) uci.set('detour', x.name, 'label', label.value.trim());
			if ((via.value || '') != (x.via || '')) {
				if (via.value) uci.set('detour', x.engine, 'via', via.value); else uci.unset('detour', x.engine, 'via');
			}
			// one change of the server: a link, else the JSON edited by hand, else the fields
			let fieldsNew = null;
			if (form) fieldsNew = JSON.stringify(form.read());   // throws with the reason of a wrong field
			if (link.value.trim()) jobs.push(function() { return callSetLink(x.name, link.value.trim()); });
			else if (cfgOrig != null && cfg.value != cfgOrig) jobs.push(function() { return callCfgSet(x.name, cfg.value); });
			else if (form && fieldsNew != fieldsOrig) jobs.push(function() { return callCfgSet(x.name, JSON.stringify(JSON.parse(fieldsNew), null, '\t')); });
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
			row('MTU', mtu, _('Packet size inside the tunnel. Lower it (1280) if some sites hang while others work.'))
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
	// what the provider reports: "Traffic: 12.3 of 100 GB · until 15.12.2026"
	usageText: function(i) {
		if (!i || (i.total == null && i.expire == null && i.upload == null && i.download == null)) return null;
		const parts = [], gb = function(b) { return '%.1f'.format(b / 1073741824); };
		const used = (i.upload || 0) + (i.download || 0);
		if (i.total > 0) parts.push(_('Traffic: %s of %s GB').format(gb(used), gb(i.total)));
		else if (i.upload != null || i.download != null) parts.push(_('Traffic: %s GB, no limit').format(gb(used)));
		if (i.expire > 0) parts.push((i.expire * 1000 < Date.now() ? _('ended %s') : _('until %s')).format(new Date(i.expire * 1000).toLocaleDateString()));
		else if (i.expire != null) parts.push(_('no end date'));
		const warn = (i.total > 0 && used >= i.total * 0.9) || (i.expire > 0 && i.expire * 1000 - Date.now() < 3 * 86400000);
		return warn ? note(parts.join(' · '), 'warning') : E('div', {}, parts.join(' · '));
	},

	renderSub: function(x, by, subState) {
		const self = this;
		const st = subState[x.subscription] || {};
		const result = E('div', { 'class': 'detour-check' });
		const head = [];
		const n = (x.servers || []).length;
		head.push(E('div', {}, [ E('strong', {}, N_(n, '%d server', '%d servers').format(n)),
			' · ' + (x.sub_engine == 'xray' ? 'Xray' : 'sing-box'),
			st.ts ? ' · ' + _('updated %s').format(fmtTime(st.ts)) : '',
			' · ' + _('updates every %s').format(this.intervalText(x.sub_interval || 24)) ]));
		const usage = this.usageText(x.sub_info);
		if (usage) head.push(usage);
		if (st.code == 'no_engine')
			head.push(pkg.offer(/xray/.test(st.message || '') ? 'xray' : 'singbox', _('The engine chosen for this subscription is not installed - the previous servers are kept.')));
		else if (st.ok === false) head.push(note(_('The last update failed - the previous servers are kept.'), 'warning'));
		if (x.via) head.push(E('div', {}, _('Connects to its servers through «%s».').format(x.via_label || x.via)));
		const il = idleLine(x);
		if (il) head.push(il);
		const nowLine = E('div', {});
		head.push(nowLine);

		// the servers: automatic (the group picks a working, fast one) or one of them; each can be checked
		// on its own (a request through that server, the subscription does not switch)
		const group = 'pick-' + x.name;
		const list = E('div', { 'class': 'detour-servers' });
		const delays = [];
		const radio = function(key, title, sub, i) {
			const r = E('input', { 'type': 'radio', 'name': group, 'value': key, 'checked': ((x.pick || '') == key) ? '' : null, 'change': function() {
				list.classList.add('spinning');
				return callPick(x.name, key).then(function(res) {
					if (!res || res.error) ui.addNotification(null, E('p', (res && res.error) || _('No answer from the router')), 'danger');
					else x.pick = key || null;
				}).finally(function() { list.classList.remove('spinning'); });
			} });
			const label = E('label', { 'class': 'detour-server' }, [ r, ' ', E('span', {}, [ E('strong', {}, title), sub ? E('span', { 'class': 'detour-muted' }, ' ' + sub) : '' ]) ]);
			if (i == null || x.idle) return label;   // not started: nothing to check a server through
			const d = E('span', { 'class': 'detour-delay detour-muted' });
			delays[i] = d;
			const b = E('button', { 'class': 'btn', 'title': _('A request through this server only; the subscription does not switch'), 'click': function(ev) {
				ev.preventDefault();
				busy(b, true);
				d.textContent = _('checking…');
				return callSubCheck(x.name, i).then(function(res) {
					d.classList.toggle('bad', !(res && res.ok));
					d.textContent = (res && res.ok) ? _('%d ms').format(res.ms)
						: (res && res.error == 'no automatic server group for ' + x.name) ? _('only in the automatic mode') : _('no answer');
				}).finally(function() { busy(b, false); });
			} }, _('Check'));
			// a download through this server only (its group's check inbound); the subscription does not switch
			const sp = E('span', { 'class': 'detour-delay detour-muted' });
			const bs = E('button', { 'class': 'btn', 'title': _('A download through this server only; the subscription does not switch'), 'click': function(ev) {
				ev.preventDefault();
				busy(bs, true);
				sp.textContent = _('measuring…');
				return callSubSpeed(x.name, i).then(function(res) {
					sp.classList.toggle('bad', !(res && res.ok));
					sp.textContent = (res && res.ok) ? _('%s Mbit/s').format(res.mbps)
						: (res && res.error == 'no automatic server group for ' + x.name) ? _('only in the automatic mode')
						: (res && res.error == 'a speed test is running') ? _('another test is running') : _('failed');
				}).finally(function() { busy(bs, false); });
			} }, _('Speed'));
			return E('div', { 'class': 'detour-server-row' }, [ label, d, sp, b, bs ]);
		};
		list.appendChild(radio('', _('Automatically'), _('a working, fast server is chosen and re-checked every few minutes')));
		(x.servers || []).forEach(function(s, i) {
			list.appendChild(radio(s.key, s.name, protoText(s.proto) + (s.server ? ' · ' + s.server + (s.port ? ':' + s.port : '') : ''), i));
		});
		// which server the automatic choice uses now and the delays it measured (sing-box's own checks)
		if (x.sub_auto && x.enabled && !x.idle) L.resolveDefault(callSubState(x.name), null).then(function(r) {
			if (!r || r.error) return;
			const s = (r.now != null) ? (x.servers || [])[r.now] : null;
			if (s) nowLine.replaceChildren(E('span', { 'class': 'detour-now' }, _('Now: %s').format(s.name)),
				r.delays[r.now] ? ' · ' + _('%d ms').format(r.delays[r.now]) : '');
			Object.keys(r.delays || {}).forEach(function(k) {
				const d = delays[+k];
				if (!d) return;
				const ms = r.delays[k];
				d.classList.toggle('bad', !ms);
				d.textContent = (+k === r.now ? _('now') + ' · ' : '') + (ms ? _('%d ms').format(ms) : _('no answer'));
			});
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
		const bSpeed = this.speedButton(x, result);
		const bEdit = E('button', { 'class': 'btn', 'click': function() { self.editSub(x, by); } }, _('Edit'));
		const bRemove = E('button', { 'class': 'btn cbi-button-negative', 'click': function() { self.removeExit(x); } }, _('Remove'));

		return E('div', { 'class': 'detour-card' }, [
			E('div', { 'class': 'detour-card-head' }, [ E('span', { 'class': 'detour-card-title' }, x.label), ' ', stateBadge(x),
				E('span', { 'class': 'detour-muted', 'title': _('Internal name: used in the configuration and the log') }, x.name) ]),
			E('div', { 'class': 'detour-card-body' }, head),
			E('details', { 'class': 'detour-details', 'open': x.pick ? '' : null }, [ E('summary', {}, _('Servers and the choice')), list ]),
			result,
			E('div', { 'class': 'detour-actions detour-card-actions' }, (x.idle && x.enabled) ? [ bUpdate, wakeButton(x), bEdit, bRemove ] : [ bUpdate, bCheck, bSpeed, bEdit, bRemove ])
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
			hwid: E('input', { 'class': 'cbi-input-text', 'value': (s && s.hwid) || '' }),
			engine: E('select', { 'class': 'cbi-input-select' }, [ [ 'singbox', 'sing-box' ], [ 'xray', 'Xray' ] ].map(function(e) {
				return E('option', { 'value': e[0], 'selected': (((s && s.engine) || 'singbox') == e[0]) ? '' : null }, e[1]);
			}))
		};
		f.via = this.viaSelect(x || { name: '' }, (s && s.via) || '', by);
		f.rows = [
			row(_('Name'), f.label, _('Shown in policies, on the overview and in notifications.')),
			row(_('Subscription address'), f.url, _('The link your VPN provider gives for apps. Kept secret: shown only here, never logged.')),
			row(_('Update every'), f.interval),
			row(_('Connect to the servers'), f.via, _('Through another exit when the provider blocks these servers.')),
			row(_('Engine'), f.engine, _('What runs the servers. sing-box by default; Xray also runs XHTTP and servers sing-box cannot connect to. Servers the engine cannot run are skipped.')),
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
		set('engine', f.engine.value == 'singbox' ? '' : f.engine.value);
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

	// a new subscription; url: the address pasted into the add field (its name and title are made from its host)
	addSub: function(by, url, added) {
		const self = this;
		const host = (/^https?:\/\/([^\/:?#@]+)/.exec(url || '') || [])[1] || '';
		const parts = host.split('.').filter(function(x) { return x; });
		// the provider's name in its domain: "sub.my-vpn.net" -> "my", "dot.ruslik31.me" -> "ruslik31"
		const word = /^[0-9.]+$/.test(host) ? '' : String((parts.length > 1 ? parts[parts.length - 2] : parts[0]) || '').toLowerCase().split(/[^a-z0-9]+/)[0];
		const name = E('input', { 'class': 'cbi-input-text', 'placeholder': 'provider', 'maxlength': 11,
			'value': word ? addexit.freeName({}, word) : '' });
		const f = this.subFields(null, null, by);
		if (url) { f.url.value = url; f.label.value = word; }
		modal(_('New subscription'), [ row(_('Internal name'), name, _('Latin letters, digits and _, up to 11; used in the configuration.')) ].concat(f.rows), function(box) {
			const n = name.value.trim();
			if (!/^[a-z][a-z0-9_]{0,10}$/.test(n)) throw new Error(_('Internal name: a-z, 0-9, _, starts with a letter, up to 11'));
			if (uci.get('detour', n) || uci.get('network', n + '_sub')) throw new Error(_('This name is already used'));
			if (!/^https?:\/\/\S+$/.test(f.url.value.trim())) throw new Error(_('The subscription address must start with http:// or https://'));
			// Xray chosen but not installed: offered here - saved, the subscription would never get its exit
			const engineOk = f.engine.value != 'xray' ? Promise.resolve(true) : L.resolveDefault(pkg.list(), null).then(function(r) {
				const c = ((r && r.components) || []).filter(function(x) { return x.id == 'xray'; })[0];
				return !c || !!c.installed;
			});
			return engineOk.then(function(ok) {
				if (!ok) { box.replaceChildren(pkg.offer('xray', _('Xray is not installed: install it here or choose sing-box.'))); return false; }
				uci.add('detour', 'subscription', n);
				self.saveSubFields(n, f);
				return applyUci().then(function() { return callSubUpdate(n); }).then(function(r) {
					if (!r || r.error) throw new Error((r && r.error) || _('No answer from the router'));
					if (added) added();
					self.refresh(_('Subscription %s added: %d servers.').format(f.label.value.trim() || n, r.servers || 0));
					return true;
				});
			});
		}, _('Add'));
	},

	// after something was added or removed: the page again from the router's state, the message on top
	refresh: function(text) {
		const self = this;
		if (text) ui.addNotification(null, E('p', {}, text), 'info');
		uci.unload('detour'); uci.unload('network');
		const old = this.root;   // render() sets this.root to the new page
		return Promise.resolve(this.load()).then(function(data) {
			const node = self.render(data);
			if (old && old.parentNode) old.parentNode.replaceChild(node, old);
		});
	},

	render: function(data) {
		const self = this;
		const info = data.info || { exits: [] };
		const subState = {};
		((data.status || {}).subscriptions || []).forEach(function(s) { subState[s.name] = s; });
		const by = this.exitsBy(info);
		const plain = info.exits.filter(function(x) { return x.kind != 'subscription'; });
		const subs = info.exits.filter(function(x) { return x.kind == 'subscription'; });
		const done = function(text) { return self.refresh(text); };

		this.root = E('div', {}, [
			E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') }),
			E('h2', {}, _('Exits')),
			E('div', { 'class': 'cbi-map-descr' }, _('An exit is a way out to the internet other than your provider: a VPN server, WARP, a proxy. Policies send chosen traffic into exits. If an exit stops, its traffic is blocked or goes to the next exit of the policy - never directly.')),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Exits')),
				E('div', { 'class': 'cbi-section-node detour-node' }, [
					plain.length ? E('div', { 'class': 'detour-cards' }, plain.map(function(x) { return self.renderExit(x, by); }))
						: E('div', { 'class': 'detour-result' }, E('em', {}, _('No exits yet.')))
				])
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Subscriptions')),
				E('div', { 'class': 'cbi-section-descr' }, _('A subscription is an address from your VPN provider that gives the current list of its servers. All of them form one exit: it picks a working server by itself, or you choose one.')),
				E('div', { 'class': 'cbi-section-node detour-node' }, [
					subs.length ? E('div', { 'class': 'detour-cards' }, subs.map(function(x) { return self.renderSub(x, by, subState); }))
						: E('div', { 'class': 'detour-result' }, E('em', {}, _('No subscriptions yet.')))
				])
			]),
			// one field for both: a subscription address opens the subscription form, anything else becomes an exit
			addexit.renderAdd(function(url, clear) { self.addSub(by, url, clear); }, done),
			addexit.renderWarp(done)
		]);
		return this.root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
