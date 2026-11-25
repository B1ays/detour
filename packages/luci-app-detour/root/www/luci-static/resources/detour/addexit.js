'use strict';
'require baseclass';
'require ui';
'require dom';
'require rpc';
'require uci';
'require detour.pkg as pkg';

// Adding on the Exits page: one field for everything a person has - an exit from a link, an Amnezia key, a
// WireGuard config, a JSON or a Clash YAML (pasted or a file), or a provider's subscription address (http(s)://,
// the Exits page opens its form) - and Cloudflare WARP registration.
// Text from the router (names of exits and servers come from subscriptions and links) never becomes HTML:
// LuCI's E() puts a string child in with innerHTML, here it always goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

const callParse = rpc.declare({ object: 'detour', method: 'exit_parse', params: [ 'text' ] });
const callExitAdd = rpc.declare({ object: 'detour', method: 'exit_add', params: [ 'text', 'picks', 'name', 'via', 'label', 'engines' ] });
const callWarpReg = rpc.declare({ object: 'detour', method: 'warp_register', params: [ 'name', 'awg' ] });
const callWarpDel = rpc.declare({ object: 'detour', method: 'warp_unregister', params: [ 'name' ] });

// what the router says about a link or a config is English (it also goes to the log); the known ones for people
function errText(e) {
	let m;
	e = String(e || '');
	if ((m = e.match(/^(.*?): (.*)$/)) && !/^vpn:\/\//.test(e) && !/^(ss|hy2|tuic|vmess):/.test(e)) { const t = errText(m[2]); if (t != m[2]) return m[1] + ': ' + t; }
	if ((m = e.match(/^unsupported scheme (.+)$/))) return _('the scheme «%s» is not supported').format(m[1]);
	if ((m = e.match(/^type (.+) is not supported$/))) return _('the type «%s» is not supported').format(m[1]);
	if ((m = e.match(/^transport "?(.+?)"? is not supported$/))) return _('the transport «%s» is not supported').format(m[1]);
	if ((m = e.match(/^(.+) is already used, skipped$/))) return _('the name %s is already used, skipped').format(m[1]);
	if ((m = e.match(/^(.+): (sing-box|xray-core) is not installed$/))) return _('%s: the %s package is not installed').format(m[1], m[2]);
	if ((m = e.match(/^(sing-box|xray-core) is not installed$/))) return _('the %s package is not installed').format(m[1]);
	if ((m = e.match(/^(Xray|sing-box) refused the configuration: (.*)$/))) return _('%s refused the configuration: %s').format(m[1], m[2]);
	if (e == 'sing-box has no XHTTP transport') return _('XHTTP runs only on Xray, and Xray cannot take this server');
	if (e == 'sing-box has no VLESS encryption') return _('VLESS encryption runs only on Xray, and Xray cannot take this server');
	if (e == 'sing-box has no ML-DSA check of Reality') return _('Reality with an ML-DSA key runs only on Xray, and Xray cannot take this server');
	if (/the ucode-mod-zlib package is needed/.test(e)) return _('this key needs the ucode-mod-zlib package');
	if (/^vpn:\/\/: no AmneziaWG/.test(e)) return _('the vpn:// key has no AmneziaWG, WireGuard or Xray (other Amnezia protocols are not supported)');
	if (/^vpn:\/\//.test(e)) return _('the vpn:// key could not be read');
	if (/not a WireGuard config/.test(e)) return _('not a WireGuard config (keys or the server address missing)');
	if (/a key is not a WireGuard key/.test(e)) return _('a key does not look like a WireGuard key');
	if (/no IPv4 Address/.test(e)) return _('the config has no IPv4 address');
	if (/^nothing recognised/.test(e)) return _('nothing recognised: a link, a key, a WireGuard config, JSON or Clash YAML is expected');
	const fixed = {
		'not a share link': _('not a link'), 'not valid JSON': _('not valid JSON'), 'no proxy in this JSON': _('no proxy in this JSON'),
		'the proxies list is empty': _('the proxies list is empty'), 'empty': _('empty'), 'nothing usable was chosen': _('nothing usable was chosen'),
		'cannot parse the link': _('the link could not be read'), 'a proxy without server/port': _('a proxy without a server or port')
	};
	if (fixed[e]) return fixed[e];
	if (/cannot (parse|decode)|bad host:port|no method:password|bad base64/.test(e)) return _('the link could not be read');
	return e;
}

// what the router said needs a package (its own words, before translation): an offer to install it
function offers(texts) {
	const t = texts.filter(function(x) { return x; }).join('\n'), out = [];
	if (/sing-box is not installed/.test(t)) out.push(pkg.offer('singbox', _('Proxy exits run on sing-box.')));
	if (/xray-core is not installed/.test(t)) out.push(pkg.offer('xray', _('This exit runs only on Xray.')));
	if (/ucode-mod-zlib package is needed/.test(t)) out.push(pkg.offer('zlib', _('Amnezia vpn:// keys need ucode-mod-zlib.')));
	return out;
}

function busy(btn, on) { btn.disabled = on; btn.classList.toggle('spinning', on); }

function result(box, r, okText) {
	if (!r || r.error)
		box.replaceChildren(E('div', { 'class': 'alert-message warning' }, (r && r.error) || _('No answer from the router')));
	else
		box.replaceChildren(E('div', { 'class': 'alert-message success' }, okText(r)));
}

// the theme's own markup, so it spaces and pads these like any LuCI form: a card (title, description,
// body), labelled rows, a row of buttons and a box for the answer (see detour.css)
function card(title, descr, body) {
	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, title),
		E('div', { 'class': 'cbi-section-descr' }, descr),
		E('div', { 'class': 'cbi-section-node detour-node' }, body)
	]);
}
function row(title, field, descr) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, title),
		E('div', { 'class': 'cbi-value-field' }, descr ? [ field, E('div', { 'class': 'cbi-value-description' }, descr) ] : field)
	]);
}
function actions(items) { return E('div', { 'class': 'detour-actions' }, items); }
function resultBox() { return E('div', { 'class': 'detour-result' }); }

return baseclass.extend({
	// one field for an exit or a subscription: a single http(s):// address is a subscription (onSub(url) opens its
	// form); anything else is an exit - a link, an Amnezia key, a WireGuard config, a JSON or a Clash YAML, pasted
	// or from a file. One exit at a time: "Add" reads it, a dialog shows what it is and adds it when agreed;
	// onDone(text) when something was added.
	renderAdd: function(onSub, onDone) {
		const self = this;
		const text = E('textarea', { 'class': 'cbi-input-textarea detour-code', 'rows': 5, 'spellcheck': 'false',
			'placeholder': 'https://… (' + _('subscription address') + ')\nvless://… ss://… trojan://… hysteria2://… tuic://… wireguard://… vpn://…\n[Interface] …\n{ "outbounds": … }\nproxies: …' });
		let fileName = '';
		const file = E('input', { 'type': 'file', 'accept': '.conf,.json,.yaml,.yml,.txt,text/*', 'style': 'display:none', 'change': function() {
			const f = file.files[0];
			if (!f) return;
			if (f.size > 256 * 1024) { box.replaceChildren(E('div', { 'class': 'alert-message warning' }, _('The file is too big for a config (over 256 KB).'))); return; }
			const r = new FileReader();
			r.onload = function() { text.value = r.result; fileName = f.name.replace(/\.[^.]*$/, ''); box.replaceChildren(); };
			r.readAsText(f);
		} });
		const bFile = E('button', { 'class': 'btn', 'click': function() { file.click(); } }, _('Choose a file…'));
		const box = resultBox();

		const bImport = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			const t = text.value.trim();
			if (!t) { box.replaceChildren(E('div', { 'class': 'alert-message warning' }, _('Paste a subscription address, a link, a key or a config first, or choose a file.'))); return; }
			// one http(s):// address: a provider's subscription
			if (/^https?:\/\/\S+$/.test(t)) { box.replaceChildren(); onSub(t, function() { text.value = ''; }); return; }
			busy(bImport, true);
			box.replaceChildren();
			return callParse(text.value).then(function(r) {
				if (!r || r.error) {
					result(box, r && r.error ? { error: errText(r.error) } : r);
					offers([ r && r.error ]).forEach(function(o) { box.appendChild(o); });
					return;
				}
				const usable = [];
				r.candidates.forEach(function(c, i) { if (!c.error) usable.push(i); });
				if (!usable.length) {
					box.replaceChildren(E('div', { 'class': 'alert-message warning' }, [ E('div', {}, _('Nothing here can become an exit.')),
						E('div', { 'class': 'detour-muted' }, r.candidates.map(function(c) { return errText(c.error); }).join('; ')) ]));
					offers(r.candidates.map(function(c) { return c.error; })).forEach(function(o) { box.appendChild(o); });
					return;
				}
				// one exit at a time: a list of servers is a subscription's work
				if (usable.length > 1) {
					box.replaceChildren(E('div', { 'class': 'alert-message warning' },
						_('There are %d servers here. Exits are added one at a time: paste one link or one config. For a set of servers from a provider paste its subscription address (https://…).').format(usable.length)));
					return;
				}
				self.confirmExit(text.value, usable[0], r.candidates[usable[0]], r.installed || {}, fileName, function(added) {
					const names = (added.added || []).map(function(a) { return a.name; }).join(', ');
					text.value = ''; fileName = '';
					onDone(_('Exit %s added. Put it into a policy on the Routing page.').format(names) +
						((added.notes && added.notes.length) ? ' (' + added.notes.map(errText).join('; ') + ')' : ''));
				});
			}).finally(function() { busy(bImport, false); });
		} }, _('Add'));

		return card(_('Add an exit or a subscription'),
			_('Paste a subscription address from your VPN provider (https://…) - all of its servers become one exit. Or one server: a link (vless, vmess, trojan, ss, hysteria2, tuic, wireguard), an Amnezia vpn:// key, a WireGuard / AmneziaWG config, a sing-box or Xray JSON or a Clash YAML - or choose such a file. Before anything is added you see what it is. Proxies run on sing-box or Xray: where both can, you choose; XHTTP only on Xray, HTTP/2, Hysteria2 and TUIC only on sing-box. WireGuard and AmneziaWG run on the router itself.'), [
			row(_('Address, link, key or config'), E('div', {}, [ text, E('div', { 'class': 'detour-actions detour-field-actions' }, [ bFile, file ]) ])),
			actions([ bImport ]), box
		]);
	},

	// an internal name nobody has yet: from the name the server gave, else from its protocol
	freeName: function(c, hint) {
		const taken = function(n) { return !!(uci.get('detour', n) || uci.get('detour', n + '_eng') || uci.get('detour', n + '_sub')); };
		let base = String(hint || c.label || c.proto || c.kind || 'exit').toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^[^a-z]+/, '').replace(/_+$/, '').slice(0, 9);
		if (!/^[a-z]/.test(base)) base = String(c.kind || 'exit').replace(/[^a-z]/g, '') || 'exit';
		if (!taken(base)) return base;
		for (let i = 2; i < 100; i++) if (!taken(base + i)) return base + i;
		return base;
	},

	// "Import": what the exit is, its names, its engine and its way to the server; added only when agreed
	confirmExit: function(textValue, idx, c, have, hint, done) {
		const KIND = { 'wg': 'WireGuard', 'awg': 'AmneziaWG', 'singbox': 'sing-box', 'xray': 'Xray' };
		const tunnel = c.kind == 'wg' || c.kind == 'awg';
		const label = E('input', { 'class': 'cbi-input-text', 'value': c.label || '', 'placeholder': c.server });
		const name = E('input', { 'class': 'cbi-input-text', 'value': this.freeName(c, hint), 'maxlength': 11 });
		const via = E('select', { 'class': 'cbi-input-select' }, [ E('option', { 'value': '' }, _('directly')) ].concat(
			uci.sections('detour', 'exit').map(function(s) { return E('option', { 'value': s['.name'] }, _('through %s').format(s.label || s['.name'])); })));
		// a server both engines run: which one (the one not installed is shown, but cannot be chosen)
		const engines = c.engines || [];
		const eng = engines.length > 1 ? E('select', { 'class': 'cbi-input-select' }, engines.map(function(e) {
			return E('option', { 'value': e, 'selected': e == c.kind ? '' : null, 'disabled': have[e] === false ? '' : null },
				KIND[e] + (have[e] === false ? ' - ' + _('not installed') : ''));
		})) : null;
		const missing = !tunnel && engines.length && engines.every(function(e) { return have[e] === false; });
		const msg = E('div');
		const info = function(t, v) { return E('div', { 'class': 'detour-info-row' }, [ E('span', { 'class': 'detour-muted' }, t), E('strong', {}, v) ]); };
		const bAdd = E('button', { 'class': 'btn cbi-button-action', 'disabled': missing ? '' : null, 'click': function() {
			const n = name.value.trim();
			if (!/^[a-z][a-z0-9_]{0,10}$/.test(n)) { dom.content(msg, E('div', { 'class': 'alert-message warning' }, _('Internal name: Latin letters, digits and _, up to 11, starting with a letter.'))); return; }
			const chosen = []; chosen[idx] = eng ? eng.value : '';
			busy(bAdd, true);
			return callExitAdd(textValue, [ idx ], n, tunnel ? '' : via.value, label.value.trim(), chosen).then(function(r) {
				if (!r || r.error || !(r.added || []).length) {
					const raw = [ r && r.error ].concat((r && r.notes) || []);
					dom.content(msg, E('div', { 'class': 'alert-message warning' }, r && r.error ? r.error.split('; ').map(errText).join('; ')
						: ((r && r.notes) || []).map(errText).join('; ') || _('No answer from the router')));
					offers(raw).forEach(function(o) { msg.appendChild(o); });
					return;
				}
				ui.hideModal();
				done(r);
			}).finally(function() { busy(bAdd, false); });
		} }, _('Add'));
		const body = [
			info(_('Protocol'), [ c.proto || KIND[c.kind], c.warp ? ' · Cloudflare WARP' : '' ].join('')),
			info(_('Server'), c.server + ':' + c.port),
			eng ? '' : info(_('Runs on'), tunnel ? _('the router itself (%s)').format(KIND[c.kind]) : KIND[c.kind]),
			missing ? offers([ c.kind == 'xray' ? 'xray-core is not installed' : 'sing-box is not installed' ])[0] : '',
			row(_('Name'), label, _('How the exit is shown everywhere.')),
			row(_('Internal name'), name, _('Latin letters, digits and _, up to 11; used in the configuration.')),
			eng ? row(_('Engine'), eng, _('Both engines can run this server.')) : '',
			tunnel ? '' : row(_('Connect to the server'), via, _('Through another exit (for example WARP) when the server itself is blocked by the provider. If that exit fails, this one stops too - nothing goes directly.')),
			msg,
			E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ', bAdd ])
		];
		ui.showModal(_('New exit «%s»').format(c.label || c.server), body);
	},

	renderWarp: function(onDone) {
		const name = E('input', { 'class': 'cbi-input-text', 'placeholder': 'warp1', 'maxlength': 12 });
		const awg = E('input', { 'type': 'checkbox', 'class': 'cbi-input-checkbox', 'checked': '' });
		const box = resultBox();
		const btn = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			busy(btn, true);
			return callWarpReg(name.value.trim(), awg.checked).then(function(r) {
				if (!r || r.error) return result(box, r);
				onDone(_('WARP exit %s registered (address %s, server %s).').format(r.name, r.address, r.endpoint));
			}).finally(function() { busy(btn, false); });
		} }, _('Register WARP'));
		const body = [
			row(_('Name'), name),
			row(_('AmneziaWG masking'), E('div', {}, [ awg, pkg.offer('awg', _('Masking needs AmneziaWG.')) ]), _('When plain WARP is blocked by the provider. Needs the AmneziaWG kernel module and openssl-util.')),
			actions([ btn ]), box
		];
		const warps = uci.sections('detour', 'exit').filter(function(s) { return s.warp == '1'; });
		if (warps.length) {
			const sel = E('select', { 'class': 'cbi-input-select' }, warps.map(function(s) { return E('option', { 'value': s['.name'] }, s['.name']); }));
			const box2 = resultBox();
			const btn2 = E('button', { 'class': 'btn cbi-button-negative', 'click': function() {
				if (!sel.value || !confirm(_('Remove WARP exit %s and its registration?').format(sel.value))) return;
				busy(btn2, true);
				return callWarpDel(sel.value).then(function(r) {
					if (!r || r.error) return result(box2, r);
					onDone(_('Removed%s.').format(r.deregistered ? '' : ' ' + _('(the registration could not be deleted at Cloudflare)')));
				}).finally(function() { busy(btn2, false); });
			} }, _('Remove'));
			body.push(row(_('Registered WARP exits'), sel), actions([ btn2 ]), box2);
		}
		return card(_('New Cloudflare WARP exit'), _('Registers a new free WARP device at Cloudflare and adds it as an exit.'), body);
	}
});
