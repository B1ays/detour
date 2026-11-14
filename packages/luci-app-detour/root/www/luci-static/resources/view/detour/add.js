'use strict';
'require view';
'require rpc';
'require uci';

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
	if (/the ucode-mod-zlib package is needed/.test(e)) return _('this key needs the ucode-mod-zlib package (System → Software)');
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

return view.extend({
	load: function() { return uci.load('detour'); },

	// an exit from whatever a person has: one or more links, an Amnezia key, a WireGuard config, a JSON or a Clash
	// YAML - pasted or from a file. First what was found, then the chosen ones become exits.
	renderLink: function() {
		const KIND = { 'wg': 'WireGuard', 'awg': 'AmneziaWG', 'singbox': 'sing-box', 'xray': 'Xray' };
		const text = E('textarea', { 'class': 'cbi-input-textarea detour-code', 'rows': 5, 'spellcheck': 'false',
			'placeholder': 'vless://… ss://… trojan://… hysteria2://… tuic://… wireguard://… vpn://…\n[Interface] …\n{ "outbounds": … }\nproxies: …' });
		const file = E('input', { 'type': 'file', 'accept': '.conf,.json,.yaml,.yml,.txt,text/*', 'style': 'display:none', 'change': function() {
			const f = file.files[0];
			if (!f) return;
			if (f.size > 256 * 1024) { box.replaceChildren(E('div', { 'class': 'alert-message warning' }, _('The file is too big for a config (over 256 KB).'))); return; }
			const r = new FileReader();
			r.onload = function() { text.value = r.result; if (!name.value) name.value = (f.name.replace(/\.[^.]*$/, '').toLowerCase().replace(/[^a-z0-9_]/g, '').replace(/^[^a-z]+/, '') || '').slice(0, 11); found.replaceChildren(); };
			r.readAsText(f);
		} });
		const bFile = E('button', { 'class': 'btn', 'click': function() { file.click(); } }, _('Choose a file…'));
		const name = E('input', { 'class': 'cbi-input-text', 'placeholder': 'vless1', 'maxlength': 11 });
		const via = E('select', { 'class': 'cbi-input-select' }, [ E('option', { 'value': '' }, _('directly')) ].concat(
			uci.sections('detour', 'exit').map(function(s) { return E('option', { 'value': s['.name'] }, _('through %s').format(s.label || s['.name'])); })));
		const found = E('div', { 'class': 'detour-servers' });
		const box = resultBox();
		let checks = [], engs = [];

		const bAdd = E('button', { 'class': 'btn cbi-button-action', 'style': 'display:none', 'click': function() {
			const picks = [];
			checks.forEach(function(c, i) { if (c && c.checked) picks.push(i); });
			if (!picks.length) { box.replaceChildren(E('div', { 'class': 'alert-message warning' }, _('Tick at least one server.'))); return; }
			if (!/^[a-z][a-z0-9_]{0,10}$/.test(name.value.trim())) { box.replaceChildren(E('div', { 'class': 'alert-message warning' }, _('Name: Latin letters, digits and _, up to 11, starting with a letter.'))); return; }
			busy(bAdd, true);
			const chosen = engs.map(function(s) { return s ? s.value : ''; });
			return callExitAdd(text.value, picks, name.value.trim(), via.value, '', chosen).then(function(r) {
				if (r && r.error) r.error = r.error.split('; ').map(errText).join('; ');
				result(box, r, function(x) {
					const names = (x.added || []).map(function(a) { return a.name; }).join(', ');
					return E('div', {}, [ E('div', {}, N_((x.added || []).length, 'Exit %s added. Put it into a policy on the Policies page.', 'Exits %s added. Put them into a policy on the Policies page.').format(names)),
						(x.notes && x.notes.length) ? E('div', { 'class': 'detour-muted' }, x.notes.map(errText).join('; ')) : '' ]);
				});
				if (r && !r.error) { text.value = ''; found.replaceChildren(); bAdd.style.display = 'none'; }
			}).finally(function() { busy(bAdd, false); });
		} }, _('Add the chosen'));

		const bParse = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			if (!text.value.trim()) return;
			busy(bParse, true);
			box.replaceChildren();
			return callParse(text.value).then(function(r) {
				if (!r || r.error) { found.replaceChildren(); bAdd.style.display = 'none'; return result(box, r && r.error ? { error: errText(r.error) } : r); }
				checks = []; engs = [];
				const have = r.installed || {};
				const usable = r.candidates.filter(function(c) { return !c.error; }).length;
				found.replaceChildren.apply(found, r.candidates.map(function(c, i) {
					if (c.error) { checks.push(null); engs.push(null); return E('div', { 'class': 'detour-muted' }, '✕ ' + errText(c.error)); }
					const cb = E('input', { 'type': 'checkbox', 'checked': '' });
					checks.push(cb);
					// a server both engines run: which one (the one not installed is shown, but cannot be chosen)
					const many = (c.engines || []).length > 1;
					const sel = many ? E('select', { 'class': 'cbi-input-select detour-engine', 'title': _('Engine') }, c.engines.map(function(e) {
						return E('option', { 'value': e, 'selected': e == c.kind ? '' : null, 'disabled': have[e] === false ? '' : null },
							KIND[e] + (have[e] === false ? ' - ' + _('not installed') : ''));
					})) : null;
					engs.push(sel);
					const one = (c.engines || []).length == 1 && c.kind != 'wg' && c.kind != 'awg';
					return E('div', { 'class': 'detour-server-row' }, [
						E('label', { 'class': 'detour-server' }, [ cb, ' ', E('span', {}, [ E('strong', {}, c.label || (c.server + ':' + c.port)),
							E('span', { 'class': 'detour-muted' }, ' ' + [ c.proto || KIND[c.kind], c.server + ':' + c.port, (many ? null : KIND[c.kind]) ].filter(function(x) { return x; }).join(' · ') + (c.warp ? ' · Cloudflare WARP' : '')) ]) ]),
						sel ? E('label', { 'class': 'detour-engine-pick' }, [ E('span', { 'class': 'detour-muted' }, _('Engine:')), ' ', sel ]) : '',
						(one && have[c.kind] === false) ? E('span', { 'class': 'detour-warn' }, _('%s is not installed').format(KIND[c.kind])) : ''
					]);
				}));
				if (!usable) { bAdd.style.display = 'none'; box.replaceChildren(E('div', { 'class': 'alert-message warning' }, _('Nothing here can become an exit.'))); return; }
				bAdd.style.display = '';
				if (usable > 1) box.replaceChildren(E('div', { 'class': 'detour-muted' }, _('Several servers: each ticked one becomes its own exit, named %s1, %s2…').format(name.value || 'name', name.value || 'name')));
			}).finally(function() { busy(bParse, false); });
		} }, _('Check what is inside'));

		return card(_('Exit from a link, a key or a file'),
			_('Paste one or more links (vless, vmess, trojan, ss, hysteria2, tuic, wireguard), an Amnezia vpn:// key, a WireGuard / AmneziaWG config, a sing-box or Xray JSON or a Clash YAML - or choose such a file. Proxies run on sing-box or Xray: where both can, you choose; XHTTP only on Xray, HTTP/2, Hysteria2 and TUIC only on sing-box. WireGuard and AmneziaWG run on the router itself.'), [
			row(_('Link, key or config'), E('div', {}, [ text, E('div', { 'class': 'detour-actions detour-field-actions' }, [ bFile, file ]) ])),
			row(_('Name'), name, _('Latin letters, digits and _, up to 11. Several servers: name1, name2…')),
			row(_('Connect to the server'), via,
				_('Through another exit (for example WARP) when the server itself is blocked by the provider. If that exit fails, this one stops too - nothing goes directly. WireGuard always connects directly.')),
			actions([ bParse, bAdd ]), found, box
		]);
	},

	renderWarp: function() {
		const name = E('input', { 'class': 'cbi-input-text', 'placeholder': 'warp1', 'maxlength': 12 });
		const awg = E('input', { 'type': 'checkbox', 'class': 'cbi-input-checkbox', 'checked': '' });
		const box = resultBox();
		const btn = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			busy(btn, true);
			return callWarpReg(name.value.trim(), awg.checked).then(function(r) {
				result(box, r, function(x) { return _('WARP exit %s registered (address %s, server %s).').format(x.name, x.address, x.endpoint); });
			}).finally(function() { busy(btn, false); });
		} }, _('Register WARP'));
		const body = [
			row(_('Name'), name),
			row(_('AmneziaWG masking'), awg, _('When plain WARP is blocked by the provider. Needs the AmneziaWG kernel module and openssl-util.')),
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
					result(box2, r, function(x) { return _('Removed%s.').format(x.deregistered ? '' : ' ' + _('(the registration could not be deleted at Cloudflare)')); });
				}).finally(function() { busy(btn2, false); });
			} }, _('Remove'));
			body.push(row(_('Registered WARP exits'), sel), actions([ btn2 ]), box2);
		}
		return card(_('Cloudflare WARP'), _('Registers a new free WARP device at Cloudflare and adds it as an exit.'), body);
	},

	render: function() {
		return E('div', {}, [
			E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') }),
			E('h2', {}, _('Add an exit')), this.renderLink(), this.renderWarp()
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
