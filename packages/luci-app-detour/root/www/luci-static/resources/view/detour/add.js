'use strict';
'require view';
'require rpc';
'require ui';
'require uci';
'require detour.msg as msg';

const callParse = rpc.declare({ object: 'detour', method: 'exit_parse', params: [ 'text' ] });
const callExitAdd = rpc.declare({ object: 'detour', method: 'exit_add', params: [ 'text', 'picks', 'name', 'via', 'label' ] });
const callWarpReg = rpc.declare({ object: 'detour', method: 'warp_register', params: [ 'name', 'awg' ] });
const callWarpDel = rpc.declare({ object: 'detour', method: 'warp_unregister', params: [ 'name' ] });
const callImportCheck = rpc.declare({ object: 'detour', method: 'import_check' });
const callImportApply = rpc.declare({ object: 'detour', method: 'import_apply' });

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

function list(title, items) {
	if (!items || !items.length) return '';
	return E('div', {}, [ E('strong', {}, title), E('ul', {}, items.map(function(x) { return E('li', {}, x); })) ]);
}

const KIND = { 'wg': 'WireGuard', 'awg': 'AmneziaWG', 'xray': _('proxy (Xray)'), 'hy2': 'Hysteria2' };

// the importer explains in English what it leaves behind; the known reasons for people
function whyText(w) {
	let m;
	const fixed = {
		'"direct" fallback is fail-open in stock; here the policy is fail-closed': _('in stock it fell back to a direct connection; here a policy with no working exit blocks its traffic instead'),
		'bad port list': _('wrong list of ports'),
		'blocking/desync lists are not part of Detour for OpenWrt': _('blocking and DPI-bypass lists are not part of Detour for OpenWrt'),
		'device-bound group (src) - per-device rules are not carried over yet': _('a group for particular devices: such rules are not carried over yet'),
		'its exit could not be carried over': _('its exit could not be carried over'),
		'its exit is not carried over': _('its exit is not carried over'),
		'its file is not in the backup': _('its file is not in the backup'),
		'no http(s) URL': _('no http(s) address'),
		'not an address': _('not an address'),
		'not an address/domain': _('neither an address nor a domain'),
		'per-device port rules are not carried over': _('port rules for particular devices are not carried over'),
		'switched off in stock': _('switched off in stock'),
		'that exit is not carried over - it connects directly': _('that exit is not carried over - this one connects directly'),
		'the main policy could not be carried over': _('the main policy could not be carried over'),
		'unknown protocol': _('unknown protocol'),
		'unknown source': _('unknown source')
	};
	if (fixed[w]) return fixed[w];
	if ((m = w.match(/^action "(.+)" is not part of Detour for OpenWrt$/))) return _('the action «%s» is not part of Detour for OpenWrt').format(m[1]);
	if ((m = w.match(/^direction (.+) not supported$/))) return _('the direction «%s» is not supported').format(m[1]);
	if ((m = w.match(/^"(direct|block)" port rules are not part of Detour for OpenWrt$/))) return m[1] == 'block' ? _('port rules «block» are not part of Detour for OpenWrt') : _('port rules «direct» are not part of Detour for OpenWrt');
	if (/^not in the catalogue/.test(w)) return _('not in the catalogue (your own or an ODoH resolver) - set it in «Router DNS» on the Settings page');
	if ((m = w.match(/^(.*): no DHCP reservation for this IP, MAC unknown$/)))
		return _('%s: this address has no DHCP reservation, the device is unknown').format({ 'device past VPN': _('a device past VPN'), 'whole device via VPN': _('a whole device through VPN') }[m[1]] || m[1]);
	return w;
}
// what the stock firmware had that is deliberately left behind (importer: "not")
const LEFT = {
	'.panel-pass': [ _('panel password'), _('LuCI uses the router\'s root password') ],
	'.totp': [ _('2FA secret'), _('set up two-factor login again (luci-plugin-2fa, a new QR code)') ],
	'server': [ _('home access server'), _('set it up again (new keys)') ],
	'sched': [ _('access schedules'), _('use firewall rules with a time window') ],
	'.zapret-on': [ 'zapret', _('install the zapret package and choose a strategy') ],
	'.split-runet': [ _('split DNS for Russian domains'), _('not needed here: the router resolves names through dnsmasq') ],
	'.doh-on': [ _('encrypted DNS'), _('choose it in «Router DNS» on the Settings page') ],
	'.warp-reg': [ _('WARP registration'), _('register WARP again here (a new device)') ]
};
function skippedText(s) {
	if (LEFT[s.what]) return LEFT[s.what][0] + ': ' + LEFT[s.what][1];
	return whatText(s.what) + ': ' + whyText(s.why);
}
function whatText(w) {
	let m;
	if ((m = w.match(/^group (.+) member (.+)$/))) return _('group «%s», entry %s').format(m[1], m[2]);
	if ((m = w.match(/^group (.+)$/))) return _('group «%s»').format(m[1]);
	if ((m = w.match(/^extra exit s(\d)( fallback)?$/))) return m[2] ? _('extra exit %d: falling back').format(+m[1]) : _('extra exit %d').format(+m[1]);
	if ((m = w.match(/^device (.+)$/))) return _('device %s').format(m[1]);
	if ((m = w.match(/^list (\S+) source (.+)$/))) return _('list %s, source %s').format(m[1], m[2]);
	if ((m = w.match(/^\.(vpn|bypass)-dst (.+)$/))) return (m[1] == 'vpn' ? _('through VPN: %s') : _('past VPN: %s')).format(m[2]);
	if (w == 'main policy') return _('the main policy');
	if ((m = w.match(/^port rule (\S+) (\S+) -> (\S+)$/)))
		return _('port rule %s for %s → %s').format(m[2], m[1] == 'any' ? _('the whole network') : m[1],
			{ 'vpn': 'VPN', 'direct': _('directly'), 'block': _('block') }[m[3]] || m[3]);
	if ((m = w.match(/^geo category (.+)$/))) return _('geo category %s').format(m[1]);
	if ((m = w.match(/^lists\/(.+)$/))) return _('stock lists «%s»').format(m[1]);
	return w;
}

// what an import will carry over, as people will then see it on the pages
function preview(r) {
	const p = r.preview;
	const cnt = function(x) {
		const a = [];
		if (x.dst) a.push(N_(x.dst, '%d address', '%d addresses').format(x.dst));
		if (x.domain) a.push(N_(x.domain, '%d site', '%d sites').format(x.domain));
		if (x.device) a.push(N_(x.device, '%d device', '%d devices').format(x.device));
		if (x.port && x.port.length) a.push(_('ports %s').format(x.port.join(', ')));
		return a.length ? a.join(', ') : _('nothing yet');
	};
	return E('div', {}, [
		list(_('Exits'), p.exits.map(function(e) {
			return E('span', {}, [ E('strong', {}, e.label), ' · ' + (KIND[e.kind] || e.kind), e.via ? ' · ' + _('connects through «%s»').format(e.via) : '' ]);
		})),
		list(_('Policies'), p.policies.map(function(x) {
			return E('span', {}, [ E('strong', {}, x.label), ': ' + x.exits.map(function(n) { return '«' + n + '»'; }).join(' → ') + ' · ' + cnt(x) ]);
		})),
		list(_('Lists'), p.lists.map(function(l) {
			return E('span', {}, [ E('strong', {}, msg.listTitle({ url: l.url, '.name': '' }) || _('own entries')),
				' · ' + (l.direct ? _('never through a tunnel') : _('through the policy «%s»').format(l.policy)) + (l.local ? ' · ' + _('with own entries') : '') ]);
		})),
		list(_('Subscriptions'), p.subscriptions.map(function(s) { return E('span', {}, [ E('strong', {}, s.label), ' · ' + _('the address stays secret') ]); })),
		(p.direct.dst + p.direct.device + p.direct.domain) ? E('div', {}, _('Always direct: %s').format(cnt(p.direct))) : '',
		r.notify ? E('div', {}, _('Telegram notifications')) : '',
		r.dns ? E('div', {}, _('Encrypted DNS: %s').format(r.dns)) : '',
		r.dhcp_hosts ? E('div', {}, N_(r.dhcp_hosts, '%d DHCP reservation', '%d DHCP reservations').format(r.dhcp_hosts)) : '',
		list(_('Not carried over'), p.skipped.map(skippedText))
	]);
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
		let checks = [];

		const bAdd = E('button', { 'class': 'btn cbi-button-action', 'style': 'display:none', 'click': function() {
			const picks = [];
			checks.forEach(function(c, i) { if (c && c.checked) picks.push(i); });
			if (!picks.length) { box.replaceChildren(E('div', { 'class': 'alert-message warning' }, _('Tick at least one server.'))); return; }
			if (!/^[a-z][a-z0-9_]{0,10}$/.test(name.value.trim())) { box.replaceChildren(E('div', { 'class': 'alert-message warning' }, _('Name: Latin letters, digits and _, up to 11, starting with a letter.'))); return; }
			busy(bAdd, true);
			return callExitAdd(text.value, picks, name.value.trim(), via.value, '').then(function(r) {
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
				checks = [];
				const usable = r.candidates.filter(function(c) { return !c.error; }).length;
				found.replaceChildren.apply(found, r.candidates.map(function(c, i) {
					if (c.error) { checks.push(null); return E('div', { 'class': 'detour-muted' }, '✕ ' + errText(c.error)); }
					const cb = E('input', { 'type': 'checkbox', 'checked': '' });
					checks.push(cb);
					return E('label', { 'class': 'detour-server' }, [ cb, ' ', E('span', {}, [ E('strong', {}, c.label || (c.server + ':' + c.port)),
						E('span', { 'class': 'detour-muted' }, ' ' + [ c.proto || KIND[c.kind], c.server + ':' + c.port, KIND[c.kind] ].filter(function(x) { return x; }).join(' · ') + (c.warp ? ' · Cloudflare WARP' : '')) ]) ]);
				}));
				if (!usable) { bAdd.style.display = 'none'; box.replaceChildren(E('div', { 'class': 'alert-message warning' }, _('Nothing here can become an exit.'))); return; }
				bAdd.style.display = '';
				if (usable > 1) box.replaceChildren(E('div', { 'class': 'detour-muted' }, _('Several servers: each ticked one becomes its own exit, named %s1, %s2…').format(name.value || 'name', name.value || 'name')));
			}).finally(function() { busy(bParse, false); });
		} }, _('Check what is inside'));

		return card(_('Exit from a link, a key or a file'),
			_('Paste one or more links (vless, vmess, trojan, ss, hysteria2, tuic, wireguard), an Amnezia vpn:// key, a WireGuard / AmneziaWG config, a sing-box or Xray JSON or a Clash YAML - or choose such a file. Proxies run on sing-box (Xray for Xray configs), WireGuard and AmneziaWG on the router itself.'), [
			row(_('Link, key or config'), E('div', {}, [ text, E('div', { 'class': 'detour-actions' }, [ bFile, file ]) ])),
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

	renderImport: function() {
		const box = resultBox();
		const applyBtn = E('button', { 'class': 'btn cbi-button-positive', 'style': 'display:none', 'click': function() {
			busy(applyBtn, true);
			return callImportApply().then(function(r) {
				if (!r || r.error) return result(box, r);
				box.replaceChildren(E('div', { 'class': 'alert-message success' }, [ _('Imported.'), list('', r.applied) ]));
				applyBtn.style.display = 'none';
			}).finally(function() { busy(applyBtn, false); });
		} }, _('Import these settings'));
		const btn = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			return ui.uploadFile('/tmp/detour-import.tgz').then(function() {
				busy(btn, true);
				return callImportCheck();
			}).then(function(r) {
				if (!r || r.error) { applyBtn.style.display = 'none'; return result(box, r); }
				box.replaceChildren(r.preview ? preview(r) : E('div', {}, [
					list(_('Exits'), r.exits), list(_('Policies'), r.policies), list(_('Lists'), r.lists),
					list(_('Subscriptions'), r.subscriptions),
					E('div', {}, _('Always direct: %s').format(r.direct)),
					list(_('Not carried over'), r.not_carried_over)
				]));
				applyBtn.style.display = '';
			}).catch(function(e) { ui.addNotification(null, E('p', e.message || e), 'danger'); })
			.finally(function() { busy(btn, false); });
		} }, _('Choose the backup file…'));
		return card(_('Import from Detour for stock firmware'),
			_('The settings backup (.tar.gz) saved in the old Detour panel. First you see what will be carried over; nothing changes until you confirm.'), [
			actions([ btn, applyBtn ]), box
		]);
	},

	render: function() {
		return E('div', {}, [
			E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') }),
			E('h2', {}, _('Add and import')), this.renderLink(), this.renderWarp(), this.renderImport()
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
