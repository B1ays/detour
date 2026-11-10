'use strict';
'require view';
'require rpc';
'require ui';
'require uci';
'require detour.msg as msg';

const callEngineAdd = rpc.declare({ object: 'detour', method: 'engine_add', params: [ 'name', 'link', 'via' ] });
const callWarpReg = rpc.declare({ object: 'detour', method: 'warp_register', params: [ 'name', 'awg' ] });
const callWarpDel = rpc.declare({ object: 'detour', method: 'warp_unregister', params: [ 'name' ] });
const callImportCheck = rpc.declare({ object: 'detour', method: 'import_check' });
const callImportApply = rpc.declare({ object: 'detour', method: 'import_apply' });

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

	renderLink: function() {
		const name = E('input', { 'class': 'cbi-input-text', 'placeholder': 'vless1', 'maxlength': 11 });
		const link = E('textarea', { 'class': 'cbi-input-textarea', 'rows': 3, 'placeholder': 'vless://… / ss://… / trojan://… / hysteria2://…' });
		const via = E('select', { 'class': 'cbi-input-select' }, [ E('option', { 'value': '' }, _('directly')) ].concat(
			uci.sections('detour', 'exit').map(function(s) { return E('option', { 'value': s['.name'] }, _('through %s').format(s.label || s['.name'])); })));
		const box = resultBox();
		const btn = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			busy(btn, true);
			return callEngineAdd(name.value.trim(), link.value.trim(), via.value).then(function(r) {
				result(box, r, function(x) { return _('Exit %s added (%s to %s). Put it into a policy on the Policies page.').format(x.name, x.type, x.server); });
			}).finally(function() { busy(btn, false); });
		} }, _('Add exit'));
		return card(_('Exit from a link'),
			_('A link from your VPN provider or your own server. The exit runs on sing-box (install the sing-box package).'), [
			row(_('Name'), name),
			row(_('Link'), link),
			row(_('Connect to the server'), via,
				_('Through another exit (for example WARP) when the server itself is blocked by the provider. If that exit fails, this one stops too - nothing goes directly.')),
			actions([ btn ]), box
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
			E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') }),
			E('h2', {}, _('Add and import')), this.renderLink(), this.renderWarp(), this.renderImport()
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
