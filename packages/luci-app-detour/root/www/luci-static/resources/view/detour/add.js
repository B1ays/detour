'use strict';
'require view';
'require rpc';
'require ui';
'require uci';

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

return view.extend({
	load: function() { return uci.load('detour'); },

	renderLink: function() {
		const name = E('input', { 'class': 'cbi-input-text', 'placeholder': 'vless1', 'maxlength': 11 });
		const link = E('textarea', { 'class': 'cbi-input-textarea', 'rows': 3, 'style': 'width:100%', 'placeholder': 'vless://… / ss://… / trojan://… / hysteria2://…' });
		const via = E('select', { 'class': 'cbi-input-select' }, [ E('option', { 'value': '' }, _('directly')) ].concat(
			uci.sections('detour', 'exit').map(function(s) { return E('option', { 'value': s['.name'] }, _('through %s').format(s.label || s['.name'])); })));
		const box = E('div');
		const btn = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			busy(btn, true);
			return callEngineAdd(name.value.trim(), link.value.trim(), via.value).then(function(r) {
				result(box, r, function(x) { return _('Exit %s added (%s to %s). Put it into a policy on the Policies page.').format(x.name, x.type, x.server); });
			}).finally(function() { busy(btn, false); });
		} }, _('Add exit'));
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Exit from a link')),
			E('p', {}, _('A link from your VPN provider or your own server. The exit runs on sing-box (install the sing-box package).')),
			E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('Name')), E('div', { 'class': 'cbi-value-field' }, name) ]),
			E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('Link')), E('div', { 'class': 'cbi-value-field' }, link) ]),
			E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('Connect to the server')), E('div', { 'class': 'cbi-value-field' }, [ via,
				E('div', { 'class': 'cbi-value-description' }, _('Through another exit (for example WARP) when the server itself is blocked by the provider. If that exit fails, this one stops too - nothing goes directly.')) ]) ]),
			btn, box
		]);
	},

	renderWarp: function() {
		const name = E('input', { 'class': 'cbi-input-text', 'placeholder': 'warp1', 'maxlength': 12 });
		const awg = E('input', { 'type': 'checkbox' });
		const box = E('div');
		const btn = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			busy(btn, true);
			return callWarpReg(name.value.trim(), awg.checked).then(function(r) {
				result(box, r, function(x) { return _('WARP exit %s registered (address %s, server %s).').format(x.name, x.address, x.endpoint); });
			}).finally(function() { busy(btn, false); });
		} }, _('Register WARP'));
		const warps = uci.sections('detour', 'exit').filter(function(s) { return s.warp == '1'; });
		const sel = E('select', { 'class': 'cbi-input-select' }, warps.map(function(s) { return E('option', { 'value': s['.name'] }, s['.name']); }));
		const box2 = E('div');
		const btn2 = E('button', { 'class': 'btn cbi-button-negative', 'click': function() {
			if (!sel.value || !confirm(_('Remove WARP exit %s and its registration?').format(sel.value))) return;
			busy(btn2, true);
			return callWarpDel(sel.value).then(function(r) {
				result(box2, r, function(x) { return _('Removed%s.').format(x.deregistered ? '' : _(' (the registration could not be deleted at Cloudflare)')); });
			}).finally(function() { busy(btn2, false); });
		} }, _('Remove'));
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Cloudflare WARP')),
			E('p', {}, _('Registers a new free WARP device at Cloudflare and adds it as an exit.')),
			E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('Name')), E('div', { 'class': 'cbi-value-field' }, name) ]),
			E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('AmneziaWG masking')), E('div', { 'class': 'cbi-value-field' }, [ awg,
				E('div', { 'class': 'cbi-value-description' }, _('When plain WARP is blocked by the provider. Needs the AmneziaWG kernel module and openssl-util.')) ]) ]),
			btn, box,
			warps.length ? E('div', { 'style': 'margin-top:1em' }, [ sel, ' ', btn2, box2 ]) : ''
		]);
	},

	renderImport: function() {
		const box = E('div');
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
				box.replaceChildren(E('div', {}, [
					list(_('Exits'), r.exits), list(_('Policies'), r.policies), list(_('Lists'), r.lists),
					E('p', {}, _('Always direct: %s').format(r.direct)),
					r.notify ? E('p', {}, _('Notifications: %s').format(r.notify)) : '',
					E('p', {}, _('DHCP reservations: %d').format(r.dhcp_hosts || 0)),
					list(_('Not carried over'), r.not_carried_over)
				]));
				applyBtn.style.display = '';
			}).catch(function(e) { ui.addNotification(null, E('p', e.message || e), 'danger'); })
			.finally(function() { busy(btn, false); });
		} }, _('Choose the backup file…'));
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Import from Detour for stock firmware')),
			E('p', {}, _('The settings backup (.tar.gz) saved in the old Detour panel. First you see what will be carried over; nothing changes until you confirm.')),
			btn, ' ', applyBtn, box
		]);
	},

	render: function() {
		return E('div', {}, [ E('h2', {}, _('Add and import')), this.renderLink(), this.renderWarp(), this.renderImport() ]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
