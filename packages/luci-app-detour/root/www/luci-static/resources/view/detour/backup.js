'use strict';
'require view';
'require rpc';
'require ui';
'require fs';

// Text from the router (names of exits and servers come from subscriptions and links) never becomes HTML:
// LuCI's E() puts a string child in with innerHTML, here it always goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

// Backup and restore of Detour's settings (backup.uc). The router writes the encrypted file, the browser
// downloads it (cgi-download); a restore uploads the file (cgi-upload), shows what it holds, then applies it.
const OUT = '/tmp/detour-backup.bin';
const IN = '/tmp/detour-restore.bin';
const BEFORE = '/etc/detour/before-restore.bin';

const callCreate = rpc.declare({ object: 'detour', method: 'backup_create', params: [ 'password' ] });
const callCheck = rpc.declare({ object: 'detour', method: 'backup_check', params: [ 'password' ] });
const callRestore = rpc.declare({ object: 'detour', method: 'backup_restore', params: [ 'password' ] });

function busy(btn, on) { btn.disabled = on; btn.classList.toggle('spinning', on); }
function warnBox(box, text) { box.replaceChildren(E('div', { 'class': 'alert-message warning' }, text)); }

// what the router says is English (it also goes to the log); the known ones for people
function errText(e) {
	e = String(e || '');
	let m;
	const fixed = {
		'the password must be at least 8 characters': _('The password must be at least 8 characters.'),
		'wrong password or a damaged file': _('Wrong password, or the file is damaged.'),
		'not a Detour backup (or not encrypted)': _('This is not a Detour backup.'),
		'not a Detour backup': _('This is not a Detour backup.'),
		'no backup file': _('The file did not reach the router.'),
		'another action is running, try again in a moment': _('Another action is running, try again in a moment.'),
		'the archive is too big': _('The backup is too big.')
	};
	if (fixed[e]) return fixed[e];
	if ((m = e.match(/^the backup is from a newer Detour \((.*)\)/))) return _('The backup was made by a newer Detour (%s): update Detour first.').format(m[1]);
	if ((m = e.match(/^the router already has network interfaces with these names \(not Detour's\): (.*)$/)))
		return _('The router already has network interfaces with these names that are not Detour exits: %s. Rename or remove them first.').format(m[1]);
	if (/unsafe path|links or special files|damaged/.test(e)) return _('The backup file is damaged or was altered - refusing it.');
	return e;
}

function save(blob, name) {
	const a = E('a', { 'href': URL.createObjectURL(blob), 'download': name, 'style': 'display:none' });
	document.body.appendChild(a);
	a.click();
	setTimeout(function() { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

function stamp(t) {
	const d = t ? new Date(t * 1000) : new Date();
	const p = function(n) { return (n < 10 ? '0' : '') + n; };
	return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
}

function fileName(host, t) {
	return 'detour-' + String(host || 'router').replace(/[^A-Za-z0-9_-]/g, '') + '-' + stamp(t) + '.enbak';
}

function download(path, name) {
	return fs.read_direct(path, 'blob').then(function(blob) { save(blob, name); });
}

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
function pwInput() { return E('input', { 'type': 'password', 'class': 'cbi-input-password', 'autocomplete': 'new-password' }); }

function names(l) { return l && l.length ? l.join(', ') : _('nothing'); }

return view.extend({
	load: function() { return Promise.resolve(); },

	renderSave: function() {
		const pw = pwInput(), pw2 = pwInput();
		const box = E('div', { 'class': 'detour-result' });
		const btn = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			if (pw.value.length < 8) return warnBox(box, _('The password must be at least 8 characters.'));
			if (pw.value != pw2.value) return warnBox(box, _('The passwords differ.'));
			busy(btn, true);
			box.replaceChildren();
			return callCreate(pw.value).then(function(r) {
				if (!r || r.error) return warnBox(box, r ? errText(r.error) : _('No answer from the router'));
				const m = r.manifest || {}, c = m.count || {};
				return download(OUT, fileName(m.host, m.created)).then(function() {
					box.replaceChildren(E('div', { 'class': 'alert-message success' }, [
						E('div', {}, _('The backup is saved: %d exits, %d policies, %d lists, %d subscriptions.').format(c.exit || 0, c.policy || 0, c.list || 0, c.subscription || 0)),
						E('div', {}, _('Keep the password: without it the file cannot be restored.')) ]));
					pw.value = ''; pw2.value = '';
				});
			}).catch(function(e) { warnBox(box, e.message || String(e)); })
			.finally(function() { fs.remove(OUT).catch(function() {}); busy(btn, false); });
		} }, _('Save a backup'));
		return card(_('Save the settings'),
			_('One file with everything of Detour: exits (with their keys), policies, lists, subscriptions, notifications, router DNS, devices\' names and modes, the panel tunnel key and the traffic history. The router\'s own settings (network, Wi-Fi, passwords) are not in it - those are saved in System → Backup / Flash Firmware.'), [
			row(_('Password'), pw, _('The file holds private keys, the Telegram token and the subscription addresses, so it is always encrypted. At least 8 characters.')),
			row(_('Password again'), pw2),
			E('div', { 'class': 'detour-actions' }, [ btn ]), box
		]);
	},

	renderRestore: function() {
		const pw = E('input', { 'type': 'password', 'class': 'cbi-input-password', 'autocomplete': 'off' });
		const box = E('div', { 'class': 'detour-result' });
		const info = E('div');
		const bApply = E('button', { 'class': 'btn cbi-button-negative', 'style': 'display:none', 'click': function() {
			if (!confirm(_('Replace the current Detour settings with the backup? The tunnels restart; for a few seconds the internet may pause.'))) return;
			busy(bApply, true);
			return callRestore(pw.value).then(function(r) {
				if (!r || r.error) return warnBox(box, r ? errText(r.error) : _('No answer from the router'));
				bApply.style.display = 'none';
				info.replaceChildren();
				const n = r.restored || {};
				const bBefore = E('button', { 'class': 'btn', 'click': function() {
					return download(BEFORE, fileName('before-restore', null)).catch(function(e) { ui.addNotification(null, E('p', e.message || String(e)), 'danger'); });
				} }, _('Download the previous settings'));
				box.replaceChildren(E('div', { 'class': 'alert-message success' }, [
					E('div', {}, _('Restored: %d exits, %d policies, %d lists, %d subscriptions, %d new device names.').format(n.exits || 0, n.policies || 0, n.lists || 0, n.subscriptions || 0, n.devices || 0)),
					E('div', {}, _('Big lists and subscriptions load in the background over the next minutes.')),
					E('div', {}, _('The previous settings are kept on the router until it restarts, encrypted with the same password:')),
					E('div', { 'class': 'detour-actions' }, [ bBefore ]) ]));
			}).catch(function(e) {
				warnBox(box, _('The router did not answer in time (%s). The restore may still be running: open the Overview in a minute.').format(e.message || String(e)));
			}).finally(function() { busy(bApply, false); });
		} }, _('Restore these settings'));

		const show = function(r) {
			const m = r.manifest || {}, b = r.backup || {}, now = r.replaced || {};
			const rows = [
				E('div', {}, [ E('strong', {}, _('Backup:') + ' '), _('%s, router «%s», Detour %s').format(m.created ? new Date(m.created * 1000).toLocaleString() : '?', m.host || '?', m.version || '?') ]),
				E('div', {}, [ E('strong', {}, _('Exits:') + ' '), names(b.exits) ]),
				E('div', {}, [ E('strong', {}, _('Policies:') + ' '), names(b.policies) ]),
				E('div', {}, [ E('strong', {}, _('Lists:') + ' '), names(b.lists) ]),
				E('div', {}, [ E('strong', {}, _('Also:') + ' '), [
					N_(b.subscriptions || 0, '%d subscription', '%d subscriptions').format(b.subscriptions || 0),
					N_(b.devices || 0, '%d device name', '%d device names').format(b.devices || 0),
					b.notify ? _('Telegram notifications') : null,
					b.warp ? N_(b.warp, '%d WARP registration', '%d WARP registrations').format(b.warp) : null,
					b.panel_tunnel_key ? _('the panel tunnel key') : null,
					(b.traffic_months || []).length ? N_(b.traffic_months.length, 'traffic history: %d month', 'traffic history: %d months').format(b.traffic_months.length) : null
				].filter(function(x) { return x; }).join(', ') ]),
				E('div', { 'class': 'detour-muted', 'style': 'margin-top:.5em' }, _('What is on the router now goes away - exits: %s; policies: %s; lists: %s. Device names the router already has stay.').format(names(now.exits), names(now.policies), names(now.lists)))
			];
			if (r.missing && r.missing.length)
				rows.push(E('div', { 'class': 'alert-message warning', 'style': 'margin-top:.5em' }, _('Not installed on this router: %s. The exits that need it will not work until it is installed (System → Software).').format(r.missing.join(', '))));
			info.replaceChildren(E('div', { 'class': 'detour-lines' }, rows));
			if (r.conflicts && r.conflicts.length) {
				warnBox(box, errText('the router already has network interfaces with these names (not Detour\'s): ' + r.conflicts.join(', ')));
				bApply.style.display = 'none';
			}
			else bApply.style.display = '';
		};

		const bCheck = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			if (pw.value.length < 8) return warnBox(box, _('Enter the password of the backup first.'));
			box.replaceChildren(); info.replaceChildren(); bApply.style.display = 'none';
			return ui.uploadFile(IN).then(function() {
				busy(bCheck, true);
				return callCheck(pw.value);
			}).then(function(r) {
				if (!r || r.error) return warnBox(box, r ? errText(r.error) : _('No answer from the router'));
				show(r);
			}).catch(function(e) { if (e && e.message) warnBox(box, e.message); })
			.finally(function() { busy(bCheck, false); });
		} }, _('Choose the backup file…'));

		return card(_('Restoring the settings'),
			_('A backup saved on this page, on this router or another one. First you see what it holds; nothing changes until you confirm. Settings of an older Detour are brought up to date.'), [
			row(_('Password'), pw),
			E('div', { 'class': 'detour-actions' }, [ bCheck, bApply ]), info, box
		]);
	},

	render: function() {
		return E('div', {}, [
			E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') }),
			E('h2', {}, _('Backup')), this.renderSave(), this.renderRestore()
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
