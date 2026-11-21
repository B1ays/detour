'use strict';
'require baseclass';
'require rpc';
'require ui';
'require dom';

// The packages Detour uses (detourd pkg_list / pkg_run / pkg_job, detour.pkgs on the router): what each component
// gives, an action with its apk log followed in a dialog, and an offer to install a component where a page needs it.
// Text from the router (the apk log) goes in as text nodes.

const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

const callList = rpc.declare({ object: 'detour', method: 'pkg_list' });
const callJob = rpc.declare({ object: 'detour', method: 'pkg_job' });
const callRun = rpc.declare({ object: 'detour', method: 'pkg_run', params: [ 'action', 'packages' ] });

const TITLES = { detour: 'Detour', singbox: 'sing-box', xray: 'Xray', awg: 'AmneziaWG', dnsproxy: 'dnsproxy',
	zlib: 'ucode-mod-zlib', qrencode: 'qrencode', tcpdump: 'tcpdump', nlbwmon: 'nlbwmon' };

let cached = null;    // the last pkg_list answer of this page
const RESERVE = 2 * 1048576;   // left free after an install: configs, logs, the next update

function mb(b) { return '%1024.1mB'.format(b || 0); }

const ERRORS = {
	'unknown action': function() { return _('Unknown action'); },
	'no package': function() { return _('No package chosen'); }
};
function errText(e) {
	let m;
	if (ERRORS[e]) return ERRORS[e]();
	if ((m = e.match(/^another action is running: (.*)$/))) return _('Another package action is running: %s').format(m[1]);
	if ((m = e.match(/^(.+) is not removed from here$/))) return _('%s is not removed from here').format(m[1]);
	return e;
}

return baseclass.extend({
	list: function() { return callList().then(function(r) { cached = r; return r; }); },

	title: function(id) { return TITLES[id] || id; },

	size: mb,

	// does what an action adds fit into the free space (with a little left)? null: unknown (no df or no sizes)
	fits: function(add, space) {
		if (!space || add == null) return null;
		return add + RESERVE <= space.free;
	},

	// "takes 52 MiB" / "will take ≈ 54 MiB, download 18 MiB, with: a, b" / "+2 MiB" for an update
	weight: function(c) {
		if (c.installed && c.upgrade_need) return _('takes %s; the update adds %s, download %s').format(mb(c.size), mb(c.upgrade_need.add), mb(c.upgrade_need.download));
		if (c.installed) return c.size ? _('takes %s').format(mb(c.size)) : '';
		if (c.need) return (c.need.deps.length ? _('will take %s, download %s, together with: %s') : _('will take %s, download %s'))
			.format(mb(c.need.add), mb(c.need.download), c.need.deps.join(', '));
		return '';
	},

	what: function(id) {
		return ({
			detour: _('Detour itself and its web interface'),
			singbox: _('Proxy exits: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC; provider subscriptions'),
			xray: _('Xray exits: XHTTP, Xray configs, VLESS encryption, Amnezia vpn:// keys of Xray'),
			awg: _('AmneziaWG exits and the masking of WARP (a kernel module and its tools)'),
			dnsproxy: _('Encrypted DNS of the router (DoH, DoT, DoQ)'),
			zlib: _('Amnezia vpn:// keys (they are compressed)'),
			qrencode: _('QR codes of exits in «Share»'),
			tcpdump: _('The DNS log of a device («what it asks for»)'),
			nlbwmon: _('Traffic by device')
		})[id] || '';
	},

	// what an install of a component takes: all its packages, or the first the index has (one of them is enough)
	installSet: function(c) {
		const ok = function(p) { return p.available || p.upgrade || p.installed; };
		if (c.id == 'tcpdump') { const p = c.packages.filter(ok)[0]; return p ? [ p.name ] : []; }
		return c.packages.filter(function(p) { return !p.installed; }).map(function(p) { return p.name; });
	},

	// run an action and follow it in a dialog; resolves with true when it went well. done(): what to do after
	// (default: reload the page - an installed component changes what the pages offer)
	run: function(action, packages, title, done) {
		return this.follow(title, done, callRun(action, packages.join(' ')).then(function(r) {
			if (!r || r.error) throw new Error(errText((r && r.error) || _('No answer from the router')));
		}));
	},

	// follow the package action that runs now (started here, or by the router - a restore of a backup) in a
	// dialog; started: a promise that rejects when the action did not start
	follow: function(title, done, started) {
		const log = E('pre', { 'class': 'detour-log' }, '…');
		const state = E('p', {}, E('em', {}, _('Running…')));
		const close = E('button', { 'class': 'btn', 'disabled': '', 'click': function() {
			ui.hideModal();
			if (done) done(); else window.location.reload();
		} }, _('Close'));
		ui.showModal(title, [ state, log, E('div', { 'class': 'right' }, [ close ]) ]);
		return Promise.resolve(started).then(function() {
			return new Promise(function(resolve) {
				let misses = 0;
				const tick = function() {
					// an upgrade of Detour restarts the daemon: some answers are missed meanwhile
					callJob().then(function(j) {
						misses = 0;
						const s = j && j.job;
						if (s) log.textContent = s.log || '…';
						log.scrollTop = log.scrollHeight;
						if (s && !s.running) {
							dom.content(state, s.code == 0 ? E('strong', { 'class': 'detour-ok' }, _('Done.')) : E('strong', { 'class': 'detour-bad' }, _('Failed: see the log.')));
							close.disabled = false;
							return resolve(s.code == 0);
						}
						window.setTimeout(tick, 1500);
					}).catch(function() {
						if (++misses > 40) { dom.content(state, E('strong', {}, _('The router does not answer - reload the page in a minute.'))); close.disabled = false; return resolve(false); }
						window.setTimeout(tick, 2000);
					});
				};
				tick();
			});
		}).catch(function(e) {
			dom.content(state, E('strong', { 'class': 'detour-bad' }, e.message));
			close.disabled = false;
			return false;
		});
	},

	// where a page needs a component: the text and an "Install" button (or why it cannot be installed here).
	// The box disappears when the component is there after all.
	offer: function(id, text) {
		const self = this;
		const act = E('span');
		const box = E('div', { 'class': 'alert-message warning detour-offer' }, [ E('span', {}, text), ' ', act ]);
		const fill = function(r) {
			const c = ((r && r.components) || []).filter(function(x) { return x.id == id; })[0];
			if (!c) return;
			if (c.installed) { box.style.display = 'none'; return; }
			if (!c.available) {
				dom.content(act, E('span', { 'class': 'detour-muted' }, r.index_ts ? _('(the repositories of this firmware do not have it)')
					: _('(the package list was never downloaded: Components → Update the list)')));
				return;
			}
			if (c.need && self.fits(c.need.add, r.space) === false) {
				dom.content(act, E('span', { 'class': 'detour-bad' }, _('Not enough space: it needs %s, %s is free.').format(mb(c.need.add), mb(r.space.free))));
				return;
			}
			if (c.need) act.appendChild(E('span', { 'class': 'detour-muted' }, '(' + self.weight(c) + ') '));
			act.appendChild(E('button', { 'class': 'btn cbi-button-action', 'click': function(ev) {
				ev.preventDefault();
				return self.run('install', self.installSet(c), _('Installing %s').format(self.title(id)));
			} }, _('Install the component %s').format(self.title(id))));
		};
		if (cached) fill(cached); else this.list().then(fill).catch(function() {});
		return box;
	}
});
