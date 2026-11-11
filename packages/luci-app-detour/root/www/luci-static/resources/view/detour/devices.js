'use strict';
'require view';
'require rpc';
'require ui';
'require uci';
'require poll';
'require dom';
'require detour.msg as msg';

// "Devices": the home network's devices, online or not, Wi-Fi or wired, today's traffic, where each one goes
// (as configured / all through a policy / always directly / no internet), its name, and what it asks for (DNS).

const callDevices = rpc.declare({ object: 'detour', method: 'devices' });
const callTraffic = rpc.declare({ object: 'detour', method: 'traffic', params: [ 'period' ] });
const callWatch = rpc.declare({ object: 'detour', method: 'dns_watch', params: [ 'mac', 'seconds' ] });
const callWatchStop = rpc.declare({ object: 'detour', method: 'dns_watch_stop' });
const callLog = rpc.declare({ object: 'detour', method: 'dns_log', params: [ 'mac' ] });
const callExplain = rpc.declare({ object: 'detour', method: 'site_explain', params: [ 'target', 'mac' ] });

const WATCH_S = 120;

function css() { return E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') }); }
function arr(v) { return Array.isArray(v) ? v : (v ? String(v).split(/\s+/) : []); }
function size(b) { return '%1024.2mB'.format(b || 0); }
function applyUci() { return uci.save().then(function() { return ui.changes.apply(); }); }
function lcl(v) { return arr(v).map(function(x) { return x.toLowerCase(); }); }
function plab(n) { return uci.get('detour', n, 'label') || n; }
function pols() { return uci.sections('detour', 'policy').filter(function(p) { return p.action != 'block'; }); }

// where the device goes now: block / direct / pol:<name> / default
function modeOf(mac) {
	const ps = uci.sections('detour', 'policy');
	for (let i = 0; i < ps.length; i++) if (ps[i].action == 'block' && lcl(ps[i].device).indexOf(mac) >= 0) return 'block';
	if (lcl(uci.get('detour', 'direct', 'device')).indexOf(mac) >= 0) return 'direct';
	for (let i = 0; i < ps.length; i++) if (ps[i].action != 'block' && lcl(ps[i].device).indexOf(mac) >= 0) return 'pol:' + ps[i]['.name'];
	return 'default';
}

function setMode(mac, mode) {
	const drop = function(sec) {
		const cur = arr(uci.get('detour', sec, 'device'));
		const left = cur.filter(function(x) { return x.toLowerCase() != mac; });
		if (left.length != cur.length) uci.set('detour', sec, 'device', left.length ? left : null);
	};
	uci.sections('detour', 'policy').forEach(function(p) { drop(p['.name']); });
	if (uci.get('detour', 'direct')) drop('direct');
	let sec = null;
	if (mode == 'direct') { if (!uci.get('detour', 'direct')) uci.add('detour', 'direct', 'direct'); sec = 'direct'; }
	else if (mode == 'block') sec = msg.blockPolicy(uci, true);
	else if (mode.indexOf('pol:') == 0) sec = mode.substr(4);
	if (sec) uci.set('detour', sec, 'device', arr(uci.get('detour', sec, 'device')).concat([ mac ]));
	return applyUci();
}

// the device's name: the fixed-address entry of /etc/config/dhcp (made for it when there is none)
function setName(mac, name) {
	let host = uci.sections('dhcp', 'host').filter(function(h) { return lcl(h.mac).indexOf(mac) >= 0; })[0];
	if (!host) { const n = uci.add('dhcp', 'host'); uci.set('dhcp', n, 'mac', mac); host = { '.name': n }; }
	uci.set('dhcp', host['.name'], 'name', name || null);
	return applyUci();
}

function goesText(r) {
	if (!r) return '…';
	if (r.error) return '—';
	const g = r.goes;
	if (g.to == 'block') return E('span', { 'class': 'detour-warn' }, _('blocked'));
	if (g.to == 'exit') return g.exit ? _('VPN «%s»').format(g.exit.label || g.exit.name) : _('VPN (no exit works)');
	if (g.to == 'direct_down') return _('directly (exits down)');
	return _('directly');
}

return view.extend({
	load: function() {
		return Promise.all([
			callDevices().catch(function() { return null; }),
			callTraffic('day').catch(function() { return null; }),
			callLog('').catch(function() { return {}; }),
			uci.load('detour'), uci.load('dhcp')
		]);
	},

	modeSelect: function(d) {
		const cur = modeOf(d.mac);
		const opts = [ [ 'default', _('as configured (by sites and lists)') ] ]
			.concat(pols().map(function(p) { return [ 'pol:' + p['.name'], _('everything through «%s»').format(p.label || p['.name']) ]; }))
			.concat([ [ 'direct', _('always directly') ], [ 'block', _('no internet') ] ]);
		const sel = E('select', { 'class': 'cbi-input-select' }, opts.map(function(o) { return E('option', { 'value': o[0], 'selected': o[0] == cur ? '' : null }, o[1]); }));
		sel.addEventListener('change', function() {
			const v = sel.value;
			if (v == 'block' && !confirm(_('The device «%s» will have no internet at all. Continue?').format(d.title))) { sel.value = cur; return; }
			return setMode(d.mac, v);
		});
		return sel;
	},

	nameModal: function(d) {
		const input = E('input', { 'class': 'cbi-input-text', 'value': d.name || d.hostname || '', 'placeholder': 'phone-anna' });
		const err = E('div', { 'class': 'detour-warn' });
		ui.showModal(_('Device name'), [
			E('p', {}, _('Latin letters, digits and hyphens: the name is also given to the device in the local DNS (%s). Saving restarts the router\'s DNS for a few seconds.').format(d.mac)),
			input, err,
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
				E('button', { 'class': 'btn cbi-button-positive', 'click': function() {
					const v = input.value.trim();
					if (v && !/^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(v)) { err.textContent = _('Only Latin letters, digits and hyphens, up to 63.'); return; }
					ui.hideModal();
					return setName(d.mac, v);
				} }, _('Save'))
			])
		]);
	},

	// "DNS log" (what the device asks for): tcpdump for 2 minutes, the names it asks, where each goes, one click to change that
	watchModal: function(d) {
		const self = this;
		const body = E('div', { 'class': 'detour-dnslog' }, E('em', {}, _('Starting…')));
		const head = E('div', { 'class': 'detour-muted' });
		const where = {};      // name -> explain result (asked once each)
		let open = true, timer = null;
		const close = function() { open = false; if (timer) clearTimeout(timer); callWatchStop(); ui.hideModal(); };
		const actions = function(name) {
			const sel = E('select', { 'class': 'cbi-input-select' }, pols().map(function(p) { return E('option', { 'value': p['.name'] }, p.label || p['.name']); }));
			const add = function(sec) {
				const cur = arr(uci.get('detour', sec, 'domain'));
				if (cur.indexOf(name) < 0) uci.set('detour', sec, 'domain', cur.concat([ name ]));
				// applied at once, without leaving the page (the dialog keeps watching); "Goes" is asked again after
				// the daemon reloaded
				return uci.save().then(function() { return uci.apply(); }).then(function() { return uci.load('detour'); })
					.then(function() { setTimeout(function() { delete where[name]; }, 2000); });
			};
			return E('span', { 'class': 'detour-dnslog-act' }, (pols().length ? [ E('button', { 'class': 'btn', 'click': function() { return add(sel.value); } }, _('through')), sel ] : []).concat([
				E('button', { 'class': 'btn', 'click': function() { if (!uci.get('detour', 'direct')) uci.add('detour', 'direct', 'direct'); return add('direct'); } }, _('directly')),
				E('button', { 'class': 'btn cbi-button-negative', 'click': function() { return add(msg.blockPolicy(uci, true)); } }, _('block'))
			]));
		};
		const draw = function(r) {
			const left = Math.max(0, (r.until || 0) - (r.now || 0));
			head.textContent = r.running ? _('Watching: %d s left. Names asked: %d, requests: %d.').format(left, r.queries.length, r.total)
				: _('Stopped. Names asked: %d, requests: %d.').format(r.queries.length, r.total || 0);
			const notes = [];
			if (r.dot) notes.push(E('div', { 'class': 'alert-message warning' }, _('The device also uses encrypted DNS (DNS over TLS): those requests cannot be seen here, and they bypass the router\'s rules for sites.')));
			if (!r.queries.length) { body.replaceChildren.apply(body, notes.concat([ E('p', { 'class': 'detour-muted' }, r.running ? _('Nothing yet. Use the device - open an app or a site.') : _('It asked nothing. It may use encrypted DNS (DoH in the browser), which cannot be seen.')) ])); return; }
			const rows = [ E('tr', { 'class': 'tr table-titles' }, [ E('th', { 'class': 'th' }, _('Site')), E('th', { 'class': 'th' }, _('Times')), E('th', { 'class': 'th' }, _('Goes')), E('th', { 'class': 'th' }, '') ]) ];
			r.queries.slice(0, 150).forEach(function(q) {
				const cell = E('td', { 'class': 'td', 'data-title': _('Goes') }, goesText(where[q.name]));
				if (!(q.name in where)) {
					where[q.name] = null;
					callExplain(q.name, d.mac).then(function(x) { where[q.name] = x || { error: true }; dom.content(cell, goesText(where[q.name])); }, function() { where[q.name] = { error: true }; });
				}
				rows.push(E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td', 'data-title': _('Site') }, [ q.name, ' ', E('span', { 'class': 'detour-muted' }, q.types.join(' ')) ]),
					E('td', { 'class': 'td', 'data-title': _('Times') }, String(q.n)),
					cell,
					E('td', { 'class': 'td' }, actions(q.name))
				]));
			});
			body.replaceChildren.apply(body, notes.concat([ E('table', { 'class': 'table' }, rows) ]));
		};
		const tick = function() {
			if (!open) return;
			return callLog(d.mac).then(function(r) {
				if (!open || !r) return;
				draw(r);
				if (r.running) timer = setTimeout(tick, 3000);
			});
		};
		ui.showModal(_('DNS log: «%s»').format(d.title), [
			head,
			E('p', { 'class': 'detour-muted' }, _('The names the device looks up in DNS for %d s: which sites and services it reaches. A change applies to every device.').format(WATCH_S)),
			body,
			E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': close }, _('Close')) ])
		], 'detour-wide');
		return callWatch(d.mac, WATCH_S).then(function(r) {
			if (r && r.error) {
				body.replaceChildren(E('div', { 'class': 'alert-message warning' }, r.error == 'no tcpdump' ? _('This needs tcpdump: install the tcpdump-mini package.') : r.error));
				return;
			}
			timer = setTimeout(tick, 1500);
		});
	},

	card: function(d, today) {
		const self = this;
		const mode = modeOf(d.mac);
		const conn = d.wifi ? (d.wifi.signal ? _('Wi-Fi «%s», signal %d dBm').format(d.wifi.ssid || d.wifi.iface, d.wifi.signal) : _('Wi-Fi «%s»').format(d.wifi.ssid || d.wifi.iface)) : (d.online ? _('wired') : '');
		const t = today[d.mac];
		return E('div', { 'class': 'detour-card' + (d.online ? '' : ' detour-offline') }, [
			E('div', { 'class': 'detour-card-head' }, [
				E('span', { 'class': 'detour-card-title' }, d.title),
				E('button', { 'class': 'btn detour-icon-btn', 'title': _('Rename'), 'aria-label': _('Rename'), 'click': function() { self.nameModal(d); } }, '✎'),
				E('span', { 'class': 'detour-badge ' + (d.online ? 'ok' : 'off') }, d.online ? _('online') : _('offline')),
				mode == 'block' ? E('span', { 'class': 'detour-badge bad' }, _('no internet')) : '',
				E('span', { 'class': 'detour-muted' }, d.mac)
			]),
			E('div', { 'class': 'detour-card-body' }, [
				E('div', {}, [ d.ips.join(', ') || _('no address now'), conn ? ' · ' + conn : '' ]),
				t ? E('div', {}, [ E('strong', {}, _('Today:')), ' ', _('downloaded %s, uploaded %s').format(size(t.rx), size(t.tx)) ]) : ''
			]),
			E('div', { 'class': 'detour-actions detour-card-actions' }, [
				E('span', {}, _('Connection:')), this.modeSelect(d),
				E('button', { 'class': 'btn', 'click': function() { return self.watchModal(d); } }, _('DNS log'))
			])
		]);
	},

	cards: function(list, traffic) {
		const self = this;
		const today = {};
		((traffic || {}).devices || []).forEach(function(x) { today[x.mac] = x; });
		list.forEach(function(d) { d.title = d.name || d.hostname || d.ips[0] || d.mac; });
		list.sort(function(a, b) { return (b.online - a.online) || a.title.localeCompare(b.title); });
		if (!list.length) return E('p', { 'class': 'detour-muted' }, _('No devices found.'));
		return E('div', { 'class': 'detour-cards' }, list.map(function(d) { return self.card(d, today); }));
	},

	render: function(data) {
		const self = this;
		if (!data[0]) return E('div', { 'class': 'alert-message warning' }, _('The Detour service is not running.'));
		const box = E('div', { 'id': 'detour-devices' }, this.cards(data[0].devices || [], data[1]));
		poll.add(function() {
			// a page with an open select or a dialog stays as it is
			if (document.querySelector('.modal') && document.body.classList.contains('modal-overlay-active')) return;
			if (document.activeElement && document.activeElement.tagName == 'SELECT') return;
			return Promise.all([ callDevices(), callTraffic('day') ]).then(function(r) { if (r[0]) dom.content(box, self.cards(r[0].devices || [], r[1])); });
		}, 30);
		return E('div', {}, [
			css(),
			E('h2', {}, _('Devices')),
			E('div', { 'class': 'cbi-map-descr' }, _('The devices of your home network. For each: whether it is online, how it is connected, how much it downloaded today, where its internet goes, and what it asks for.')),
			(data[2] || {}).available === false ? E('div', { 'class': 'alert-message notice' }, _('The DNS log needs tcpdump: install the tcpdump-mini package.')) : '',
			E('div', { 'class': 'cbi-section' }, box)
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
