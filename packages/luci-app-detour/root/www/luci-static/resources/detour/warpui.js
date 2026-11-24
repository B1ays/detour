'use strict';
'require baseclass';
'require rpc';
'require ui';
'require uci';

// Text from the router never becomes HTML: LuCI's E() puts a string child in with innerHTML, here it always
// goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

// A WARP exit (warppick.uc on the router): the Cloudflare point it lands on, its pool of addresses to move to
// (filled by a scanner tunnel next to the live one), the filters of points and countries, the pool's settings.

const callPool = rpc.declare({ object: 'detour', method: 'warp_pool', params: [ 'name' ] });
const callScan = rpc.declare({ object: 'detour', method: 'warp_scan', params: [ 'name' ] });
const callUse = rpc.declare({ object: 'detour', method: 'warp_use', params: [ 'name', 'endpoint' ] });
const callDrop = rpc.declare({ object: 'detour', method: 'warp_drop', params: [ 'name', 'endpoint' ] });
const callProto = rpc.declare({ object: 'detour', method: 'warp_proto', params: [ 'name', 'awg', 'mask' ] });

function list(v) { return Array.isArray(v) ? v : (v ? String(v).split(/[\s,]+/).filter(Boolean) : []); }
function country(cc) {
	if (!cc) return '';
	try { return new Intl.DisplayNames([ document.documentElement.lang || 'en' ], { type: 'region' }).of(cc) || cc; }
	catch (e) { return cc; }
}
function point(colo, cc) { return colo ? colo + (cc ? ' · ' + country(cc) : '') : '—'; }
function ago(ts) {
	if (!ts) return _('never');
	const s = Math.max(0, Math.floor(Date.now() / 1000) - ts);
	if (s < 90) return _('just now');
	if (s < 5400) return _('%d min ago').format(Math.round(s / 60));
	if (s < 172800) return _('%d h ago').format(Math.round(s / 3600));
	return _('%d days ago').format(Math.round(s / 86400));
}
function row(title, field, descr) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, title),
		E('div', { 'class': 'cbi-value-field' }, descr ? [ field, E('div', { 'class': 'cbi-value-description' }, descr) ] : field)
	]);
}
// the last check's tries: address, where it led, why it was not taken
const VERDICT = {
	pass: function() { return _('taken'); }, filtered: function() { return _('point filtered'); }, torn: function() { return _('cut after the handshake'); },
	hs: function() { return _('handshake, no answer'); }, none: function() { return _('no handshake'); }, error: function() { return _('error'); }
};
function lastRun(l) {
	if (!l || !(l.results || []).length) return l && l.outage ? E('p', { 'class': 'detour-bad' }, _('Last check: no address answered - WARP seems unreachable, the pool is kept.')) : '';
	return E('details', { 'class': 'detour-details' }, [
		E('summary', {}, N_(l.results.length, 'Last scan: %d address tried', 'Last scan: %d addresses tried').format(l.results.length)),
		E('table', { 'class': 'table' }, l.results.map(function(r) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, r.endpoint),
				E('td', { 'class': 'td' }, r.colo ? point(r.colo, r.country) : '—'),
				E('td', { 'class': 'td' }, E('span', { 'class': r.verdict == 'pass' ? 'detour-ok' : 'detour-muted' }, (VERDICT[r.verdict] || function() { return r.verdict; })())),
				E('td', { 'class': 'td' }, r.ms != null ? _('%d ms').format(r.ms) + (r.loss ? ', ' + r.loss + '%' : '') : '')
			]);
		}))
	]);
}
function busy(btn, on) { btn.disabled = on; btn.classList.toggle('spinning', on); }
function sleep(ms) { return new Promise(function(r) { window.setTimeout(r, ms); }); }

return baseclass.extend({
	// "Point HEL · Finland. Pool: 4 addresses, scanned 2 h ago" - filled when the pool comes
	summary: function(x) {
		const el = E('div', {}, x.colo ? _('Point %s').format(point(x.colo, x.colo_country)) : '');
		callPool(x.name).then(function(p) {
			if (!p || p.error) return;
			const good = (p.entries || []).filter(function(e) { return e.ok; }).length;
			el.replaceChildren(
				p.colo ? _('Point %s').format(point(p.colo, p.country)) + '. ' : '',
				good ? N_(good, 'Pool: %d address to move to', 'Pool: %d addresses to move to').format(good) : _('Pool: empty'),
				p.scan ? ', ' + _('scanned %s').format(ago(p.scan)) : '',
				(p.running == x.name) ? ' · ' + _('checking now…') : '');
		}).catch(function() { });
		return el;
	},

	// the pool: the addresses, "use", "remove", "scan now"
	poolDialog: function(x, onClose) {
		const body = E('div', {}, E('em', {}, _('Loading…')));
		const status = E('div', { 'class': 'detour-muted' });
		let closed = false;
		const bScan = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			busy(bScan, true);
			return callScan(x.name).then(function(r) {
				if (!r || r.error) throw new Error((r && r.error) || _('No answer from the router'));
				return watch();
			}).catch(function(e) { status.replaceChildren(E('span', { 'class': 'detour-bad' }, e.message)); })
				.finally(function() { busy(bScan, false); });
		} }, _('Scan now'));
		const act = function(btn, call, ep) {
			busy(btn, true);
			return call(x.name, ep).then(function(r) {
				if (!r || r.error) throw new Error((r && r.error) || _('No answer from the router'));
				return watch();
			}).catch(function(e) { status.replaceChildren(E('span', { 'class': 'detour-bad' }, e.message)); })
				.finally(function() { busy(btn, false); });
		};
		const draw = function(p) {
			if (!p || p.error) { body.replaceChildren(E('em', {}, (p && p.error) || _('No answer from the router'))); return; }
			const s = p.settings || {};
			const filt = [];
			if ((s.colo || []).length) filt.push(_('only points %s').format(s.colo.join(', ')));
			if ((s.xcolo || []).filter(function(c) { return c != 'NONE'; }).length) filt.push(_('without points %s').format(s.xcolo.filter(function(c) { return c != 'NONE'; }).join(', ')));
			if ((s.country || []).length) filt.push(_('only countries %s').format(s.country.map(country).join(', ')));
			if ((s.xcountry || []).length) filt.push(_('without countries %s').format(s.xcountry.map(country).join(', ')));
			const rows = [ E('tr', { 'class': 'tr table-titles' }, [ _('Address'), _('Point'), _('Ping'), _('Loss'), _('Checked'), '' ].map(function(t) { return E('th', { 'class': 'th' }, t); })) ];
			(p.entries || []).forEach(function(e) {
				const cur = e.endpoint == p.endpoint;
				const bUse = E('button', { 'class': 'btn', 'click': function() { return act(bUse, callUse, e.endpoint); } }, _('Use'));
				const bDrop = E('button', { 'class': 'btn cbi-button-negative', 'click': function() { return act(bDrop, callDrop, e.endpoint); } }, '×');
				bDrop.title = _('Remove from the pool');
				rows.push(E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td', 'data-title': _('Address') }, [ e.endpoint, cur ? E('strong', {}, ' · ' + _('now')) : '' ]),
					E('td', { 'class': 'td', 'data-title': _('Point') }, point(e.colo, e.country)),
					E('td', { 'class': 'td', 'data-title': _('Ping') }, e.ms != null ? _('%d ms').format(e.ms) : '—'),
					E('td', { 'class': 'td', 'data-title': _('Loss') }, e.loss != null ? e.loss + '%' : '—'),
					E('td', { 'class': 'td', 'data-title': _('Checked') }, e.fails ? [ ago(e.seen), E('span', { 'class': 'detour-bad' }, ' · ' + _('did not answer')) ] : ago(e.ok)),
					E('td', { 'class': 'td', 'style': 'white-space: nowrap' }, cur ? '' : [ bUse, ' ', bDrop ])
				]));
			});
			body.replaceChildren(
				E('p', {}, [ _('Now: %s, point %s.').format(p.endpoint, point(p.colo, p.country)), ' ',
					filt.length ? _('Filters: %s.').format(filt.join('; ')) : _('No filters: any point.') ]),
				(p.entries || []).length ? E('table', { 'class': 'table' }, rows)
					: E('p', { 'class': 'detour-muted' }, _('The pool is empty: no address that passes the filters was found yet.')),
				lastRun(p.last),
				E('p', { 'class': 'detour-muted' }, _('When the point is wrong or the tunnel stops, Detour moves to the best address of the pool (a few seconds). The pool is refilled through a second tunnel with the same key - the working one is not interrupted. Last scan: %s.').format(ago(p.scan))));
			status.replaceChildren((p.running || p.queued) ? E('em', {}, p.running == x.name ? _('Checking and scanning now (up to a few minutes)…') : _('Waiting for another WARP exit\'s check…')) : '');
		};
		const load = function() { return callPool(x.name).then(function(p) { if (!closed) draw(p); return p; }); };
		// while the router works on it: every 3 s
		const watch = function() {
			return sleep(1500).then(load).then(function(p) {
				if (!closed && p && (p.running || p.queued)) return sleep(1500).then(watch);
			});
		};
		ui.showModal(_('Address pool of «%s»').format(x.label), [ body, status,
			E('div', { 'class': 'right' }, [ bScan, ' ', E('button', { 'class': 'btn', 'click': function() { closed = true; ui.hideModal(); if (onClose) onClose(); } }, _('Close')) ]) ]);
		load().then(function(p) { if (p && (p.running || p.queued)) return watch(); });
	},

	// the WARP settings in the exit's edit dialog -> { nodes, save() } (save stages UCI, throws with the reason)
	fields: function(x) {
		const g = function(o) { return uci.get('detour', x.name, o); };
		const text = function(o, ph) {
			const v = list(g(o)).filter(function(c) { return c.toUpperCase() != 'NONE'; }).join(' ');
			return E('input', { 'class': 'cbi-input-text', 'value': v, 'placeholder': ph || '' });
		};
		const num = function(v, ph) { return E('input', { 'class': 'cbi-input-text', 'type': 'number', 'min': 0, 'value': v != null ? v : '', 'placeholder': ph }); };
		const colo = text('warp_colo', 'HEL ARN WAW');
		const xc = g('warp_exclude_colo');
		const xcolo = E('input', { 'class': 'cbi-input-text', 'value': xc == null ? 'DME' : list(xc).filter(function(c) { return c.toUpperCase() != 'NONE'; }).join(' ') });
		const cc = text('warp_country', 'FI SE DE');
		const xcc = text('warp_exclude_country', 'RU');
		const size = num(g('warp_pool'), '6');
		const min = num(g('warp_pool_min'), '3');
		const check = num(g('warp_check') != null ? Math.round(+g('warp_check') / 60) : null, '15');
		const every = num(g('warp_scan_every') != null ? Math.round(+g('warp_scan_every') / 3600) : null, '6');
		const ports = text('warp_ports', '891 500 1701 4500 854 878 894 908 2408');
		const budget = num(g('warp_budget'), '150');
		const isAwg = x.kind == 'amneziawg';
		const proto = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': 'wg', 'selected': isAwg ? null : '' }, 'WireGuard'),
			E('option', { 'value': 'awg', 'selected': isAwg ? '' : null }, _('AmneziaWG (masking)')) ]);
		const mask = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': '' }, isAwg ? _('keep the current one') : 'QUIC'),
			E('option', { 'value': 'quic' }, 'QUIC'), E('option', { 'value': 'dns' }, 'DNS'), E('option', { 'value': 'stun' }, 'STUN') ]);
		if (!isAwg) mask.removeChild(mask.options[1]);
		const maskRow = row(_('Imitation packet (I1)'), mask, _('What the first packet looks like to the provider. If WARP stops shaking hands, try another one.'));
		const showMask = function() { maskRow.style.display = proto.value == 'awg' ? '' : 'none'; };
		proto.addEventListener('change', showMask);
		showMask();
		const nodes = [
			E('h4', {}, _('Protocol')),
			row(_('Protocol'), proto, _('AmneziaWG masks the tunnel when the provider blocks plain WireGuard. The key and the registration stay.')),
			maskRow,
			E('h4', {}, _('Cloudflare points')),
			E('div', { 'class': 'cbi-value-description' }, _('Where the WARP tunnel lands decides what it can open: the Moscow point DME filters sites. Points are airport codes (HEL - Helsinki, ARN - Stockholm, WAW - Warsaw), countries are two-letter codes.')),
			row(_('Only these points'), colo, _('Empty: any point that is not excluded.')),
			row(_('Exclude points'), xcolo, _('DME by default. Empty: no point is excluded.')),
			row(_('Only these countries'), cc, _('Countries of the points. Empty: any.')),
			row(_('Exclude countries'), xcc),
			E('h4', {}, _('Address pool')),
			row(_('Pool size'), size, _('How many checked addresses to keep for a quick move (1-20).')),
			row(_('Refill below'), min, _('Fewer working addresses than this: the pool is refilled at the next check.')),
			row(_('Check every, min'), check, _('How often the point of the tunnel is checked. A tunnel that stops is checked at once. 0: never.')),
			row(_('Rescan every, h'), every, _('How often the pool is rechecked and refreshed with new addresses.')),
			row(_('Ports to try'), ports, _('UDP ports of WARP the scanner tries. Empty: the usual list.')),
			row(_('Scan time, s'), budget, _('How long one check with a scan may take (20-900).'))
		];
		const codes = function(el, n, what) {
			const l = list(el.value.toUpperCase());
			const re = new RegExp('^[A-Z]{' + n + '}$');
			l.forEach(function(c) { if (!re.test(c)) throw new Error(_('%s: «%s» is not a code of %d letters').format(what, c, n)); });
			return l;
		};
		const setl = function(o, l) { if (l.length) uci.set('detour', x.name, o, l); else uci.unset('detour', x.name, o); };
		const setn = function(o, el, lo, hi, mul, what) {
			const v = el.value.trim();
			if (v === '') return uci.unset('detour', x.name, o);
			const n = parseInt(v, 10);
			if (!/^\d+$/.test(v) || n < lo || n > hi) throw new Error(_('%s: a number from %d to %d').format(what, lo, hi));
			uci.set('detour', x.name, o, String(n * mul));
		};
		return {
			nodes: nodes,
			save: function() {
				const a = codes(colo, 3, _('Only these points')), b = codes(xcolo, 3, _('Exclude points'));
				const c = codes(cc, 2, _('Only these countries')), d = codes(xcc, 2, _('Exclude countries'));
				setl('warp_colo', a);
				// empty means "nothing excluded" - not the default DME
				if (b.length == 1 && b[0] == 'DME') uci.unset('detour', x.name, 'warp_exclude_colo');
				else uci.set('detour', x.name, 'warp_exclude_colo', b.length ? b : [ 'none' ]);
				setl('warp_country', c); setl('warp_exclude_country', d);
				setn('warp_pool', size, 1, 20, 1, _('Pool size'));
				setn('warp_pool_min', min, 0, 20, 1, _('Refill below'));
				setn('warp_check', check, 0, 1440, 60, _('Check every, min'));
				setn('warp_scan_every', every, 1, 168, 3600, _('Rescan every, h'));
				const pl = list(ports.value);
				pl.forEach(function(p) { if (!/^\d+$/.test(p) || +p < 1 || +p > 65535) throw new Error(_('Ports to try: «%s» is not a port').format(p)); });
				setl('warp_ports', pl);
				setn('warp_budget', budget, 20, 900, 1, _('Scan time, s'));
			},
			// after the UCI apply: the protocol / I1 change (the router rebuilds the interface)
			after: function() {
				const awg = proto.value == 'awg';
				if (awg == isAwg && !(awg && mask.value)) return Promise.resolve();
				return callProto(x.name, awg, awg ? (mask.value || (isAwg ? '' : 'quic')) : '').then(function(r) {
					if (!r || r.error) throw new Error((r && r.error) || _('No answer from the router'));
				});
			}
		};
	}
});
