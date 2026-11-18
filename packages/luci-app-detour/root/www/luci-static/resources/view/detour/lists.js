'use strict';
'require view';
'require detour.load as pdata';
'require rpc';
'require ui';
'require uci';
'require detour.msg as msg';

// Text from the router (names of exits and servers come from subscriptions and links) never becomes HTML:
// LuCI's E() puts a string child in with innerHTML, here it always goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

// Big lists as cards: a readable name (its label, else what its source is), where it goes (the policy by its
// name, or never through a tunnel), its sources, its state; Update now / Edit / Turn off / Remove in one row.
// Adding: a ready-made category in one click, or own sources.

const callStatus = rpc.declare({ object: 'detour', method: 'status' });
const callUpdate = rpc.declare({ object: 'detour', method: 'lists_update', params: [ 'name' ] });
const callCatNames = rpc.declare({ object: 'detour', method: 'catalog_names' });
const callCatRefresh = rpc.declare({ object: 'detour', method: 'catalog_refresh' });

function busy(btn, on) { btn.disabled = on; btn.classList.toggle('spinning', on); }
function note(text, cls) { return E('div', { 'class': 'alert-message ' + (cls || 'notice') }, text); }
function arr(v) { return Array.isArray(v) ? v : (v ? String(v).split(/\s+/) : []); }
function applyUci() { return uci.save().then(function() { return ui.changes.apply(); }); }

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
		return Promise.resolve().then(function() { return onSave(); }).then(function(done) { if (done) ui.hideModal(); })
			.catch(function(e) { box.replaceChildren(note(e.message || String(e), 'warning')); })
			.finally(function() { busy(save, false); });
	} }, saveText || _('Save'));
	ui.showModal([ title ], [ E('div', { 'class': 'detour-node' }, body), box,
		E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ', save ]) ]);
}

// lists-update writes English messages (they also go to the log); the known ones are shown translated
function failText(m) {
	let x, kept = / ?;? previous data kept$/.test(m);
	m = m.replace(/;? ?previous data kept$/, '');
	let t = m;
	if ((x = m.match(/^download failed: (.+)$/))) t = _('download failed: %s').format(msg.sourceText(x[1]));
	else if ((x = m.match(/^only (\d+) entries \(minimum (\d+)\)$/))) t = _('only %d entries (minimum %d)').format(+x[1], +x[2]);
	else if ((x = m.match(/^file missing: (.+)$/))) t = _('file missing: %s').format(x[1]);
	else if ((x = m.match(/^unknown policy '(.+)'$/))) t = _('unknown policy %s').format(x[1]);
	else if ((x = m.match(/^not enough memory: needs ~([0-9.]+) MB, ([0-9.]+) MB left for lists$/))) t = _('not enough memory on the router: it needs ~%s MB more, %s MB are left for lists').format(x[1], x[2]);
	else if ((x = m.match(/^download too big for the memory: over (\d+) MB$/))) t = _('the download is bigger than the memory can take (over %d MB)').format(+x[1]);
	return kept ? t + '; ' + _('the previous list stays in use') : t;
}

function mbs(b) { const m = Math.max(0, b / 1048576); return m < 10 ? m.toFixed(1) : String(Math.round(m)); }

function policyLabel(n) {
	if (uci.get('detour', n, '.type') != 'policy') return _('nowhere: its policy «%s» no longer exists - choose another in «Edit»').format(n);
	if (uci.get('detour', n, 'action') == 'block') return _('blocked (the policy «%s»)').format(uci.get('detour', n, 'label') || n);
	if (uci.get('detour', n, 'action') == 'direct') return _('never through a tunnel (the policy «%s»)').format(uci.get('detour', n, 'label') || n);
	return _('through the policy «%s»').format(uci.get('detour', n, 'label') || n);
}

return view.extend({
	load: function() {
		return pdata.all({ cfg: uci.load('detour'), status: L.resolveDefault(callStatus(), {}) });
	},

	renderList: function(l, st) {
		const self = this;
		const name = l['.name'];
		const s = st[name];
		const enabled = l.enabled != '0';
		const body = [ E('div', {}, [ E('strong', {}, (_('Goes:') + ' ')), policyLabel(l.policy || '') ]) ];
		const srcs = arr(l.url).map(function(u) { return msg.sourceText(u); });
		if (l.file) srcs.push(_('file %s').format(l.file));
		if (srcs.length) body.push(E('div', { 'class': 'detour-muted' }, _('Source: %s').format(srcs.join(', '))));
		if (s) {
			const kind = { 'cidr': _('addresses'), 'domain': _('domains') }[s.kind] || '';
			body.push(E('div', {}, [ N_(s.count || 0, '%d entry', '%d entries').format(s.count || 0), kind ? ' · ' + kind : '',
				s.ts ? ' · ' + _('updated %s').format(new Date(s.ts * 1000).toLocaleString()) : '',
				s.upstream ? ' · ' + _('the source changed %s').format(new Date(s.upstream).toLocaleDateString()) : '' ]));
			if (!s.ok && s.message) body.push(note(failText(s.message), 'warning'));
		}
		else if (enabled) body.push(E('em', {}, _('not loaded yet')));

		const bUpdate = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			busy(bUpdate, true);
			return callUpdate(name).then(function(r) {
				if (r && r.error) ui.addNotification(null, E('p', r.error), 'danger');
				else location.reload();
			}).finally(function() { busy(bUpdate, false); });
		} }, _('Update now'));
		const bEdit = E('button', { 'class': 'btn', 'click': function() { self.edit(l); } }, _('Edit'));
		const bToggle = E('button', { 'class': 'btn', 'click': function() { uci.set('detour', name, 'enabled', enabled ? '0' : '1'); return applyUci(); } },
			enabled ? _('Turn off') : _('Turn on'));
		const bRemove = E('button', { 'class': 'btn cbi-button-negative', 'click': function() {
			ui.showModal([ _('Remove the list «%s»?').format(msg.listTitle(l)) ], [
				E('p', {}, _('What came only from this list goes directly from now on.')),
				E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
					E('button', { 'class': 'btn cbi-button-negative', 'click': function() { uci.remove('detour', name); ui.hideModal(); return applyUci(); } }, _('Remove')) ]) ]);
		} }, _('Remove'));

		return E('div', { 'class': 'detour-card' }, [
			E('div', { 'class': 'detour-card-head' }, [ E('span', { 'class': 'detour-card-title' }, msg.listTitle(l)), ' ',
				E('span', { 'class': 'detour-badge ' + (!enabled ? 'off' : (s && !s.ok ? 'bad' : 'ok')) }, !enabled ? _('switched off') : (s && !s.ok ? _('update failed') : _('on'))),
				E('span', { 'class': 'detour-muted', 'title': _('Internal name: used in the configuration and the log') }, name) ]),
			E('div', { 'class': 'detour-card-body' }, body),
			E('div', { 'class': 'detour-actions detour-card-actions' }, [ bUpdate, bEdit, bToggle, bRemove ])
		]);
	},

	policySelect: function(cur) {
		// "never through a tunnel" / "block": the direct / blocking policy, made on save when there is none yet
		const opts = uci.sections('detour', 'policy').map(function(p) {
			const k = msg.policyKind(p), l = p.label || p['.name'];
			return E('option', { 'value': p['.name'], 'selected': cur == p['.name'] ? '' : null },
				k == 'block' ? _('block (the policy «%s»)').format(l) : (k == 'direct' ? _('never through a tunnel (the policy «%s»)').format(l) : _('through the policy «%s»').format(l)));
		});
		if (!msg.directPolicy(uci)) opts.push(E('option', { 'value': '__direct' }, _('never through a tunnel')));
		if (!msg.blockPolicy(uci)) opts.push(E('option', { 'value': '__block' }, _('block')));
		return E('select', { 'class': 'cbi-input-select' }, opts);
	},

	// pre: { name, url, kind, label } - a new list from the catalogue
	edit: function(l, pre) {
		const isNew = !l;
		l = l || {};
		const name = E('input', { 'class': 'cbi-input-text', 'placeholder': 'yt', 'maxlength': 20 });
		const preset = E('select', { 'class': 'cbi-input-select' }, [ E('option', { 'value': '' }, _('— own sources (below) —')) ]
			.concat(msg.PRESETS.map(function(p) { return E('option', { 'value': p[0] }, p[1]); })));
		const label = E('input', { 'class': 'cbi-input-text', 'value': l.label || '', 'placeholder': isNew ? '' : msg.listTitle(l) });
		const policy = this.policySelect(l.policy || (uci.sections('detour', 'policy')[0] || {})['.name']);
		const url = E('textarea', { 'class': 'cbi-input-textarea', 'rows': 3, 'placeholder': 'https://…\nv2fly:youtube' }, arr(l.url).join('\n'));
		const file = E('input', { 'class': 'cbi-input-text', 'value': l.file || '', 'placeholder': '/etc/detour/lists/my.txt' });
		const kind = E('select', { 'class': 'cbi-input-select' }, [ [ 'auto', _('detect by itself') ], [ 'cidr', _('addresses') ], [ 'domain', _('domains') ] ].map(function(k) {
			return E('option', { 'value': k[0], 'selected': (l.kind || 'auto') == k[0] ? '' : null }, k[1]); }));
		const minl = E('input', { 'class': 'cbi-input-text', 'value': l.min_lines || '', 'placeholder': '10' });
		preset.addEventListener('change', function() {
			const p = msg.PRESETS.filter(function(x) { return x[0] == preset.value; })[0];
			if (!p) return;
			url.value = p[2]; kind.value = p[3]; if (!label.value) label.value = p[1];
			if (isNew && !name.value) name.value = 'l_' + p[0];
		});
		if (pre) { url.value = pre.url; kind.value = pre.kind; label.value = pre.label; name.value = pre.name; }
		const body = [];
		if (isNew && !pre) body.push(row(_('Ready-made list'), preset, _('Popular categories, kept up to date by their authors (runetfreedom, v2fly). Or give your own sources below.')));
		if (isNew) body.push(row(_('Internal name'), name, _('Latin letters, digits and _; used in the configuration.')));
		body.push(
			row(_('Name'), label, _('How the list is shown everywhere. Empty: made from its source.')),
			row(_('Goes'), policy, _('Through which policy (its exits) the addresses of the list go - or never through a tunnel, whatever the policies say.')),
			row(_('Sources'), url, _('One per line: an http(s) address of a list, or a v2fly category as v2fly:NAME (for example v2fly:youtube). Address lists: one IP or range per line; domain lists: plain, hosts, dnsmasq, adblock or v2fly/geosite text.')),
			row(_('Local file'), file, _('Optional: a file on the router with more entries.')),
			row(_('Contents'), kind, _('Usually detected by itself.')),
			row(_('Minimum entries'), minl, _('A download with fewer entries is treated as a failure, and the previous list stays in use.'))
		);
		modal(isNew ? _('New list') : _('List «%s»').format(msg.listTitle(l)), body, function() {
			let n = l['.name'];
			if (isNew) {
				n = name.value.trim();
				if (!/^[a-z][a-z0-9_]{0,19}$/.test(n)) throw new Error(_('Internal name: a-z, 0-9, _, starts with a letter'));
				if (uci.get('detour', n)) throw new Error(_('This name is already used'));
			}
			const urls = url.value.split(/\s+/).filter(function(x) { return x; });
			const bad = urls.filter(function(u) { return !/^https?:\/\/\S+$/.test(u) && !/^v2fly:[a-z0-9!._-]+$/.test(u); });
			if (bad.length) throw new Error(_('Not a source: %s').format(bad.join(', ')));
			if (!urls.length && !file.value.trim()) throw new Error(_('Give a source or a file'));
			if (minl.value.trim() && !/^\d+$/.test(minl.value.trim())) throw new Error(_('Minimum entries: a number'));
			if (isNew) uci.add('detour', 'list', n);
			const set = function(k, v) { if (v && (!Array.isArray(v) || v.length)) uci.set('detour', n, k, v); else uci.unset('detour', n, k); };
			set('label', label.value.trim());
			set('policy', policy.value == '__block' ? msg.blockPolicy(uci, true) : (policy.value == '__direct' ? msg.directPolicy(uci, true) : policy.value));
			set('url', urls);
			set('file', file.value.trim());
			set('kind', kind.value == 'auto' ? '' : kind.value);
			set('min_lines', minl.value.trim());
			return applyUci().then(function() { return callUpdate(n); }).then(function() { return true; });
		}, isNew ? _('Add') : _('Save'));
	},

	// the catalogue: every category of v2fly and runetfreedom with how many entries it has (counted when the
	// package was built, tools/geo-catalog.py) and about how much memory it takes on the router
	catalog: function() {
		const self = this;
		const search = E('input', { 'class': 'cbi-input-text', 'placeholder': _('youtube, telegram, openai, steam…') });
		const kindSel = E('select', { 'class': 'cbi-input-select' }, [ [ '', _('domains and addresses') ], [ 'domain', _('domains') ], [ 'cidr', _('addresses') ] ].map(function(k) { return E('option', { 'value': k[0] }, k[1]); }));
		const srcSel = E('select', { 'class': 'cbi-input-select' }, [ [ '', _('all sources') ], [ 'v2fly', 'v2fly' ], [ 'rf', 'runetfreedom' ] ].map(function(k) { return E('option', { 'value': k[0] }, k[1]); }));
		const out = E('div', { 'class': 'detour-servers' }, E('em', {}, _('Loading…')));
		const have = {};
		uci.sections('detour', 'list').forEach(function(l) { arr(l.url).forEach(function(u) { have[u] = msg.listTitle(l); }); });
		// memory: what an entry costs on this router and how much the lists may still take (lists_memory of status)
		const mem = self.mem || null;
		const bytes = function(e) { return e.n * (mem ? mem.per[e.kind] : (e.kind == 'cidr' ? 250 : 300)); };
		const size = function(e) {
			if (e.n == null) return _('size unknown until added');
			const b = bytes(e);
			return b > 1048576 ? _('~%s MB').format((b / 1048576).toFixed(1)) : _('~%d KB').format(Math.max(1, Math.round(b / 1024)));
		};
		let all = [];
		const draw = function() {
			const q = search.value.trim().toLowerCase();
			const hits = all.filter(function(e) {
				return (!kindSel.value || e.kind == kindSel.value) && (!srcSel.value || e.src == srcSel.value) &&
					(!q || e.key.indexOf(q) >= 0 || e.title.toLowerCase().indexOf(q) >= 0);
			}).sort(function(a, b) { return (!q ? 0 : (a.key == q ? -1 : b.key == q ? 1 : 0)) || (b.n || 0) - (a.n || 0); });
			const rows = hits.slice(0, 60).map(function(e) {
				// does not fit: refused by the router anyway; more than half of what is left: said
				const nofit = mem && e.n != null && bytes(e) > mem.left;
				const big = !nofit && mem && e.n != null && bytes(e) > mem.left / 2;
				return E('div', { 'class': 'detour-server-row' }, [
					E('span', {}, [ E('strong', {}, e.title), E('span', { 'class': 'detour-muted' },
						' ' + [ e.src == 'v2fly' ? 'v2fly «' + e.key + '»' : 'runetfreedom «' + e.key + '»' ].concat(e.n != null ? [ N_(e.n, '%d entry', '%d entries').format(e.n), size(e) ] : [ _('new: the number of entries is known once added') ]).join(' · ')) ]),
					nofit ? E('span', { 'class': 'detour-delay bad' }, _('does not fit: %s MB are left for lists').format(mbs(mem.left))) : '',
					big ? E('span', { 'class': 'detour-delay bad' }, _('takes most of the %s MB left for lists').format(mbs(mem.left))) : '',
					have[e.url] ? E('span', { 'class': 'detour-muted' }, _('already added')) : E('button', { 'class': 'btn', 'disabled': nofit ? '' : null, 'click': function() {
						ui.hideModal();
						self.edit(null, { url: e.url, kind: e.kind, label: e.title, name: ('l_' + e.key.replace(/[^a-z0-9_]/g, '_')).slice(0, 20) });
					} }, _('Add'))
				]);
			});
			if (hits.length > 60) rows.push(E('div', { 'class': 'detour-muted' }, _('and %d more: narrow the search').format(hits.length - 60)));
			out.replaceChildren.apply(out, rows.length ? rows : [ E('em', {}, _('Nothing found.')) ]);
		};
		[ search, kindSel, srcSel ].forEach(function(el) { el.addEventListener(el.tagName == 'INPUT' ? 'input' : 'change', draw); });
		// where the v2fly names come from: the router's own copy of the upstream listing (refreshed nightly and by
		// the button), else the catalogue built into this version
		const origin = E('span', { 'class': 'detour-muted' });
		const refresh = E('button', { 'class': 'btn', 'click': function() {
			busy(refresh, true);
			return callCatRefresh().then(function(r) {
				if (r && r.error) origin.textContent = _('The list of categories did not come: %s').format(r.error);
				return load(r);
			}).finally(function() { busy(refresh, false); });
		} }, _('Refresh the list of categories'));
		ui.showModal(_('Catalogue of categories'), [
			E('div', { 'class': 'cbi-value-description' }, _('Categories kept up to date by their authors: v2fly (services and sites of the world) and runetfreedom (what is blocked in Russia). The numbers of entries are from the time this version was built; a category that appeared later shows its number once added.')),
			E('div', { 'class': 'detour-actions' }, [ search, kindSel, srcSel ]),
			E('div', { 'class': 'detour-actions' }, [ origin, refresh ]),
			out,
			E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Close')) ])
		]);
		let built = null;
		const mk = function(src, key, n, url, kind) { return { src, key, n, url, kind, title: msg.listTitle({ url: [ url ], '.name': key }) }; };
		// names: the router's (when it has them) - the numbers from the built-in catalogue, unknown for a new category
		const load = function(names) {
			const c = built || {};
			const known = {};
			(c.v2fly || []).forEach(function(x) { known[x[0]] = x[1]; });
			const v2 = (names && names.v2fly && names.v2fly.length) ? names.v2fly.map(function(k) { return [ k, k in known ? known[k] : null ]; }) : (c.v2fly || []);
			// 0: the category has nothing a router can use (only TLDs, keywords, regexps) - not offered
			all = v2.filter(function(x) { return x[1] !== 0; }).map(function(x) { return mk('v2fly', x[0], x[1], 'v2fly:' + x[0], 'domain'); })
				.concat((c.rfgs || []).map(function(x) { return mk('rf', x[0], x[1], msg.RFGS + x[0] + '.txt', 'domain'); }))
				.concat((c.rfip || []).map(function(x) { return mk('rf', x[0], x[1], msg.RF + x[0] + '.txt', 'cidr'); }));
			if (names && names.v2fly && names.v2fly.length) {
				const fresh = names.v2fly.filter(function(k) { return !(k in known); }).length;
				origin.textContent = _('v2fly categories: %d, as of %s (checked %s)').format(names.v2fly.length,
					names.date ? new Date(names.date).toLocaleDateString() : '?', names.checked ? new Date(names.checked * 1000).toLocaleString() : '?') +
					(fresh ? ' · ' + _('new since this version: %d').format(fresh) : '');
			}
			else origin.textContent = _('v2fly categories: built into this version (%s)').format(c.generated || '?');
			draw();
		};
		pdata.all({
			built: L.Request.get(L.resource('detour/geo-catalog.json') + '?v=' + encodeURIComponent(L.env.resource_version || '')).then(function(r) { return r.json(); }),
			names: L.resolveDefault(callCatNames(), null)
		}).then(function(r) {
			built = r.built;
			load(r.names);
			search.focus();
		}).catch(function() { out.replaceChildren(E('em', {}, _('The catalogue is missing from this build.'))); });
	},

	render: function(data) {
		const self = this;
		const st = {};
		((data.status || {}).lists || []).forEach(function(l) { st[l.name] = l; });
		this.mem = (data.status || {}).lists_memory || null;
		const m = this.mem;
		const all = uci.sections('detour', 'list');
		return E('div', {}, [
			E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') }),
			E('h2', {}, _('Lists')),
			E('div', { 'class': 'cbi-map-descr' }, _('Big sets of sites or addresses from the internet: everything blocked in Russia, a service (YouTube, Telegram…). Each list goes through a policy or never through a tunnel. They are updated every night; if a source does not answer, the previous list stays in use.')),
			m ? E('div', { 'class': 'cbi-map-descr detour-mem' }, [
				E('div', { 'class': 'detour-share', 'title': Math.round(m.used * 100 / Math.max(1, m.cap)) + '%' }, E('div', { 'style': 'width:' + Math.min(100, m.used * 100 / Math.max(1, m.cap)) + '%' })),
				E('span', {}, _('Memory: the lists take ~%s MB; up to %s MB more can be added (the router has %s MB, %s MB of it stay free for everything else).')
					.format(mbs(m.used), mbs(m.left), mbs(m.total), mbs(m.reserve)))
			]) : '',
			E('div', { 'class': 'cbi-section' }, [
				E('div', { 'class': 'cbi-section-node detour-node' }, [
					all.length ? E('div', { 'class': 'detour-cards' }, all.map(function(l) { return self.renderList(l, st); }))
						: E('div', { 'class': 'detour-result' }, E('em', {}, _('No lists yet.'))),
					E('div', { 'class': 'detour-actions' }, [ E('button', { 'class': 'btn cbi-button-add', 'click': function() { self.edit(null); } }, _('Add list')),
						E('button', { 'class': 'btn', 'click': function() { self.catalog(); } }, _('Catalogue of categories…')) ])
				])
			])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
