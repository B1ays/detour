'use strict';
'require view';
'require detour.load as pdata';
'require rpc';
'require ui';
'require uci';
'require detour.msg as msg';
'require detour.policyutil as pu';
'require detour.listsui as lists';
'require detour.sitecheckui as sitecheck';

// Text from the router (names of exits and servers come from subscriptions and links) never becomes HTML:
// LuCI's E() puts a string child in with innerHTML, here it always goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

// The policies in the order they are checked, each a link to its own page (policy.js): its state (a dot), type,
// what it holds and what it is doing now (the exit in use, no exit working, a list that did not update). The
// order changes with the arrows (a narrow screen: in the «Change the order» mode) and is applied with the page's
// buttons. Below the last one, what no policy takes: directly through the provider. A new policy: one button, its
// type chosen in the dialog; it opens on its own page. Lists whose policy is gone are shown here to be moved.

const callStatus = rpc.declare({ object: 'detour', method: 'status' });
const callLeases = rpc.declare({ object: 'luci-rpc', method: 'getDHCPLeases', expect: { '': {} } });
const BASE = 'admin/services/detour/policies';

function busy(btn, on) { btn.disabled = on; btn.classList.toggle('spinning', on); }
function note(text, cls) { return E('div', { 'class': 'alert-message ' + (cls || 'notice') }, text); }

function row(title, field, descr) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, title),
		E('div', { 'class': 'cbi-value-field' }, descr ? [ field, E('div', { 'class': 'cbi-value-description' }, descr) ] : field)
	]);
}

return view.extend({
	load: function() {
		return pdata.all({ cfg: uci.load('detour'), status: L.resolveDefault(callStatus(), {}), leases: L.resolveDefault(callLeases(), {}) });
	},

	// ---- a new policy: its type, name and (a VPN one) first exit; then its own page ----
	addPolicy: function() {
		let kind = 'vpn';
		const kinds = [
			[ 'vpn', _('Through VPN'), _('VPN'), _('The traffic goes through the chosen exits.') ],
			[ 'direct', _('Directly'), _('Directly'), _('Never through a tunnel: an exception for the policies below.') ],
			[ 'block', _('Block'), _('Blocks'), _('Lets nothing through.') ] ];
		const label = E('input', { 'class': 'cbi-input-text', 'id': 'np-label' });
		const name = E('input', { 'class': 'cbi-input-text', 'id': 'np-name', 'placeholder': 'vpn2', 'maxlength': 11 });
		const exits = uci.sections('detour', 'exit');
		const exit = E('select', { 'class': 'cbi-input-select', 'id': 'np-exit' }, exits.map(function(e) { return E('option', { 'value': e['.name'] }, e.label || e['.name']); }));
		const exitRow = row(_('First exit'), exits.length ? exit : note(_('There are no exits yet: add one on the Exits page. Without an exit the traffic of this policy is blocked.'), 'warning'),
			_('The other exits, their order and what happens when they fail are set on the policy\'s page.'));
		const ph = { vpn: _('for example: Blocked sites'), direct: _('for example: Russian sites'), block: _('for example: Advertising') };
		const choose = function(k) {
			kind = k;
			label.placeholder = ph[k];
			exitRow.hidden = k != 'vpn';
			cards.querySelectorAll('.detour-kind').forEach(function(c) { c.classList.toggle('on', c.dataset.kind == k); });
		};
		const cards = E('fieldset', { 'class': 'detour-kinds' }, [ E('legend', {}, _('Type of policy')) ].concat(kinds.map(function(k) {
			const r = E('input', { 'type': 'radio', 'name': 'np-kind', 'id': 'np-k-' + k[0], 'checked': k[0] == kind ? '' : null, 'change': function() { choose(k[0]); } });
			return E('label', { 'class': 'detour-kind', 'for': 'np-k-' + k[0], 'data-kind': k[0] }, [ r,
				E('span', {}, [ E('span', { 'class': 'detour-kind-head' }, [ E('strong', {}, k[1]), E('span', { 'class': 'detour-type' }, k[2]) ]),
					E('span', { 'class': 'detour-muted' }, k[3]) ]) ]);
		})));
		const box = E('div', { 'class': 'detour-result' });
		const create = E('button', { 'class': 'btn cbi-button-positive', 'click': function() {
			try {
				const n = name.value.trim();
				if (!/^[a-z][a-z0-9_]{0,10}$/.test(n)) throw new Error(_('Internal name: a-z, 0-9, _, starts with a letter, up to 11'));
				if (uci.get('detour', n)) throw new Error(_('This name is already used'));
				const used = {};
				uci.sections('detour', 'policy').forEach(function(s) { used[+s.id] = true; });
				let id = 1; while (used[id] && id <= 250) id++;
				if (id > 250) throw new Error(_('No free policy id: 250 policies is the limit'));
				uci.add('detour', 'policy', n);
				uci.set('detour', n, 'id', String(id));
				uci.set('detour', n, 'label', label.value.trim() || (kind == 'block' ? _('Block') : (kind == 'direct' ? _('Directly') : n)));
				if (kind == 'vpn') { if (exits.length) uci.set('detour', n, 'exit', [ exit.value ]); }
				else {
					// a blocking or direct policy goes first: what it covers must not be taken by another policy before it
					// (a direct one can then be moved below the policies it should not make exceptions in)
					uci.set('detour', n, 'action', kind);
					const first = uci.sections('detour', 'policy')[0];
					if (first && first['.name'] != n) uci.move('detour', n, first['.name']);
				}
				busy(create, true);
				// saved (not applied yet): its page shows it, «Apply» there or here sends it to the router
				return uci.save().then(function() { location.href = L.url(BASE, n); });
			} catch (e) { box.replaceChildren(note(e.message || String(e), 'warning')); }
		} }, _('Create'));
		ui.showModal(_('New policy'), [
			E('div', { 'class': 'detour-node' }, [ cards,
				row(_('Name'), label, _('How the policy is shown everywhere.')),
				row(_('Internal name'), name, _('Latin letters, digits and _, up to 11; used in the configuration.')),
				exitRow,
				E('div', { 'class': 'cbi-value-description' }, _('Sites, addresses, devices and lists are added on the policy\'s page: it opens right after.')) ]),
			box,
			E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ', create ]) ]);
		choose(kind);
		label.focus();
	},

	// ---- the list ----
	card: function(p, idx, all) {
		const self = this, name = p['.name'], on = p.enabled != '0', kind = msg.policyKind(p);
		const live = pu.live(p, this.st, this.listSt);
		const head = E('span', { 'class': 'detour-pcard-head' }, [
			E('span', { 'class': 'detour-dot ' + (on ? 'on' : 'off'), 'role': 'img', 'aria-label': on ? _('on') : _('switched off'), 'title': on ? _('on') : _('switched off') }),
			E('span', { 'class': 'detour-card-title' + (on ? '' : ' detour-dim') }, p.label || name),
			E('span', { 'class': 'detour-type' }, pu.typeText(kind)),
			(p.label && p.label != name) ? E('span', { 'class': 'detour-muted detour-pcard-name', 'title': _('Internal name: used in the configuration and the log') }, name) : '' ]);
		const link = E('a', { 'class': 'detour-pcard-link', 'href': L.url(BASE, name) }, [
			E('span', { 'class': 'detour-pcard-body' }, [ head,
				E('span', { 'class': 'detour-pcard-sum' + (on ? '' : ' detour-dim') }, pu.summary(p)),
				live ? E('span', { 'class': 'detour-live ' + live.tone }, live.text) : '' ]),
			E('span', { 'class': 'detour-pcard-go', 'aria-hidden': 'true' }, '›') ]);
		// the order: changed here only, the router gets it with «Apply»
		const order = E('div', { 'class': 'detour-order' }, [
			E('button', { 'class': 'btn', 'title': _('Checked earlier'), 'aria-label': _('Higher: %s').format(p.label || name), 'disabled': idx == 0 ? '' : null, 'click': function() {
				self.move(name, all[idx - 1]['.name'], false); } }, '↑'),
			E('button', { 'class': 'btn', 'title': _('Checked later'), 'aria-label': _('Lower: %s').format(p.label || name), 'disabled': idx == all.length - 1 ? '' : null, 'click': function() {
				self.move(name, all[idx + 1]['.name'], true); } }, '↓') ]);
		return E('div', { 'class': 'detour-pcard' + (live && live.tone ? ' ' + live.tone : '') }, [ order, link ]);
	},

	// the «Change the order» mode of a narrow screen: names with big arrows, nothing to open by mistake
	reorderRow: function(p, idx, all) {
		const self = this, name = p['.name'], on = p.enabled != '0';
		return E('div', { 'class': 'detour-rrow' }, [
			E('span', { 'class': 'detour-muted detour-rrow-pos' }, String(idx + 1)),
			E('span', { 'class': 'detour-dot ' + (on ? 'on' : 'off'), 'role': 'img', 'aria-label': on ? _('on') : _('switched off') }),
			E('span', { 'class': 'detour-rrow-name' }, p.label || name),
			E('button', { 'class': 'btn detour-big', 'aria-label': _('Higher: %s').format(p.label || name), 'disabled': idx == 0 ? '' : null, 'click': function() {
				self.move(name, all[idx - 1]['.name'], false); } }, '↑'),
			E('button', { 'class': 'btn detour-big', 'aria-label': _('Lower: %s').format(p.label || name), 'disabled': idx == all.length - 1 ? '' : null, 'click': function() {
				self.move(name, all[idx + 1]['.name'], true); } }, '↓') ]);
	},

	// what no policy takes: always last, not a policy
	restRow: function() {
		// the mark of the end of the list: a drawn arrow down and to the right, where the arrows of a policy are
		const ns = 'http://www.w3.org/2000/svg';
		const svg = document.createElementNS(ns, 'svg');
		svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('width', '18'); svg.setAttribute('height', '18'); svg.setAttribute('aria-hidden', 'true');
		[ 'M5 4v9a3 3 0 0 0 3 3h11', 'M15 12l4 4-4 4' ].forEach(function(d) {
			const p = document.createElementNS(ns, 'path');
			p.setAttribute('d', d); p.setAttribute('fill', 'none'); p.setAttribute('stroke', 'currentColor'); p.setAttribute('stroke-width', '1.8');
			p.setAttribute('stroke-linecap', 'round'); p.setAttribute('stroke-linejoin', 'round');
			svg.appendChild(p);
		});
		return E('div', { 'class': 'detour-pcard rest' }, [ E('div', { 'class': 'detour-order detour-rest-mark' }, [ svg ]),
			E('div', { 'class': 'detour-pcard-body' }, [
				E('span', { 'class': 'detour-pcard-head' }, [
					E('span', { 'class': 'detour-card-title' }, _('Everything else')), E('span', { 'class': 'detour-type' }, _('Directly')),
					E('span', { 'class': 'detour-muted' }, _('always last')) ]),
				E('span', { 'class': 'detour-pcard-sum' }, _('What matches no policy above goes directly through your provider.')) ]) ]);
	},

	move: function(name, other, after) {
		uci.move('detour', name, other, after);
		this.pending = this.order() != this.origOrder || this.otherChanges;
		this.renderCards();
	},

	order: function() { return uci.sections('detour', 'policy').map(function(p) { return p['.name']; }).join(' '); },

	renderCards: function() {
		const self = this;
		const all = uci.sections('detour', 'policy');
		this.count.textContent = _('Policies · %d').format(all.length);
		this.reorderBtn.textContent = this.reorder ? _('Done') : _('↑↓ Change the order');
		this.reorderBtn.classList.toggle('cbi-button-positive', !!this.reorder);
		this.root.classList.toggle('detour-reordering', !!this.reorder);
		this.cards.replaceChildren(E('div', { 'class': 'detour-cards' }, (all.length ? all.map(function(p, i) {
			return self.reorder ? self.reorderRow(p, i, all) : self.card(p, i, all);
		}) : [ E('div', { 'class': 'detour-result' }, E('em', {}, _('No policies yet: everything goes directly.'))) ]).concat([ this.restRow() ])));
		this.pendingBar.hidden = !this.pending;
		this.pendingBar.firstChild.textContent = this.order() != this.origOrder ? _('The order of the policies has changed. It takes effect after «Apply».') : _('Changes not saved');
	},

	// lists whose policy is gone (removed by hand, an old backup): they go nowhere until moved to a policy
	renderOrphans: function() {
		const self = this;
		const orphans = uci.sections('detour', 'list').filter(function(l) { return uci.get('detour', l.policy || '', '.type') != 'policy'; });
		if (!orphans.length) { this.orphans.replaceChildren(); return; }
		const opts = { mem: this.mem,
			onChange: function() { self.otherChanges = true; self.pending = true; self.renderCards(); self.renderOrphans(); },
			onRefresh: function() { return L.resolveDefault(callStatus(), null).then(function(s) { if (s) { self.st = s; self.listSt = lists.states(s); } self.renderOrphans(); }); } };
		this.orphans.replaceChildren(E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Lists without a policy')),
			E('div', { 'class': 'cbi-section-descr' }, _('Their policy is gone, so they go nowhere. Choose a policy for each in «Edit», or remove them.')),
			E('div', { 'class': 'cbi-section-node detour-node' }, E('div', { 'class': 'detour-cards' }, orphans.map(function(l) { return lists.card(l, self.listSt, opts); }))) ]));
	},

	render: function(data) {
		const self = this;
		const st = data.status || {};
		this.st = st; this.listSt = lists.states(st); this.mem = st.lists_memory || null;
		this.pending = false; this.otherChanges = false; this.reorder = false; this.origOrder = this.order();
		this.cards = E('div');
		this.orphans = E('div');
		this.count = E('h3');
		this.reorderBtn = E('button', { 'class': 'btn', 'click': function() { self.reorder = !self.reorder; self.renderCards(); } });
		// the page's own buttons below (Reset / Save / Apply, as on the other pages) take the new order
		this.pendingBar = E('div', { 'class': 'alert-message warning', 'hidden': '' }, E('p', {}));
		// leaving the page with an order not applied: the browser asks
		window.addEventListener('beforeunload', function(ev) { if (self.pending) { ev.preventDefault(); ev.returnValue = ''; } });
		this.root = E('div', { 'class': 'detour-policies-page' }, [
			E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') }),
			E('h2', {}, _('Routing')),
			E('div', { 'class': 'cbi-map-descr' }, _('A policy says where devices, sites, addresses, ports and lists go: through VPN exits, directly (never through a tunnel) or nowhere (blocked). Policies are checked from top to bottom, the first that matches takes the traffic; what matches none goes directly through your provider.')),
			E('div', { 'class': 'detour-actions detour-add-row' }, [ E('button', { 'class': 'btn cbi-button-add', 'click': function() { self.addPolicy(); } }, _('Add policy')) ]),
			this.mem ? E('div', { 'class': 'cbi-section detour-mem-section' }, [ E('h3', {}, _('Memory for lists')), lists.memory(this.mem) ]) : '',
			this.pendingBar,
			E('div', { 'class': 'cbi-section' }, [
				E('div', { 'class': 'detour-list-head' }, [ this.count, this.reorderBtn ]),
				E('div', { 'class': 'cbi-section-node detour-node' }, this.cards)
			]),
			this.orphans,
			// where a site goes by these policies, and does it open
			sitecheck.render({ leases: data.leases, status: st })
		]);
		this.renderCards();
		this.renderOrphans();
		return this.root;
	},

	// the standard buttons of the page: «Save» keeps the new order among the unsaved changes, «Apply» applies
	// it (with everything else not applied yet), «Reset» drops what is not saved yet, as on the other pages
	handleSave: function() {
		this.pending = false; this.otherChanges = false;
		this.renderCards();
		// the header's «Unsaved changes» counter, as after a form's «Save»
		return uci.save().then(function() { if (ui.changes && ui.changes.init) ui.changes.init(); });
	},
	handleSaveApply: function(ev, mode) {
		return this.handleSave(ev).then(function() { return ui.changes.apply(mode == '0'); });
	},
	handleReset: function() {
		const self = this;
		uci.unload('detour');
		return uci.load('detour').then(function() { self.origOrder = self.order(); self.pending = false; self.otherChanges = false; self.renderCards(); self.renderOrphans(); });
	}
});
