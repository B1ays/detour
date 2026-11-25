'use strict';
'require view';
'require detour.load as pdata';
'require rpc';
'require ui';
'require uci';
'require detour.msg as msg';
'require detour.policyutil as pu';
'require detour.listsui as lists';

// One policy on its own page (admin/services/detour/policies/<name>, the menu's "policies/*" node - it stands
// before "policies" in the menu JSON: the dispatcher copies a node's action from every entry of the same path,
// so the wildcard one placed after would take the list's own address too). What it is and does now, its
// settings (folded "Basic": name, exits with their state, what happens when they fail), what goes through it
// (sites, addresses, devices, networks, ports - as tags, or a text box for many at once) and its lists.
// Every change is staged in UCI like a form's: the page's «Save» / «Apply» / «Reset» take it, leaving with
// changes not saved is asked. A pin (the exit chosen by hand) is the daemon's: it goes with «Apply».

const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

const callStatus = rpc.declare({ object: 'detour', method: 'status' });
const callHints = rpc.declare({ object: 'luci-rpc', method: 'getHostHints', expect: { '': {} } });
const callLeases = rpc.declare({ object: 'luci-rpc', method: 'getDHCPLeases', expect: { '': {} } });
const callPin = rpc.declare({ object: 'detour', method: 'pin', params: [ 'policy', 'exit' ] });
const callUnpin = rpc.declare({ object: 'detour', method: 'unpin', params: [ 'policy' ] });

const LIST_URL = 'admin/services/detour/policies';
function note(text, cls) { return E('div', { 'class': 'alert-message ' + (cls || 'notice') }, text); }
function lines(t) { return t.split(/[\s,]+/).map(function(x) { return x.trim(); }).filter(function(x) { return x; }); }
function chevron() { return E('span', { 'class': 'detour-chevron', 'aria-hidden': 'true' }); }

function field(title, input, descr, id) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': id || null }, title),
		E('div', { 'class': 'cbi-value-field' }, descr ? [ input, E('div', { 'class': 'cbi-value-description' }, descr) ] : input)
	]);
}

// values as tags with a remove button and an "add" box; «Edit as text» turns them into a text box (one a line)
// for many changes at once, «Done» back into tags. o: { values, check(x) -> normalized | null, bad, placeholder,
// textHelp, onChange(values) }
function tagField(o) {
	let values = o.values.slice(), mode = 'tags';
	const wrap = E('div', { 'class': 'detour-tags-field' });
	const err = E('div', { 'class': 'detour-field-error', 'role': 'alert' });
	const parse = function(text) {
		const ok = [], bad = [];
		lines(text).forEach(function(x) { const v = o.check(x); if (v == null) bad.push(x); else if (ok.indexOf(v) < 0) ok.push(v); });
		return { ok: ok, bad: bad };
	};
	const set = function(v) { values = v; o.onChange(values.slice()); };
	const draw = function() {
		err.textContent = '';
		if (mode == 'text') {
			const ta = E('textarea', { 'class': 'cbi-input-textarea detour-tags-text', 'rows': Math.min(14, Math.max(4, values.length + 1)), 'spellcheck': 'false' }, values.join('\n'));
			const done = E('button', { 'class': 'btn cbi-button-positive', 'click': function(ev) {
				ev.preventDefault();
				const r = parse(ta.value);
				if (r.bad.length) { err.textContent = o.bad.format(r.bad.join(', ')); return; }
				if (r.ok.join(' ') != values.join(' ')) set(r.ok);
				mode = 'tags'; draw();
			} }, _('Done'));
			const cancel = E('button', { 'class': 'btn', 'click': function(ev) { ev.preventDefault(); mode = 'tags'; draw(); } }, _('Cancel'));
			wrap.replaceChildren(ta, E('div', { 'class': 'cbi-value-description' }, o.textHelp), err, E('div', { 'class': 'detour-actions' }, [ done, cancel ]));
			ta.focus();
			return;
		}
		const tags = E('div', { 'class': 'detour-tags', 'role': 'list' }, values.length ? values.map(function(v) {
			return E('span', { 'class': 'detour-tag', 'role': 'listitem' }, [ E('span', {}, v),
				E('button', { 'class': 'detour-tag-x', 'aria-label': _('Remove %s').format(v), 'title': _('Remove %s').format(v), 'click': function(ev) {
					ev.preventDefault(); set(values.filter(function(x) { return x != v; })); draw();
				} }, '×') ]);
		}) : E('span', { 'class': 'detour-muted' }, _('none yet')));
		const box = E('input', { 'class': 'cbi-input-text', 'placeholder': o.placeholder, 'aria-label': o.placeholder });
		const add = function() {
			const r = parse(box.value);
			if (!r.ok.length && !r.bad.length) return;
			const next = values.slice();
			r.ok.forEach(function(v) { if (next.indexOf(v) < 0) next.push(v); });
			if (next.length != values.length) set(next);
			draw();
			const nb = wrap.querySelector('input');
			if (r.bad.length) { nb.value = r.bad.join(' '); nb.classList.add('cbi-input-invalid'); err.textContent = o.bad.format(r.bad.join(', ')); }
			nb.focus();
		};
		box.addEventListener('keydown', function(ev) { if (ev.key == 'Enter') { ev.preventDefault(); add(); } });
		box.addEventListener('input', function() { box.classList.remove('cbi-input-invalid'); err.textContent = ''; });
		const asText = E('button', { 'class': 'detour-link', 'click': function(ev) { ev.preventDefault(); mode = 'text'; draw(); } },
			_('Edit as text') + (values.length ? ' · ' + values.length : ''));
		wrap.replaceChildren(tags, E('div', { 'class': 'detour-tag-add' }, [ box, E('button', { 'class': 'btn', 'click': function(ev) { ev.preventDefault(); add(); } }, _('Add')) ]), err, asText);
	};
	draw();
	return wrap;
}

return view.extend({
	load: function() {
		return pdata.all({ cfg: uci.load('detour'), status: L.resolveDefault(callStatus(), {}), hints: L.resolveDefault(callHints(), {}),
			leases: L.resolveDefault(callLeases(), {}), dhcp: L.resolveDefault(uci.load('dhcp'), null), network: L.resolveDefault(uci.load('network'), null) });
	},

	// ---- the state of the page: changes not saved yet, the pin wanted ----
	// the current value of an option (uci.get of a whole section does not show what was set since loading)
	opt: function(k) { return uci.get('detour', this.p['.name'], k); },

	changed: function() {
		this.dirty = true;
		this.msg = '';
		this.syncFooter();
		this.drawHead();
		this.drawBasicPeek();
	},

	// the standard footer (Reset / Save / Apply): «Save» and «Reset» only with something to save, a line saying so;
	// on a narrow screen the footer shows only then. «Apply» stays: it also applies what other pages saved.
	syncFooter: function() {
		const self = this;
		document.body.classList.toggle('detour-page-clean', !this.dirty);
		const bar = document.querySelector('.cbi-page-actions');
		if (!bar) return;
		bar.querySelectorAll('.cbi-button-save, .cbi-button-reset').forEach(function(b) { b.disabled = !self.dirty; });
		let line = bar.querySelector('.detour-unsaved');
		if (!line) { line = E('span', { 'class': 'detour-unsaved', 'role': 'status' }); bar.insertBefore(line, bar.firstChild); }
		line.classList.toggle('ok', !this.dirty && !!this.msg);
		line.textContent = this.dirty ? _('Changes not saved') : (this.msg || '');
	},

	// leaving with changes not saved: asked here (links of this page) and by the browser (the menu, the tabs)
	leave: function(url) {
		const self = this;
		if (!this.dirty) { location.href = url; return; }
		ui.showModal(_('Leave without saving?'), [
			E('p', {}, _('The changes on this page are not saved and will be lost.')),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn cbi-button-negative', 'click': function() { self.dirty = false; ui.hideModal(); location.href = url; } }, _('Leave without saving')), ' ',
				E('button', { 'class': 'btn cbi-button-positive', 'click': ui.hideModal }, _('Stay')) ]) ]);
	},

	// ---- the head: the dot of its state, the name, its type, on / off, remove ----
	drawHead: function() {
		const self = this, p = this.p, name = p['.name'], on = this.opt('enabled') != '0';
		const kind = msg.policyKind(p), label = this.opt('label') || name;
		this.head.replaceChildren(
			E('h2', { 'class': 'detour-policy-title' }, [
				E('span', { 'class': 'detour-dot ' + (on ? 'on' : 'off'), 'role': 'img', 'aria-label': on ? _('on') : _('switched off'), 'title': on ? _('on') : _('switched off') }),
				E('span', { 'class': on ? '' : 'detour-dim' }, label),
				E('span', { 'class': 'detour-type' }, pu.typeText(kind)),
				label != name ? E('span', { 'class': 'detour-muted', 'title': _('Internal name: used in the configuration and the log') }, name) : '' ]),
			E('div', { 'class': 'detour-actions' }, [
				E('button', { 'class': 'btn', 'click': function() {
					if (on) uci.set('detour', name, 'enabled', '0'); else uci.unset('detour', name, 'enabled');
					self.changed(); self.drawBanner();
				} }, on ? _('Turn off') : _('Turn on')),
				E('button', { 'class': 'btn cbi-button-negative', 'click': function() { self.remove(); } }, _('Remove the policy')) ]));
	},

	drawBanner: function() {
		const self = this, p = this.p;
		if (this.opt('enabled') != '0') { this.banner.replaceChildren(); return; }
		this.banner.replaceChildren(E('div', { 'class': 'detour-off-banner', 'role': 'status' }, [
			E('div', {}, [ E('strong', {}, _('The policy is switched off')), E('div', { 'class': 'detour-muted' },
				_('Nothing goes through it: its traffic is checked by the policies below, then goes by «Everything else».')) ]),
			E('button', { 'class': 'btn cbi-button-positive', 'click': function() { uci.unset('detour', p['.name'], 'enabled'); self.changed(); self.drawBanner(); } }, _('Turn on')) ]));
	},

	remove: function() {
		const self = this, p = this.p;
		const ls = pu.listsOf(p['.name']);
		const names = ls.map(function(l) { return msg.listTitle(l); }).join(', ');
		ui.showModal([ _('Remove the policy «%s»?').format(p.label || p['.name']) ], [
			E('p', {}, p.action == 'block'
				? (ls.length ? _('Its lists (%s) are removed too. What it blocked opens again.').format(names) : _('What it blocked opens again.'))
				: p.action == 'direct'
				? (ls.length ? _('Its lists (%s) are removed too. What it sent directly goes by the other policies from now on.').format(names)
				: _('What it sent directly goes by the other policies from now on.'))
				: (ls.length ? _('Its lists (%s) are removed too. What went through it goes directly from now on.').format(names)
				: _('What went through it goes directly from now on.'))),
			E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
				E('button', { 'class': 'btn cbi-button-negative', 'click': function() {
					ls.forEach(function(l) { uci.remove('detour', l['.name']); });
					uci.remove('detour', p['.name']);
					if (uci.get('detour', 'main', 'dns_policy') == p['.name']) { uci.set('detour', 'main', 'dns', 'off'); uci.unset('detour', 'main', 'dns_policy'); }
					ui.hideModal();
					// applied at once, and the page that comes back after the apply is the list
					self.dirty = false;
					history.replaceState(null, '', L.url(LIST_URL));
					return uci.save().then(function() { return ui.changes.apply(); });
				} }, _('Remove')) ]) ]);
	},

	// ---- Basic (folded): name, exits, when they fail, IPv6 ----
	basicPeek: function() {
		const p = this.p, kind = msg.policyKind(p);
		if (kind != 'vpn') return this.opt('label') || p['.name'];
		const ex = pu.arr(this.opt('exit'));
		const want = this.pinWant;
		return (ex.length ? _('through %s').format(ex.map(function(e) { return pu.exitLabel(e) + (e == want ? ' ' + _('(pinned)') : ''); }).join(' → ')) : _('no exit'))
			+ ' · ' + (this.opt('on_down') == 'direct' ? _('none works: directly') : _('none works: blocked'));
	},
	drawBasicPeek: function() { if (this.peek) this.peek.textContent = this.basicPeek(); },

	exitRows: function() {
		const self = this, p = this.p, name = p['.name'];
		const st = {};
		(this.st.exits || []).forEach(function(e) { st[e.name] = e; });
		const lv = (this.st.policies || []).filter(function(x) { return x.name == name; })[0];
		const box = E('div', { 'class': 'detour-exits' });
		const draw = function() {
			const cur = pu.arr(uci.get('detour', name, 'exit'));
			// the list changed: staged in UCI, the row list drawn again (the rows' buttons and the "add" select use it)
			const set = function(list) { uci.set('detour', name, 'exit', list); if (self.pinWant && list.indexOf(self.pinWant) < 0) self.pinWant = ''; self.changed(); draw(); };
			const rows = cur.map(function(n, i) {
				const s = st[n];
				const pinned = self.pinWant == n;
				// its state now: unknown until applied; an exit of a policy that is off is not started (idle)
				const health = !s ? { t: _('not applied yet'), c: '' }
					: s.idle ? { t: _('not started'), c: '' }
					: s.healthy ? { t: s.ms ? _('works · %d ms').format(s.ms) : _('works'), c: 'ok' }
					: { t: s.last_ok ? _('not answering since %s').format(new Date(s.last_ok * 1000).toLocaleTimeString()) : _('not answering'), c: 'bad' };
				return E('div', { 'class': 'detour-exit-row' + (pinned ? ' pinned' : '') }, [
					E('span', { 'class': 'detour-muted' }, String(i + 1)),
					E('div', { 'class': 'detour-exit-main' }, [
						E('div', {}, [ E('strong', {}, pu.exitLabel(n)),
							lv && lv.active == n ? E('span', { 'class': 'detour-chip now' }, _('now')) : '',
							pinned ? E('span', { 'class': 'detour-chip pin' }, _('pinned')) : '' ]),
						E('div', { 'class': 'detour-health ' + health.c }, [ E('span', { 'class': 'detour-dot sm ' + (health.c || 'off'), 'aria-hidden': 'true' }), health.t ]) ]),
					E('button', { 'class': 'btn', 'aria-pressed': pinned ? 'true' : 'false', 'click': function(ev) { ev.preventDefault(); self.pinWant = pinned ? '' : n; self.changed(); draw(); } },
						pinned ? _('Unpin') : _('Pin')),
					E('button', { 'class': 'btn', 'aria-label': _('Higher: %s').format(pu.exitLabel(n)), 'disabled': i == 0 ? '' : null, 'click': function(ev) {
						ev.preventDefault(); const l = cur.slice(); l[i] = l[i - 1]; l[i - 1] = n; set(l); } }, '↑'),
					E('button', { 'class': 'btn', 'aria-label': _('Remove the exit %s').format(pu.exitLabel(n)), 'click': function(ev) {
						ev.preventDefault(); set(cur.filter(function(x) { return x != n; })); } }, '×') ]);
			});
			const free = uci.sections('detour', 'exit').map(function(e) { return e['.name']; }).filter(function(n) { return cur.indexOf(n) < 0; });
			const sel = E('select', { 'class': 'cbi-input-select', 'aria-label': _('— add an exit —'), 'change': function() { if (sel.value) set(cur.concat([ sel.value ])); } },
				[ E('option', { 'value': '' }, free.length ? _('— add an exit —') : _('— no more exits —')) ].concat(free.map(function(n) { return E('option', { 'value': n }, pu.exitLabel(n)); })));
			box.replaceChildren.apply(box, (rows.length ? rows : [ note(_('No exit: the traffic of this policy is blocked.'), 'warning') ]).concat([ sel ]));
		};
		draw();
		return box;
	},

	drawBasic: function() {
		const self = this, p = this.p, name = p['.name'], kind = msg.policyKind(p);
		const label = E('input', { 'class': 'cbi-input-text', 'id': 'pol-label', 'value': p.label || '', 'placeholder': name, 'input': function() {
			if (label.value.trim()) uci.set('detour', name, 'label', label.value.trim()); else uci.unset('detour', name, 'label');
			self.changed();
		} });
		const body = [ field(_('Name'), label, _('How the policy is shown everywhere.'), 'pol-label') ];
		if (kind == 'block') body.push(note(_('A blocking policy: what matches it gets no internet at all. Sites get «no such name», addresses and ports are refused at once.')));
		else if (kind == 'direct') body.push(note(_('A direct policy: what matches it never goes through a tunnel, it goes directly through your provider. Put it above the policies it should make exceptions in.')));
		else {
			const onDown = E('select', { 'class': 'cbi-input-select', 'id': 'pol-down', 'change': function() {
				if (onDown.value == 'direct' && !confirm(_('When every exit of this policy fails, its traffic will go directly through your provider: the provider sees which sites these are, and blocked ones will not open anyway. Let it through?')))
					onDown.value = 'block';
				if (onDown.value == 'direct') uci.set('detour', name, 'on_down', 'direct'); else uci.unset('detour', name, 'on_down');
				self.changed();
			} }, [ E('option', { 'value': 'block', 'selected': p.on_down != 'direct' ? '' : null }, _('block it (nothing leaks)')),
				E('option', { 'value': 'direct', 'selected': p.on_down == 'direct' ? '' : null }, _('let it go directly through the provider')) ]);
			const v6 = E('input', { 'type': 'checkbox', 'id': 'pol-v6', 'checked': p.ipv6_block == '1' ? '' : null, 'change': function() {
				if (v6.checked) uci.set('detour', name, 'ipv6_block', '1'); else uci.unset('detour', name, 'ipv6_block'); self.changed(); } });
			body.push(
				field(_('Exits'), this.exitRows(), _('In order: the traffic goes through the first working exit; when it fails, through the next one, and back when it works again. A pinned exit is used while it works; when it fails, the others take over in this order.')),
				field(_('If no exit works'), onDown, _('Blocked is safer: nothing goes past the tunnel. Directly keeps things working without the VPN, but the provider sees this traffic.'), 'pol-down'),
				field(_('IPv6'), E('label', {}, [ v6, ' ', _('refuse all IPv6 of the network') ]),
					_('IPv6 does not go through the tunnel. Sites of the policy lose their IPv6 addresses anyway; addresses and lists do not know the IPv6 addresses of a service, so a device could reach it directly over IPv6. With this on, devices use IPv4 for everything (the policies below this one too).')));
		}
		const content = E('div', { 'class': 'cbi-section-node detour-fold-body', 'id': 'pol-basic', 'hidden': this.basicOpen ? null : '' }, body);
		this.peek = E('span', { 'class': 'detour-fold-peek' }, this.basicPeek());
		const toggle = E('button', { 'class': 'detour-fold-head', 'aria-expanded': this.basicOpen ? 'true' : 'false', 'aria-controls': 'pol-basic', 'click': function() {
			self.basicOpen = !self.basicOpen;
			toggle.setAttribute('aria-expanded', self.basicOpen ? 'true' : 'false');
			content.hidden = !self.basicOpen;
		} }, [ chevron(), E('span', { 'class': 'detour-fold-title' }, _('Basic')), this.peek ]);
		this.basic.replaceChildren(E('div', { 'class': 'cbi-section detour-fold' }, [ toggle, content ]));
	},

	// ---- what goes through it ----
	devicePicker: function(current, onChange) {
		const devs = this.devs;
		const known = Object.keys(devs).filter(function(m) { return pu.RE_MAC.test(m); }).sort(function(a, b) {
			return ((devs[a].name || '~') + a).localeCompare((devs[b].name || '~') + b); });
		const cur = current.map(function(m) { return m.toLowerCase(); });
		const boxes = {};
		const extra = E('input', { 'class': 'cbi-input-text', 'placeholder': 'aa:bb:cc:dd:ee:ff', 'aria-label': _('Other devices by MAC address, separated by spaces:'),
			'value': cur.filter(function(m) { return known.map(function(k) { return k.toLowerCase(); }).indexOf(m) < 0; }).join(' ') });
		const get = function() {
			const out = Object.keys(boxes).filter(function(m) { return boxes[m].checked; });
			lines(extra.value.toLowerCase()).forEach(function(m) { if (out.indexOf(m) < 0) out.push(m); });
			return out;
		};
		const err = E('div', { 'class': 'detour-field-error', 'role': 'alert' });
		const fire = function() {
			const v = get(), bad = v.filter(function(m) { return !pu.RE_MAC.test(m); });
			err.textContent = bad.length ? _('Not a MAC address: %s').format(bad.join(', ')) : '';
			onChange(v.filter(function(m) { return pu.RE_MAC.test(m); }));
		};
		const list = E('div', { 'class': 'detour-servers' }, known.map(function(m) {
			boxes[m.toLowerCase()] = E('input', { 'type': 'checkbox', 'checked': cur.indexOf(m.toLowerCase()) >= 0 ? '' : null, 'change': fire });
			return E('label', { 'class': 'detour-server' }, [ boxes[m.toLowerCase()], ' ', pu.deviceName(m, devs) ]);
		}));
		extra.addEventListener('change', fire);
		return E('div', {}, [ known.length ? list : E('em', {}, _('The router does not know any devices yet.')),
			E('div', { 'class': 'cbi-value-description' }, _('Other devices by MAC address, separated by spaces:')), extra, err ]);
	},

	// the router's own networks (guest, IoT ...): not the provider's, not a tunnel of an exit
	networkPicker: function(current, onChange) {
		const exitIfs = {};
		uci.sections('detour', 'exit').forEach(function(e) { exitIfs[e.iface || e['.name']] = true; });
		const nets = uci.sections('network', 'interface').filter(function(s) {
			const n = s['.name'];
			return n != 'loopback' && !/^wan/.test(n) && !exitIfs[n] && [ 'wireguard', 'amneziawg', 'none', 'pppoe', 'dhcpv6', '6in4', '6to4' ].indexOf(s.proto) < 0;
		}).map(function(s) { return s['.name']; });
		const boxes = {};
		const fire = function() {
			const out = Object.keys(boxes).filter(function(n) { return boxes[n].checked; });
			// a network of the policy the router no longer has stays as it was (Overview reports it)
			current.forEach(function(n) { if (!(n in boxes) && out.indexOf(n) < 0) out.push(n); });
			onChange(out);
		};
		return E('div', { 'class': 'detour-servers' }, nets.length ? nets.map(function(n) {
			boxes[n] = E('input', { 'type': 'checkbox', 'checked': current.indexOf(n) >= 0 ? '' : null, 'change': fire });
			return E('label', { 'class': 'detour-server' }, [ boxes[n], ' ', n ]);
		}) : E('em', {}, _('The router has no other networks.')));
	},

	drawWhat: function() {
		const self = this, p = this.p, name = p['.name'], kind = msg.policyKind(p);
		const block = kind == 'block', direct = kind == 'direct';
		const put = function(k) { return function(v) { if (v.length) uci.set('detour', name, k, v); else uci.unset('detour', name, k); self.changed(); }; };
		const addr = function(x) { return pu.isAddr(x) ? x : null; };
		this.what.replaceChildren(E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, block ? _('What is blocked') : (direct ? _('What goes directly') : _('What goes through'))),
			E('div', { 'class': 'cbi-section-descr' }, block ? _('Anything that matches one of these is blocked. Bigger sets (advertising, a service) are lists, below.')
				: direct ? _('Anything that matches one of these goes directly. Bigger sets (all Russian sites, a service) are lists, below.')
				: _('Anything that matches one of these goes through the policy. Bigger sets (all blocked sites, a service) are lists, below.')),
			E('div', { 'class': 'cbi-section-node' }, [
				field(_('Sites'), tagField({ values: pu.arr(p.domain), placeholder: _('add a site, for example example.com'), bad: _('Not a site: %s'),
					check: function(x) { const d = pu.asciiDomain(x.replace(/^https?:\/\//, '').replace(/\/.*$/, '')); return pu.isDomain(d) ? d : null; },
					textHelp: _('One per line. A site includes its subdomains (example.com covers www.example.com). Devices must use the router\'s DNS (they do by default).'), onChange: put('domain') })),
				field(_('Addresses'), tagField({ values: pu.arr(p.dst), placeholder: _('add an address or a range'), bad: _('Not an address or a range: %s'), check: addr,
					textHelp: _('IP addresses or ranges (CIDR), one per line.'), onChange: put('dst') })),
				field(_('Devices'), this.devicePicker(pu.arr(p.device), put('device')),
					block ? _('The checked devices get no internet at all.') : (direct ? _('All traffic of the checked devices goes directly.') : _('All traffic of the checked devices goes through the policy.'))),
				field(_('Devices by address'), tagField({ values: pu.arr(p.src), placeholder: _('add an address or a subnet of a device'), bad: _('Not an address or a range: %s'), check: addr,
					textHelp: _('IP addresses or subnets of devices, one per line: a fixed address, a subnet, devices behind another router (where the router sees no MAC address).'), onChange: put('src') })),
				field(_('Networks'), this.networkPicker(pu.arr(p.network), put('network')),
					block ? _('All devices of the checked networks get no internet at all.') : (direct ? _('All traffic of the checked networks goes directly.') : _('All traffic of the checked networks goes through the policy.'))),
				field(_('Ports'), tagField({ values: pu.arr(p.port), placeholder: _('add a port: 443, udp/443, tcp/6000-6100'), bad: _('Not a port: %s'), check: function(x) { return pu.isPort(x) ? x.toLowerCase() : null; },
					textHelp: _('Destination ports: 443 (TCP and UDP), udp/443, tcp/6000-6100. All traffic of the network to these ports goes through the policy.'), onChange: put('port') }))
			])
		]));
	},

	// ---- its lists ----
	drawLists: function() {
		const self = this, name = this.p['.name'];
		const ls = pu.listsOf(name);
		const st = lists.states(this.st);
		const mem = this.st.lists_memory || null;
		const own = ls.reduce(function(s, l) { return s + (l.enabled != '0' ? lists.bytes(st[l['.name']], mem) : 0); }, 0);
		const opts = {
			policy: name, mem: mem,
			onChange: function() { self.changed(); self.drawLists(); },
			onRefresh: function() { return L.resolveDefault(callStatus(), null).then(function(s) { if (s) self.st = s; self.drawLists(); }); }
		};
		this.lists.replaceChildren(E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Lists of this policy')),
			E('div', { 'class': 'cbi-section-descr' }, _('Big sets of sites or addresses from the internet. They are updated every night; if a source does not answer, the previous list stays in use.')),
			E('div', { 'class': 'cbi-section-node detour-node' }, [
				E('div', { 'class': 'detour-actions' }, [
					E('button', { 'class': 'btn cbi-button-add', 'click': function() { lists.edit(null, null, opts); } }, _('Add list')),
					E('button', { 'class': 'btn', 'click': function() { lists.catalog(opts); } }, _('Catalogue of categories…')) ]),
				lists.memory(mem, own),
				ls.length ? E('div', { 'class': 'detour-cards' }, ls.map(function(l) { return lists.card(l, st, opts); }))
					: E('em', { 'class': 'detour-result' }, _('No lists in this policy yet.'))
			])
		]));
	},

	render: function(data) {
		const self = this;
		const name = (L.env.requestpath || [])[4];
		const css = E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') });
		this.p = name ? uci.get('detour', name) : null;
		if (!this.p || this.p['.type'] != 'policy') {
			// not here: removed or renamed since the link was made
			this.missing = true;
			return E('div', {}, [ css, E('div', { 'class': 'cbi-section detour-missing' }, [
				E('h2', {}, _('There is no policy «%s»').format(name || '')),
				E('p', {}, _('It was removed or renamed. The link to it no longer leads anywhere.')),
				E('a', { 'class': 'btn cbi-button-action', 'href': L.url(LIST_URL) }, _('← All policies')) ]) ]);
		}
		this.st = data.status || {};
		this.devs = pu.homeDevices(data.hints, data.leases);
		const lv = (this.st.policies || []).filter(function(x) { return x.name == name; })[0];
		this.pinWas = (lv && lv.pinned) || '';
		this.pinWant = this.pinWas;
		this.dirty = false; this.msg = ''; this.basicOpen = false;
		window.addEventListener('beforeunload', function(ev) { if (self.dirty) { ev.preventDefault(); ev.returnValue = ''; } });
		const back = function(ev) { ev.preventDefault(); self.leave(L.url(LIST_URL)); };
		this.head = E('div', { 'class': 'detour-policy-head' });
		this.banner = E('div');
		this.basic = E('div');
		this.what = E('div');
		this.lists = E('div');
		this.drawHead(); this.drawBanner(); this.drawBasic(); this.drawWhat(); this.drawLists();
		window.setTimeout(function() { self.syncFooter(); }, 0);
		return E('div', { 'class': 'detour-policy-page' }, [ css,
			// a narrow screen: a bar with the way back (the theme's own bar is not this page's)
			E('div', { 'class': 'detour-backbar' }, [
				E('a', { 'class': 'detour-back', 'href': L.url(LIST_URL), 'aria-label': _('Back to the policies'), 'click': back },
					E('span', { 'class': 'detour-back-arrow', 'aria-hidden': 'true' })),
				E('div', {}, [ E('strong', {}, this.p.label || name), E('div', { 'class': 'detour-muted' }, _('Policies')) ]) ]),
			E('nav', { 'class': 'detour-crumbs', 'aria-label': _('Path') }, [
				E('a', { 'href': L.url(LIST_URL), 'click': back }, _('← Policies')), E('span', { 'aria-hidden': 'true' }, '›'), E('span', {}, this.p.label || name) ]),
			this.head, this.banner,
			E('h3', { 'class': 'detour-group' }, _('Settings')),
			this.basic, this.what,
			E('h3', { 'class': 'detour-group' }, _('Lists')),
			this.lists
		]);
	},

	handleSave: function() {
		const self = this;
		if (this.missing) return Promise.resolve();
		const pinLater = this.pinWant != this.pinWas;
		return uci.save().then(function() {
			if (ui.changes && ui.changes.init) ui.changes.init();
			self.dirty = false;
			self.msg = pinLater ? _('Saved. The pinned exit takes effect with «Apply».') : _('Saved. It takes effect with «Apply».');
			self.syncFooter();
			// LuCI enables the footer's button again once this returns: the state goes back on after it
			window.setTimeout(function() { self.syncFooter(); }, 100);
		});
	},
	handleSaveApply: function(ev, mode) {
		const self = this;
		if (this.missing) return ui.changes.apply(mode == '0');
		const name = this.p['.name'];
		return this.handleSave(ev).then(function() {
			if (self.pinWant == self.pinWas) return;
			// the exit chosen by hand: told to the router (a refusal is said; the rest is applied all the same)
			return (self.pinWant ? callPin(name, self.pinWant) : callUnpin(name)).then(function(r) {
				if (r && r.error) ui.addNotification(null, E('p', _('The exit was not chosen: %s').format(r.error)), 'warning');
				else self.pinWas = self.pinWant;
			}).catch(function(e) { ui.addNotification(null, E('p', _('The exit was not chosen: %s').format(e.message || e)), 'warning'); });
		}).then(function() { self.dirty = false; return ui.changes.apply(mode == '0'); });
	},
	handleReset: function() {
		if (this.missing) return Promise.resolve();
		this.dirty = false;
		location.reload();
	}
});
