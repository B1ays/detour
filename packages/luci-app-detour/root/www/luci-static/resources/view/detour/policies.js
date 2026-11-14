'use strict';
'require view';
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

// Policies as cards in the order they are checked: what goes through (devices by name, addresses, domains,
// ports, the lists attached), where (the exits in order, what happens when they fail), editing, moving up and
// down, removal. Plain UCI (config "detour", sections "policy"), applied the standard LuCI way.

const callStatus = rpc.declare({ object: 'detour', method: 'status' });
const callHints = rpc.declare({ object: 'luci-rpc', method: 'getHostHints', expect: { '': {} } });
const callLeases = rpc.declare({ object: 'luci-rpc', method: 'getDHCPLeases', expect: { '': {} } });

function busy(btn, on) { btn.disabled = on; btn.classList.toggle('spinning', on); }
function note(text, cls) { return E('div', { 'class': 'alert-message ' + (cls || 'notice') }, text); }
function arr(v) { return Array.isArray(v) ? v : (v ? String(v).split(/\s+/) : []); }
function lines(t) { return t.split(/[\s,]+/).map(function(x) { return x.trim(); }).filter(function(x) { return x; }); }
function applyUci() { return uci.save().then(function() { return ui.changes.apply(); }); }

function row(title, field, descr) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, title),
		E('div', { 'class': 'cbi-value-field' }, descr ? [ field, E('div', { 'class': 'cbi-value-description' }, descr) ] : field)
	]);
}

function modal(title, body, onSave) {
	const box = E('div', { 'class': 'detour-result' });
	const save = E('button', { 'class': 'btn cbi-button-positive', 'click': function() {
		busy(save, true);
		return Promise.resolve().then(function() { return onSave(); }).then(function(done) { if (done) ui.hideModal(); })
			.catch(function(e) { box.replaceChildren(note(e.message || String(e), 'warning')); })
			.finally(function() { busy(save, false); });
	} }, _('Save'));
	ui.showModal([ title ], [ E('div', { 'class': 'detour-node' }, body), box,
		E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ', save ]) ]);
}

const RE_MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i;
// the same checks as the router's (core.uc is_v4 / is_v6, the port range): what passes here is applied there
function isV4(a) {
	const m = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})(\/(0|[1-9]\d?))?$/.exec(a);
	if (!m) return false;
	for (let i = 1; i <= 4; i++) if (+m[i] > 255) return false;
	return m[6] == null || +m[6] <= 32;
}
function isV6(a) {
	const m = /^([0-9a-f:]+)(\/(0|[1-9]\d{0,2}))?$/i.exec(a);
	if (!m || m[1].indexOf(':') < 0 || (m[3] != null && +m[3] > 128)) return false;
	const halves = m[1].split('::');
	if (halves.length > 2) return false;
	let n = 0;
	for (const h of halves) {
		if (h == '') continue;
		for (const g of h.split(':')) { if (!/^[0-9a-f]{1,4}$/i.test(g)) return false; n++; }
	}
	return halves.length == 2 ? n <= 7 : n == 8;
}
function isPort(x) {
	const m = /^(tcp\/|udp\/)?(\d{1,5})(-(\d{1,5}))?$/i.exec(x);
	if (!m) return false;
	const lo = +m[2], hi = m[4] != null ? +m[4] : lo;
	return lo >= 1 && hi <= 65535 && hi >= lo;
}
// a domain with a dot; the zone may be punycode (.xn--p1ai is .рф)
// сайт.рф -> xn--80aswg.xn--p1ai (dnsmasq and the lists take the ASCII form); plain ASCII is only lower-cased
function asciiDomain(x) {
	x = x.toLowerCase();
	if (!/[^\x00-\x7f]/.test(x)) return x;
	try { return new URL('http://' + x).hostname; } catch (e) { return x; }
}
const RE_DOM = /^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?\.([a-z]{2,}|xn--[a-z0-9-]*[a-z0-9])$/i;

return view.extend({
	load: function() {
		return Promise.all([ uci.load('detour'), L.resolveDefault(callStatus(), {}), L.resolveDefault(callHints(), {}),
			L.resolveDefault(callLeases(), {}), L.resolveDefault(uci.load('dhcp'), null) ]).then(function(r) {
			// the devices of the home network: DHCP leases and reserved addresses (getHostHints also knows the
			// router's tunnel and WAN neighbours), named from the lease, the reservation or the hints
			const hints = r[2] || {}, lan = {};
			const put = function(mac, name, ip) {
				if (!mac || !RE_MAC.test(mac)) return;
				const k = mac.toUpperCase(), h = lan[k] || (lan[k] = { name: null, ipaddrs: [] });
				if (name && !h.name) h.name = name;
				if (ip && h.ipaddrs.indexOf(ip) < 0) h.ipaddrs.push(ip);
			};
			((r[3] || {}).dhcp_leases || []).forEach(function(l) { put(l.macaddr, l.hostname, l.ipaddr); });
			uci.sections('dhcp', 'host').forEach(function(h) { arr(h.mac).forEach(function(m) { put(m, h.name, h.ip); }); });
			Object.keys(lan).forEach(function(k) { const h = hints[k] || {}; if (!lan[k].name && h.name) lan[k].name = h.name; });
			r[2] = lan;
			return r;
		});
	},

	exitLabel: function(n) { return uci.get('detour', n, 'label') || n; },

	deviceName: function(mac, hints) {
		const h = hints[mac.toUpperCase()] || hints[mac.toLowerCase()] || {};
		const ip = (h.ipaddrs || h.ipv4 || [])[0];
		return (h.name ? h.name + ' ' : '') + '(' + (ip ? ip + ', ' : '') + mac.toLowerCase() + ')';
	},

	renderPolicy: function(p, idx, all, st, hints) {
		const self = this;
		const name = p['.name'];
		const label = p.label || name;
		const exits = arr(p.exit);
		const live = (st.policies || []).filter(function(x) { return x.name == name; })[0] || {};
		const lists = uci.sections('detour', 'list').filter(function(l) { return l.policy == name && l.enabled != '0'; });
		const enabled = p.enabled != '0';

		const body = [];
		const kind = msg.policyKind(p);
		const block = kind == 'block';
		const direct = p.on_down == 'direct';
		// where
		if (kind == 'direct') {
			body.push(E('div', {}, [ E('strong', {}, _('Never through a tunnel.')), ' ',
				_('What matches goes directly through your provider, and the policies below this one never take it.') ]));
		}
		else if (block) {
			body.push(E('div', {}, [ E('strong', {}, _('Lets nothing through.')), ' ',
				_('Addresses, devices and ports below are refused at once, the sites get «no such name» - apps stop trying instead of waiting.') ]));
			if (st.blocked) body.push(E('div', { 'class': 'detour-muted' }, _('Refused since the start: %d connections.').format(st.blocked)));
		}
		else if (!exits.length) body.push(note(_('No exit: the traffic of this policy is blocked. Choose an exit in «Edit».'), 'warning'));
		else {
			body.push(E('div', {}, [ E('strong', {}, (_('Goes through:') + ' ')), exits.map(function(e) { return self.exitLabel(e); }).join(' → '),
				live.active ? E('span', { 'class': 'detour-muted' }, ' ' + _('(now: %s%s)').format(self.exitLabel(live.active), live.pinned ? ', ' + _('chosen by hand') : '')) : '' ]));
			body.push(E('div', { 'class': 'detour-muted' }, direct
				? (exits.length > 1 ? _('Through the first working exit in this order; when it fails - through the next one, and back when it works again. If all of them fail, this traffic goes directly through your provider (as chosen in «Edit»).')
					: _('If this exit fails, this traffic goes directly through your provider (as chosen in «Edit»).'))
				: (exits.length > 1 ? _('Through the first working exit in this order; when it fails - through the next one, and back when it works again. If all of them fail, this traffic is blocked, not sent directly.')
					: _('If this exit fails, this traffic is blocked, not sent directly. Add a second exit to have a spare.'))));
			if (live.direct) body.push(note(_('Now no exit works: this traffic goes directly, the provider sees it.'), 'warning'));
		}
		// what
		const what = [];
		const devs = arr(p.device);
		if (devs.length) what.push(E('div', {}, [ E('strong', {}, (_('Devices (all their traffic):') + ' ')), devs.map(function(d) { return self.deviceName(d, hints); }).join(', ') ]));
		const dsts = arr(p.dst);
		if (dsts.length) what.push(E('div', {}, [ E('strong', {}, (_('Addresses:') + ' ')), dsts.slice(0, 6).join(', ') + (dsts.length > 6 ? ' ' + _('and %d more').format(dsts.length - 6) : '') ]));
		const doms = arr(p.domain);
		if (doms.length) what.push(E('div', {}, [ E('strong', {}, (_('Sites:') + ' ')), doms.slice(0, 8).join(', ') + (doms.length > 8 ? ' ' + _('and %d more').format(doms.length - 8) : ''),
			E('span', { 'class': 'detour-muted' }, ' ' + _('(with subdomains)')) ]));
		const ports = arr(p.port);
		if (ports.length) what.push(E('div', {}, [ E('strong', {}, (_('Ports:') + ' ')), ports.join(', ') ]));
		if (lists.length) what.push(E('div', {}, [ E('strong', {}, (_('Lists:') + ' ')), lists.map(function(l) { return msg.listTitle(l); }).join(', '),
			' ', E('a', { 'href': L.url('admin/services/detour/lists') }, _('(on the Lists page)')) ]));
		if (!what.length) what.push(E('em', {}, _('Nothing goes through it yet: add devices, sites, addresses, ports or lists.')));

		const bEdit = E('button', { 'class': 'btn cbi-button-action', 'click': function() { self.edit(p, hints, kind); } }, _('Edit'));
		const bUp = E('button', { 'class': 'btn', 'title': _('Checked earlier'), 'disabled': idx == 0 ? '' : null, 'click': function() {
			uci.move('detour', name, all[idx - 1]['.name']); return applyUci(); } }, '↑ ' + _('Higher priority'));
		const bDown = E('button', { 'class': 'btn', 'title': _('Checked later'), 'disabled': idx == all.length - 1 ? '' : null, 'click': function() {
			uci.move('detour', name, all[idx + 1]['.name'], true); return applyUci(); } }, '↓ ' + _('Lower priority'));
		const bToggle = E('button', { 'class': 'btn', 'click': function() { uci.set('detour', name, 'enabled', enabled ? '0' : '1'); return applyUci(); } },
			enabled ? _('Turn off') : _('Turn on'));
		const bRemove = E('button', { 'class': 'btn cbi-button-negative', 'click': function() { self.remove(p, lists); } }, _('Remove'));

		return E('div', { 'class': 'detour-card' }, [
			E('div', { 'class': 'detour-card-head' }, [ E('span', { 'class': 'detour-muted' }, String(idx + 1) + '.'),
				E('span', { 'class': 'detour-card-title' }, label), ' ',
				E('span', { 'class': 'detour-badge ' + (enabled ? (block ? 'bad' : 'ok') : 'off') },
					enabled ? (block ? _('blocks') : (kind == 'direct' ? _('directly') : _('on'))) : _('switched off')),
				E('span', { 'class': 'detour-muted', 'title': _('Internal name: used in the configuration and the log') }, name) ]),
			E('div', { 'class': 'detour-card-body' }, body.concat(what)),
			E('div', { 'class': 'detour-actions detour-card-actions' }, [ bEdit, bUp, bDown, bToggle, bRemove ])
		]);
	},

	remove: function(p, lists) {
		const label = p.label || p['.name'];
		ui.showModal([ _('Remove the policy «%s»?').format(label) ], [
			E('p', {}, p.action == 'block'
				? (lists.length ? _('Its lists (%s) are removed too. What it blocked opens again.').format(lists.map(function(l) { return msg.listTitle(l); }).join(', ')) : _('What it blocked opens again.'))
				: p.action == 'direct'
				? (lists.length ? _('Its lists (%s) are removed too. What it sent directly goes by the other policies from now on.').format(lists.map(function(l) { return msg.listTitle(l); }).join(', '))
				: _('What it sent directly goes by the other policies from now on.'))
				: (lists.length ? _('Its lists (%s) are removed too. What went through it goes directly from now on.').format(lists.map(function(l) { return msg.listTitle(l); }).join(', '))
				: _('What went through it goes directly from now on.'))),
			E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
				E('button', { 'class': 'btn cbi-button-negative', 'click': function() {
					lists.forEach(function(l) { uci.remove('detour', l['.name']); });
					uci.remove('detour', p['.name']);
					if (uci.get('detour', 'main', 'dns_policy') == p['.name']) { uci.set('detour', 'main', 'dns', 'off'); uci.unset('detour', 'main', 'dns_policy'); }
					ui.hideModal();
					return applyUci();
				} }, _('Remove')) ]) ]);
	},

	// the exits of a policy, in order: a list with up / down / remove and an "add" select
	exitPicker: function(current) {
		const self = this;
		let chosen = current.slice();
		const box = E('div', { 'class': 'detour-picker' });
		const all = uci.sections('detour', 'exit').map(function(e) { return e['.name']; });
		const draw = function() {
			const rows = chosen.map(function(n, i) {
				return E('div', { 'class': 'detour-pick-row' }, [
					E('span', {}, (i + 1) + '. ' + self.exitLabel(n)),
					E('button', { 'class': 'btn', 'disabled': i == 0 ? '' : null, 'click': function(ev) { ev.preventDefault(); const t = chosen[i - 1]; chosen[i - 1] = n; chosen[i] = t; draw(); } }, '↑'),
					E('button', { 'class': 'btn', 'disabled': i == chosen.length - 1 ? '' : null, 'click': function(ev) { ev.preventDefault(); const t = chosen[i + 1]; chosen[i + 1] = n; chosen[i] = t; draw(); } }, '↓'),
					E('button', { 'class': 'btn cbi-button-negative', 'click': function(ev) { ev.preventDefault(); chosen.splice(i, 1); draw(); } }, '×')
				]);
			});
			const free = all.filter(function(n) { return chosen.indexOf(n) < 0; });
			const sel = E('select', { 'class': 'cbi-input-select', 'change': function() { if (sel.value) { chosen.push(sel.value); draw(); } } },
				[ E('option', { 'value': '' }, free.length ? _('— add an exit —') : _('— no more exits —')) ].concat(free.map(function(n) { return E('option', { 'value': n }, self.exitLabel(n)); })));
			box.replaceChildren.apply(box, rows.concat([ sel ]));
		};
		draw();
		box.get = function() { return chosen; };
		return box;
	},

	devicePicker: function(current, hints) {
		const self = this;
		const known = Object.keys(hints).filter(function(m) { return RE_MAC.test(m); }).sort(function(a, b) {
			return ((hints[a].name || '~') + a).localeCompare((hints[b].name || '~') + b); });
		const cur = current.map(function(m) { return m.toLowerCase(); });
		const boxes = {};
		const list = E('div', { 'class': 'detour-servers' }, known.map(function(m) {
			boxes[m.toLowerCase()] = E('input', { 'type': 'checkbox', 'checked': cur.indexOf(m.toLowerCase()) >= 0 ? '' : null });
			return E('label', { 'class': 'detour-server' }, [ boxes[m.toLowerCase()], ' ', self.deviceName(m, hints) ]);
		}));
		const extra = E('input', { 'class': 'cbi-input-text', 'placeholder': 'aa:bb:cc:dd:ee:ff',
			'value': cur.filter(function(m) { return !boxes[m]; }).join(' ') });
		const wrap = E('div', {}, [ known.length ? list : E('em', {}, _('The router does not know any devices yet.')),
			E('div', { 'class': 'cbi-value-description' }, _('Other devices by MAC address, separated by spaces:')), extra ]);
		wrap.get = function() {
			const out = Object.keys(boxes).filter(function(m) { return boxes[m].checked; });
			lines(extra.value.toLowerCase()).forEach(function(m) { if (out.indexOf(m) < 0) out.push(m); });
			return out;
		};
		return wrap;
	},

	// kind: 'vpn' (through exits), 'block' (no exits, nothing gets through) or 'direct' (no exits, never a tunnel)
	edit: function(p, hints, kind) {
		const isNew = !p;
		p = p || {};
		kind = isNew ? (kind || 'vpn') : msg.policyKind(p);
		const block = kind == 'block', direct = kind == 'direct', vpn = kind == 'vpn';
		const name = E('input', { 'class': 'cbi-input-text', 'placeholder': 'vpn2', 'maxlength': 11 });
		const label = E('input', { 'class': 'cbi-input-text', 'value': p.label || '', 'placeholder': _('for example: Blocked sites') });
		const exits = this.exitPicker(arr(p.exit));
		const devices = this.devicePicker(arr(p.device), hints);
		const dst = E('textarea', { 'class': 'cbi-input-textarea', 'rows': 3, 'placeholder': '203.0.113.0/24' }, arr(p.dst).join('\n'));
		const dom = E('textarea', { 'class': 'cbi-input-textarea', 'rows': 4, 'placeholder': 'example.com' }, arr(p.domain).join('\n'));
		const port = E('input', { 'class': 'cbi-input-text', 'value': arr(p.port).join(' '), 'placeholder': 'udp/443 tcp/6000-6100' });
		// when every exit is down: blocked (the default, nothing leaks) or directly - asked for, with the price said
		const onDown = E('select', { 'class': 'cbi-input-select', 'change': function() {
			if (onDown.value == 'direct' && !confirm(_('When every exit of this policy fails, its traffic will go directly through your provider: the provider sees which sites these are, and blocked ones will not open anyway. Let it through?')))
				onDown.value = 'block';
		} }, [ E('option', { 'value': 'block', 'selected': p.on_down != 'direct' ? '' : null }, _('block it (nothing leaks)')),
			E('option', { 'value': 'direct', 'selected': p.on_down == 'direct' ? '' : null }, _('let it go directly through the provider')) ]);
		const body = [];
		if (isNew) body.push(row(_('Internal name'), name, _('Latin letters, digits and _, up to 11; used in the configuration.')));
		body.push(row(_('Name'), label, _('How the policy is shown everywhere.')));
		if (block) body.push(note(_('A blocking policy: what matches it gets no internet at all. Sites get «no such name», addresses and ports are refused at once.')));
		else if (direct) body.push(note(_('A direct policy: what matches it never goes through a tunnel, it goes directly through your provider. Put it above the policies it should make exceptions in.')));
		else body.push(
			row(_('Exits'), exits, _('In order: the traffic goes through the first working exit; when it fails, through the next one, and back when it works again.')),
			row(_('If no exit works'), onDown, _('Blocked is safer: nothing goes past the tunnel. Directly keeps things working without the VPN, but the provider sees this traffic.')));
		body.push(
			E('h4', {}, block ? _('What is blocked') : (direct ? _('What goes directly') : _('What goes through'))),
			E('div', { 'class': 'cbi-value-description' }, block ? _('Anything that matches one of these is blocked. Bigger sets (advertising, a service) are added as lists on the Lists page.')
				: direct ? _('Anything that matches one of these goes directly. Bigger sets (all Russian sites, a service) are added as lists on the Lists page.')
				: _('Anything that matches one of these goes through the policy. Bigger sets (all blocked sites, a service) are added as lists on the Lists page.')),
			row(_('Devices'), devices, block ? _('The checked devices get no internet at all.') : (direct ? _('All traffic of the checked devices goes directly.') : _('All traffic of the checked devices goes through the policy.'))),
			row(_('Sites'), dom, _('One per line. A site includes its subdomains (example.com covers www.example.com). Devices must use the router\'s DNS (they do by default).')),
			row(_('Addresses'), dst, _('IP addresses or ranges (CIDR), one per line.')),
			row(_('Ports'), port, _('Destination ports: 443 (TCP and UDP), udp/443, tcp/6000-6100, separated by spaces. All traffic of the network to these ports goes through the policy.'))
		);
		const self = this;
		modal(isNew ? (block ? _('New blocking policy') : (direct ? _('New direct policy') : _('New policy'))) : _('Policy «%s»').format(p.label || p['.name']), body, function() {
			let n = p['.name'];
			if (isNew) {
				n = name.value.trim();
				if (!/^[a-z][a-z0-9_]{0,10}$/.test(n)) throw new Error(_('Internal name: a-z, 0-9, _, starts with a letter, up to 11'));
				if (uci.get('detour', n)) throw new Error(_('This name is already used'));
			}
			const bad = [];
			const d = lines(dst.value), o = lines(dom.value).map(asciiDomain), pt = lines(port.value), dv = devices.get();
			d.forEach(function(x) { if (!isV4(x) && !isV6(x)) bad.push(x); });
			o.forEach(function(x) { if (!RE_DOM.test(x)) bad.push(x); });
			pt.forEach(function(x) { if (!isPort(x)) bad.push(x); });
			dv.forEach(function(x) { if (!RE_MAC.test(x)) bad.push(x); });
			if (bad.length) throw new Error(_('Not understood: %s').format(bad.join(', ')));
			if (isNew) {
				uci.add('detour', 'policy', n);
				const used = {};
				uci.sections('detour', 'policy').forEach(function(s) { used[+s.id] = true; });
				let id = 1; while (used[id] && id <= 250) id++;
				if (id > 250) throw new Error(_('No free policy id: 250 policies is the limit'));
				uci.set('detour', n, 'id', String(id));
				// a blocking or direct policy goes first: what it covers must not be taken by another policy before it
				// (a direct one can then be moved below the policies it should not make exceptions in)
				if (!vpn) {
					uci.set('detour', n, 'action', kind);
					const first = uci.sections('detour', 'policy')[0];
					if (first && first['.name'] != n) uci.move('detour', n, first['.name']);
				}
			}
			const set = function(k, v) { if (v && (!Array.isArray(v) || v.length)) uci.set('detour', n, k, v); else uci.unset('detour', n, k); };
			set('label', label.value.trim() || (block ? _('Block') : (direct ? _('Directly') : '')));
			if (vpn) { set('exit', exits.get()); set('on_down', onDown.value == 'direct' ? 'direct' : null); }
			set('device', dv); set('dst', d); set('domain', o); set('port', pt);
			return applyUci().then(function() { return true; });
		});
	},

	render: function(data) {
		const self = this;
		const st = data[1] || {};
		const hints = data[2] || {};
		const all = uci.sections('detour', 'policy');
		return E('div', {}, [
			E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') }),
			E('h2', {}, _('Policies')),
			E('div', { 'class': 'cbi-map-descr' }, _('A policy says where devices, sites, addresses, ports and lists go: through VPN exits, directly (never through a tunnel) or nowhere (blocked). Policies are checked from top to bottom, the first that matches takes the traffic; what matches none goes directly through your provider.')),
			E('div', { 'class': 'cbi-section' }, [
				E('div', { 'class': 'cbi-section-node detour-node' }, [
					all.length ? E('div', { 'class': 'detour-cards' }, all.map(function(p, i) { return self.renderPolicy(p, i, all, st, hints); }))
						: E('div', { 'class': 'detour-result' }, E('em', {}, _('No policies yet: everything goes directly.'))),
					E('div', { 'class': 'detour-actions' }, [ E('button', { 'class': 'btn cbi-button-add', 'click': function() { self.edit(null, hints); } }, _('Add policy')),
						E('button', { 'class': 'btn', 'click': function() { self.edit(null, hints, 'direct'); } }, _('Add direct')),
						E('button', { 'class': 'btn', 'click': function() { self.edit(null, hints, 'block'); } }, _('Add blocking')) ])
				])
			])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
