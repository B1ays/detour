'use strict';
'require view';
'require rpc';
'require ui';
'require uci';
'require detour.msg as msg';

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
	ui.showModal(title, [ E('div', { 'class': 'detour-node' }, body), box,
		E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ', save ]) ]);
}

const RE_MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i;
const RE_IP = /^([0-9]{1,3}(\.[0-9]{1,3}){3}(\/[0-9]{1,2})?|[0-9a-f:]+:[0-9a-f:]*(\/[0-9]{1,3})?)$/i;
const RE_DOM = /^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?\.[a-z]{2,}$/i;
const RE_PORT = /^(tcp\/|udp\/)?\d{1,5}(-\d{1,5})?$/i;

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
		// where
		if (!exits.length) body.push(note(_('No exit: the traffic of this policy is blocked. Choose an exit in «Edit».'), 'warning'));
		else {
			body.push(E('div', {}, [ E('strong', {}, (_('Goes through:') + ' ')), exits.map(function(e) { return self.exitLabel(e); }).join(' → '),
				live.active ? E('span', { 'class': 'detour-muted' }, ' ' + _('(now: %s%s)').format(self.exitLabel(live.active), live.pinned ? ', ' + _('chosen by hand') : '')) : '' ]));
			body.push(E('div', { 'class': 'detour-muted' }, exits.length > 1
				? _('Through the first working exit in this order; when it fails - through the next one, and back when it works again. If all of them fail, this traffic is blocked, not sent directly.')
				: _('If this exit fails, this traffic is blocked, not sent directly. Add a second exit to have a spare.')));
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

		const bEdit = E('button', { 'class': 'btn cbi-button-edit', 'click': function() { self.edit(p, hints); } }, _('Edit'));
		const bUp = E('button', { 'class': 'btn', 'title': _('Checked earlier'), 'disabled': idx == 0 ? '' : null, 'click': function() {
			uci.move('detour', name, all[idx - 1]['.name']); return applyUci(); } }, '↑ ' + _('Up'));
		const bDown = E('button', { 'class': 'btn', 'title': _('Checked later'), 'disabled': idx == all.length - 1 ? '' : null, 'click': function() {
			uci.move('detour', name, all[idx + 1]['.name'], true); return applyUci(); } }, '↓ ' + _('Down'));
		const bToggle = E('button', { 'class': 'btn', 'click': function() { uci.set('detour', name, 'enabled', enabled ? '0' : '1'); return applyUci(); } },
			enabled ? _('Turn off') : _('Turn on'));
		const bRemove = E('button', { 'class': 'btn cbi-button-negative', 'click': function() { self.remove(p, lists); } }, _('Remove'));

		return E('div', { 'class': 'detour-card' }, [
			E('div', { 'class': 'detour-card-head' }, [ E('span', { 'class': 'detour-muted' }, String(idx + 1) + '.'),
				E('span', { 'class': 'detour-card-title' }, label), ' ',
				E('span', { 'class': 'detour-badge ' + (enabled ? 'ok' : 'off') }, enabled ? _('on') : _('off')),
				E('span', { 'class': 'detour-muted', 'title': _('Internal name: used in the configuration and the log') }, name) ]),
			E('div', { 'class': 'detour-card-body' }, body.concat(what)),
			E('div', { 'class': 'detour-actions detour-card-actions' }, [ bEdit, bUp, bDown, bToggle, bRemove ])
		]);
	},

	remove: function(p, lists) {
		const label = p.label || p['.name'];
		ui.showModal(_('Remove the policy «%s»?').format(label), [
			E('p', {}, lists.length ? _('Its lists (%s) are removed too. What went through it goes directly from now on.').format(lists.map(function(l) { return msg.listTitle(l); }).join(', '))
				: _('What went through it goes directly from now on.')),
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

	edit: function(p, hints) {
		const isNew = !p;
		p = p || {};
		const name = E('input', { 'class': 'cbi-input-text', 'placeholder': 'vpn2', 'maxlength': 11 });
		const label = E('input', { 'class': 'cbi-input-text', 'value': p.label || '', 'placeholder': _('for example: Blocked sites') });
		const exits = this.exitPicker(arr(p.exit));
		const devices = this.devicePicker(arr(p.device), hints);
		const dst = E('textarea', { 'class': 'cbi-input-textarea', 'rows': 3, 'placeholder': '203.0.113.0/24' }, arr(p.dst).join('\n'));
		const dom = E('textarea', { 'class': 'cbi-input-textarea', 'rows': 4, 'placeholder': 'example.com' }, arr(p.domain).join('\n'));
		const port = E('input', { 'class': 'cbi-input-text', 'value': arr(p.port).join(' '), 'placeholder': 'udp/443 tcp/6000-6100' });
		const body = [];
		if (isNew) body.push(row(_('Internal name'), name, _('Latin letters, digits and _, up to 11; used in the configuration.')));
		body.push(
			row(_('Name'), label, _('How the policy is shown everywhere.')),
			row(_('Exits'), exits, _('In order: the traffic goes through the first working exit; when it fails, through the next one, and back when it works again. If all fail, the traffic is blocked, not sent directly.')),
			E('h4', {}, _('What goes through')),
			E('div', { 'class': 'cbi-value-description' }, _('Anything that matches one of these goes through the policy. Bigger sets (all blocked sites, a service) are added as lists on the Lists page.')),
			row(_('Devices'), devices, _('All traffic of the checked devices goes through the policy.')),
			row(_('Sites'), dom, _('One per line. A site includes its subdomains (example.com covers www.example.com). Devices must use the router\'s DNS (they do by default).')),
			row(_('Addresses'), dst, _('IP addresses or ranges (CIDR), one per line.')),
			row(_('Ports'), port, _('Destination ports: 443 (TCP and UDP), udp/443, tcp/6000-6100, separated by spaces. All traffic of the network to these ports goes through the policy.'))
		);
		const self = this;
		modal(isNew ? _('New policy') : _('Policy «%s»').format(p.label || p['.name']), body, function() {
			let n = p['.name'];
			if (isNew) {
				n = name.value.trim();
				if (!/^[a-z][a-z0-9_]{0,10}$/.test(n)) throw new Error(_('Internal name: a-z, 0-9, _, starts with a letter, up to 11'));
				if (uci.get('detour', n)) throw new Error(_('This name is already used'));
			}
			const bad = [];
			const d = lines(dst.value), o = lines(dom.value).map(function(x) { return x.toLowerCase(); }), pt = lines(port.value), dv = devices.get();
			d.forEach(function(x) { if (!RE_IP.test(x)) bad.push(x); });
			o.forEach(function(x) { if (!RE_DOM.test(x)) bad.push(x); });
			pt.forEach(function(x) { if (!RE_PORT.test(x)) bad.push(x); });
			dv.forEach(function(x) { if (!RE_MAC.test(x)) bad.push(x); });
			if (bad.length) throw new Error(_('Not understood: %s').format(bad.join(', ')));
			if (isNew) {
				uci.add('detour', 'policy', n);
				const used = {};
				uci.sections('detour', 'policy').forEach(function(s) { used[+s.id] = true; });
				let id = 1; while (used[id] && id < 250) id++;
				uci.set('detour', n, 'id', String(id));
			}
			const set = function(k, v) { if (v && (!Array.isArray(v) || v.length)) uci.set('detour', n, k, v); else uci.unset('detour', n, k); };
			set('label', label.value.trim());
			set('exit', exits.get());
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
			E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') }),
			E('h2', {}, _('Policies')),
			E('div', { 'class': 'cbi-map-descr' }, _('A policy says what goes through which exits: devices, sites, addresses, ports, lists. Policies are checked from top to bottom, the first that matches takes the traffic; what matches none goes directly through your provider. «Always direct» in Settings is checked before all of them.')),
			E('div', { 'class': 'cbi-section' }, [
				E('div', { 'class': 'cbi-section-node detour-node' }, [
					all.length ? E('div', { 'class': 'detour-cards' }, all.map(function(p, i) { return self.renderPolicy(p, i, all, st, hints); }))
						: E('div', { 'class': 'detour-result' }, E('em', {}, _('No policies yet: everything goes directly.'))),
					E('div', { 'class': 'detour-actions' }, [ E('button', { 'class': 'btn cbi-button-add', 'click': function() { self.edit(null, hints); } }, _('Add policy')) ])
				])
			])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
