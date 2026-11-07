'use strict';
'require view';
'require form';
'require uci';
'require network';
'require rpc';
'require ui';
'require tools.widgets as widgets';

const callStatus = rpc.declare({ object: 'detour', method: 'status' });
const callSubUpdate = rpc.declare({ object: 'detour', method: 'sub_update', params: [ 'name' ] });
let subState = {};

function nextId(type) {
	const used = {};
	uci.sections('detour', type).forEach(function(s) { used[+s.id] = true; });
	for (let i = 1; i <= 250; i++) if (!used[i]) return String(i);
	return '';
}

function uniqueId(type) {
	return function(section_id, value) {
		if (!/^[0-9]+$/.test(value) || +value < 1 || +value > 250) return _('A number from 1 to 250');
		const dup = uci.sections('detour', type).filter(function(s) { return s['.name'] != section_id && s.id == value; });
		return dup.length ? _('Already used by %s').format(dup[0]['.name']) : true;
	};
}

return view.extend({
	load: function() {
		return Promise.all([ uci.load('detour'), network.getNetworks(), callStatus().catch(function() { return {}; }) ]).then(function(r) {
			subState = {};
			((r[2] || {}).subscriptions || []).forEach(function(s) { subState[s.name] = s; });
			return r;
		});
	},

	render: function() {
		const m = new form.Map('detour', _('Exits'),
			_('An exit is a tunnel interface (WireGuard, AmneziaWG or the tun device of a proxy engine). ' +
			  'Traffic sent to an exit can only leave through its device: when it is down, that traffic is blocked, not sent directly.'));

		const s = m.section(form.GridSection, 'exit');
		s.addremove = true;
		s.anonymous = false;
		s.nodescriptions = true;
		s.sortable = false;
		s.addbtntitle = _('Add exit');

		let o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.editable = true;

		o = s.option(form.Value, 'label', _('Description'));
		o.optional = true;
		o.modalonly = true;

		o = s.option(widgets.NetworkSelect, 'iface', _('Interface'),
			_('The netifd interface of the tunnel. Its device is used unless set below.'));
		o.nocreate = true;
		o.rmempty = false;

		o = s.option(form.Value, 'device', _('Device'), _('Only when the device name differs from the interface name (proxy tun).'));
		o.optional = true;
		o.modalonly = true;
		o.datatype = 'netdevname';

		o = s.option(form.Value, 'probe', _('Health check'),
			_('An IP address to ping through the tunnel, or an http(s) URL. Empty: only the device state is checked.'));
		o.optional = true;
		o.validate = function(section_id, v) {
			if (!v) return true;
			if (/^https?:\/\//.test(v)) return true;
			return /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(v) ? true : _('An IPv4 address or an http(s) URL');
		};

		o = s.option(form.Value, 'id', _('Number'), _('Internal number 1-250, part of the packet mark. Do not change while in use.'));
		o.modalonly = true;
		o.rmempty = false;
		o.cfgvalue = function(section_id) { return uci.get('detour', section_id, 'id') || nextId('exit'); };
		o.validate = uniqueId('exit');

		// subscriptions: one exit "<name>_sub" per subscription, its servers in an automatic group
		const ss = m.section(form.GridSection, 'subscription', _('Subscriptions'),
			_('An address from your VPN provider that returns the current list of servers. ' +
			  'All its servers form one exit (named NAME_sub) that picks a working, fast one by itself. Updated every night. ' +
			  'Name: up to 11 characters a-z, 0-9, _.'));
		ss.addremove = true;
		ss.anonymous = false;
		ss.nodescriptions = true;
		ss.addbtntitle = _('Add subscription');

		o = ss.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.editable = true;

		o = ss.option(form.Value, 'label', _('Description'));
		o.optional = true;

		o = ss.option(form.Value, 'url', _('Subscription address'), _('Kept secret: it is shown only here and never logged.'));
		o.password = true;
		o.rmempty = false;
		o.modalonly = true;
		o.validate = function(id, v) { return /^https?:\/\/\S+$/.test(v || '') ? true : _('http(s) address'); };

		o = ss.option(form.ListValue, 'via', _('Connect to the servers'));
		o.value('', _('directly'));
		uci.sections('detour', 'exit').forEach(function(e) {
			if (!/_sub$/.test(e['.name'])) o.value(e['.name'], _('through %s').format(e.label || e['.name']));
		});
		o.modalonly = true;

		o = ss.option(form.Value, 'user_agent', _('Client name (User-Agent)'), _('Some providers choose the format by it.'));
		o.placeholder = 'v2rayNG/1.10.0';
		o.optional = true;
		o.modalonly = true;

		o = ss.option(form.Value, 'hwid', _('Device id (x-hwid)'), _('Only if your provider counts devices.'));
		o.optional = true;
		o.modalonly = true;

		o = ss.option(form.DummyValue, '_state', _('State'));
		o.modalonly = false;
		o.textvalue = function(id) {
			const st = (subState || {})[id];
			if (!st) return E('em', {}, _('not loaded yet'));
			// the daemon writes a stable code with each state; its message (English) is the fallback
			const text = {
				'updated': function() {
					return N_(st.count, '%d server', '%d servers').format(st.count) +
						(st.skipped ? ', ' + N_(st.skipped, '%d skipped', '%d skipped').format(st.skipped) : '');
				},
				'disabled': function() { return _('disabled'); },
				'bad_url': function() { return _('bad address'); },
				'private': function() { return _('the address points into a private network'); },
				'download_failed': function() { return _('download failed, the previous servers are kept'); },
				'no_servers': function() { return _('no usable servers in the answer, the previous servers are kept'); }
			}[st.code];
			return E('span', { 'class': st.ok ? '' : 'detour-warn' }, [ text ? text() : (st.message || ''), ' ',
				E('small', {}, '(' + new Date(st.ts * 1000).toLocaleString() + ')') ]);
		};

		o = ss.option(form.Button, '_update', _('Update'));
		o.modalonly = false;
		o.editable = true;
		o.inputtitle = _('Update now');
		o.inputstyle = 'action';
		o.onclick = function(ev, id) {
			return callSubUpdate(id).then(function(r) {
				if (r && r.error) ui.addNotification(null, E('p', r.error), 'danger');
				else ui.addNotification(null, E('p', _('%d servers').format((r && r.servers) || 0)), 'info');
				window.setTimeout(function() { location.reload(); }, 800);
			});
		};

		// detour.css: the last field of a card must not touch its bottom (Argon gives the node no padding)
		return m.render().then(function(node) {
			node.insertBefore(E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') }), node.firstChild);
			return node;
		});
	}
});
