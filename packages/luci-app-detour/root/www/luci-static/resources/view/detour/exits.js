'use strict';
'require view';
'require form';
'require uci';
'require network';
'require tools.widgets as widgets';

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
		return Promise.all([ uci.load('detour'), network.getNetworks() ]);
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

		return m.render();
	}
});
