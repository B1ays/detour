'use strict';
'require view';
'require form';
'require uci';

function nextId() {
	const used = {};
	uci.sections('detour', 'policy').forEach(function(s) { used[+s.id] = true; });
	for (let i = 1; i <= 250; i++) if (!used[i]) return String(i);
	return '';
}

return view.extend({
	load: function() {
		return uci.load('detour');
	},

	render: function() {
		const exits = uci.sections('detour', 'exit');
		const m = new form.Map('detour', _('Policies'),
			_('A policy says what goes through the tunnel: whole devices, address ranges or domains. ' +
			  'The first working exit in its list carries the traffic; policies are checked from top to bottom.'));

		const s = m.section(form.GridSection, 'policy');
		s.addremove = true;
		s.anonymous = false;
		s.sortable = true;
		s.nodescriptions = true;
		s.addbtntitle = _('Add policy');

		s.tab('general', _('General'));
		s.tab('match', _('What goes through'));

		let o = s.taboption('general', form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.editable = true;

		o = s.taboption('general', form.Value, 'label', _('Description'));
		o.optional = true;
		o.modalonly = true;

		o = s.taboption('general', form.DynamicList, 'exit', _('Exits'),
			_('In order of preference. When the first one fails, the next working one takes over; it comes back automatically.'));
		exits.forEach(function(e) { o.value(e['.name'], e.label || e['.name']); });
		o.rmempty = false;
		o.textvalue = function(section_id) { return (uci.get('detour', section_id, 'exit') || []).join(' → '); };

		o = s.taboption('general', form.Value, 'id', _('Number'), _('Internal number 1-250, part of the packet mark.'));
		o.modalonly = true;
		o.rmempty = false;
		o.cfgvalue = function(section_id) { return uci.get('detour', section_id, 'id') || nextId(); };
		o.validate = function(section_id, value) {
			if (!/^[0-9]+$/.test(value) || +value < 1 || +value > 250) return _('A number from 1 to 250');
			const dup = uci.sections('detour', 'policy').filter(function(x) { return x['.name'] != section_id && x.id == value; });
			return dup.length ? _('Already used by %s').format(dup[0]['.name']) : true;
		};

		o = s.taboption('match', form.DynamicList, 'device', _('Devices'), _('MAC addresses: all traffic of these devices.'));
		o.datatype = 'macaddr';
		o.modalonly = true;

		o = s.taboption('match', form.DynamicList, 'dst', _('Addresses'), _('IP addresses or ranges (CIDR), IPv4 or IPv6.'));
		o.datatype = 'ipaddr';
		o.modalonly = true;

		o = s.taboption('match', form.DynamicList, 'domain', _('Domains'),
			_('A domain also covers its subdomains. The router\'s DNS must be used by the devices (it is by default).'));
		o.datatype = 'hostname';
		o.modalonly = true;

		o = s.option(form.DummyValue, '_summary', _('Matches'));
		o.modalonly = false;
		o.textvalue = function(section_id) {
			const n = function(k) { return (uci.get('detour', section_id, k) || []).length; };
			return _('%d devices, %d addresses, %d domains').format(n('device'), n('dst'), n('domain'));
		};

		return m.render();
	}
});
