'use strict';
'require view';
'require form';
'require uci';

return view.extend({
	load: function() {
		return uci.load('detour');
	},

	render: function() {
		const m = new form.Map('detour', _('Detour settings'));

		let s = m.section(form.NamedSection, 'main', 'main', _('General'));
		let o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1';

		o = s.option(form.Value, 'probe_period', _('Check exits every (s)'));
		o.datatype = 'range(1,60)';
		o.placeholder = '2';

		o = s.option(form.Value, 'fails', _('Failed checks before switching'));
		o.datatype = 'range(1,10)';
		o.placeholder = '2';

		s = m.section(form.NamedSection, 'main', 'main', _('Router DNS'),
			_('Through the tunnel: the router resolves names via the exits of the selected policy, so the provider does not see the queries. ' +
			  'If all of its exits are down, it switches to an encrypted resolver (DoH/DoT/DoQ) directly; traffic of the policies stays blocked.'));
		o = s.option(form.ListValue, 'dns', _('Mode'));
		o.value('off', _('Not managed (provider DNS)'));
		o.value('tunnel', _('Through the tunnel'));
		o.default = 'off';

		o = s.option(form.ListValue, 'dns_policy', _('Policy'));
		uci.sections('detour', 'policy').forEach(function(p) { o.value(p['.name'], p.label || p['.name']); });
		o.depends('dns', 'tunnel');

		o = s.option(form.DynamicList, 'dns_server', _('Resolvers through the tunnel'));
		o.datatype = 'ip4addr';
		o.placeholder = '1.1.1.1';
		o.depends('dns', 'tunnel');

		o = s.option(form.DynamicList, 'dns_fallback', _('Encrypted fallback resolvers'),
			_('quic://, tls:// or https:// addresses. Needs the dnsproxy package.'));
		o.placeholder = 'quic://dns.adguard-dns.com';
		o.depends('dns', 'tunnel');

		s = m.section(form.NamedSection, 'direct', 'direct', _('Always direct'),
			_('Addresses that never go through a tunnel, whatever the policies say.'));
		o = s.option(form.DynamicList, 'dst', _('Addresses'));
		o.datatype = 'ipaddr';

		return m.render();
	}
});
