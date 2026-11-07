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

		if (!uci.get('detour', 'notify')) uci.add('detour', 'notify', 'notify');
		s = m.section(form.NamedSection, 'notify', 'notify', _('Telegram notifications'),
			_('Create a bot with @BotFather, paste its token, write /start to the bot and put your chat id here. ' +
			  'Messages go through a working tunnel first, then directly; undelivered ones wait and are sent later.'));
		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o = s.option(form.Value, 'tg_token', _('Bot token'));
		o.password = true;
		o.validate = function(section_id, v) { return (!v || /^[0-9]+:[A-Za-z0-9_-]{30,}$/.test(v)) ? true : _('Looks like 123456:ABC… from @BotFather'); };
		o = s.option(form.Value, 'tg_chat', _('Chat id'));
		o.datatype = 'integer';
		o = s.option(form.MultiValue, 'event', _('Notify about'));
		o.value('exit_down', _('an exit stopped responding'));
		o.value('exit_up', _('an exit works again'));
		o.value('switch', _('a policy switched to another exit'));
		o.value('all_down', _('a policy has no working exit (its traffic is blocked)'));
		o.default = 'exit_down exit_up all_down switch';
		o = s.option(form.Value, 'tg_api', _('Own Bot API address'), _('Only if api.telegram.org is blocked for you and you run a Bot API proxy.'));
		o.placeholder = 'https://api.telegram.org';
		o.datatype = 'string';
		o.optional = true;
		o.validate = function(section_id, v) { return (!v || /^https?:\/\/[^\s]+$/.test(v)) ? true : _('http(s) address'); };

		s = m.section(form.NamedSection, 'direct', 'direct', _('Always direct'),
			_('Addresses that never go through a tunnel, whatever the policies say.'));
		o = s.option(form.DynamicList, 'dst', _('Addresses'));
		o.datatype = 'ipaddr';
		o = s.option(form.DynamicList, 'device', _('Devices'), _('MAC addresses of devices that never use a tunnel.'));
		o.datatype = 'macaddr';
		o = s.option(form.DynamicList, 'domain', _('Domains'));
		o.datatype = 'hostname';

		return m.render();
	}
});
