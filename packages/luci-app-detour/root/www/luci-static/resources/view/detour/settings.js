'use strict';
'require view';
'require form';
'require uci';
'require rpc';

// Text from the router (names of exits and servers come from subscriptions and links) never becomes HTML:
// LuCI's E() puts a string child in with innerHTML, here it always goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

const callTunStatus = rpc.declare({ object: 'detour', method: 'sshtun_status' });
const callTunKeygen = rpc.declare({ object: 'detour', method: 'sshtun_keygen' });
const callTunTest = rpc.declare({ object: 'detour', method: 'sshtun_test' });
const callTunForget = rpc.declare({ object: 'detour', method: 'sshtun_forget' });

// a list option shown as checkboxes, one per line: the theme's multi-select cuts long names to a few letters
const CheckList = form.MultiValue.extend({
	renderWidget: function(section_id, option_index, cfgvalue) {
		const chosen = L.toArray(cfgvalue != null ? cfgvalue : this.default);
		const id = this.cbid(section_id);
		return E('div', { 'class': 'detour-checklist', 'id': id }, this.keylist.map(function(k, i) {
			return E('label', {}, [
				E('input', { 'type': 'checkbox', 'value': k, 'checked': chosen.indexOf(k) > -1 ? '' : null, 'disabled': this.readonly ? '' : null }),
				E('span', {}, this.vallist[i])
			]);
		}, this));
	},
	formvalue: function(section_id) {
		const box = this.map.findElement('id', this.cbid(section_id));
		if (!box) return null;
		return Array.prototype.filter.call(box.querySelectorAll('input[type=checkbox]'), function(c) { return c.checked; })
			.map(function(c) { return c.value; });
	}
});

return view.extend({
	load: function() {
		return Promise.all([ uci.load('detour'), L.resolveDefault(callTunStatus(), {}) ]);
	},

	// "The panel through your own VPS": key, server key check, state (sshtun.uc / ssh-tunnel.sh in stock)
	tunInfo: function(st) {
		const box = E('div');
		const info = E('div');
		const show = function(t) {
			t = t || {};
			info.replaceChildren(
				E('div', {}, [ E('strong', {}, (_('State:') + ' ')), !t.on ? _('switched off') : (t.connected ? _('connected') : (t.running ? _('connecting…') : _('not running (check the connection first)'))) ]),
				t.target ? E('div', {}, [ E('strong', {}, (_('Leads to:') + ' ')), t.target, ' ', E('span', { 'class': 'cbi-value-description' }, (/:443$/.test(t.target) ? _('(LuCI over HTTPS: the VPS sees nothing)') : _('(LuCI over HTTP: the VPS can see the pages - enable HTTPS in uhttpd)'))) ]) : '',
				t.pubkey ? E('div', {}, [ E('strong', {}, _('Router key - put it into ~/.ssh/authorized_keys of the user on the VPS:')), E('pre', { 'class': 'detour-key' }, t.pubkey) ]) : E('div', {}, _('No router key yet.')),
				t.host_fp ? E('div', {}, [ E('strong', {}, (_('Server key:') + ' ')), E('code', {}, t.host_fp), E('div', { 'class': 'cbi-value-description' }, _('Compare with ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub on the VPS.')) ]) : '',
				t.last ? E('div', { 'class': 'cbi-value-description' }, _('Last: %s').format(t.last)) : '');
		};
		const refresh = function() { return L.resolveDefault(callTunStatus(), {}).then(show); };
		const act = function(btn, fn, okText) {
			btn.disabled = true;
			return fn().then(function(r) {
				box.replaceChildren(E('div', { 'class': 'alert-message ' + ((!r || r.error) ? 'warning' : 'success') }, (!r) ? _('No answer from the router') : (r.error || okText(r))));
				return refresh();
			}).finally(function() { btn.disabled = false; });
		};
		const bKey = E('button', { 'class': 'btn cbi-button-action', 'click': function(ev) { ev.preventDefault(); return act(bKey, callTunKeygen, function() { return _('Key ready.'); }); } }, _('Create router key'));
		const bTest = E('button', { 'class': 'btn cbi-button-action', 'click': function(ev) { ev.preventDefault(); return act(bTest, callTunTest, function(r) { return _('The VPS accepted the key and gave the port. Server key %s recorded; from now on it must not change.').format(r.host_fp || ''); }); } }, _('Check the connection'));
		const bForget = E('button', { 'class': 'btn cbi-button-negative', 'click': function(ev) { ev.preventDefault();
			if (!confirm(_('Forget the server key? The tunnel stops; the next check accepts whatever key the server shows.'))) return;
			return act(bForget, callTunForget, function() { return _('Server key forgotten.'); }); } }, _('Forget the server key'));
		show(st);
		return E('div', {}, [ info, E('div', { 'style': 'margin-top:.5em' }, [ bKey, ' ', bTest, ' ', bForget ]), box,
			E('div', { 'class': 'cbi-value-description' }, _('Save the settings above before checking.')) ]);
	},

	render: function(data) {
		const tunStatus = data[1];
		const self = this;
		const m = new form.Map('detour', _('Detour settings'));

		let s = m.section(form.NamedSection, 'main', 'main', _('General settings'));
		let o = s.option(form.Flag, 'enabled', _('Enabled'),
			_('Off: no policy works, all traffic goes directly through the provider.'));
		o.default = '1';

		o = s.option(form.Value, 'probe_period', _('Check exits every (s)'),
			_('How often an exit is checked with a real request while it fails, has just started, or sends without getting answers. Shorter: a failure is noticed sooner.'));
		o.datatype = 'range(1,60)';
		o.placeholder = '2';

		o = s.option(form.Value, 'probe_idle', _('Check a working idle exit every (s)'),
			_('An exit that works and carries nothing is checked this often; one that carries traffic and gets answers, once a minute. Each check is about 5 KB of traffic.'));
		o.datatype = 'range(2,600)';
		o.placeholder = '30';

		o = s.option(form.Value, 'fails', _('Failed checks before switching'),
			_('How many checks in a row must fail before a policy moves to its next exit. 2 with checks every 2 s: about 4-6 s.'));
		o.datatype = 'range(1,10)';
		o.placeholder = '2';

		s = m.section(form.NamedSection, 'main', 'main', _('Router DNS'),
			_('Through the tunnel: the router resolves names via the exits of the selected policy, so the provider does not see the queries. ' +
			  'If all of its exits are down, it switches to an encrypted resolver (DoH/DoT/DoQ) directly; traffic of the policies stays blocked. ' +
			  'Encrypted: the router always asks the encrypted resolvers directly, whatever the exits do.'));
		o = s.option(form.ListValue, 'dns', _('DNS mode'));
		o.value('off', _('Not managed (provider DNS)'));
		o.value('tunnel', _('Through the tunnel'));
		o.value('encrypted', _('Encrypted (DoH/DoT/DoQ), directly'));
		o.default = 'off';

		o = s.option(form.ListValue, 'dns_policy', _('Policy'));
		uci.sections('detour', 'policy').forEach(function(p) { if (p.action != 'block' && p.action != 'direct') o.value(p['.name'], p.label || p['.name']); });
		o.depends('dns', 'tunnel');

		o = s.option(form.DynamicList, 'dns_server', _('Resolvers through the tunnel'));
		o.datatype = 'ip4addr';
		o.placeholder = '1.1.1.1';
		o.depends('dns', 'tunnel');

		o = s.option(form.DynamicList, 'dns_fallback', _('Encrypted resolvers'),
			_('quic://, tls:// or https:// addresses, asked in parallel. Through the tunnel: used when its exits are down; encrypted: always. Needs the dnsproxy package.'));
		o.placeholder = 'quic://dns.adguard-dns.com';
		o.depends('dns', 'tunnel');
		o.depends('dns', 'encrypted');

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
		o = s.option(CheckList, 'event', _('Notify about'),
			_('While the provider\'s internet is gone (and 3 minutes after it is back) nothing is said about the exits: they fall and rise with the line, one message about the line says it all.'));
		o.value('exit_down', _('an exit stopped responding'));
		o.value('exit_up', _('an exit works again'));
		o.value('switch', _('a policy moved to another exit, WARP moved to another point'));
		o.value('all_down', _('a policy has no working exit, its traffic is blocked (and when it works again)'));
		o.value('boot', _('the router rebooted: how many exits came up'));
		o.value('wan', _('the provider\'s internet went away and came back'));
		o.value('list_fail', _('a list failed to update'));
		o.value('sub_fail', _('a subscription failed to update'));
		o.value('sub_expire', _('a subscription ends in 3 days or 90% of its traffic is used'));
		o.default = 'exit_down exit_up all_down switch boot wan list_fail sub_fail sub_expire';
		o = s.option(form.ListValue, 'lang', _('Language'), _('Of the messages. Automatically: the language of LuCI.'));
		o.value('', _('automatically'));
		o.value('en', 'English');
		o.value('ru', 'Русский');
		o = s.option(form.Value, 'tg_api', _('Own Bot API address'), _('Only if api.telegram.org is blocked for you and you run a Bot API proxy.'));
		o.placeholder = 'https://api.telegram.org';
		o.datatype = 'string';
		o.optional = true;
		o.validate = function(section_id, v) { return (!v || /^https?:\/\/[^\s]+$/.test(v)) ? true : _('http(s) address'); };

		if (!uci.get('detour', 'sshtun')) uci.add('detour', 'sshtun', 'sshtun');
		s = m.section(form.NamedSection, 'sshtun', 'sshtun', _('The panel through your own VPS (SSH)'),
			_('Open LuCI from outside without a public address and without opening ports: the router itself connects to your server ' +
			  'over SSH and holds a port there that leads to LuCI at home. The connection always goes directly, around the policies. ' +
			  'Then open https://127.0.0.1:PORT through ssh -L on your computer, or https://VPS:PORT when the port is public (PORT is the port on the VPS below).'));
		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o = s.option(form.Value, 'host', _('Server'));
		o.datatype = 'host';
		o.placeholder = 'vps.example.com';
		o = s.option(form.Value, 'port', _('SSH port'));
		o.datatype = 'port';
		o.placeholder = '22';
		o = s.option(form.Value, 'user', _('User'));
		o.placeholder = 'tunnel';
		o.validate = function(section_id, v) { return (!v || /^[A-Za-z0-9._-]+$/.test(v)) ? true : _('Letters, digits, . _ -'); };
		o = s.option(form.Value, 'rport', _('Port on the VPS'));
		o.datatype = 'port';
		o.placeholder = '18443';
		o = s.option(form.Flag, 'public', _('Listen on all addresses of the VPS'),
			_('Otherwise only on 127.0.0.1 of the VPS (reach it with ssh -L). Needs GatewayPorts clientspecified in sshd_config.'));
		o = s.option(form.DummyValue, '_tun', _('Key and state'));
		o.renderWidget = function() { return self.tunInfo(tunStatus); };

		// detour.css: the last field of a card must not touch its bottom (Argon gives the node no padding)
		return m.render().then(function(node) {
			node.insertBefore(E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') }), node.firstChild);
			return node;
		});
	}
});
