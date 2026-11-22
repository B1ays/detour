'use strict';
'require view';
'require detour.load as pdata';
'require form';
'require uci';
'require rpc';
'require fs';
'require detour.pkg as pkg';

// Text from the router (names of exits and servers come from subscriptions and links) never becomes HTML:
// LuCI's E() puts a string child in with innerHTML, here it always goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

const callStatus = rpc.declare({ object: 'detour', method: 'status' });
const callDnsProviders = rpc.declare({ object: 'detour', method: 'dns_providers' });
const callLogLevel = rpc.declare({ object: 'detour', method: 'log_level', params: [ 'level' ] });
const callLogsArchive = rpc.declare({ object: 'detour', method: 'logs_archive' });

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
		return pdata.all({ cfg: uci.load('detour'), status: L.resolveDefault(callStatus(), {}), dnsprov: L.resolveDefault(callDnsProviders(), { providers: [] }) });
	},

	// "Log": the level (set at once through the daemon: verbose ends by itself after 24 h) and the archive of logs
	logInfo: function(st) {
		const box = E('div');
		const state = E('div', { 'class': 'cbi-value-description' });
		const kb = function(n) { return n < 1024 ? '%d B'.format(n) : (n < 1048576 ? '%.0f KB'.format(n / 1024) : '%.1f MB'.format(n / 1048576)); };
		const show = function(l) {
			l = l || {};
			sel.value = l.level == 'verbose' ? 'verbose' : 'normal';
			state.textContent = (l.level == 'verbose' && l.until)
				? _('Verbose until %s; the log takes %s.').format(new Date(l.until * 1000).toLocaleString(), kb(l.size || 0))
				: (l.size ? _('Normal; a verbose log of %s from before is kept until the router restarts.').format(kb(l.size)) : _('Normal level.'));
		};
		const sel = E('select', { 'class': 'cbi-input-select', 'change': function() {
			sel.disabled = true;
			return callLogLevel(sel.value).then(function(r) {
				if (!r || r.error) box.replaceChildren(E('div', { 'class': 'alert-message warning' }, (r && r.error) || _('No answer from the router')));
				else box.replaceChildren();
				show(r);
			}).finally(function() { sel.disabled = false; });
		} }, [ E('option', { 'value': 'normal' }, _('Normal level')), E('option', { 'value': 'verbose' }, _('Verbose level')) ]);
		const bGet = E('button', { 'class': 'btn cbi-button-action', 'click': function(ev) {
			ev.preventDefault();
			bGet.disabled = true;
			box.replaceChildren(E('em', {}, _('Collecting the logs…')));
			return callLogsArchive().then(function(r) {
				if (!r || r.error || !r.path) throw new Error((r && r.error) || _('No answer from the router'));
				return fs.read_direct(r.path, 'blob').then(function(blob) {
					const a = E('a', { 'href': URL.createObjectURL(blob), 'download': r.name || 'detour-logs.tar.gz', 'style': 'display:none' });
					document.body.appendChild(a);
					a.click();
					setTimeout(function() { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
					box.replaceChildren(E('div', { 'class': 'alert-message success' }, _('Saved: %s (%s).').format(r.name, kb(r.size || blob.size))));
				});
			}).catch(function(e) {
				box.replaceChildren(E('div', { 'class': 'alert-message warning' }, e.message || String(e)));
			}).finally(function() { bGet.disabled = false; });
		} }, _('Download the logs (.tar.gz)'));
		show(st);
		return E('div', {}, [ sel, state, E('div', { 'style': 'margin-top:.5em' }, [ bGet ]), box ]);
	},

	render: function(data) {
		const self = this;
		const m = new form.Map('detour', _('Detour settings'));

		let s = m.section(form.NamedSection, 'main', 'main', _('General settings'));
		// switching Detour on and off: only the switch on the Overview (it asks before switching off)
		let o = s.option(form.Value, 'probe_period', _('Check exits every (s)'),
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
		// the two fwmark bytes (policy, exit): only when another program uses the same bits (pbr, mwan3)
		o = s.option(form.Value, 'fw_mask', _('Packet mark bits'),
			_('Change only when another program uses the same bits: pbr (0x00ff0000) or mwan3 (0x3f00) - a message on the Overview says so. For example 0x0ffff000.'));
		o.placeholder = '0x00ffff00';
		o.optional = true;
		o.validate = function(section_id, v) {
			if (!v) return true;
			const n = /^(0x)?[0-9a-fA-F]{1,8}$/.test(v) ? parseInt(v.replace(/^0x/i, ''), 16) : -1;
			for (let sh = 0; sh <= 12; sh++) if (n === 0xffff * Math.pow(2, sh)) return true;
			return _('0xffff shifted by whole bits: 0x0000ffff ... 0x0ffff000');
		};

		s = m.section(form.NamedSection, 'main', 'main', _('Router DNS'),
			_('Through the tunnel: the router resolves names via the exits of the selected policy, so the provider does not see the queries. ' +
			  'If all of its exits are down, it switches to an encrypted resolver (DoH/DoT/DoQ) directly; traffic of the policies stays blocked. ' +
			  'Encrypted: the router always asks the encrypted resolvers directly, whatever the exits do.'));
		o = s.option(form.ListValue, 'dns', _('DNS mode'));
		o.value('off', _('Not managed (provider DNS)'));
		o.value('tunnel', _('Through the tunnel'));
		// encrypted needs dnsproxy (dnsmasq itself does not encrypt): not offered without it
		const hasProxy = !!(data.status || {}).dnsproxy;
		o.value('encrypted', hasProxy ? _('Encrypted (DoH/DoT/DoQ), directly') : _('Encrypted (DoH/DoT/DoQ) - install the dnsproxy package first'));
		o.default = 'off';
		o.validate = function(section_id, v) { return (v != 'encrypted' || hasProxy) ? true : _('Encrypted DNS needs the dnsproxy package'); };
		if (!hasProxy) {
			o = s.option(form.DummyValue, '_dnsproxy', ' ');
			o.renderWidget = function() { return pkg.offer('dnsproxy', _('Encrypted DNS needs dnsproxy.')); };
		}

		o = s.option(form.ListValue, 'dns_policy', _('Policy'));
		uci.sections('detour', 'policy').forEach(function(p) { if (p.action != 'block' && p.action != 'direct') o.value(p['.name'], p.label || p['.name']); });
		o.depends('dns', 'tunnel');

		o = s.option(form.DynamicList, 'dns_server', _('Resolvers through the tunnel'));
		o.datatype = 'ip4addr';
		o.placeholder = '1.1.1.1';
		o.depends('dns', 'tunnel');

		// the encrypted resolvers: a known provider and one of its protocols (the daemon has their addresses,
		// detour.dnsprov), or addresses typed in ("Custom"). Each provider has its own protocol list, all of them
		// on the one option dns_proto; a hidden one keeps what is there (retain), so does the custom list
		const provs = (data.dnsprov || {}).providers || [];
		// a note only where the provider filters something
		const NOTE = { malware: _('blocks malicious sites') };
		const PROTO = { https: 'DNS-over-HTTPS', tls: 'DNS-over-TLS', quic: 'DNS-over-QUIC', dnscrypt: 'DNSCrypt' };
		const both = function(opt, extra) {
			opt.depends(Object.assign({ dns: 'tunnel' }, extra || {}));
			opt.depends(Object.assign({ dns: 'encrypted' }, extra || {}));
		};
		o = s.option(form.ListValue, 'dns_provider', _('Encrypted DNS provider'),
			_('Asked directly, not through the tunnel. Through the tunnel: used when its exits are down; encrypted: always. Its own plain servers resolve the names of its encrypted ones. Needs the dnsproxy package: without it, through the tunnel falls back to the provider\'s DNS while the exits are down.'));
		o.value('', _('Custom: the addresses below'));
		provs.forEach(function(p) { o.value(p.id, NOTE[p.note] ? '%s (%s)'.format(p.name, NOTE[p.note]) : p.name); });
		o.retain = true;
		both(o);
		provs.forEach(function(p) {
			o = s.option(form.ListValue, '_proto_' + p.id, _('Protocol'), _('The ones %s has and dnsproxy speaks.').format(p.name));
			o.ucioption = 'dns_proto';
			p.protos.forEach(function(k) { o.value(k, PROTO[k] || k); });
			o.default = p.protos[0];
			o.rmempty = false;
			o.retain = true;
			// the protocol of another provider (switched just now): this one's first
			o.cfgvalue = function(section_id) {
				const v = uci.get('detour', section_id, 'dns_proto');
				return (v && p.protos.indexOf(v) > -1) ? v : p.protos[0];
			};
			both(o, { dns_provider: p.id });
		});

		o = s.option(form.DynamicList, 'dns_fallback', _('Encrypted resolvers'),
			_('quic://, tls://, https:// or sdns:// addresses, asked in parallel.'));
		o.placeholder = 'quic://dns.adguard-dns.com';
		o.retain = true;
		both(o, { dns_provider: '' });

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

		s = m.section(form.NamedSection, 'main', 'main', _('Detour logs'),
			_('The verbose level is only for diagnosing the system. It switches itself off after 24 hours.'));
		o = s.option(form.DummyValue, '_log', _('Detour log level'));
		o.renderWidget = function() { return self.logInfo((data.status || {}).log); };

		// detour.css: the last field of a card must not touch its bottom (Argon gives the node no padding)
		return m.render().then(function(node) {
			node.insertBefore(E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') }), node.firstChild);
			return node;
		});
	}
});
