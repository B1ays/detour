'use strict';
'require view';
'require form';
'require uci';
'require rpc';
'require ui';

const callStatus = rpc.declare({ object: 'detour', method: 'status' });
const callUpdate = rpc.declare({ object: 'detour', method: 'lists_update', params: [ 'name' ] });

return view.extend({
	load: function() {
		return Promise.all([ uci.load('detour'), callStatus().catch(() => ({})) ]);
	},

	render: function(data) {
		const st = {};
		((data[1] || {}).lists || []).forEach(function(l) { st[l.name] = l; });

		const m = new form.Map('detour', _('Lists'),
			_('Big lists of addresses or domains from the internet or a local file. ' +
			  'They are updated every night; if a source does not answer, the previous list stays in use. ' +
			  'Address lists: one IP or range (CIDR) per line. Domain lists: plain, hosts, dnsmasq or adblock format.'));

		const s = m.section(form.GridSection, 'list');
		s.addremove = true;
		s.anonymous = false;
		s.nodescriptions = true;
		s.addbtntitle = _('Add list');

		let o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.editable = true;

		o = s.option(form.ListValue, 'policy', _('Goes'));
		uci.sections('detour', 'policy').forEach(function(p) { o.value(p['.name'], _('through policy %s').format(p.label || p['.name'])); });
		o.value('direct', _('never through a tunnel'));
		o.rmempty = false;

		o = s.option(form.DynamicList, 'url', _('Sources (URL)'));
		o.datatype = 'string';
		o.validate = function(id, v) { return (!v || /^https?:\/\/\S+$/.test(v)) ? true : _('http(s) address'); };
		o.modalonly = true;

		o = s.option(form.Value, 'file', _('Local file'), _('Optional: a file on the router with more entries.'));
		o.optional = true;
		o.modalonly = true;

		o = s.option(form.ListValue, 'kind', _('Contents'));
		o.value('auto', _('detect'));
		o.value('cidr', _('addresses'));
		o.value('domain', _('domains'));
		o.default = 'auto';
		o.modalonly = true;

		o = s.option(form.Value, 'min_lines', _('Minimum entries'), _('A download with fewer entries is treated as a failure.'));
		o.datatype = 'uinteger';
		o.placeholder = '10';
		o.modalonly = true;

		o = s.option(form.DummyValue, '_state', _('State'));
		o.modalonly = false;
		o.textvalue = function(id) {
			const l = st[id];
			if (!l) return E('em', {}, _('not loaded yet'));
			const when = l.ts ? new Date(l.ts * 1000).toLocaleString() : '';
			return E('span', { 'style': l.ok ? '' : 'color:#c62828' }, [
				_('%d entries').format(l.count || 0), ' ', E('small', {}, '(' + (l.kind || '') + ', ' + when + ')'),
				l.ok ? '' : E('div', {}, l.message || '')
			]);
		};

		o = s.option(form.Button, '_update', _('Update'));
		o.modalonly = false;
		o.editable = true;   // a grid shows non-editable options as text ("none")
		o.inputtitle = _('Update now');
		o.inputstyle = 'action';
		o.onclick = function(ev, id) {
			return callUpdate(id).then(function(r) {
				if (r && r.error) ui.addNotification(null, E('p', r.error), 'danger');
				else ui.addNotification(null, E('p', _('List %s updated').format(id)), 'info');
				return window.setTimeout(function() { location.reload(); }, 800);
			});
		};

		return m.render();
	}
});
