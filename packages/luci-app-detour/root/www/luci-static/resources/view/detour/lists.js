'use strict';
'require view';
'require form';
'require uci';
'require rpc';
'require ui';

const callStatus = rpc.declare({ object: 'detour', method: 'status' });
const callUpdate = rpc.declare({ object: 'detour', method: 'lists_update', params: [ 'name' ] });

// lists-update writes English messages (they also go to the log); the known ones are shown translated
function failText(m) {
	let x, kept = / ?;? previous data kept$/.test(m);
	m = m.replace(/;? ?previous data kept$/, '');
	let t = m;
	if ((x = m.match(/^download failed: (.+)$/))) t = _('download failed: %s').format(x[1]);
	else if ((x = m.match(/^only (\d+) entries \(minimum (\d+)\)$/))) t = _('only %d entries (minimum %d)').format(+x[1], +x[2]);
	else if ((x = m.match(/^file missing: (.+)$/))) t = _('file missing: %s').format(x[1]);
	else if ((x = m.match(/^unknown policy '(.+)'$/))) t = _('unknown policy %s').format(x[1]);
	return kept ? t + '; ' + _('the previous list stays in use') : t;
}

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
			  'Address lists: one IP or range (CIDR) per line. Domain lists: plain, hosts, dnsmasq, adblock or v2fly/geosite text (domain:, full:). ' +
			  'A v2fly domain-list-community category is given as v2fly:NAME (for example v2fly:youtube), its include: lines are followed.'));

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
		o.validate = function(id, v) { return (!v || /^https?:\/\/\S+$/.test(v) || /^v2fly:[a-z0-9!._-]+$/.test(v)) ? true : _('http(s) address or v2fly:NAME'); };
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
			const kind = { 'cidr': _('addresses'), 'domain': _('domains') }[l.kind] || l.kind || '';
			return E('span', { 'class': l.ok ? '' : 'detour-warn' }, [
				N_(l.count || 0, '%d entry', '%d entries').format(l.count || 0), ' ', E('small', {}, '(' + kind + ', ' + when + ')'),
				l.ok ? '' : E('div', {}, failText(l.message || ''))
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

		// detour.css: the last field of a card must not touch its bottom (Argon gives the node no padding)
		return m.render().then(function(node) {
			node.insertBefore(E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') }), node.firstChild);
			return node;
		});
	}
});
