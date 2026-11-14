'use strict';
'require view';
'require ui';
'require dom';
'require detour.pkg as pkg';

// "Components": the packages Detour uses - what each gives, installed or not, an upgrade, a removal. Only these
// packages: never "upgrade everything" (that would upgrade the firmware's own packages too).

const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

function css() { return E('link', { 'rel': 'stylesheet', 'href': L.resource('detour/detour.css') + '?v=' + encodeURIComponent(L.env.resource_version || '') }); }
function td(title, content) { return E('td', { 'class': 'td', 'data-title': title }, content); }
// what needs a component, in words: exits by their names, the router's DNS mode
function usedText(u) {
	return u.map(function(x) {
		if (x.kind == 'exit') return _('exit «%s»').format(x.name);
		if (x.kind == 'dns') return x.name == 'encrypted' ? _('the router\'s encrypted DNS') : _('the fallback of the router\'s DNS');
		return x.name;
	}).join(', ');
}

return view.extend({
	load: function() { return pkg.list().catch(function() { return null; }); },

	state: function(c) {
		const v = c.packages.filter(function(p) { return p.installed; }).map(function(p) { return p.installed; })[0];
		if (c.installed && c.upgradable) {
			const to = c.packages.filter(function(p) { return p.upgrade; }).map(function(p) { return p.upgrade; })[0];
			return E('span', {}, [ E('span', { 'class': 'detour-badge warn' }, _('update available')), ' ', v || '', ' → ', to || '' ]);
		}
		if (c.installed) return E('span', {}, [ E('span', { 'class': 'detour-badge ok' }, _('installed')), ' ', v || '' ]);
		if (c.available) return E('span', { 'class': 'detour-badge off' }, _('not installed'));
		return E('span', { 'class': 'detour-muted' }, _('not in the repositories of this firmware'));
	},

	actions: function(c) {
		const out = [];
		const name = pkg.title(c.id);
		if (!c.installed && c.available)
			out.push(E('button', { 'class': 'btn cbi-button-action', 'click': function() {
				return pkg.run('install', pkg.installSet(c), _('Installing %s').format(name)); } }, _('Install')));
		if (c.installed && c.upgradable)
			out.push(E('button', { 'class': 'btn cbi-button-action', 'click': function() {
				const p = c.packages.filter(function(x) { return x.upgrade; }).map(function(x) { return x.name; });
				return pkg.run('upgrade', p, _('Updating %s').format(name)); } }, _('Update to the new version')));
		if (c.installed && !c.core)
			out.push(E('button', { 'class': 'btn cbi-button-negative', 'click': function() {
				const p = c.packages.filter(function(x) { return x.installed; }).map(function(x) { return x.name; });
				let t = _('Remove %s (%s)?').format(name, p.join(', '));
				if (c.used.length) t += '\n\n' + _('In use now: %s. These stop working without it.').format(usedText(c.used));
				if (!confirm(t)) return;
				return pkg.run('remove', p, _('Removing %s').format(name)); } }, _('Remove')));
		return E('div', { 'class': 'detour-actions' }, out);
	},

	render: function(r) {
		const self = this;
		if (!r) return E('div', {}, [ css(), E('h2', {}, _('Components')),
			E('div', { 'class': 'alert-message warning' }, _('The Detour service is not running.')) ]);
		const rows = [ E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, _('Component')), E('th', { 'class': 'th' }, _('What it gives')),
			E('th', { 'class': 'th' }, _('State')), E('th', { 'class': 'th' }, '') ]) ];
		r.components.forEach(function(c) {
			rows.push(E('tr', { 'class': 'tr' }, [
				td(_('Component'), [ E('strong', {}, pkg.title(c.id)), E('br'), E('span', { 'class': 'detour-muted' }, c.packages.map(function(p) { return p.name; }).join(c.id == 'tcpdump' ? ' / ' : ', ')) ]),
				td(_('What it gives'), [ pkg.what(c.id), c.used.length ? E('div', { 'class': 'detour-muted' }, _('In use: %s').format(usedText(c.used))) : '' ]),
				td(_('State'), self.state(c)),
				td('', self.actions(c))
			]));
		});
		const when = r.index_ts ? new Date(r.index_ts * 1000).toLocaleString() : _('never');
		const head = E('div', { 'class': 'detour-actions' }, [
			E('span', {}, _('The package list of the repositories: %s').format(when)),
			E('button', { 'class': 'btn', 'click': function() { return pkg.run('update', [], _('Updating the package list')); } }, _('Update the list'))
		]);
		const view = E('div', {}, [
			css(),
			E('h2', {}, _('Components')),
			E('div', { 'class': 'cbi-map-descr' }, _('The packages Detour uses. Only these are installed, updated or removed here - never the rest of the firmware. An update of Detour itself restarts it: the page reloads after it.')),
			E('div', { 'class': 'cbi-section' }, [ head, E('table', { 'class': 'table' }, rows) ])
		]);
		// an action that is still running (the page was reloaded meanwhile): follow it
		if (r.job && r.job.running) window.setTimeout(function() { self.follow(r.job); }, 0);
		return view;
	},

	follow: function(j) {
		ui.showModal(_('%s: %s').format(j.action, j.packages), [ E('p', {}, E('em', {}, _('Still running… the page reloads when it is done.'))) ]);
		const tick = function() {
			pkg.list().then(function(r) { if (r.job && r.job.running) window.setTimeout(tick, 2000); else window.location.reload(); })
				.catch(function() { window.setTimeout(tick, 3000); });
		};
		tick();
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
