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
			return E('div', { 'class': 'detour-pkg-state' }, [ E('span', { 'class': 'detour-badge warn' }, _('update available')), E('span', {}, (v || '') + ' → ' + (to || '')) ]);
		}
		if (c.installed) return E('div', {}, [ E('div', { 'class': 'detour-pkg-state' }, [ E('span', { 'class': 'detour-badge ok' }, _('installed')), E('span', {}, v || '') ]), this.service(c) ]);
		if (c.available) return E('div', { 'class': 'detour-pkg-state' }, E('span', { 'class': 'detour-badge off' }, _('not installed')));
		return E('span', { 'class': 'detour-muted' }, _('not in the repositories of this firmware'));
	},

	// a component that runs as a service (nlbwmon): does it work, as the traffic counting saw it last
	service: function(c) {
		const s = c.service;
		if (!s) return '';
		const when = s.restarted ? ' ' + _('Detour restarted it at %s.').format(new Date(s.restarted * 1000).toLocaleString()) : '';
		if (s.state == 'ok') return E('div', { 'class': 'detour-muted' }, _('Running, counts the traffic.') + when);
		if (s.state == 'hung') return E('div', { 'class': 'detour-bad' }, _('Running but does not answer: the traffic is not counted. Detour restarts it by itself after 10 minutes of silence.') + when);
		return E('div', { 'class': 'detour-bad' }, _('Not running: the traffic is not counted (System → Startup: nlbwmon).'));
	},

	actions: function(c, space) {
		const out = [];
		const name = pkg.title(c.id);
		// what does not fit is not offered: a full flash breaks more than the package (configs, the next boot)
		const noRoom = function(add) {
			return E('div', { 'class': 'detour-bad' }, _('Not enough space: it needs %s, %s is free.').format(pkg.size(add), pkg.size(space.free)));
		};
		if (!c.installed && c.available && c.need && pkg.fits(c.need.add, space) === false) out.push(noRoom(c.need.add));
		else if (!c.installed && c.available)
			out.push(E('button', { 'class': 'btn cbi-button-action', 'click': function() {
				return pkg.run('install', pkg.installSet(c), _('Installing %s').format(name)); } }, _('Install')));
		if (c.installed && c.upgradable && c.upgrade_need && pkg.fits(c.upgrade_need.add, space) === false) out.push(noRoom(c.upgrade_need.add));
		else if (c.installed && c.upgradable)
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
			E('th', { 'class': 'th' }, _('Component')), E('th', { 'class': 'th' }, _('Purpose')),
			E('th', { 'class': 'th' }, _('State')), E('th', { 'class': 'th' }, '') ]) ];
		r.components.forEach(function(c) {
			rows.push(E('tr', { 'class': 'tr' }, [
				td(_('Component'), [ E('strong', {}, pkg.title(c.id)), E('br'), E('span', { 'class': 'detour-muted' }, c.packages.map(function(p) { return p.name; }).join(c.id == 'tcpdump' ? ' / ' : ', ')) ]),
				td(_('Purpose'), [ pkg.what(c.id), c.used.length ? E('div', { 'class': 'detour-muted' }, _('In use: %s').format(usedText(c.used))) : '' ]),
				td(_('State'), [ self.state(c), pkg.weight(c) ? E('div', { 'class': 'detour-pkg-weight' }, pkg.weight(c)) : '' ]),
				td('', self.actions(c, r.space))
			]));
		});
		const when = r.index_ts ? new Date(r.index_ts * 1000).toLocaleString() : _('never');
		// the space for packages: a bar, and a warning when little is left (an update of sing-box takes ~50 MiB)
		const sp = r.space;
		const used = sp ? (sp.total - sp.free) : 0;
		const low = sp && sp.free < 10 * 1048576;
		const head = E('div', { 'class': 'detour-pkg-top' }, [
			E('div', { 'class': 'detour-space' }, [
				sp ? E('div', {}, [ E('strong', {}, _('Free for packages:') + ' '), _('%s of %s').format(pkg.size(sp.free), pkg.size(sp.total)) ]) : '',
				sp ? E('div', { 'class': 'detour-share' + (low ? ' low' : ''), 'title': Math.round(used * 100 / Math.max(1, sp.total)) + '%' },
					E('div', { 'style': 'width:' + Math.min(100, used * 100 / Math.max(1, sp.total)) + '%' })) : '',
				E('div', { 'class': 'detour-muted' }, _('The package list of the repositories: %s').format(when))
			]),
			E('button', { 'class': 'btn', 'click': function() { return pkg.run('update', [], _('Updating the package list')); } }, _('Update the list'))
		]);
		const space = low ? E('div', { 'class': 'alert-message warning' }, _('Little space is left: %s. Installing or updating a component may fail, and a full flash can stop the router from saving its settings. Remove what is not used, or move the overlay to a USB drive (extroot).').format(pkg.size(sp.free))) : '';
		const view = E('div', {}, [
			css(),
			E('h2', {}, _('Components')),
			E('div', { 'class': 'cbi-map-descr' }, _('The packages Detour uses. Only these are installed, updated or removed here - never the rest of the firmware. An update of Detour itself restarts it: the page reloads after it.')),
			E('div', { 'class': 'cbi-section' }, [ head, space, E('table', { 'class': 'table' }, rows) ])
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
