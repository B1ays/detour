'use strict';
'require baseclass';

// A page's data by name, never by position. load() of a view:
//     'require detour.load as pdata';  ...  return pdata.all({ status: L.resolveDefault(callStatus(), {}), cfg: uci.load('detour') });
// render(data) then reads data.status, data.cfg. The parts are fetched at once (Promise.all); a part added or
// removed leaves the others where they are - with an array (data[1], data[2]) every part after a removed one
// silently became the next one's data. A name that is not among the parts throws at once, so a part removed
// while still in use is an error on the page, not a quiet wrong value hidden behind "|| {}".
// tools/check-ui.sh refuses data[<digit>] and Promise.all in the views: parallel parts go through here.

return baseclass.extend({
	all: function(parts) {
		const names = Object.keys(parts);
		return Promise.all(names.map(function(k) { return parts[k]; })).then(function(values) {
			const out = {};
			names.forEach(function(k, i) { out[k] = values[i]; });
			return new Proxy(out, {
				get: function(t, k) {
					// "then": a promise asks it of what it resolves with; symbols and JSON: the runtime's own
					if (typeof k != 'string' || k in t || k == 'then' || k == 'toJSON') return t[k];
					throw new Error('page data: no part "%s" (loaded: %s)'.format(k, names.join(', ')));
				}
			});
		});
	}
});
