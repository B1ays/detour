'use strict';
'require baseclass';

// Shared by the Detour pages: the daemon's events and configuration errors (English, they also go to the
// log) shown translated with the names people gave to exits and policies; readable names of big lists from
// their sources; a few ready-made categories to add a list in one click.

// names of categories as people know them (v2fly domain-list-community, runetfreedom)
const CAT = {
	'ru-blocked': _('Blocked in Russia'), 'ru-blocked-all': _('Blocked in Russia (all)'), 'ru-blocked-community': _('Blocked in Russia (community)'),
	're-filter': 'Re:filter', 'google': 'Google', 'youtube': 'YouTube', 'meta': _('Meta (Facebook, Instagram, WhatsApp)'),
	'facebook': 'Facebook', 'instagram': 'Instagram', 'whatsapp': 'WhatsApp', 'telegram': 'Telegram', 'twitter': 'Twitter (X)',
	'discord': 'Discord', 'openai': _('OpenAI (ChatGPT)'), 'anthropic': _('Anthropic (Claude)'), 'google-gemini': 'Google Gemini',
	'jetbrains': 'JetBrains', 'jetbrains-ai': 'JetBrains AI', 'cloudflare': 'Cloudflare', 'cloudfront': 'Amazon CloudFront',
	'netflix': 'Netflix', 'spotify': 'Spotify', 'tiktok': 'TikTok', 'twitch': 'Twitch', 'linkedin': 'LinkedIn', 'github': 'GitHub',
	'microsoft': 'Microsoft', 'apple': 'Apple', 'amazon': 'Amazon', 'steam': 'Steam', 'notion': 'Notion', 'figma': 'Figma',
	'medium': 'Medium', 'reddit': 'Reddit', 'pinterest': 'Pinterest', 'soundcloud': 'SoundCloud', 'canva': 'Canva'
};
function catName(k) { return CAT[k] || (k.charAt(0).toUpperCase() + k.slice(1)); }

const RF = 'https://cdn.jsdelivr.net/gh/runetfreedom/russia-blocked-geoip@release/text/';
const RFGS = 'https://cdn.jsdelivr.net/gh/runetfreedom/russia-blocked-geosite@release/';

// ready-made lists: [ id, title, url, kind ]
const PRESETS = [
	[ 'rugs', _('Everything blocked in Russia - domains'), RFGS + 'ru-blocked.txt', 'domain' ],
	[ 'ruip', _('Everything blocked in Russia - addresses'), RF + 'ru-blocked.txt', 'cidr' ],
	[ 'yt', 'YouTube', 'v2fly:youtube', 'domain' ],
	[ 'tg', _('Telegram (domains and addresses)'), 'v2fly:telegram', 'domain' ],
	[ 'tgip', _('Telegram - addresses'), RF + 'telegram.txt', 'cidr' ],
	[ 'meta', _('Meta (Facebook, Instagram, WhatsApp)'), 'v2fly:meta', 'domain' ],
	[ 'x', 'Twitter (X)', 'v2fly:twitter', 'domain' ],
	[ 'dc', 'Discord', 'v2fly:discord', 'domain' ],
	[ 'ai', _('OpenAI (ChatGPT)'), 'v2fly:openai', 'domain' ],
	[ 'cl', _('Anthropic (Claude)'), 'v2fly:anthropic', 'domain' ],
	[ 'gem', 'Google Gemini', 'v2fly:google-gemini', 'domain' ],
	[ 'goo', _('Google - domains'), 'v2fly:google', 'domain' ],
	[ 'gooip', _('Google - addresses'), RF + 'google.txt', 'cidr' ],
	[ 'nf', 'Netflix', 'v2fly:netflix', 'domain' ],
	[ 'sp', 'Spotify', 'v2fly:spotify', 'domain' ],
	[ 'tt', 'TikTok', 'v2fly:tiktok', 'domain' ],
	[ 'tw', 'Twitch', 'v2fly:twitch', 'domain' ],
	[ 'cf', _('Cloudflare - addresses (much of the internet)'), RF + 'cloudflare.txt', 'cidr' ]
];

return baseclass.extend({
	PRESETS: PRESETS,
	catName: catName,
	RF: RF,
	RFGS: RFGS,

	// the blocking policy (action block): its name, made (first in order, label "Block") when there is none yet.
	// uci must be loaded; the caller saves and applies.
	blockPolicy: function(uci, make) {
		const have = uci.sections('detour', 'policy').filter(function(p) { return p.action == 'block'; })[0];
		if (have || !make) return have ? have['.name'] : null;
		let n = 'block';
		for (let i = 2; uci.get('detour', n); i++) n = 'block' + i;
		const used = {};
		uci.sections('detour', 'policy').forEach(function(s) { used[+s.id] = true; });
		let id = 1; while (used[id] && id < 250) id++;
		const first = uci.sections('detour', 'policy')[0];
		uci.add('detour', 'policy', n);
		uci.set('detour', n, 'id', String(id));
		uci.set('detour', n, 'action', 'block');
		uci.set('detour', n, 'label', _('Block'));
		if (first) uci.move('detour', n, first['.name']);
		return n;
	},

	// a list's name for people: its own label, else what its first source is
	listTitle: function(s) {
		if (s.label) return s.label;
		const u = (Array.isArray(s.url) ? s.url : (s.url ? [ s.url ] : []))[0] || '';
		let m;
		if ((m = u.match(/^v2fly:(.+)$/))) return _('%s - domains').format(catName(m[1]));
		if ((m = u.match(/russia-blocked-geosite[^/]*\/(.+)\.txt$/))) return _('%s - domains').format(catName(m[1]));
		if ((m = u.match(/russia-blocked-geoip[^/]*\/text\/(.+)\.txt$/))) return _('%s - addresses').format(catName(m[1]));
		if (/iplist\.opencck\.org/.test(u)) return _('Blocked addresses (opencck)');
		if ((m = u.match(/^https?:\/\/([^/]+)/))) return m[1];
		if (s.file) return s.file.replace(/^.*\//, '');
		return s['.name'];
	},

	// where a source comes from, short
	sourceText: function(u) {
		let m;
		if ((m = u.match(/^v2fly:(.+)$/))) return _('v2fly category «%s»').format(m[1]);
		if (/runetfreedom\/russia-blocked-geosite/.test(u)) return _('runetfreedom, domains: %s').format(u.replace(/^.*\//, ''));
		if (/runetfreedom\/russia-blocked-geoip/.test(u)) return _('runetfreedom, addresses: %s').format(u.replace(/^.*\//, ''));
		if ((m = u.match(/^https?:\/\/([^/?]+)/))) return m[1];
		return u;
	},

	// labels: { name: label } of exits and policies; returns the text with names replaced and translated
	event: function(line, labels) {
		const L = function(n) { return labels[n] ? '«' + labels[n] + '»' : n; };
		let m;
		if ((m = line.match(/^exit (\S+) (up|down)$/))) return (m[2] == 'up' ? _('Exit %s works') : _('Exit %s stopped answering')).format(L(m[1]));
		if ((m = line.match(/^exit (\S+): (\S+) up, route restored$/))) return _('Exit %s: tunnel up').format(L(m[1]));
		if ((m = line.match(/^exit (\S+): (\S+) down$/))) return _('Exit %s: tunnel down').format(L(m[1]));
		if ((m = line.match(/^policy (\S+): (\S+) -> (\S+?)( \(pinned .*\))?$/)))
			return (m[2] == '-' ? _('Policy %s goes through %s') : _('Policy %s switched from %s to %s')).format(L(m[1]), ...(m[2] == '-' ? [ L(m[3]) ] : [ L(m[2]), L(m[3]) ])) + (m[4] ? ' ' + _('(chosen by hand)') : '');
		if ((m = line.match(/^policy (\S+): pinned to (\S+)$/))) return _('Policy %s: exit %s chosen by hand').format(L(m[1]), L(m[2]));
		if ((m = line.match(/^policy (\S+): unpinned$/))) return _('Policy %s: the exit is chosen automatically again').format(L(m[1]));
		if ((m = line.match(/^policy (\S+): switch failed: (.*)$/))) return _('Policy %s: switching failed (%s)').format(L(m[1]), m[2]);
		if ((m = line.match(/^policy (\S+): no working exit - goes directly$/))) return _('Policy %s: no exit works - its traffic goes directly (as chosen)').format(L(m[1]));
		if ((m = line.match(/^policy (\S+): an exit works again - through it$/))) return _('Policy %s: an exit works again - the traffic goes through it').format(L(m[1]));
		if ((m = line.match(/^router DNS: (\S+)$/))) return { 'tunnel': _('Router DNS goes through the tunnel again'), 'fallback': _('Router DNS: the policy\'s exits are down - encrypted DNS directly') }[m[1]] || line;
		if ((m = line.match(/^(start|reload|import): (\d+) exits, (\d+) policies$/)))
			return ({ 'start': _('Detour started'), 'reload': _('Settings applied'), 'import': _('Settings imported') }[m[1]]) + ': ' +
				N_(+m[2], '%d exit', '%d exits').format(+m[2]) + ', ' + N_(+m[3], '%d policy', '%d policies').format(+m[3]);
		if ((m = line.match(/^new under a policy: .* - their direct flows reset \((\d+)\)$/))) return _('New addresses, devices or ports under a policy: their open direct connections were reset');
		if ((m = line.match(/^WARP (\S+) moved to (\S+) \(colo (\S+), was (\S+)\)$/))) return _('WARP %s moved to point %s (was %s)').format(L(m[1]), m[3], m[4]);
		if ((m = line.match(/^WARP (\S+): (.*)$/))) return _('WARP %s: %s').format(L(m[1]), m[2]);
		if ((m = line.match(/^LuCI: (\S+) -> (ok|error)$/))) {
			const act = { 'lists-update': _('update lists'), 'sub-update': _('update a subscription'), 'engine-add': _('add an exit from a link'),
				'warp-register': _('register WARP'), 'warp-unregister': _('remove WARP'), 'import': _('import settings'),
				'exit-remove': _('remove an exit'), 'exit-pick': _('choose a server of a subscription'), 'exit-config-set': _('edit an exit'),
				'exit-set-link': _('another server for an exit'), 'sshtun': _('panel through a VPS') }[m[1]] || m[1];
			return _('Action «%s» from the panel: %s').format(act, m[2] == 'ok' ? _('done') : _('failed'));
		}
		if ((m = line.match(/^config: (.*)$/))) return _('Configuration: %s').format(this.configError(m[1], labels));
		if ((m = line.match(/^2FA guard(?: error)?: (.*)$/))) return _('Two-factor login protection: %s').format(m[1]);
		return line;
	},

	configError: function(t, labels) {
		const L = function(n) { return labels[n] ? '«' + labels[n] + '»' : n; };
		let m;
		if ((m = t.match(/^policy (\S+): no valid exit$/))) return _('policy %s has no exit - its traffic is blocked').format(L(m[1]));
		if ((m = t.match(/^policy (\S+): unknown exit "(.*)"$/))) return _('policy %s refers to a missing exit %s').format(L(m[1]), m[2]);
		if ((m = t.match(/^policy (\S+): bad port "(.*)"$/))) return _('policy %s: wrong port «%s»').format(L(m[1]), m[2]);
		if ((m = t.match(/^policy (\S+): bad domain "(.*)"$/))) return _('policy %s: wrong domain «%s»').format(L(m[1]), m[2]);
		if ((m = t.match(/^policy (\S+): bad device MAC "(.*)"$/))) return _('policy %s: wrong device address «%s»').format(L(m[1]), m[2]);
		if (/^router DNS through the tunnel: dnsproxy is not installed/.test(t)) return _('DNS through the tunnel: the dnsproxy package is not installed - if the exits fail, the provider\'s DNS is used unencrypted');
		if (/^encrypted router DNS: dnsproxy is not installed/.test(t)) return _('encrypted DNS: the dnsproxy package is not installed - the provider\'s DNS is used unencrypted');
		return t;
	}
});
