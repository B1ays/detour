// Translations of the messages Detour sends to people (Telegram notifications). The texts are written in
// English inside _('…'); a language is a JSON dictionary English -> translation in /usr/share/detour/i18n,
// made by tools/i18n.py (its RU_NOTIFY dictionary). The log stays English.
// The language: option lang of the notify section ('en', 'ru'); empty = as LuCI (luci.main.lang),
// and for LuCI's "auto" - Russian when the Russian LuCI translation is installed, else English.
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';

const DIR = '/usr/share/detour/i18n';
const dicts = {};

function known(l) { return l == 'en' || !!fs.access(DIR + '/' + l + '.json'); }

export function lang() {
	const c = cursor();
	let l = c.get('detour', 'notify', 'lang');
	if (!l || l == 'auto') l = c.get('luci', 'main', 'lang');
	if (!l || l == 'auto') l = fs.access('/usr/lib/lua/luci/i18n/base.ru.lmo') ? 'ru' : 'en';
	l = lc(split(l, /[_-]/)[0]);
	return known(l) ? l : 'en';
};

function dict(l) {
	if (l == 'en') return null;
	if (!(l in dicts)) {
		let d = null;
		try { d = json(fs.readfile(DIR + '/' + l + '.json') ?? 'null'); } catch (e) { d = null; }
		dicts[l] = d;
	}
	return dicts[l];
}

// the translation of s, or s itself
export function _(s) {
	const d = dict(lang());
	return (d && d[s] != null) ? d[s] : s;
};
