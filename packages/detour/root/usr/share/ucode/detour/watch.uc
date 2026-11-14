// Notifications about what happens around the exits (the daemon's own events - exits, policies - are sent
// by detourd): the router came back after a reboot, the provider's internet went away and came back, a big
// list or a subscription failed to update, a subscription is running out of time or traffic.
// Texts are for people (translated, detour.i18n; with the names people gave); the log stays English.
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, RUN, log } from 'detour.core';
import * as notify from 'detour.notify';
import { _, lang } from 'detour.i18n';

export function q(s) { return sprintf(_('"%s"'), s); }

export function dur(s) {
	s = int(s);
	if (s < 90) return sprintf(_('%d s'), s);
	if (s < 5400) return sprintf(_('%d min'), int((s + 30) / 60));
	return sprintf(_('%d h %d min'), int(s / 3600), int((s % 3600) / 60));
}

function gb(b) { return sprintf(_('%.1f GB'), b / 1073741824.0); }

function day(t) {
	const l = localtime(t);
	return lang() == 'en' ? sprintf('%04d-%02d-%02d', l.year, l.mon, l.mday) : sprintf('%02d.%02d.%04d', l.mday, l.mon, l.year);
}

// a big list's name: its label, else what its source is (LuCI does the same, msg.listTitle)
function list_title(s) {
	if (s.label) return s.label;
	const u = (type(s.url) == 'array' ? s.url[0] : s.url) ?? '';
	let m;
	if ((m = match(u, /^v2fly:(.+)$/))) return m[1];
	if ((m = match(u, /russia-blocked-geo(site|ip)[^\/]*\/(text\/)?(.+)\.txt$/))) return m[3] + (m[1] == 'ip' ? ' ' + _('(addresses)') : '');
	if ((m = match(u, /^https?:\/\/([^\/?]+)/))) return m[1];
	if (s.file) return replace(s.file, /^.*\//, '');
	return s['.name'];
}

// lists-update writes English reasons; the known ones for people. A subscription's address never appears.
function list_reason(m) {
	m = replace(m ?? '', /;? ?previous data kept$/, '');
	let x;
	if ((x = match(m, /^download failed: https?:\/\/([^\/?]+)/))) return sprintf(_('could not download from %s'), x[1]);
	if ((x = match(m, /^download failed: v2fly:(.+)$/))) return sprintf(_('could not download the v2fly category %s'), x[1]);
	if ((x = match(m, /^only ([0-9]+) entries \(minimum ([0-9]+)\)$/))) return sprintf(_('only %s entries came (at least %s needed)'), x[1], x[2]);
	if ((x = match(m, /^file missing: (.+)$/))) return sprintf(_('no file %s'), x[1]);
	if ((x = match(m, /^unknown policy '(.+)'$/))) return sprintf(_('its policy %s is gone'), x[1]);
	if ((x = match(m, /^not enough memory: needs ~([0-9.]+) MB, ([0-9.]+) MB left for lists$/)))
		return sprintf(_('not enough router memory: ~%s MB more needed, %s MB left for lists'), x[1], x[2]);
	if ((x = match(m, /^download too big for the memory: over ([0-9]+) MB$/))) return sprintf(_('the download is bigger than the memory holds (over %s MB)'), x[1]);
	return m;
}

// a function: translated in the language set at the time of the message
function sub_reason(st) {
	return {
		download_failed: _('the provider did not answer'),
		no_servers: _('no suitable servers in the answer'),
		bad_url: _('wrong subscription address'),
		private: _('the subscription address points into the local network'),
	}[st.code] ?? st.message;
}

let t_start = null, boot_pending = false, boot_sent = false;
let wan_ok = true, wan_miss = 0, wan_since = null;
const seen = {};          // status file -> { ok, ts } as last seen
let warned = {};          // sub expiry / traffic: one message a day per kind

export function init() {
	t_start = time();
	// a router that has just booted (not a daemon restart): one message once the exits had their chance
	const up = +split(fs.readfile('/proc/uptime') ?? '0', ' ')[0];
	boot_pending = up < 600;
}

// the provider's internet: the main table has a default route (PPPoE / DHCP gone = no route)
function wan_present() {
	return length(trim(run('ip -4 route show default table main 2>/dev/null').out)) > 0;
}

let wan_back = 0;
export function wan_down() { return !wan_ok; }
// the exits fall and rise with the provider's line: say nothing about them meanwhile and for 3 min after
export function quiet() { return !wan_ok || time() - wan_back < 180; }

function check_wan() {
	const ok = wan_present();
	if (ok) {
		wan_miss = 0;
		if (!wan_ok) {
			wan_ok = true;
			wan_back = time();
			log(sprintf('WAN back after %d s', time() - wan_since));
			notify.event('wan', null, sprintf(_("The provider's internet is back (it was gone for %s)"), dur(time() - wan_since)));
		}
		return;
	}
	// two ticks in a row: a PPPoE reconnect of a second is not an outage
	if (wan_ok && ++wan_miss >= 2) {
		wan_ok = false;
		wan_since = time();
		log('WAN down: no default route');
		notify.event('wan', null, _("The provider's internet is gone. Messages about the exits wait until it is back"));
	}
}

// exits: [{ name, label, enabled }], healthy(name) -> bool, ready: every exit reported once
function check_boot(exits, healthy, ready) {
	if (!boot_pending || boot_sent) return;
	if (!ready && time() - t_start < 300) return;
	boot_sent = true;
	const on = filter(exits, (e) => e.enabled);
	const bad = map(filter(on, (e) => !healthy(e)), (e) => q(e.label ?? e.name));
	let t = sprintf(_('The router rebooted, Detour works: %d of %d exits work'), length(on) - length(bad), length(on));
	if (length(bad)) t += '. ' + sprintf(_('Did not come up: %s'), join(', ', bad));
	notify.event('boot', null, t);
}

function read(f) { try { return json(fs.readfile(f) ?? 'null'); } catch (e) { return null; } }

// a failure is told once, when an update that had worked (or a fresh one) fails; quiet until it works again
function check_lists() {
	const c = cursor();
	for (let f in fs.glob(RUN + '/lists/*.status') ?? []) {
		const st = read(f);
		if (!st?.name) continue;
		const prev = seen[f];
		seen[f] = { ok: st.ok, ts: st.ts };
		if (st.ok || st.message == 'disabled') continue;
		if (prev && (!prev.ok ? true : prev.ts == st.ts)) continue;
		if (!prev && st.ts < t_start) continue;   // an old failure from before the daemon started
		const s = c.get_all('detour', st.name) ?? { '.name': st.name };
		notify.event('list_fail', null, sprintf(_('The list %s did not update: %s. %s'), q(list_title(s)), list_reason(st.message),
			st.count > 0 ? sprintf(_('The previous one works (entries: %d)'), st.count) : _('There is no previous one, the list is empty for now')));
	}
}

function check_subs() {
	const c = cursor();
	const today = day(time());
	for (let f in fs.glob(RUN + '/subs/*.status') ?? []) {
		const st = read(f);
		if (!st?.name) continue;
		const s = c.get_all('detour', st.name);
		if (!s || s.enabled == '0') continue;
		const label = q(s.label ?? st.name);
		const prev = seen[f];
		seen[f] = { ok: st.ok, ts: st.ts };
		if (!st.ok && !(prev && (!prev.ok || prev.ts == st.ts)) && !(!prev && st.ts < t_start))
			notify.event('sub_fail', null, sprintf(_('The subscription %s did not update: %s. The previous servers stay'), label, sub_reason(st)));
		const i = st.info;
		if (!i) continue;
		if (i.expire > 0 && i.expire - time() < 3 * 86400 && warned[st.name + ':exp'] != today) {
			warned[st.name + ':exp'] = today;
			notify.event('sub_expire', null, i.expire > time()
				? sprintf(_('The subscription %s ends on %s'), label, day(i.expire))
				: sprintf(_('The subscription %s ended on %s'), label, day(i.expire)));
		}
		const used = (i.upload ?? 0) + (i.download ?? 0);
		if (i.total > 0 && used >= i.total * 0.9 && warned[st.name + ':traffic'] != today) {
			warned[st.name + ':traffic'] = today;
			notify.event('sub_expire', null, sprintf(_('The subscription %s: %d%% of the traffic used (%s of %s)'), label, int(used * 100 / i.total), gb(used), gb(i.total)));
		}
	}
}

export function tick(exits, healthy, ready) {
	// a list or subscription removed (and maybe made again under the same name) starts afresh
	for (let f in keys(seen)) if (!fs.access(f)) delete seen[f];
	check_wan();
	check_boot(exits, healthy, ready);
	check_lists();
	check_subs();
}
