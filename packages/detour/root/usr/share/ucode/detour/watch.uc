// Notifications about what happens around the exits (the daemon's own events - exits, policies - are sent
// by detourd): the router came back after a reboot, the provider's internet went away and came back, a big
// list or a subscription failed to update, a subscription is running out of time or traffic.
// Texts are for people (Russian, with the names people gave); the log stays English.
'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { run, RUN, log } from 'detour.core';
import * as notify from 'detour.notify';

export function q(s) { return '«' + s + '»'; }

export function dur(s) {
	s = int(s);
	if (s < 90) return sprintf('%d с', s);
	if (s < 5400) return sprintf('%d мин', int((s + 30) / 60));
	return sprintf('%d ч %d мин', int(s / 3600), int((s % 3600) / 60));
}

function gb(b) { return sprintf('%.1f ГБ', b / 1073741824.0); }

function day(t) { const l = localtime(t); return sprintf('%02d.%02d.%04d', l.mday, l.mon, l.year); }

// a big list's name: its label, else what its source is (LuCI does the same, msg.listTitle)
function list_title(s) {
	if (s.label) return s.label;
	const u = (type(s.url) == 'array' ? s.url[0] : s.url) ?? '';
	let m;
	if ((m = match(u, /^v2fly:(.+)$/))) return m[1];
	if ((m = match(u, /russia-blocked-geo(site|ip)[^\/]*\/(text\/)?(.+)\.txt$/))) return m[3] + (m[1] == 'ip' ? ' (адреса)' : '');
	if ((m = match(u, /^https?:\/\/([^\/?]+)/))) return m[1];
	if (s.file) return replace(s.file, /^.*\//, '');
	return s['.name'];
}

// lists-update writes English reasons; the known ones for people. A subscription's address never appears.
function list_reason(m) {
	m = replace(m ?? '', /;? ?previous data kept$/, '');
	let x;
	if ((x = match(m, /^download failed: https?:\/\/([^\/?]+)/))) return 'не удалось скачать с ' + x[1];
	if ((x = match(m, /^download failed: v2fly:(.+)$/))) return 'не удалось скачать категорию v2fly ' + x[1];
	if ((x = match(m, /^only ([0-9]+) entries \(minimum ([0-9]+)\)$/))) return sprintf('пришло только %s записей (нужно не меньше %s)', x[1], x[2]);
	if ((x = match(m, /^file missing: (.+)$/))) return 'нет файла ' + x[1];
	if ((x = match(m, /^unknown policy '(.+)'$/))) return 'его политики ' + x[1] + ' больше нет';
	if ((x = match(m, /^not enough memory: needs ~([0-9.]+) MB, ([0-9.]+) MB left for lists$/)))
		return sprintf('не хватает памяти роутера: нужно ещё ~%s МБ, для списков осталось %s МБ', x[1], x[2]);
	if ((x = match(m, /^download too big for the memory: over ([0-9]+) MB$/))) return sprintf('скачанное больше, чем помещается в память (больше %s МБ)', x[1]);
	return m;
}

const SUB_REASON = {
	download_failed: 'провайдер не ответил',
	no_servers: 'в ответе нет подходящих серверов',
	bad_url: 'неверный адрес подписки',
	private: 'адрес подписки указывает во внутреннюю сеть',
};

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
			notify.event('wan', null, 'Интернет у провайдера вернулся (не было ' + dur(time() - wan_since) + ')');
		}
		return;
	}
	// two ticks in a row: a PPPoE reconnect of a second is not an outage
	if (wan_ok && ++wan_miss >= 2) {
		wan_ok = false;
		wan_since = time();
		log('WAN down: no default route');
		notify.event('wan', null, 'Пропал интернет у провайдера. Сообщения о выходах подождут его возвращения');
	}
}

// exits: [{ name, label, enabled }], healthy(name) -> bool, ready: every exit reported once
function check_boot(exits, healthy, ready) {
	if (!boot_pending || boot_sent) return;
	if (!ready && time() - t_start < 300) return;
	boot_sent = true;
	const on = filter(exits, (e) => e.enabled);
	const bad = map(filter(on, (e) => !healthy(e)), (e) => q(e.label ?? e.name));
	let t = sprintf('Роутер перезагрузился, Detour работает: выходов работает %d из %d', length(on) - length(bad), length(on));
	if (length(bad)) t += '. Не поднялись: ' + join(', ', bad);
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
		notify.event('list_fail', null, sprintf('Список %s не обновился: %s. %s', q(list_title(s)), list_reason(st.message),
			st.count > 0 ? sprintf('Работает прежний (записей: %d)', st.count) : 'Прежнего нет, список пока пуст'));
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
			notify.event('sub_fail', null, sprintf('Подписка %s не обновилась: %s. Остались прежние серверы', label, SUB_REASON[st.code] ?? st.message));
		const i = st.info;
		if (!i) continue;
		if (i.expire > 0 && i.expire - time() < 3 * 86400 && warned[st.name + ':exp'] != today) {
			warned[st.name + ':exp'] = today;
			notify.event('sub_expire', null, i.expire > time()
				? sprintf('Подписка %s заканчивается %s', label, day(i.expire))
				: sprintf('Подписка %s закончилась %s', label, day(i.expire)));
		}
		const used = (i.upload ?? 0) + (i.download ?? 0);
		if (i.total > 0 && used >= i.total * 0.9 && warned[st.name + ':traffic'] != today) {
			warned[st.name + ':traffic'] = today;
			notify.event('sub_expire', null, sprintf('Подписка %s: израсходовано %d%% трафика (%s из %s)', label, int(used * 100 / i.total), gb(used), gb(i.total)));
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
