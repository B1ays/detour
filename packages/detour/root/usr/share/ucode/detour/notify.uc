// Notifications (Telegram Bot API). The interesting message ("tunnel down") is sent exactly when
// the tunnel is dead and api.telegram.org may be blocked by the provider: try through a working
// exit first, then directly; undelivered messages wait in a queue and go out with their time
// once any path works. The bot token never appears on a command line (curl -K file, mode 600).
'use strict';

import * as fs from 'fs';
import * as uloop from 'uloop';
import { cursor } from 'uci';
import { log, RUN } from 'detour.core';

const QUEUE = RUN + '/outbox.json';
const ND = RUN + '/notify';      // owned by the "dtnotify" user, mode 700
const MAXQ = 30;

// every kind of message; option event of the notify section picks some (LuCI: "Notify about")
export const ALL_EVENTS = [ 'exit_down', 'exit_up', 'all_down', 'switch', 'boot', 'wan', 'list_fail', 'sub_fail', 'sub_expire' ];

let busy = false;
let last_sent = {};       // throttle key -> time

export function config() {
	const s = cursor().get_all('detour', 'notify') ?? {};
	const ev = s.event ?? ALL_EVENTS;
	return {
		enabled: s.enabled == '1' && !!s.tg_token && !!s.tg_chat,
		token: s.tg_token, chat: s.tg_chat,
		api: s.tg_api ?? 'https://api.telegram.org',
		events: (type(ev) == 'array') ? ev : [ ev ],
		throttle: int(s.throttle ?? 60),
		name: s.router_name ?? 'Detour',
	};
}

function load_q() {
	try { return json(fs.readfile(QUEUE) ?? '[]'); } catch (e) { return []; }
}

function save_q(q) {
	while (length(q) > MAXQ) shift(q);
	fs.writefile(QUEUE + '.tmp', sprintf('%J', q));
	fs.rename(QUEUE + '.tmp', QUEUE);
}

// event: key from cfg.events; key: throttle key (e.g. 'exit_down:warp')
export function event(ev, key, text) {
	const c = config();
	if (!c.enabled || index(c.events, ev) < 0) return false;
	const now = time();
	if (key && last_sent[key] && now - last_sent[key] < c.throttle) return false;
	if (key) last_sent[key] = now;
	const q = load_q();
	push(q, { t: now, text });
	save_q(q);
	return true;
}

function fmt_time(t) {
	const lt = localtime(t);
	return sprintf('%02d:%02d', lt.hour, lt.min);
}

// paths: list of devices of working exits (tried first), then direct (null)
export function flush(paths, done_cb) {
	const c = config();
	if (busy || !c.enabled) return;
	const q = load_q();
	if (!length(q)) return;
	busy = true;
	const m = q[0];
	let text = c.name + ': ' + m.text;
	if (time() - m.t > 90) text += sprintf(' (в %s)', fmt_time(m.t));
	// curl runs as the system user "dtnotify": its traffic is exempt from the policies, so the
	// direct attempt really goes direct even when the API's address is on a VPN list
	const user = (fs.access('/etc/passwd') && match(fs.readfile('/etc/passwd'), /(^|\n)dtnotify:/)) ? 'dtnotify' : null;
	fs.mkdir(ND, 0700);
	if (user) system(sprintf('chown %s %s', user, ND));
	fs.writefile(ND + '/curl.cfg', '');
	fs.chmod(ND + '/curl.cfg', 0600);
	fs.writefile(ND + '/curl.cfg', sprintf('url = "%s/bot%s/sendMessage"\n', c.api, c.token));
	fs.writefile(ND + '/body.json', sprintf('%J', { chat_id: c.chat, text, disable_web_page_preview: true }));
	if (user) system(sprintf('chown %s %s/curl.cfg %s/body.json', user, ND, ND));
	fs.unlink(ND + '/out');
	// -p <never written>: otherwise busybox start-stop-daemon refuses ("already running") while
	// another curl of this user is still alive
	const run_as = user ? sprintf('start-stop-daemon -S -p %s/none.pid -c %s -x /usr/bin/curl --', ND, user) : 'curl';
	const tries = [ ...(paths ?? []), null ];
	let i = 0;
	let attempt;
	attempt = function() {
		if (i >= length(tries)) { busy = false; return; }
		const dev = tries[i++];
		const cmd = sprintf("%s -s -m 10 %s -K %s/curl.cfg -H 'Content-Type: application/json' --data-binary @%s/body.json -o %s/out -w '%%{http_code}' > %s/code 2>/dev/null",
			run_as, dev ? "--interface '" + dev + "'" : '', ND, ND, ND, RUN);
		uloop.process('/bin/sh', [ '-c', cmd ], {}, function(code) {
			const http = trim(fs.readfile(RUN + '/code') ?? '');
			const out = fs.readfile(ND + '/out') ?? '';
			let resp = null;
			try { resp = json(out); } catch (e) { }
			if (http == '200' && resp?.ok === true) {
				const q2 = load_q(); shift(q2); save_q(q2);
				busy = false;
				log(sprintf('notify: sent via %s', dev ?? 'direct'));
				if (done_cb) done_cb(dev ?? 'direct');
				// the rest of the queue goes the same way at once (a burst - reboot, line back - is not spread over minutes)
				if (length(load_q())) flush(dev ? [ dev ] : [], done_cb);
				return;
			}
			if (http == '401' || http == '400' || http == '404') {
				// wrong token/chat: retrying will not help, drop the message
				const q2 = load_q(); shift(q2); save_q(q2);
				busy = false;
				log(sprintf('notify: rejected by the API (HTTP %s), message dropped', http));
				return;
			}
			attempt();
		});
	};
	attempt();
}

export function queued() { return length(load_q()); }

// queue a test message regardless of event filters/throttle; false when not configured
export function test() {
	if (!config().enabled) return false;
	const q = load_q();
	push(q, { t: time(), text: 'Проверочное сообщение: уведомления работают' });
	save_q(q);
	return true;
}
