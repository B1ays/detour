// Notifications: Telegram (Bot API) and/or ntfy (ntfy.sh or an own server; options telegram, ntfy). The interesting
// message ("tunnel down") is sent exactly when the tunnel is dead and the service may be blocked by the
// provider: try through a working exit first, then directly; undelivered messages wait in a queue and go out
// with their time once any path works. Each channel has its own queue and goes on its own: one that fails or
// refuses holds nothing of the other back. The bot token, the ntfy token and the topic never appear on a command
// line (curl -K file and a body file, mode 600).
'use strict';

import * as fs from 'fs';
import * as uloop from 'uloop';
import { cursor } from 'uci';
import { log, vlog, RUN } from 'detour.core';
import { _ } from 'detour.i18n';

const OLDQ = RUN + '/outbox.json';   // the one queue of before (moved into the channels' queues)
const ND = RUN + '/notify';      // owned by the "dtnotify" user, mode 700
const MAXQ = 30;
export const CHANNELS = [ 'telegram', 'ntfy' ];

// every kind of message; option event of the notify section picks some (LuCI: "Notify about")
export const ALL_EVENTS = [ 'exit_down', 'exit_up', 'all_down', 'switch', 'boot', 'wan', 'list_fail', 'sub_fail', 'sub_expire' ];

let busy = {};            // channel -> a message on its way
let last_sent = {};       // throttle key -> time

export function config() {
	const s = cursor().get_all('detour', 'notify') ?? {};
	const ev = s.event ?? ALL_EVENTS;
	// Telegram is on unless switched off (configs from before the channels), ntfy when switched on; a channel
	// counts once it is filled in
	const channels = filter(CHANNELS, (ch) => ch == 'ntfy'
		? (s.ntfy == '1' && !!s.ntfy_topic)
		: (s.telegram != '0' && !!s.tg_token && !!s.tg_chat));
	return {
		channels,
		enabled: s.enabled == '1' && length(channels) > 0,
		token: s.tg_token, chat: s.tg_chat,
		api: s.tg_api ?? 'https://api.telegram.org',
		ntfy_url: replace(s.ntfy_url || 'https://ntfy.sh', /\/+$/, ''), topic: s.ntfy_topic, ntfy_token: s.ntfy_token,
		events: (type(ev) == 'array') ? ev : [ ev ],
		throttle: int(s.throttle ?? 60),
		name: s.router_name ?? 'Detour',
	};
};

function qfile(ch) { return RUN + '/outbox-' + ch + '.json'; }

function read_q(f) {
	try { return json(fs.readfile(f) ?? '[]') ?? []; } catch (e) { return []; }
}

function load_q(ch) { return read_q(qfile(ch)); }

function save_q(ch, q) {
	while (length(q) > MAXQ) shift(q);
	fs.writefile(qfile(ch) + '.tmp', sprintf('%J', q));
	fs.rename(qfile(ch) + '.tmp', qfile(ch));
}

// a message for every channel that is on
function enqueue(c, m) {
	for (let ch in c.channels) { const q = load_q(ch); push(q, m); save_q(ch, q); }
}

// what waited in the single queue of an older version goes to the channels now on
function migrate(c) {
	if (!fs.access(OLDQ)) return;
	for (let m in read_q(OLDQ)) enqueue(c, m);
	fs.unlink(OLDQ);
}

// event: key from cfg.events; key: throttle key (e.g. 'exit_down:warp')
export function event(ev, key, text) {
	const c = config();
	if (!c.enabled || index(c.events, ev) < 0) return false;
	const now = time();
	if (key && last_sent[key] && now - last_sent[key] < c.throttle) return false;
	if (key) last_sent[key] = now;
	enqueue(c, { t: now, text });
	return true;
};

// a value inside "..." of a curl config: \ and " escaped
function cq(s) { return replace(replace('' + s, /\\/g, '\\\\'), /"/g, '\\"'); }

// what curl is given for one message: the config (URL, secret headers) and the JSON body
function request(c, ch, text) {
	if (ch == 'ntfy') {
		// JSON publishing: POST to the server's root, the topic in the body (not in the URL, not in the log)
		let cfg = sprintf('url = "%s"\n', cq(c.ntfy_url));
		if (c.ntfy_token) cfg += sprintf('header = "Authorization: Bearer %s"\n', cq(c.ntfy_token));
		return { cfg, body: { topic: c.topic, title: c.name, message: text } };
	}
	return { cfg: sprintf('url = "%s/bot%s/sendMessage"\n', cq(c.api), cq(c.token)),
		body: { chat_id: c.chat, text: c.name + ': ' + text, disable_web_page_preview: true } };
}

// the answer of the service: delivered
function accepted(ch, http, resp) {
	return http == '200' && (ch == 'ntfy' ? !!resp?.id : resp?.ok === true);
}

function fmt_time(t) {
	const lt = localtime(t);
	return sprintf('%02d:%02d', lt.hour, lt.min);
}

// the first message of one channel's queue: through the paths in turn, then the next message
function flush_one(c, ch, paths, done_cb) {
	if (busy[ch]) return;
	const q = load_q(ch);
	if (!length(q)) return;
	busy[ch] = true;
	const m = q[0];
	let text = m.text;
	if (time() - m.t > 90) text += ' ' + sprintf(_('(at %s)'), fmt_time(m.t));
	// curl runs as the system user "dtnotify": its traffic is exempt from the policies, so the
	// direct attempt really goes direct even when the API's address is on a VPN list
	const user = (fs.access('/etc/passwd') && match(fs.readfile('/etc/passwd'), /(^|\n)dtnotify:/)) ? 'dtnotify' : null;
	fs.mkdir(ND, 0700);
	if (user) system(sprintf('chown %s %s', user, ND));
	const F = ND + '/' + ch;     // <ch>.cfg (the secrets), <ch>.json (the body), <ch>.out (the answer)
	const req = request(c, ch, text);
	for (let x in [ [ '.cfg', req.cfg ], [ '.json', sprintf('%J', req.body) ] ]) {
		fs.writefile(F + x[0], '');
		fs.chmod(F + x[0], 0600);
		fs.writefile(F + x[0], x[1]);
	}
	if (user) system(sprintf('chown %s %s.cfg %s.json', user, F, F));
	fs.unlink(F + '.out');
	// -p <never written>: otherwise busybox start-stop-daemon refuses ("already running") while
	// another curl of this user is still alive
	const run_as = user ? sprintf('start-stop-daemon -S -p %s/none.pid -c %s -x /usr/bin/curl --', ND, user) : 'curl';
	const code_f = RUN + '/notify-' + ch + '.code';
	const tries = [ ...(paths ?? []), null ];
	let i = 0;
	let attempt;
	attempt = function() {
		if (i >= length(tries)) { busy[ch] = false; return; }
		const dev = tries[i++];
		const cmd = sprintf("%s -s -m 10 %s -K %s.cfg -H 'Content-Type: application/json' --data-binary @%s.json -o %s.out -w '%%{http_code}' > %s 2>/dev/null",
			run_as, dev ? "--interface '" + dev + "'" : '', F, F, F, code_f);
		uloop.process('/bin/sh', [ '-c', cmd ], {}, function(code) {
			const http = trim(fs.readfile(code_f) ?? '');
			const out = fs.readfile(F + '.out') ?? '';
			let resp = null;
			try { resp = json(out); } catch (e) { }
			const why = resp?.description ?? resp?.error;
			vlog('notify', sprintf('via %s (%s): HTTP %s%s', dev ?? 'direct', ch, http || '-', why ? ' (' + why + ')' : ''));
			if (accepted(ch, http, resp)) {
				const q2 = load_q(ch); shift(q2); save_q(ch, q2);
				busy[ch] = false;
				log(sprintf('notify: sent via %s (%s)', dev ?? 'direct', ch));
				if (done_cb) done_cb(dev ?? 'direct');
				// the rest of the queue goes the same way at once (a burst - reboot, line back - is not spread over minutes)
				if (length(load_q(ch))) flush_one(c, ch, dev ? [ dev ] : [], done_cb);
				return;
			}
			if (index([ '400', '401', '403', '404', '413' ], http) >= 0) {
				// wrong token/chat/topic, no access to the topic: retrying will not help, drop the message
				const q2 = load_q(ch); shift(q2); save_q(ch, q2);
				busy[ch] = false;
				log(sprintf('notify: rejected by the API (HTTP %s), message dropped (%s)', http, ch));
				return;
			}
			attempt();
		});
	};
	attempt();
}

// paths: list of devices of working exits (tried first), then direct (null)
export function flush(paths, done_cb) {
	const c = config();
	if (!c.enabled) return;
	migrate(c);
	for (let ch in c.channels) flush_one(c, ch, paths, done_cb);
};

// waiting in the queues of the channels now on
export function queued() {
	let n = length(read_q(OLDQ));
	for (let ch in config().channels) n += length(load_q(ch));
	return n;
};

// queue a test message regardless of event filters/throttle; false when not configured
export function test() {
	const c = config();
	if (!c.enabled) return false;
	enqueue(c, { t: time(), text: _('Test message: notifications work') });
	return true;
};
