// "Download the logs" (LuCI, Settings): one .tar.gz with what a diagnosis needs - the verbose log, the syslog, the
// state, the configuration and the network as Detour sees it. Every file is named here: no directory is swept in
// (WARP registrations, outbound files with keys, the panel tunnel's key stay out), and what is written passes
// core.redact - keys, passwords, tokens, UUIDs, share links. conntrack: counts, not the flows (no visited sites).
'use strict';

import * as fs from 'fs';
import * as core from 'detour.core';
import * as engines from 'detour.engines';
import { cursor } from 'uci';

export const OUT = '/tmp/detour-logs.tar.gz';
const WORK = core.RUN + '/logs-archive';

// a command's output (stdout and stderr), unmodified apart from the secrets
function cmd(c) { return core.redact(core.run(c).out); }

export function archive() {
	const host = replace(trim(fs.readfile('/proc/sys/kernel/hostname') ?? 'router'), /[^A-Za-z0-9_-]/g, '') || 'router';
	const l = localtime(time());
	const name = sprintf('detour-logs-%s-%04d%02d%02d-%02d%02d', host, l.year, l.mon, l.mday, l.hour, l.min);
	const dir = WORK + '/' + name;
	core.run('rm -rf ' + core.shq(WORK));
	fs.mkdir(core.RUN); fs.mkdir(WORK, 0700); fs.mkdir(dir, 0700);
	const files = [];
	const put = (f, text) => {
		const p = dir + '/' + f;
		if (index(f, '/') > 0) fs.mkdir(dir + '/' + split(f, '/')[0], 0700);
		fs.writefile(p, text ?? '');
		push(files, f);
	};
	const rel = trim(replace(fs.readfile('/etc/openwrt_release') ?? '', /\n/g, ' '));

	// the verbose log (now and the rotated part)
	for (let f in [ core.VLOG + '.1', core.VLOG ])
		if (fs.access(f)) put('detour/' + replace(f, /^.*\//, ''), core.redact(fs.readfile(f)));
	const st = cursor().get('detour', 'main', 'log_level') == 'verbose' ? 'verbose' : 'normal';

	put('syslog.txt', cmd('logread'));
	put('dmesg.txt', cmd('dmesg'));
	put('status.json', cmd('ubus call detour status'));
	put('exits.json', cmd('/usr/sbin/detour exit-info'));
	put('components.json', cmd('ubus call detour pkg_list'));

	// the configuration as written, secrets masked
	for (let c in [ 'detour', 'network', 'firewall', 'dhcp', 'system' ])
		put('config/' + c + '.txt', cmd('uci export ' + c));
	// what the engines were given (the rendered configs, not the outbound files)
	for (let e in engines.list()) {
		const f = sprintf('%s/engines/%s.json', core.RUN, e.name);
		if (fs.access(f)) put('config/engine-' + e.name + '.json', core.redact(fs.readfile(f)));
	}
	if (fs.access(core.RUN + '/ruleset.nft')) put('config/ruleset-applied.nft', fs.readfile(core.RUN + '/ruleset.nft'));

	// the network now
	put('net/nft-detour.txt', cmd('nft list table inet detour'));
	put('net/nft-all.txt', cmd('nft list ruleset'));
	put('net/ip.txt', join('\n', map([ 'ip -4 rule', 'ip -6 rule', 'ip -4 route show table all', 'ip -6 route show table all', 'ip addr', 'ip -s link',
		'cat /etc/iproute2/rt_tables', 'wg show all' ], (c) => '### ' + c + '\n' + cmd(c))));
	put('net/interfaces.json', cmd('ubus call network.interface dump'));
	const L = core.marks();
	let ct = '### conntrack -C\n' + cmd('conntrack -C') + '\n';
	ct += '### flows by mark (ct mark & 0x' + sprintf('%x', L.both) + '), counts only\n';
	const counts = {};
	// read here, not through core.run: its verbose record would hold the start of the list - addresses of sites
	const pp = fs.popen('conntrack -L 2>/dev/null', 'r');
	const flows = pp ? (pp.read('all') ?? '') : '';
	if (pp) pp.close();
	for (let line in split(flows, '\n')) {
		const m = match(line, / mark=([0-9]+)/);
		if (!m) continue;
		const k = sprintf('0x%08x', int(m[1]) & L.both);
		counts[k] = (counts[k] ?? 0) + 1;
	}
	for (let k in sort(keys(counts))) ct += sprintf('%s %d\n', k, counts[k]);
	put('net/conntrack.txt', ct);
	put('net/dnsmasq.txt', cmd('ls -l /tmp/dnsmasq.d /tmp/dnsmasq.*.d 2>/dev/null; cat /tmp/detour/dns.servers 2>/dev/null'));

	// the system
	put('system.txt', join('\n', map([ 'cat /etc/openwrt_release', 'uname -a', 'uptime', 'free', 'df -h', 'cat /proc/loadavg',
		'apk list -I 2>/dev/null', 'ps w', 'ls -l /tmp/detour /tmp/detour/lists /etc/detour', 'cat /tmp/detour/pkg/log 2>/dev/null' ],
		(c) => '### ' + c + '\n' + cmd(c))));

	put('README.txt', sprintf(
		'Detour %s - logs of %s, %04d-%02d-%02d %02d:%02d\n%s\nlog level: %s\n\n' +
		'Keys, passwords, tokens, UUIDs and share links are masked (***). Flows are counted, not listed.\n\nFiles:\n%s\n',
		core.VERSION, host, l.year, l.mon, l.mday, l.hour, l.min, rel, st, join('\n', map(sort(files), (f) => '  ' + f))));

	fs.unlink(OUT);
	const r = core.run(sprintf('umask 077; tar -C %s -czf %s %s', core.shq(WORK), core.shq(OUT), core.shq(name)));
	core.run('rm -rf ' + core.shq(WORK));
	if (r.code != 0) return { error: 'tar: ' + trim(r.out) };
	fs.chmod(OUT, 0600);
	return { ok: true, path: OUT, name: name + '.tar.gz', size: fs.stat(OUT)?.size ?? 0, files: length(files) };
};
