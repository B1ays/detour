'use strict';
'require baseclass';

// Text from the router (names of exits and servers come from subscriptions and links) never becomes HTML:
// LuCI's E() puts a string child in with innerHTML, here it always goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

// The settings of a sing-box proxy outbound as form fields: server, keys, security (TLS / Reality), transport.
// read() returns the outbound with the fields written back into a copy of the original, so anything the form
// does not show (multiplex, padding, …) stays as it was.

const TYPES = [ 'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'tuic' ];
const SS_METHODS = [ '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
	'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305' ];
const FP = [ '', 'chrome', 'firefox', 'safari', 'ios', 'edge', 'android', 'random', 'randomized' ];

function input(v, ph) { return E('input', { 'class': 'cbi-input-text', 'value': v == null ? '' : String(v), 'placeholder': ph || '' }); }
function select(v, opts) {
	return E('select', { 'class': 'cbi-input-select' }, opts.map(function(o) {
		const val = Array.isArray(o) ? o[0] : o, txt = Array.isArray(o) ? o[1] : (o || '—');
		return E('option', { 'value': val, 'selected': String(v == null ? '' : v) == val ? '' : null }, txt);
	}));
}
function check(v) { return E('input', { 'type': 'checkbox', 'class': 'cbi-input-checkbox', 'checked': v ? '' : null }); }
function row(title, field, descr) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, title),
		E('div', { 'class': 'cbi-value-field' }, descr ? [ field, E('div', { 'class': 'cbi-value-description' }, descr) ] : field)
	]);
}
function val(el) { return el.value.trim(); }
function set(o, k, v) { if (v === '' || v == null) delete o[k]; else o[k] = v; }

return baseclass.extend({
	supported: function(o) { return o && !o.protocol && TYPES.indexOf(o.type) >= 0; },

	// o: the outbound (sing-box); returns { node, read() }
	build: function(o) {
		const t = o.type;
		const tls = o.tls || {}, tr = o.transport || {};
		const f = {};
		const rows = [];
		const show = function(r, on) { r.style.display = on ? '' : 'none'; };

		f.server = input(o.server, 'vpn.example.org');
		f.port = input(o.server_port, '443');
		rows.push(row(_('Server address'), f.server), row(_('Server port'), f.port));

		if (t == 'vless' || t == 'vmess' || t == 'tuic') { f.uuid = input(o.uuid, 'xxxxxxxx-xxxx-…'); rows.push(row('UUID', f.uuid)); }
		if (t == 'trojan' || t == 'shadowsocks' || t == 'hysteria2' || t == 'tuic') { f.password = input(o.password); rows.push(row(_('Password'), f.password)); }
		if (t == 'shadowsocks') {
			f.method = select(o.method, SS_METHODS.indexOf(o.method) >= 0 ? SS_METHODS : SS_METHODS.concat([ o.method ]));
			rows.push(row(_('Encryption'), f.method));
		}
		if (t == 'vless') {
			f.flow = select(o.flow || '', [ [ '', _('not set') ], [ 'xtls-rprx-vision', 'xtls-rprx-vision' ] ]);
			rows.push(row('Flow', f.flow, _('Vision is used with TCP and TLS or Reality, as the server says.')));
		}
		if (t == 'vmess') { f.vsec = select(o.security || 'auto', [ 'auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero' ]); rows.push(row(_('Encryption'), f.vsec)); }
		if (t == 'hysteria2') {
			f.obfs = input(o.obfs && o.obfs.password, _('empty: no obfuscation'));
			rows.push(row(_('Obfuscation password (salamander)'), f.obfs));
		}
		if (t == 'tuic') {
			f.cc = select(o.congestion_control || '', [ [ '', _('default') ], 'cubic', 'new_reno', 'bbr' ]);
			rows.push(row(_('Congestion control'), f.cc));
		}

		// security: TLS-based protocols (hysteria2, tuic) always have TLS; vless / vmess / trojan choose
		const quic = (t == 'hysteria2' || t == 'tuic');
		const secRows = [];
		if (!quic && t != 'shadowsocks') {
			f.sec = select(tls.reality && tls.reality.enabled ? 'reality' : (tls.enabled ? 'tls' : 'none'),
				[ [ 'none', _('not set') ], [ 'tls', 'TLS' ], [ 'reality', 'Reality' ] ]);
			rows.push(row(_('Security'), f.sec, _('As the server is set up: Reality pretends to be another site, TLS is an ordinary certificate.')));
		}
		if (t != 'shadowsocks') {
			f.sni = input(tls.server_name, _('the server address'));
			f.fp = select((tls.utls && tls.utls.fingerprint) || '', FP);
			f.alpn = input((tls.alpn || []).join(','), quic ? 'h3' : 'h2,http/1.1');
			f.insecure = check(tls.insecure);
			f.pbk = input(tls.reality && tls.reality.public_key);
			f.sid = input(tls.reality && tls.reality.short_id);
			const rSni = row('SNI', f.sni, _('The site name shown in the handshake. For Reality - the site it pretends to be.'));
			const rFp = row(_('Browser fingerprint'), f.fp, _('Which browser the handshake imitates (uTLS). Reality needs one; chrome if unsure.'));
			const rAlpn = row('ALPN', f.alpn);
			const rIns = row(_('Do not check the certificate'), f.insecure, _('Only for your own server with a self-made certificate.'));
			const rPbk = row(_('Reality public key'), f.pbk), rSid = row('Short ID', f.sid);
			secRows.push(rSni, rFp, rAlpn, rIns, rPbk, rSid);
			const upd = function() {
				const s = quic ? 'tls' : f.sec.value;
				[ rSni, rFp, rAlpn ].forEach(function(r) { show(r, s != 'none'); });
				show(rIns, s == 'tls'); show(rPbk, s == 'reality'); show(rSid, s == 'reality');
				if (quic) show(rFp, false);
			};
			if (f.sec) f.sec.addEventListener('change', upd);
			upd();
			secRows.forEach(function(r) { rows.push(r); });
		}

		// transport
		if (t == 'vless' || t == 'vmess' || t == 'trojan') {
			f.net = select(tr.type || 'tcp', [ [ 'tcp', 'TCP' ], [ 'ws', 'WebSocket' ], [ 'grpc', 'gRPC' ], [ 'http', 'HTTP/2' ], [ 'httpupgrade', 'HTTPUpgrade' ] ]);
			f.path = input(tr.path, '/');
			f.host = input(tr.type == 'ws' ? (tr.headers && tr.headers.Host) : (Array.isArray(tr.host) ? tr.host.join(',') : tr.host));
			f.svc = input(tr.service_name);
			const rPath = row(_('Path'), f.path), rHost = row('Host', f.host), rSvc = row(_('gRPC service name'), f.svc);
			rows.push(row(_('Transport'), f.net), rPath, rHost, rSvc);
			const upd = function() {
				const n = f.net.value;
				show(rPath, n == 'ws' || n == 'http' || n == 'httpupgrade');
				show(rHost, n == 'ws' || n == 'http' || n == 'httpupgrade');
				show(rSvc, n == 'grpc');
			};
			f.net.addEventListener('change', upd);
			upd();
		}

		return {
			node: E('div', {}, rows),
			read: function() {
				const n = JSON.parse(JSON.stringify(o));
				const port = parseInt(val(f.port), 10);
				if (!val(f.server)) throw new Error(_('The server address is empty'));
				if (!(port >= 1 && port <= 65535)) throw new Error(_('The port must be 1-65535'));
				n.server = val(f.server); n.server_port = port;
				if (f.uuid) { if (!/^[0-9a-fA-F-]{8,}$/.test(val(f.uuid))) throw new Error(_('UUID looks wrong')); n.uuid = val(f.uuid); }
				if (f.password) set(n, 'password', f.password.value);
				if (f.method) n.method = f.method.value;
				if (f.flow) set(n, 'flow', f.flow.value);
				if (f.vsec) n.security = f.vsec.value;
				if (f.obfs) { if (val(f.obfs)) n.obfs = { type: 'salamander', password: f.obfs.value }; else delete n.obfs; }
				if (f.cc) set(n, 'congestion_control', f.cc.value);
				if (f.sni) {
					const s = quic ? 'tls' : f.sec.value;
					if (s == 'none') delete n.tls;
					else {
						const nt = n.tls || {};
						nt.enabled = true;
						set(nt, 'server_name', val(f.sni));
						const alpn = val(f.alpn) ? val(f.alpn).split(/\s*,\s*/) : null;
						if (alpn) nt.alpn = alpn; else delete nt.alpn;
						if (s == 'tls' && f.insecure.checked) nt.insecure = true; else delete nt.insecure;
						const fp = f.fp.value || (s == 'reality' ? 'chrome' : '');
						if (fp && !quic) nt.utls = { enabled: true, fingerprint: fp }; else delete nt.utls;
						if (s == 'reality') {
							if (!val(f.pbk)) throw new Error(_('Reality needs the public key'));
							nt.reality = { enabled: true, public_key: val(f.pbk), short_id: val(f.sid) };
						}
						else delete nt.reality;
						n.tls = nt;
					}
				}
				if (f.net) {
					const k = f.net.value;
					if (k == 'tcp') delete n.transport;
					else if (k == 'ws') n.transport = { type: 'ws', path: val(f.path) || '/', headers: val(f.host) ? { Host: val(f.host) } : undefined };
					else if (k == 'grpc') n.transport = { type: 'grpc', service_name: val(f.svc) };
					else if (k == 'http') n.transport = { type: 'http', path: val(f.path) || '/', host: val(f.host) ? val(f.host).split(/\s*,\s*/) : undefined };
					else n.transport = { type: 'httpupgrade', path: val(f.path) || '/', host: val(f.host) || undefined };
					if (n.transport) n.transport = JSON.parse(JSON.stringify(n.transport));
				}
				return n;
			}
		};
	}
});
