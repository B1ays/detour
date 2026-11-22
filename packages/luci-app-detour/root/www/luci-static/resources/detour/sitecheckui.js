'use strict';
'require baseclass';
'require rpc';
'require ui';
'require uci';
'require detour.msg as msg';

// Text from the router (names of exits and servers come from subscriptions and links) never becomes HTML:
// LuCI's E() puts a string child in with innerHTML, here it always goes in as a text node.
const E = function(tag, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr)) { data = attr; attr = {}; }
	return L.dom.create(tag, attr, (typeof data == 'string' || typeof data == 'number') ? [ data ] : data);
};

// "Check a site" (the last part of the Policies page): where an address goes and why (the rule that wins and the ones that also matched), and does it
// open directly and through an exit. Then one click: through VPN, never through a tunnel, or blocked.

const callExplain = rpc.declare({ object: 'detour', method: 'site_explain', params: [ 'target', 'mac' ] });
const callCheck = rpc.declare({ object: 'detour', method: 'site_check', params: [ 'target', 'exit' ] });

function busy(btn, on) { btn.disabled = on; btn.classList.toggle('spinning', on); }
function note(text, cls) { return E('div', { 'class': 'alert-message ' + (cls || 'notice') }, text); }
function applyUci() { return uci.save().then(function() { return ui.changes.apply(); }); }
function arr(v) { return Array.isArray(v) ? v : (v ? String(v).split(/\s+/) : []); }
function row(title, field, descr) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, title),
		E('div', { 'class': 'cbi-value-field' }, descr ? [ field, E('div', { 'class': 'cbi-value-description' }, descr) ] : field)
	]);
}

function plab(n) { return '«' + (uci.get('detour', n, 'label') || n) + '»'; }
function listsText(ls) {
	return (ls || []).map(function(l) { const s = uci.get('detour', l.list); return '«' + (s ? msg.listTitle(Object.assign({ '.name': l.list }, s)) : l.list) + '»'; }).join(', ');
}

// one matched rule, in words
function matchText(m) {
	switch (m.why) {
	case 'local': return _('a local address (%s): never through a tunnel').format(m.ip);
	case 'device': return _('the device is in the policy %s').format(plab(m.policy));
	case 'address': return _('the address %s is in the policy %s').format(m.value, plab(m.policy));
	case 'domain': return _('the site %s is in the policy %s').format(m.value, plab(m.policy));
	case 'domain_list': return (m.lists && m.lists.length) ? _('the list %s of the policy %s').format(listsText(m.lists), plab(m.policy)) : _('a site of the policy %s').format(plab(m.policy));
	case 'address_list': return _('the list %s of the policy %s').format(listsText(m.lists), plab(m.policy));
	case 'port': return _('the port %s is in the policy %s').format(m.value, plab(m.policy));
	}
	return m.why;
}

function goesText(r) {
	const g = r.goes;
	if (g.to == 'block') return _('Blocked by the policy %s.').format(plab(g.policy));
	if (g.to == 'direct' && g.policy) return _('Directly through your provider: the policy %s never sends it through a tunnel.').format(plab(g.policy));
	if (g.to == 'direct_down') return _('Through the policy %s - but none of its exits works now, so directly (as chosen for it).').format(plab(g.policy));
	if (g.to == 'exit') return g.exit ? _('Through the policy %s, now via the exit «%s».').format(plab(g.policy), g.exit.label || g.exit.name)
		: _('Through the policy %s; no exit works now - blocked.').format(plab(g.policy));
	return r.matches.length ? _('Directly through your provider.') : _('Directly through your provider: no rule matches it.');
}

const ST = {
	ok: function(p) { return _('opens (%d ms)').format(p.ms); },
	http_block: function(p) { return _('the site refused (HTTP %d)').format(p.code); },
	stub: function() { return _('a provider\'s stub page instead of the site'); },
	http_err: function(p) { return _('the site answered with an error (HTTP %d)').format(p.code); },
	dns: function() { return _('the name is not found'); },
	refused: function() { return _('the connection is refused'); },
	silent: function() { return _('no answer'); },
	sni: function() { return _('connected, but the TLS handshake never starts (cut by the site name)'); },
	freeze: function() { return _('started loading and froze'); },
	reset: function() { return _('the connection is reset'); },
	tls: function() { return _('a TLS or certificate error'); },
	fail: function() { return _('failed'); }
};
const VERDICT = {
	direct_ok: function() { return [ _('It opens directly: no VPN is needed for it.'), 'success' ]; },
	need_vpn: function() { return [ _('Directly it does not open, through the VPN it does: worth sending through the VPN.'), 'warning' ]; },
	geo: function() { return [ _('The site itself refuses visitors from Russia; through the VPN it opens.'), 'warning' ]; },
	both_bad: function() { return [ _('It opens neither directly nor through the VPN: the trouble seems to be the site itself.'), 'warning' ]; },
	no_vpn: function() { return [ _('No working exit to compare with.'), 'notice' ]; },
	unclear: function() { return [ _('The site answers «forbidden» both ways: it refuses automatic requests, the check cannot tell.'), 'notice' ]; }
};

return baseclass.extend({
	// one click after the check: the site (or address) goes to a VPN policy, to the "Directly" one, or is blocked
	actions: function(r) {
		const isIp = !!r.ip;
		const key = isIp ? 'dst' : 'domain';
		const val = r.host;
		const pols = uci.sections('detour', 'policy').filter(function(p) { return msg.policyKind(p) == 'vpn'; });
		const sel = E('select', { 'class': 'cbi-input-select' }, pols.map(function(p) { return E('option', { 'value': p['.name'] }, p.label || p['.name']); }));
		const add = function(sec, k) {
			msg.moveTo(uci, sec, k, val);
			return applyUci();
		};
		const items = [];
		if (pols.length) items.push(E('div', { 'class': 'detour-actions' }, [
			E('button', { 'class': 'btn cbi-button-action', 'click': function() { return add(sel.value, key); } }, isIp ? _('Send this address through') : _('Send this site through')), sel ]));
		items.push(E('div', { 'class': 'detour-actions' }, [
			E('button', { 'class': 'btn', 'click': function() { return add(msg.directPolicy(uci, true), key); } }, _('Never through a tunnel')),
			E('button', { 'class': 'btn cbi-button-negative', 'click': function() { return add(msg.blockPolicy(uci, true), key); } }, _('Block'))
		]));
		items.push(E('div', { 'class': 'cbi-value-description' }, isIp ? _('The address %s is added to the chosen rule.').format(val)
			: _('The site %s (with its subdomains) is added to the chosen rule.').format(val)));
		return E('div', { 'class': 'detour-lines detour-check-acts' }, items);
	},

	// data: { leases (getDHCPLeases), status } - what the Policies page has loaded anyway
	render: function(data) {
		const self = this;
		const leases = (data.leases || {}).dhcp_leases || [];
		const st = data.status || {};
		const target = E('input', { 'class': 'cbi-input-text', 'placeholder': 'youtube.com / https://example.org/page / 203.0.113.5' });
		const dev = E('select', { 'class': 'cbi-input-select' }, [ E('option', { 'value': '' }, _('any device')) ].concat(leases.map(function(l) {
			return E('option', { 'value': l.macaddr }, (l.hostname ? l.hostname + ' ' : '') + '(' + l.ipaddr + ')');
		})));
		const via = E('select', { 'class': 'cbi-input-select' }, [ E('option', { 'value': '' }, _('the one the rules choose')) ].concat(
			(st.exits || []).filter(function(e) { return e.healthy; }).map(function(e) { return E('option', { 'value': e.name }, uci.get('detour', e.name, 'label') || e.name); })));
		const where = E('div', { 'class': 'detour-lines' }), opens = E('div', { 'class': 'detour-lines' }), acts = E('div', { 'class': 'detour-lines' });
		const btn = E('button', { 'class': 'btn cbi-button-action', 'click': function() {
			const q = target.value.trim();
			if (!q) return;
			busy(btn, true);
			where.replaceChildren(E('em', {}, _('Looking up the rules…')));
			opens.replaceChildren(); acts.replaceChildren();
			return callExplain(q, dev.value).then(function(r) {
				if (!r || r.error) { where.replaceChildren(note(r && r.error == 'bad target' ? _('This is not a site name, an address or a link.') : ((r && r.error) || _('No answer from the router')), 'warning')); return; }
				const items = [ E('div', {}, [ E('strong', {}, _('Where it goes:') + ' '), goesText(r) ]) ];
				if (!r.ip) items.push(E('div', { 'class': 'detour-muted' }, r.ips.length ? _('The name gives: %s').format(r.ips.join(', '))
					: (r.goes.to == 'block' ? _('The name gets «no such name» - the blocking does that.') : _('The name is not found.'))));
				if (r.matches.length) {
					items.push(E('div', {}, [ E('strong', {}, _('Why:') + ' '), matchText(r.matches[0]) ]));
					if (r.matches.length > 1) items.push(E('div', {}, [ E('div', {}, _('Also matched, but checked later - so they lose:')),
						E('ul', {}, r.matches.slice(1).map(function(m) { return E('li', {}, matchText(m)); })) ]));
				}
				where.replaceChildren.apply(where, items);
				acts.replaceChildren(E('h4', {}, _('Change it')), self.actions(r));
				// does it open: a few seconds, both ways at once
				if (r.goes.to == 'block') return;
				opens.replaceChildren(E('em', {}, _('Opening it directly and through an exit (up to 15 s)…')));
				const ex = via.value || (r.goes.to == 'exit' && r.goes.exit ? r.goes.exit.name : '');
				return callCheck(q, ex).then(function(c) {
					if (!c || c.error) { opens.replaceChildren(note((c && c.error) || _('No answer from the router'), 'warning')); return; }
					const v = VERDICT[c.verdict] ? VERDICT[c.verdict]() : [ c.verdict, 'notice' ];
					opens.replaceChildren(
						E('div', {}, [ E('strong', {}, _('Directly:') + ' '), (ST[c.direct.st] || ST.fail)(c.direct) ]),
						c.vpn ? E('div', {}, [ E('strong', {}, _('Through «%s»:').format(c.exit_label || c.exit) + ' '), (ST[c.vpn.st] || ST.fail)(c.vpn) ]) : '',
						note(v[0], v[1]));
				});
			}).finally(function() { busy(btn, false); });
		} }, _('Check'));
		target.addEventListener('keydown', function(ev) { if (ev.key == 'Enter') btn.click(); });

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Check a site')),
			E('div', { 'class': 'cbi-section-descr' }, _('Where a site or an address goes by your rules, and why; does it open directly and through the VPN. The router opens it itself, the same way a device would.')),
			E('div', { 'class': 'cbi-section-node detour-node' }, [
				row(_('Site or address'), target),
				row(_('From the device'), dev, _('Rules for devices count only for the chosen one.')),
				row(_('Compare through'), via),
				E('div', { 'class': 'detour-actions' }, [ btn ]),
				E('div', { 'class': 'detour-result detour-lines' }, [ where, opens, acts ])
			])
		]);
	}
});
