// Encrypted DNS providers the router can use without typing addresses (main.dns_provider + main.dns_proto);
// the addresses are AdGuard's list of known DNS providers (adguard-dns.io/kb/general/dns-providers), the protocols
// only those the provider has and dnsproxy speaks: DNS-over-HTTPS (https://), DNS-over-TLS (tls://),
// DNS-over-QUIC (quic://), DNSCrypt (sdns:// stamps). IPv4 servers only (a router often has no IPv6). Each one's
// plain addresses resolve the names of its servers (dnsproxy's bootstrap) - the provider itself, not a third one.
// A provider here is its unfiltered or general-purpose variant: the router's DNS answers the whole network.
'use strict';

export const PROTOS = [ 'https', 'tls', 'quic', 'dnscrypt' ];

export const PROVIDERS = [
	{ id: 'adguard', name: 'AdGuard DNS', note: 'unfiltered',
		bootstrap: [ '94.140.14.140:53', '94.140.14.141:53' ],
		https: [ 'https://unfiltered.adguard-dns.com/dns-query' ],
		tls: [ 'tls://unfiltered.adguard-dns.com' ],
		quic: [ 'quic://unfiltered.adguard-dns.com' ],
		dnscrypt: [ 'sdns://AQIAAAAAAAAAEjk0LjE0MC4xNC4xNDA6NTQ0MyC16ETWuDo-PhJo62gfvqcN48X6aNvWiBQdvy7AZrLa-iUyLmRuc2NyeXB0LnVuZmlsdGVyZWQubnMxLmFkZ3VhcmQuY29t' ] },
	{ id: 'cloudflare', name: 'Cloudflare', note: 'standard',
		bootstrap: [ '1.1.1.1:53', '1.0.0.1:53' ],
		https: [ 'https://cloudflare-dns.com/dns-query' ],
		tls: [ 'tls://one.one.one.one' ] },
	{ id: 'google', name: 'Google Public DNS', note: 'standard',
		bootstrap: [ '8.8.8.8:53', '8.8.4.4:53' ],
		https: [ 'https://dns.google/dns-query' ],
		tls: [ 'tls://dns.google' ] },
	{ id: 'quad9', name: 'Quad9', note: 'malware',
		bootstrap: [ '9.9.9.9:53', '149.112.112.112:53' ],
		https: [ 'https://dns.quad9.net/dns-query' ],
		tls: [ 'tls://dns.quad9.net' ],
		dnscrypt: [ 'sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0' ] },
	{ id: 'opendns', name: 'Cisco OpenDNS', note: 'malware',
		bootstrap: [ '208.67.222.222:53', '208.67.220.220:53' ],
		https: [ 'https://doh.opendns.com/dns-query' ],
		tls: [ 'tls://dns.opendns.com' ],
		dnscrypt: [ 'sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ' ] },
];

function find(id) {
	for (let p in PROVIDERS) if (p.id == id) return p;
	return null;
}

// what LuCI offers: the providers, the protocols each one has (in PROTOS order) and their addresses
export function list() {
	return map(PROVIDERS, (p) => ({ id: p.id, name: p.name, note: p.note,
		protos: filter(PROTOS, (k) => length(p[k] ?? [])),
		addrs: (function() { const a = {}; for (let k in PROTOS) if (length(p[k] ?? [])) a[k] = p[k]; return a; })() }));
};

// provider + protocol -> { upstreams, bootstrap, proto } | { error }; no protocol or one it lacks: its first
export function resolve(id, proto) {
	const p = find(id);
	if (!p) return { error: sprintf('unknown DNS provider "%s"', id) };
	let k = proto;
	if (!k || !length(p[k] ?? [])) {
		const first = filter(PROTOS, (x) => length(p[x] ?? []))[0];
		if (k) return { error: sprintf('DNS provider %s has no %s, %s is used', p.name, k, first), upstreams: p[first], bootstrap: p.bootstrap, proto: first };
		k = first;
	}
	return { upstreams: p[k], bootstrap: p.bootstrap, proto: k };
};
