"""Lab stub of the Cloudflare WARP client API (no real registration).
POST /v0a2158/reg       -> registration (checks the headers/body the real API expects)
DELETE /v0a2158/reg/<id> -> deregistration (needs Authorization: Bearer <token>)
GET /setpeer?key=<server pubkey>&ep=<ip>&v4=<client v4> -> what the next registration returns
GET /log                -> request log
Run: python tests/stub/warp_stub.py 8767
"""
import json
import secrets
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

LOG = 'warp_stub.log'
PEER = {'key': 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 'ep': '162.159.192.1', 'v4': '172.16.0.2'}
REGS = {}


def log(rec):
    rec['t'] = int(time.time())
    with open(LOG, 'a', encoding='utf-8') as f:
        f.write(json.dumps(rec) + '\n')


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        b = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == '/setpeer':
            q = parse_qs(u.query)
            for k in ('key', 'ep', 'v4'):
                if k in q:
                    PEER[k] = q[k][0]
            self._send(200, PEER)
        elif u.path == '/log':
            try:
                data = open(LOG, encoding='utf-8').read().encode()
            except OSError:
                data = b''
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self._send(404, {})

    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(n)
        ua = self.headers.get('User-Agent', '')
        cv = self.headers.get('CF-Client-Version', '')
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        ok = (self.path == '/v0a2158/reg' and ua == 'okhttp/3.12.1' and cv == 'a-6.10-2158'
              and isinstance(body, dict) and body.get('key') and body.get('tos'))
        log({'op': 'reg', 'ok': bool(ok), 'ua': ua, 'cv': cv, 'key': (body or {}).get('key')})
        if not ok:
            self._send(400, {'success': False})
            return
        rid, tok = 't.' + secrets.token_hex(8), secrets.token_hex(16)
        REGS[rid] = tok
        self._send(200, {
            'id': rid, 'token': tok, 'account': {'warp_plus': False},
            'config': {
                'client_id': 'AAAA',
                'peers': [{'public_key': PEER['key'],
                           'endpoint': {'v4': PEER['ep'] + ':0', 'v6': '[2606:4700:d0::a29f:c001]:0',
                                        'host': 'engage.cloudflareclient.com:2408'}}],
                'interface': {'addresses': {'v4': PEER['v4'], 'v6': '2606:4700:110:8a1a::2'}},
            }})

    def do_DELETE(self):
        rid = self.path.rsplit('/', 1)[-1]
        auth = self.headers.get('Authorization', '')
        ok = rid in REGS and auth == 'Bearer ' + REGS[rid]
        log({'op': 'del', 'ok': ok, 'id': rid})
        if ok:
            del REGS[rid]
        self._send(200 if ok else 401, {'success': ok})


if __name__ == '__main__':
    HTTPServer(('0.0.0.0', int(sys.argv[1]) if len(sys.argv) > 1 else 8767), H).serve_forever()
