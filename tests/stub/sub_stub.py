"""Lab stub of a subscription provider.
POST /set/links  body: share links, one per line   POST /set/json  body: a sing-box config
GET  /sub/<token>/b64   -> base64 of the links        GET /sub/<token>/json -> the sing-box config
GET  /log               -> requests (path, user-agent, x-hwid)
POST /set/userinfo  body: a subscription-userinfo value (empty = none); the answers then carry it and
                    profile-update-interval: 12
Run: python tests/stub/sub_stub.py 8768
"""
import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

DATA = {'links': b'', 'json': b'{}', 'userinfo': b''}
LOG = []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='text/plain'):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        if code == 200 and DATA['userinfo'] and self.path.startswith('/sub/'):
            self.send_header('subscription-userinfo', DATA['userinfo'].decode())
            self.send_header('profile-update-interval', '12')
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n)
        if self.path == '/set/links':
            DATA['links'] = body
        elif self.path == '/set/json':
            DATA['json'] = body
        elif self.path == '/set/userinfo':
            DATA['userinfo'] = body.strip()
        self._send(200, b'ok')

    def do_GET(self):
        if self.path == '/log':
            self._send(200, json.dumps(LOG).encode(), 'application/json')
            return
        LOG.append({'path': self.path, 'ua': self.headers.get('User-Agent'), 'hwid': self.headers.get('x-hwid')})
        if self.path.endswith('/b64'):
            self._send(200, base64.b64encode(DATA['links']))
        elif self.path.endswith('/json'):
            self._send(200, DATA['json'], 'application/json')
        else:
            self._send(404, b'')


if __name__ == '__main__':
    HTTPServer(('0.0.0.0', int(sys.argv[1]) if len(sys.argv) > 1 else 8768), H).serve_forever()
