"""Lab stub of the Telegram Bot API sendMessage (no real sends).
POST /bot<token>/sendMessage -> {"ok": true}; every request is appended to tg_stub.log as JSON.
GET /log -> the log; GET /fail?n=N -> the next N requests answer 502 (simulate a blocked API).
Run: python tests/stub/tg_stub.py 8766
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

LOG = 'tg_stub.log'
fail_next = 0


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
        global fail_next
        u = urlparse(self.path)
        if u.path == '/log':
            try:
                data = open(LOG, encoding='utf-8').read()
            except OSError:
                data = ''
            b = data.encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        elif u.path == '/fail':
            fail_next = int(parse_qs(u.query).get('n', ['1'])[0])
            self._send(200, {'fail_next': fail_next})
        else:
            self._send(404, {'ok': False})

    def do_POST(self):
        global fail_next
        n = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n).decode('utf-8', 'replace')
        parts = self.path.split('/')
        ok_path = len(parts) == 3 and parts[1].startswith('bot') and parts[2] == 'sendMessage'
        rec = {'t': int(time.time()), 'from': self.client_address[0], 'path_ok': ok_path,
               'token_len': len(parts[1]) - 3 if ok_path else 0, 'failed': fail_next > 0}
        try:
            rec['msg'] = json.loads(body)
        except ValueError:
            rec['raw'] = body[:200]
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        if fail_next > 0:
            fail_next -= 1
            self._send(502, {'ok': False})
            return
        self._send(200 if ok_path else 404, {'ok': ok_path, 'result': {'message_id': 1}})


if __name__ == '__main__':
    HTTPServer(('0.0.0.0', int(sys.argv[1]) if len(sys.argv) > 1 else 8766), H).serve_forever()
