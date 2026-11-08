"""Teste HTTP real em loopback com SQLite temporário e sem fontes externas."""
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer
import server


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.db_patch = patch.object(server, 'DB_PATH', Path(cls.directory.name) / 'test.sqlite3')
        cls.db_patch.start()
        server.init_db()
        cls.app = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        cls.thread = threading.Thread(target=cls.app.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.app.shutdown()
        cls.app.server_close()
        cls.thread.join()
        cls.db_patch.stop()
        cls.directory.cleanup()

    def request(self, method, path, data=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.app.server_port, timeout=3)
        body = json.dumps(data).encode() if data is not None else None
        request_headers = {'Content-Type': 'application/json'}
        request_headers.update(headers or {})
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        status, raw = response.status, response.read()
        connection.close()
        return status, json.loads(raw) if raw and raw.startswith(b'{') else raw

    def test_static_assets_and_unexposed_files(self):
        for path in ('/', '/analysis.js', '/style.css', '/dark.css'):
            self.assertEqual(self.request('GET', path)[0], 200)
        for path in ('/server.py', '/data/reviews.sqlite3', '/%2e%2e/server.py'):
            self.assertEqual(self.request('GET', path)[0], 404)
        self.assertEqual(self.request('HEAD', '/server.py')[0], 404)

    def test_html_requests_current_version_of_javascript(self):
        from html.parser import HTMLParser
        from urllib.parse import urlparse, parse_qs
        class Scripts(HTMLParser):
            def __init__(self):
                super().__init__()
                self.urls = []
            def handle_starttag(self, tag, attrs):
                if tag == 'script':
                    self.urls.append(dict(attrs).get('src', ''))
        status, body = self.request('GET', '/')
        parser = Scripts()
        parser.feed(body.decode())
        self.assertEqual(len(parser.urls), 1)
        asset = parser.urls[0]
        self.assertEqual(parse_qs(urlparse(asset).query).get('v'), [server.VERSION])
        self.assertEqual(self.request('GET', '/' + asset)[0], 200)

    def test_stale_asset_validator_cannot_return_old_code(self):
        # An old browser cache may send a future If-Modified-Since value.
        for path in ('/', '/analysis.js', '/analysis.js?v=' + server.VERSION):
            status, body = self.request('GET', path, headers={
                'If-Modified-Since': 'Wed, 31 Dec 2098 23:59:59 GMT'})
            self.assertEqual(status, 200)
            self.assertTrue(body)

    def test_block_foreign_origin_and_rebinding_host(self):
        status, _ = self.request('POST', '/api/analyze', {'url': 'https://example.com'}, {'Origin': 'https://other.example'})
        self.assertEqual(status, 403)
        status, _ = self.request('GET', '/api/reviews', headers={'Host': 'attacker.example:%d' % self.app.server_port})
        self.assertEqual(status, 403)

    def test_analyze_uses_post_json_and_validates_target(self):
        self.assertEqual(self.request('GET', '/api/analyze?url=https://example.com')[0], 405)
        for data in ([], {}, {'url': 'http://127.0.0.1'}, {'url': 'https://example.com:22'}):
            self.assertEqual(self.request('POST', '/api/analyze', data)[0], 400)

    def test_certificate_failure_returns_analysis_instead_of_http_error(self):
        import ssl
        import socket
        from contextlib import ExitStack
        for code in (10, 62, 18, 19):
            error = ssl.SSLCertVerificationError(1, 'RAW_TLS_DETAIL')
            error.verify_code = code
            addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.215.14', 443))]
            with self.subTest(verify_code=code), ExitStack() as stack:
                server.ANALYSIS_CACHE.clear()
                stack.enter_context(patch.object(server, '_resolve', return_value=addresses))
                stack.enter_context(patch.object(server._PinnedHTTP, 'connect', side_effect=error))
                stack.enter_context(patch.object(server, 'get_domain_age', return_value=(5000, '2010-01-01', 'rdap', None)))
                stack.enter_context(patch.object(server, '_evaluate_threat_intel', return_value=(None, 'Sem configuração.', False, 0)))
                stack.enter_context(patch.object(server, '_check_email_security', return_value=(None, 'Opcional.', {})))
                status, result = self.request('POST', '/api/analyze', {'url': 'https://expired.badssl.com/'})
            self.assertEqual(status, 200)
            self.assertEqual(result['level'], 'baixo')
            self.assertLessEqual(result['score'], 40)
            self.assertTrue(any(cap['name'] == 'Certificado inválido' for cap in result['capsApplied']))
            self.assertNotIn('RAW_TLS_DETAIL', json.dumps(result))

    def test_review_persistence_idempotency_and_rate_limit(self):
        payload = {'id': 'ec14d575-e37e-46a3-93b4-3d3d6d2c9001', 'rating': 5,
                   'useful': 'yes', 'name': 'Teste', 'comment': '<script>window.BAD=true</script>', 'consent': True}
        self.assertEqual(self.request('POST', '/api/reviews', payload)[0], 201)
        self.assertEqual(self.request('POST', '/api/reviews', payload)[0], 200)
        status, result = self.request('GET', '/api/reviews')
        self.assertEqual(result['stats']['total'], 1)
        self.assertEqual(result['reviews'][0]['comment'], '<script>window.BAD=true</script>')
        # Reopen database: persistence must not depend on handler state.
        with server.connect() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM reviews').fetchone()[0], 1)
        changed = dict(payload, comment='Outro texto')
        self.assertEqual(self.request('POST', '/api/reviews', changed)[0], 409)
        another = dict(payload, id='ec14d575-e37e-46a3-93b4-3d3d6d2c9002')
        self.assertEqual(self.request('POST', '/api/reviews', another)[0], 429)

    def test_invalid_review_is_rejected(self):
        for data in ({}, [], {'rating': True, 'consent': True},
                     {'rating': 5, 'useful': 'yes', 'name': '', 'comment': '', 'consent': False}):
            self.assertEqual(self.request('POST', '/api/reviews', data)[0], 400)


class DeadlineTests(unittest.TestCase):
    def test_slow_trickle_response_is_interrupted(self):
        import socket
        import time
        from http.server import BaseHTTPRequestHandler
        class SlowHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '100')
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b'x')
                        self.wfile.flush()
                        time.sleep(0.01)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        app = ThreadingHTTPServer(('127.0.0.1', 0), SlowHandler)
        thread = threading.Thread(target=app.serve_forever, daemon=True)
        thread.start()
        connect = socket.create_connection
        real_dns = socket.getaddrinfo
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.215.14', 80))]
        def local_socket(address, *args, **kwargs):
            return connect(('127.0.0.1', app.server_port), *args, **kwargs)
        try:
            with patch.object(server.socket, 'getaddrinfo', side_effect=lambda host, port, *a, **kw: public if host == 'example.com' else real_dns(host, port, *a, **kw)), \
                 patch.object(server.socket, 'create_connection', side_effect=local_socket), \
                 patch.object(server, 'REQUEST_SECONDS', 0.05, create=True):
                started = time.monotonic()
                with self.assertRaises((TimeoutError, socket.timeout, OSError)):
                    with server._fetch('http://example.com/', 'GET') as response:
                        response.read(100)
                self.assertLess(time.monotonic() - started, 0.8)
        finally:
            app.shutdown()
            app.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
