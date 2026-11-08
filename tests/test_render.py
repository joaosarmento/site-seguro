"""Simula a chegada de requisições pelo proxy do Render, sem acessar a internet."""
import http.client
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        cls.port = sock.getsockname()[1]
        sock.close()
        env = os.environ.copy()
        env.pop('SITE_SEGURO_ORIGIN', None)
        env.update(PORT=str(cls.port), SITE_SEGURO_DB=str(Path(cls.temp.name) / 'reviews.sqlite3'))
        cls.proc = subprocess.Popen([sys.executable, str(ROOT / 'backend/app.py')], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=.1):
                    return
            except OSError:
                if cls.proc.poll() is not None:
                    raise RuntimeError('Servidor terminou durante a inicialização')
                time.sleep(.05)
        raise RuntimeError('Servidor não iniciou')

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)
        cls.temp.cleanup()

    def request(self, method, path, host='site-seguro.onrender.com', origin=None, body=None):
        headers = {'Host': host}
        if origin is not None:
            headers['Origin'] = origin
        if body is not None:
            headers['Content-Type'] = 'application/json'
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=4)
        try:
            conn.request(method, path, body=body, headers=headers)
            res = conn.getresponse()
            return res.status, res.read().decode('utf-8')
        finally:
            conn.close()

    def test_public_host_serves_site_and_assets(self):
        status, html = self.request('GET', '/')
        self.assertEqual(status, 200)
        self.assertIn('Verifique um endereço', html)
        self.assertEqual(self.request('GET', '/analysis.js')[0], 200)

    def test_api_accepts_same_origin_and_rejects_other_origin(self):
        self.assertEqual(self.request('POST', '/api/analyze', origin='https://site-seguro.onrender.com', body='{}')[0], 400)
        self.assertEqual(self.request('POST', '/api/analyze', origin='https://attacker.example', body='{}')[0], 403)

    def test_unapproved_host_is_rejected(self):
        self.assertEqual(self.request('GET', '/', host='attacker.example')[0], 403)

    def test_custom_origin_configuration_takes_precedence(self):
        env = os.environ.copy()
        env.update(PORT='12345', SITE_SEGURO_ORIGIN='https://outro.example')
        code = """
import os, sys
sys.path.insert(0, sys.argv[1])
import app
app.engine.make_ssl_context = lambda: None
app.engine.init_db = lambda: None
class FakeServer:
    def __init__(self, *args): pass
    def serve_forever(self): print('ORIGEM=' + os.environ['SITE_SEGURO_ORIGIN'])
    def server_close(self): pass
app.ThreadingHTTPServer = FakeServer
sys.argv = ['app.py']
app.main()
"""
        output = subprocess.check_output([sys.executable, '-c', code, str(ROOT / 'backend')], env=env, text=True)
        self.assertIn('ORIGEM=https://outro.example', output)

if __name__ == '__main__':
    unittest.main()
