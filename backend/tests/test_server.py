"""Regressões de rede, pontuação e persistência; nenhuma conexão externa."""
import io
import json
import os
import ssl
import socket
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch
import server


class Response:
    def __init__(self, status=200, headers=None, body=b''):
        self.status = status
        self.headers = headers or {}
        self.body = io.BytesIO(body)
    def read(self, size=-1):
        return self.body.read(size)
    def close(self):
        pass
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.close()


class NetworkTests(unittest.TestCase):
    def test_redirect_http_error_is_followed(self):
        redirect = urllib.error.HTTPError('https://example.com/', 302, '',
                                         {'Location': '/final'}, io.BytesIO())
        with patch.object(server, '_fetch', side_effect=[redirect, Response()]):
            with patch.object(server, '_hostname_is_public', return_value=(True, None)):
                # urllib surfaces redirects as exceptions; both forms must work.
                with patch.object(server.socket, 'getaddrinfo', return_value=[
                        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.215.14', 443))]):
                    hops, final, detail, failed = server._follow_redirects('https://example.com/')
        self.assertEqual(final, 'https://example.com/final')
        self.assertFalse(failed)
        self.assertEqual(len(hops), 1)

    def test_head_rejection_falls_back_to_get(self):
        rejected = urllib.error.HTTPError('https://example.com/', 405, '', {}, io.BytesIO())
        methods = []
        def fetch(url, method='HEAD'):
            methods.append(method)
            if method == 'HEAD':
                raise rejected
            return Response()
        with patch.object(server, '_fetch', side_effect=fetch):
            server._follow_redirects('https://example.com/')
        self.assertEqual(methods, ['HEAD', 'GET'])

    def test_redirect_to_private_network_is_blocked(self):
        with patch.object(server, '_fetch', return_value=Response(302, {'Location': 'http://127.0.0.1/'})):
            with self.assertRaises(ValueError):
                server._follow_redirects('https://example.com/')

    def test_timeout_is_not_invalid_certificate(self):
        with patch.object(server.socket, 'getaddrinfo', return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.215.14', 443))]):
            with patch.object(server.socket, 'create_connection', side_effect=socket.timeout()):
                result = server._check_tls('example.com')
        self.assertIsNone(result['valid'])

    def test_network_failure_not_reported_as_missing_headers(self):
        with patch.object(server, '_fetch', side_effect=urllib.error.URLError(socket.timeout())):
            headers, error = server._fetch_headers('https://example.com/')
        self.assertIsNone(headers)
        self.assertTrue(error)

    def test_fractional_points_are_preserved(self):
        self.assertEqual(server._make_check('HSTS', 4.5, 5, '')['score'], 4.5)

    def test_optional_intelligence_has_no_guessed_points(self):
        unknown = {'status': 'unknown', 'detail': 'Sem configuração.'}
        with patch.object(server, '_check_safe_browsing', return_value=unknown), \
             patch.object(server, '_check_urlhaus', return_value=unknown), \
             patch.object(server, '_check_virustotal', return_value=unknown):
            score, detail, malicious, count = server._evaluate_threat_intel('https://example.com/', 'example.com')
        self.assertIsNone(score)
        self.assertFalse(malicious)

    def test_get_redirect_does_not_get_graded_as_destination(self):
        response = Response(302, {'Content-Type': 'text/html', 'Location': 'https://other.example/'}, b'<html>Redirect</html>')
        with patch.object(server, '_fetch', return_value=response):
            headers, error = server._fetch_headers('https://example.com/')
        self.assertIsNone(headers)
        self.assertTrue(error)
        with patch.object(server, '_open_public', return_value=Response(302, {'Content-Type': 'text/html'}, b'<html>Redirect</html>')):
            body, error = server._fetch_html('https://example.com/')
        self.assertIsNone(body)
        self.assertTrue(error)

    def test_certificate_failure_is_not_invalid_url(self):
        error = ssl.SSLCertVerificationError(1, 'RAW_TLS_DETAIL')
        error.verify_code = 10
        with patch.object(server, '_fetch', side_effect=error):
            hops, final, detail, failed = server._follow_redirects('https://expired.badssl.com/')
        self.assertTrue(failed)
        self.assertEqual(final, 'https://expired.badssl.com/')
        self.assertNotIn('RAW_TLS_DETAIL', detail)

    def test_certificate_failure_does_not_abort_headers_or_html(self):
        error = ssl.SSLCertVerificationError(1, 'RAW_TLS_DETAIL')
        error.verify_code = 10
        for function, transport in [(server._fetch_headers, '_fetch'), (server._fetch_html, '_open_public')]:
            with self.subTest(function=function.__name__):
                with patch.object(server, transport, side_effect=error):
                    data, message = function('https://expired.badssl.com/')
                self.assertIsNone(data)
                self.assertTrue(message)
                self.assertNotIn('RAW_TLS_DETAIL', message)

    def test_self_signed_is_untrusted_but_missing_issuer_remains_unknown(self):
        for code, expected in [(18, False), (19, False), (20, None), (10, False), (62, False)]:
            error = ssl.SSLCertVerificationError(1, 'RAW_TLS_DETAIL')
            error.verify_code = code
            with self.subTest(verify_code=code):
                with patch.object(server, '_public_addresses', return_value=['93.184.215.14']), \
                     patch.object(server._PinnedHTTP, 'connect', side_effect=error):
                    result = server._check_tls('example.com')
                self.assertIs(result['valid'], expected)
                self.assertNotIn('RAW_TLS_DETAIL', result['error'])

    def test_ipv4_is_reachable_when_dns_lists_ipv6_first(self):
        from unittest.mock import MagicMock
        sock = MagicMock()
        attempted = []
        def connect(address, **kwargs):
            attempted.append(address[0])
            if ':' in address[0]:
                raise socket.timeout()
            return sock
        connection = server._PinnedHTTP('example.com', 80,
                    ['2606:4700:10::ac42:93f3', '2606:4700:10::6814:179a', '104.20.23.154'])
        try:
            with patch.object(server.socket, 'create_connection', side_effect=connect):
                connection.connect()
            self.assertIn('104.20.23.154', attempted)
            self.assertIs(connection.sock, sock)
        finally:
            if connection.deadline_timer is not None:
                connection.deadline_timer.cancel()
            connection.close()

    def test_ipv4_failure_can_fall_back_to_ipv6(self):
        from unittest.mock import MagicMock
        sock = MagicMock()
        attempts = []
        def connect(address, **kwargs):
            attempts.append(address[0])
            if ':' not in address[0]:
                raise socket.timeout()
            return sock
        connection = server._PinnedHTTP('example.com', 80,
                    ['2606:4700:10::ac42:93f3', '104.20.23.154'])
        try:
            with patch.object(server.socket, 'create_connection', side_effect=connect):
                connection.connect()
            self.assertEqual(attempts, ['104.20.23.154', '2606:4700:10::ac42:93f3'])
            self.assertIs(connection.sock, sock)
        finally:
            if connection.deadline_timer is not None:
                connection.deadline_timer.cancel()
            connection.close()


class CacheTests(unittest.TestCase):
    def test_cache_does_not_reuse_result_for_another_page(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(server, 'DB_PATH', Path(directory) / 'reviews.sqlite3'):
                server.init_db()
                with patch.object(server, 'analyze_url', side_effect=lambda url: {'url': url}):
                    server.cached_or_analyze('example.com', 'https://example.com/one')
                    result, hit = server.cached_or_analyze('example.com', 'https://example.com/two')
                self.assertEqual(result['url'], 'https://example.com/two')
                self.assertFalse(hit)


class ContentAndCoverageTests(unittest.TestCase):
    def test_html_analysis_works_without_optional_libraries(self):
        result, error = server._analyze_html(b'<html><form action="/login"><input type="password"></form></html>', 'example.com')
        self.assertIsNone(error)
        self.assertEqual(result['score'], 10)

    def test_protocol_relative_external_password_form_is_detected(self):
        result, error = server._analyze_html(b'<form action="//other.example/collect"><input type="password"></form>', 'example.com')
        self.assertIsNone(error)
        self.assertEqual(result['score'], 10)
        self.assertEqual(result['signals'][0]['code'], 'external_password_form')
        self.assertIn('other.example', result['detail'])

    def test_missing_dns_library_is_unverified(self):
        with patch.object(server, 'DNS_OK', False):
            score, detail, info = server._check_email_security('example.com')
        self.assertIsNone(score)
        self.assertIsNone(info['spf'])

    def test_unknown_connections_have_no_invalid_certificate_penalty(self):
        from contextlib import ExitStack
        doubles = {
            '_public_addresses': ['93.184.215.14'],
            '_dns_info': {'ok': True, 'ips': ['93.184.215.14'], 'ipv4': ['93.184.215.14'], 'ipv6': []},
            '_follow_redirects': ([], 'https://example.com/', 'Tempo limite.', True),
            '_check_tls': {'valid': None, 'error': 'Tempo limite.'},
            '_fetch_headers': (None, 'Tempo limite.'),
            'get_domain_age': (None, None, None, 'Indisponível.'),
            '_evaluate_threat_intel': (None, 'Sem configuração.', False, 0),
            '_fetch_html': (None, 'Tempo limite.'),
            '_check_email_security': (None, 'Indisponível.', {}),
            '_check_infrastructure': (None, 'Informativo.', {}),
        }
        with ExitStack() as stack:
            for name, result in doubles.items():
                stack.enter_context(patch.object(server, name, return_value=result))
            result = server.analyze_url('https://example.com')
        self.assertIn(result['level'], ('medio', 'alto'))
        self.assertIsInstance(result['score'], int)
        self.assertTrue(result['partial'])
        self.assertEqual(result['verifiedChecks'], 1)  # Apenas semelhança de nomes pontua sem rede.
        self.assertLess(result['coverage'], 70)
        self.assertFalse(result['capsApplied'])

    def test_positive_technical_signals_do_not_confirm_unchecked_reputation(self):
        from contextlib import ExitStack
        headers = {'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
                   'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
                   'x-frame-options': 'DENY', 'x-content-type-options': 'nosniff',
                   'referrer-policy': 'no-referrer', 'permissions-policy': 'geolocation=()'}
        doubles = {
            '_public_addresses': ['93.184.215.14'],
            '_dns_info': {'ok': True, 'ips': ['93.184.215.14'], 'ipv4': ['93.184.215.14'], 'ipv6': []},
            '_follow_redirects': ([], 'https://example.com/', 'HTTP 200.', False),
            '_check_tls': {'valid': True, 'version': 'TLSv1.3', 'issuer': 'CA'},
            '_fetch_headers': (headers, None),
            'get_domain_age': (5000, '2010-01-01', 'rdap', None),
            '_evaluate_threat_intel': (None, 'Sem configuração.', False, 0),
            '_fetch_html': (b'<html>Example page</html>', None),
            '_check_email_security': (None, 'Opcional.', {}),
        }
        with ExitStack() as stack:
            for name, result in doubles.items():
                stack.enter_context(patch.object(server, name, return_value=result))
            result = server.analyze_url('https://example.com')
        self.assertIn(result['level'], ('medio', 'alto'))
        self.assertIsInstance(result['score'], int)
        self.assertTrue(result['partial'])
        self.assertGreater(result['measuredScore'], 80)
        self.assertFalse(result['reputationVerified'])

    def test_private_and_non_web_destinations_are_blocked(self):
        for url in ['http://127.0.0.1', 'http://[::1]', 'http://169.254.169.254',
                    'file:///etc/passwd', 'http://example.com:22', 'https://user:pass@example.com']:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    server.analyze_url(url)

    def test_fetch_connects_to_validated_ip_not_hostname(self):
        from unittest.mock import MagicMock
        sock = MagicMock()
        sock.makefile.return_value = io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.215.14', 80))]
        with patch.object(server.socket, 'getaddrinfo', return_value=addresses) as dns, \
             patch.object(server.socket, 'create_connection', return_value=sock) as connect:
            with server._fetch('http://example.com/', 'GET') as response:
                self.assertEqual(response.read(), b'OK')
        self.assertEqual(connect.call_args.args[0], ('93.184.215.14', 80))
        self.assertEqual(dns.call_count, 1)


if __name__ == '__main__':
    unittest.main()
