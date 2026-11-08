"""Site Seguro 0.10.1 — protótipo acadêmico local, sem dependências obrigatórias.
Execute python3 server.py; abra http://127.0.0.1:8765.
POST /api/analyze: {"url": "https://example.com/"}.
Pontuação do link = qualidade técnica observada, limitada pelas evidências de risco.
Fontes indisponíveis não pontuam. Veja LEIA-ME.md para limites e configuração.
"""
import argparse
import contextvars
import queue
import base64
import gzip
import http.client
import io
import sys
from html.parser import HTMLParser
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# ---------- dependências opcionais (degradam graciosamente) ----------
try:
    import dns.resolver  # noqa: F401
    DNS_OK = True
except ImportError:
    DNS_OK = False



from risk_model import registrable_domain, brand_signal, age_signal, decide_risk, consolidate_score

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get('SITE_SEGURO_DB', str(ROOT / 'data' / 'reviews.sqlite3')))
LOCK = threading.Lock()

FETCH_TIMEOUT = 10
REQUEST_SECONDS = 10
ANALYSIS_SECONDS = 65
_ANALYSIS_DEADLINE = contextvars.ContextVar('analysis_deadline', default=None)
_TLS_OBSERVATIONS = contextvars.ContextVar('tls_observations', default=None)
_TLS_SUCCESSES = contextvars.ContextVar('tls_successes', default=None)
_THREAT_RESULTS = contextvars.ContextVar('threat_results', default=None)
INVALID_CERT_CODES = frozenset((9, 10, 18, 19, 62, 64))
DNS_SLOTS = threading.BoundedSemaphore(8)
MAX_REDIRECTS = 5
MAX_BYTES_READ = 64 * 1024
VERSION = '0.10.1'
WEIGHTS = {'dns': 0, 'redirects': 10, 'tls': 55, 'hsts': 0, 'headers': 10,
           'url': 0, 'age': 0, 'reputation': 0, 'html': 20, 'email': 0,
           'typosquatting': 5, 'infrastructure': 0}
USER_AGENT = 'SiteSeguroBot/' + VERSION + ' (+academico; nao indexar)'
ANALYSIS_CACHE = {}
ANALYSIS_SLOTS = threading.BoundedSemaphore(3)

BLOCKED_HOSTNAMES = {
    'localhost', 'localhost.localdomain', 'ip6-localhost', 'metadata.google.internal',
}

RDAP_BOOTSTRAP = 'https://rdap.org/domain/'
RDAP_TIMEOUT = 10

SHORTENERS = {
    'bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'cutt.ly', 'rb.gy',
    'ow.ly', 'buff.ly', 'goo.gl', 't.ly', 'shorte.st', 'rebrand.ly',
}

POPULAR_NAMES = [
    'google', 'facebook', 'whatsapp', 'instagram', 'youtube', 'netflix',
    'amazon', 'mercadolivre', 'americanas', 'magazineluiza', 'nubank',
    'itau', 'bradesco', 'santander', 'caixa', 'sicoob', 'picpay', 'inter',
    'c6bank', 'gov', 'serpro', 'receita', 'inss', 'apple', 'microsoft',
    'paypal', 'steam', 'twitch', 'twitter', 'tiktok', 'binance', 'coinbase',
]


def _remaining(limit=REQUEST_SECONDS):
    deadline = _ANALYSIS_DEADLINE.get()
    if deadline is None:
        return limit
    left = deadline - time.monotonic()
    if left <= 0:
        raise socket.timeout('Prazo total da análise atingido.')
    return min(limit, left)


def _resolve(hostname, port):
    # System getaddrinfo has no portable cancellation. Bound waiting and the
    # number of daemon resolver workers, so DNS cannot retain an analysis slot.
    timeout = _remaining(REQUEST_SECONDS)
    if not DNS_SLOTS.acquire(blocking=False):
        raise socket.timeout('DNS ocupado.')
    result = queue.Queue(maxsize=1)
    def resolve():
        try:
            result.put((socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM), None))
        except Exception as exc:
            result.put((None, exc))
        finally:
            DNS_SLOTS.release()
    threading.Thread(target=resolve, daemon=True).start()
    try:
        addresses, error = result.get(timeout=timeout)
    except queue.Empty:
        raise socket.timeout('Tempo limite do DNS.') from None
    if error:
        raise error
    return addresses


def _shutdown_socket(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    finally:
        sock.close()


class _TimedResponse(http.client.HTTPResponse):
    def read(self, amt=None):
        deadline = getattr(self, '_request_deadline', None)
        if deadline is not None and time.monotonic() >= deadline:
            raise socket.timeout('Tempo limite da resposta.')
        data = super().read(amt)
        if deadline is not None and time.monotonic() >= deadline:
            raise socket.timeout('Tempo limite da resposta.')
        return data

    def close(self):
        timer = getattr(self, '_deadline_timer', None)
        if timer is not None:
            timer.cancel()
        super().close()


def make_ssl_context():
    """Default trust + system CA on macOS; respect an explicit SSL_CERT_FILE."""
    context = ssl.create_default_context()
    if not os.environ.get('SSL_CERT_FILE'):
        if sys.platform == 'darwin' and Path('/etc/ssl/cert.pem').is_file():
            context.load_verify_locations(cafile='/etc/ssl/cert.pem')
        try:
            import certifi
        except ImportError:
            pass
        else:
            context.load_verify_locations(cafile=certifi.where())
    context.set_alpn_protocols(['http/1.1'])
    return context


def network_error(exc):
    """Explain errors without leaking URL tokens, credentials or raw exceptions."""
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, ssl.SSLCertVerificationError):
        if getattr(reason, 'verify_code', None) in (18, 19):
            return 'A conexão não é confiável: certificado autoassinado ou raiz não confiável.'
        if getattr(reason, 'verify_code', None) in (2, 20, 21):
            return ('Não foi possível validar a cadeia do certificado. Pode faltar uma CA '
                    'no Python ou na rede. Consulte LEIA-ME.md e execute python3 server.py --diagnostico.')
        return 'O certificado não passou na validação TLS (nome, validade ou cadeia).'
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return 'Tempo limite de conexão. Tente novamente ou confira a conexão/VPN.'
    if isinstance(reason, socket.gaierror):
        return 'Não foi possível resolver o domínio pelo DNS.'
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (401, 403):
            return 'A fonte exige autenticação ou recusou a consulta (HTTP %d).' % exc.code
        if exc.code == 429:
            return 'Limite de consultas da fonte atingido (HTTP 429).'
        return 'A fonte respondeu HTTP %d.' % exc.code
    return 'Conexão indisponível. Confira a rede, o proxy e a disponibilidade da fonte.'


def _record_tls_failure(hostname, port, error):
    observations = _TLS_OBSERVATIONS.get()
    if observations is not None and getattr(error, 'verify_code', None) in INVALID_CERT_CODES:
        observations[(hostname, port)] = {'valid': False, 'error': network_error(error),
                                          'observedDuring': 'conexão HTTP/TLS'}


def _observed_tls_failure(hostname, port):
    return (_TLS_OBSERVATIONS.get() or {}).get((hostname, port))


def _tls_details(ssock):
    cert = ssock.getpeercert() or {}
    not_after = cert.get('notAfter', '')
    days_left = (ssl.cert_time_to_seconds(not_after) - time.time()) / 86400 if not_after else None
    issuer = dict(x[0] for x in cert.get('issuer', []))
    return {'valid': True, 'version': ssock.version(), 'alpn': ssock.selected_alpn_protocol(),
            'cipher': (ssock.cipher() or ('?',))[0], 'daysLeft': days_left,
            'notAfter': not_after, 'issuer': issuer.get('organizationName') or issuer.get('commonName') or '?'}


class DestinationError(ValueError):
    """Invalid input or unsafe destination; separate from TLS verification errors."""


def normalize_url(value):
    if not isinstance(value, str) or not value.strip():
        raise DestinationError('Informe um endereço para análise.')
    value = value.strip()
    if len(value) > 2048 or re.search(r'[\s\\\x00-\x1f\x7f]', value):
        raise DestinationError('Endereço inválido: remova espaços e caracteres de controle.')
    if not re.match(r'^[a-z][a-z0-9+.-]*://', value, re.I):
        value = 'https://' + value
    try:
        parsed = urlparse(value)
        host = (parsed.hostname or '').encode('idna').decode('ascii').lower().rstrip('.')
        port = parsed.port
    except (ValueError, UnicodeError):
        raise DestinationError('Domínio ou porta inválidos.') from None
    if parsed.scheme not in ('http', 'https') or not host:
        raise DestinationError('Use um endereço HTTP ou HTTPS válido.')
    if port is not None and port not in (80, 443):
        raise DestinationError('Use as portas web padrão 80 ou 443.')
    if parsed.username is not None or parsed.password is not None:
        raise DestinationError('Remova o usuário e a senha embutidos no endereço.')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                     for label in host.split('.')):
            raise DestinationError('Nome de domínio inválido.')
    if host in BLOCKED_HOSTNAMES or host.endswith(('.localhost', '.local', '.internal')):
        raise DestinationError('Endereços de rede interna não podem ser analisados.')
    authority = '[' + host + ']' if ':' in host else host
    if port is not None:
        authority += ':' + str(port)
    path = urllib.parse.quote(parsed.path or '/', safe="/%:@!$&'()*+,;=-._~")
    query = urllib.parse.quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
    return urllib.parse.urlunparse((parsed.scheme, authority, path, parsed.params, query, ''))


def _public_addresses(hostname, port):
    infos = _resolve(hostname, port)
    ips = list(dict.fromkeys(info[4][0] for info in infos))
    if not ips:
        raise socket.gaierror('O DNS não retornou endereços.')
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        mapped = getattr(addr, 'ipv4_mapped', None)
        if (not addr.is_global or addr.is_multicast
                or (mapped and not mapped.is_global)
                or getattr(addr, 'sixtofour', None) or getattr(addr, 'teredo', None)):
            raise DestinationError('O domínio aponta para uma rede interna ou um IP não público.')
    return ips


class _PinnedHTTP(http.client.HTTPConnection):
    """Use only validated IPs; try both address families within one deadline."""
    response_class = _TimedResponse

    def __init__(self, host, port, ips, timeout=FETCH_TIMEOUT, context=None):
        super().__init__(host, port, timeout=timeout)
        self.ips = ips
        self.context = context
        self.deadline = time.monotonic() + _remaining(min(timeout, REQUEST_SECONDS))
        self.deadline_timer = None

    def connect(self):
        ipv4 = [ip for ip in self.ips if ':' not in ip]
        ipv6 = [ip for ip in self.ips if ':' in ip]
        candidates = [ipv4[0], ipv6[0]] if ipv4 and ipv6 else self.ips[:2]
        last = None
        for index, ip in enumerate(candidates):
            sock = None
            try:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout('Tempo limite da conexão.')
                attempt_deadline = time.monotonic() + remaining / (len(candidates) - index)
                sock = socket.create_connection((ip, self.port), timeout=remaining / (len(candidates) - index))
                if self.context:
                    sock.settimeout(max(0.001, attempt_deadline - time.monotonic()))
                    sock = self.context.wrap_socket(sock, server_hostname=self.host)
                    successes = _TLS_SUCCESSES.get()
                    if successes is not None:
                        successes[(self.host, self.port)] = _tls_details(sock)
                sock.settimeout(max(0.001, self.deadline - time.monotonic()))
                self.sock = sock
                self.deadline_timer = threading.Timer(max(0, self.deadline - time.monotonic()), _shutdown_socket, args=(sock,))
                self.deadline_timer.daemon = True
                self.deadline_timer.start()
                return
            except ssl.SSLCertVerificationError as exc:
                _record_tls_failure(self.host, self.port, exc)
                # Preserve an observed certificate failure instead of masking it
                # with a timeout on another address.
                if sock is not None:
                    sock.close()
                raise
            except OSError as exc:
                if sock is not None:
                    sock.close()
                last = exc
        raise last or OSError('Conexão indisponível.')


def _open_public(url, method='GET', headers=None, data=None, timeout=FETCH_TIMEOUT):
    url = normalize_url(url)
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    ips = _public_addresses(parsed.hostname, port)
    connection = _PinnedHTTP(parsed.hostname, port, ips, timeout,
                             make_ssl_context() if parsed.scheme == 'https' else None)
    target = urllib.parse.urlunparse(('', '', parsed.path, parsed.params, parsed.query, ''))
    request_headers = {'User-Agent': USER_AGENT, 'Accept-Encoding': 'identity',
                       'Connection': 'close'}
    request_headers.update(headers or {})
    try:
        connection.request(method, target, body=data, headers=request_headers)
        response = connection.getresponse()
        response._request_deadline = connection.deadline
        response._deadline_timer = connection.deadline_timer
        return response
    except Exception:
        if connection.deadline_timer is not None:
            connection.deadline_timer.cancel()
        connection.close()
        raise


def _api_json(url, data=None, headers=None):
    # RDAP may redirect to the registry. Validate and pin every hop.
    method = 'POST' if data is not None else 'GET'
    for hop in range(MAX_REDIRECTS + 1):
        with _open_public(url, method, headers, data, timeout=RDAP_TIMEOUT) as response:
            if response.status in (301, 302, 303, 307, 308):
                location = response.headers.get('Location')
                if not location or hop == MAX_REDIRECTS:
                    raise ValueError('Redirecionamento inválido da fonte.')
                destination = urllib.parse.urljoin(url, location)
                if urlparse(destination).scheme != 'https':
                    raise ValueError('A fonte redirecionou para conexão sem HTTPS.')
                # Never forward API keys or POST payloads across origins.
                if data is not None or headers and any(k.lower() in ('x-apikey', 'auth-key') for k in headers):
                    raise ValueError('Redirecionamento autenticado não permitido.')
                url = destination
                continue
            if response.status >= 400:
                raise urllib.error.HTTPError(url, response.status, '', response.headers, None)
            raw = response.read(MAX_BYTES_READ + 1)
            if len(raw) > MAX_BYTES_READ:
                raise ValueError('Resposta da fonte acima do limite.')
            return json.loads(raw.decode('utf-8'))
    raise ValueError('Muitos redirecionamentos.')


# =====================================================================
# Banco de dados
# =====================================================================

def connect():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as con:
        con.execute(
            'CREATE TABLE IF NOT EXISTS reviews ('
            'id TEXT PRIMARY KEY, name TEXT NOT NULL, '
            'rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5), '
            'useful TEXT NOT NULL CHECK(useful IN (\'yes\',\'partly\',\'no\')), '
            'comment TEXT NOT NULL, created_at TEXT NOT NULL, '
            'ip_hash TEXT NOT NULL, created_ts REAL NOT NULL)'
        )
        con.execute('CREATE INDEX IF NOT EXISTS reviews_created ON reviews(created_ts DESC)')
        con.execute('CREATE INDEX IF NOT EXISTS reviews_ip_time ON reviews(ip_hash,created_ts)')
        con.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        con.execute('INSERT OR IGNORE INTO settings VALUES (?,?)', ('salt', secrets.token_hex(32)))
        con.execute('DROP TABLE IF EXISTS url_cache')


def validate(data):
    if not isinstance(data, dict):
        raise ValueError('Envie uma avaliação válida.')
    if data.get('consent') is not True:
        raise ValueError('Confirme que sua avaliação pode aparecer no site.')
    if type(data.get('rating')) is not int or data['rating'] not in range(1, 6):
        raise ValueError('Escolha uma nota de 1 a 5.')
    if data.get('useful') not in ('yes', 'partly', 'no'):
        raise ValueError('Informe se a explicação ajudou.')
    for key, limit in [('name', 40), ('comment', 500)]:
        if not isinstance(data.get(key), str) or len(data[key]) > limit:
            raise ValueError('Nome ou comentário acima do limite permitido.')
        data[key] = data[key].strip()
    if not re.fullmatch(r'[a-f0-9-]{36}', str(data.get('id', ''))):
        raise ValueError('Identificador de envio inválido. Atualize a página.')
    return data


# =====================================================================
# Utilitários
# =====================================================================

def _hostname_is_public(hostname):
    try:
        _public_addresses(hostname, 443)
        return True, None
    except ValueError as exc:
        return False, str(exc)
    except OSError as exc:
        return False, network_error(exc)


def _make_check(title, score, max_score, detail, category='Geral'):
    if max_score == 0:
        return {'title': title, 'score': None, 'max': 0, 'detail': detail,
                'category': category, 'status': 'informational'}
    return {'title': title, 'score': round(score, 1) if score is not None else None,
            'max': max_score, 'detail': detail, 'category': category,
            'status': 'unverified' if score is None else 'checked'}


def _weighted_check(key, title, score, base_max, detail, category='Geral', availability=1):
    weight = WEIGHTS[key]
    availability = max(0, min(1, availability)) if score is not None else 0
    available = round(weight * availability, 1)
    scaled = None if score is None or not weight or not available else max(0, min(available, score * available / base_max))
    check = _make_check(title, scaled, weight, detail, category)
    check['availableMax'] = available
    if weight and 0 < available < weight:
        check['status'] = 'partial'
    return check


def _summarize_checks(checks, caps):
    scored = [c for c in checks if c['max'] > 0]
    maximum = sum(c['max'] for c in scored)
    measured = [c for c in scored if c['score'] is not None]
    available = sum(max(0, min(c['max'], c.get('availableMax', c['max']))) for c in measured)
    points = sum(max(0, min(c['score'], c.get('availableMax', c['max']))) for c in measured)
    coverage = round(100 * available / maximum) if maximum else 0
    quality = round(100 * points / available) if available else None
    # Missing data earns no points. Bound sparse observations before alert caps.
    estimate = quality if quality is not None else 50
    limits = list(caps)
    if coverage < 20:
        limits.append(('Poucos dados técnicos', 55))
    elif coverage < 70:
        limits.append(('Cobertura técnica limitada', 75))
    applied_cap = None
    if limits:
        name, value = min(limits, key=lambda item: item[1])
        if estimate > value:
            estimate = value
            applied_cap = {'name': name, 'value': value}
    return {'score': max(0, min(100, estimate)), 'measuredScore': quality,
            'coverage': coverage, 'technicalCoverage': coverage, 'appliedCap': applied_cap, 'availablePoints': round(available, 1),
            'earnedPoints': round(points, 1), 'partial': available < maximum,
            'coverageLevel': 'alta' if coverage >= 80 else 'média' if coverage >= 40 else 'baixa',
                'verifiedChecks': len(measured), 'totalScoredChecks': len(scored),
            'partialChecks': sum(0 < c.get('availableMax', c['max']) < c['max'] for c in measured)}



def _fetch(url, method='HEAD'):
    return _open_public(url, method=method, headers={'Accept': '*/*'})


def _fetch_headers(url):
    try:
        with _fetch(url, method='GET') as response:
            if 300 <= response.status < 400:
                return None, 'O destino mudou na consulta GET; cabeçalhos não verificados.'
            if response.status in (401, 403, 429) or response.status >= 500:
                return None, 'O destino recusou a consulta ou está indisponível (HTTP %d).' % response.status
            return {k.lower(): v for k, v in response.headers.items()}, None
    except DestinationError:
        raise
    except Exception as exc:
        return None, network_error(exc)


def _fetch_html(url, max_bytes=256 * 1024):
    try:
        with _open_public(url, headers={'Accept': 'text/html,application/xhtml+xml'}) as response:
            if 300 <= response.status < 400:
                return None, 'O destino mudou na consulta GET; HTML não verificado.'
            if response.status >= 400:
                return None, 'Conteúdo indisponível (HTTP %d).' % response.status
            ctype = response.headers.get('Content-Type', '')
            if 'html' not in ctype.lower():
                return None, 'O destino não retornou conteúdo HTML.'
            raw = response.read(max_bytes + 1)
            if len(raw) > max_bytes:
                return None, 'HTML acima do limite de 256 KiB; análise não realizada.'
            if 'gzip' in response.headers.get('Content-Encoding', '').lower():
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                    raw = stream.read(max_bytes + 1)
                if len(raw) > max_bytes:
                    return None, 'HTML descompactado acima do limite de 256 KiB.'
            return raw, None
    except DestinationError:
        raise
    except Exception as exc:
        return None, network_error(exc)


# =====================================================================
# DNS / TLS / HSTS / Cabeçalhos
# =====================================================================

def _dns_info(hostname):
    try:
        infos = _resolve(hostname, 443)
    except OSError:
        return {'ok': False, 'ips': [], 'ipv4': [], 'ipv6': []}
    ips = sorted({info[4][0] for info in infos})
    return {
        'ok': True,
        'ips': ips,
        'ipv4': [ip for ip in ips if '.' in ip],
        'ipv6': [ip for ip in ips if ':' in ip],
    }


def _check_tls(hostname, port=443):
    observed = _observed_tls_failure(hostname, port)
    if observed is not None:
        return dict(observed)
    success = (_TLS_SUCCESSES.get() or {}).get((hostname, port))
    if success is not None:
        return dict(success)
    connection = None
    try:
        ips = _public_addresses(hostname, port)
        connection = _PinnedHTTP(hostname, port, ips, context=make_ssl_context())
        connection.connect()
        with connection.sock as ssock:
            return _tls_details(ssock)
    except ssl.SSLCertVerificationError as exc:
        # Missing issuer can be a local CA configuration issue, not a bad site.
        invalid = getattr(exc, 'verify_code', None) in INVALID_CERT_CODES
        return {'valid': False if invalid else None, 'error': network_error(exc)}
    except DestinationError:
        raise
    except Exception as exc:
        return {'valid': None, 'error': network_error(exc)}

    finally:
        if connection is not None:
            if connection.deadline_timer is not None:
                connection.deadline_timer.cancel()
            connection.close()


def _check_hsts(headers):
    hsts = headers.get('strict-transport-security', '')
    if not hsts:
        return {'present': False, 'maxAge': 0, 'includeSubdomains': False, 'preload': False}
    m = re.search(r'max-age\s*=\s*(\d+)', hsts, re.I)
    return {
        'present': True,
        'maxAge': int(m.group(1)) if m else 0,
        'includeSubdomains': bool(re.search(r'includeSubDomains', hsts, re.I)),
        'preload': bool(re.search(r'\bpreload\b', hsts, re.I)),
    }


def _evaluate_security_headers(headers):
    """Approximate enforced script/framing controls, not a full CSP browser audit."""
    present, missing = [], []
    script_score, frame_score = 0, 0
    script_detail = ''
    for policy in headers.get('content-security-policy', '').split(','):
        directives = {}
        for raw in policy.split(';'):
            tokens = raw.strip().split()
            if tokens:
                directives.setdefault(tokens[0].lower(), tokens[1:])
        scripts = directives.get('script-src-elem', directives.get('script-src', directives.get('default-src')))
        if scripts:
            lowered = [v.lower() for v in scripts]
            nonce_or_hash = any(re.fullmatch(r"'(?:nonce|sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2}'", v)
                                for v in scripts)
            # Element-only policy leaves eval and inline event handlers unrestricted.
            value = 4 if 'script-src' in directives or 'default-src' in directives else 2
            reasons = [] if value == 4 else ['política só para elementos script']
            if "'unsafe-inline'" in lowered and not nonce_or_hash:
                value -= 2
                reasons.append('unsafe-inline permitido')
            # eval falls back to script-src/default-src, never script-src-elem.
            evaluation = directives.get('script-src', directives.get('default-src', []))
            if "'unsafe-eval'" in [v.lower() for v in evaluation]:
                value -= 1
                reasons.append('unsafe-eval permitido')
            if any(v in ('*', 'http:', 'https:', 'data:') for v in lowered):
                value -= 2
                reasons.append('origens amplas para scripts')
            if value > script_score:
                script_score = value
                script_detail = '; ' + ', '.join(reasons) if reasons else ''
        ancestors = directives.get('frame-ancestors', [])
        broad_framing = any(v in ('*', 'http:', 'https:') or
                            re.fullmatch(r'https?://\*(?::(?:\*|\d+))?(?:/.*)?', v, re.I)
                            for v in ancestors)
        if ancestors and not broad_framing:
            frame_score = 4
    if script_score:
        present.append('CSP de scripts (%s/4; análise aproximada%s)' % (script_score, script_detail))
    else:
        missing.append('CSP com restrição efetiva de scripts')
    if headers.get('content-security-policy-report-only'):
        present.append('CSP Report-Only (monitoramento; não bloqueia e não pontua)')
    if headers.get('x-frame-options', '').strip().upper() in ('DENY', 'SAMEORIGIN'):
        frame_score = 4
    (present if frame_score else missing).append('Proteção contra enquadramento')
    nosniff = headers.get('x-content-type-options', '').strip().lower() == 'nosniff'
    (present if nosniff else missing).append('nosniff')
    return script_score + frame_score + (2 if nosniff else 0), present, missing


def _follow_redirects(raw_url):
    redirects, seen = [], set()
    current = normalize_url(raw_url)
    for hop in range(MAX_REDIRECTS + 1):
        if current in seen:
            return redirects, current, 'Ciclo de redirecionamentos detectado.', True
        seen.add(current)
        try:
            try:
                response = _fetch(current, method='HEAD')
            except urllib.error.HTTPError as exc:
                response = exc
            if getattr(response, 'status', None) in (405, 501) or getattr(response, 'code', None) in (405, 501):
                response.close()
                try:
                    response = _fetch(current, method='GET')
                except urllib.error.HTTPError as exc:
                    response = exc
            with response:
                code = getattr(response, 'status', None) or getattr(response, 'code', 200)
                if code not in (301, 302, 303, 307, 308):
                    if code in (401, 403, 429) or code >= 500:
                        return redirects, current, 'Destino recusou a consulta (HTTP %d).' % code, True
                    return redirects, current, '%d redirecionamento(s); destino respondeu HTTP %d.' % (len(redirects), code), False
                location = response.headers.get('Location')
                if not location:
                    return redirects, current, 'Redirecionamento sem destino.', True
                if hop == MAX_REDIRECTS:
                    return redirects, current, 'Limite de redirecionamentos atingido.', True
                destination = normalize_url(urllib.parse.urljoin(current, location))
                target_host = urlparse(destination).hostname
                # Validate before returning or requesting any redirected destination.
                try:
                    _public_addresses(target_host, urlparse(destination).port or
                                      (443 if urlparse(destination).scheme == 'https' else 80))
                except OSError as exc:
                    redirects.append((code, destination))
                    return redirects, destination, 'Destino do redirecionamento não verificado. ' + network_error(exc), True
                redirects.append((code, destination))
                current = destination
        except DestinationError:
            raise
        except Exception as exc:
            return redirects, current, network_error(exc), True
    return redirects, current, 'Limite de redirecionamentos atingido.', True


# =====================================================================
# Idade do domínio (RDAP)
# =====================================================================

def _registrable_domain(hostname):
    return registrable_domain(hostname)


def _second_level_name(hostname):
    return registrable_domain(hostname).split('.')[0]


def _parse_iso_date(s):
    if not isinstance(s, str) or not s.strip():
        return None
    try:
        dt = datetime.fromisoformat(s.strip().replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _rdap_lookup(domain):
    data = _api_json(RDAP_BOOTSTRAP + urllib.parse.quote(domain, safe=''),
                     headers={'Accept': 'application/rdap+json'})
    for event in data.get('events', []):
        if event.get('eventAction') == 'registration':
            dt = _parse_iso_date(event.get('eventDate'))
            if dt and dt <= datetime.now(timezone.utc):
                return dt
    raise ValueError('RDAP sem data de registro disponível.')





def get_domain_age(hostname):
    try:
        ipaddress.ip_address(hostname)
        return None, None, None, 'Não se aplica a um endereço IP.'
    except ValueError:
        pass
    try:
        created = _rdap_lookup(_registrable_domain(hostname))
        return (datetime.now(timezone.utc) - created).days, created.date().isoformat(), 'rdap', None
    except Exception as exc:
        return None, None, None, 'Idade não verificada. ' + network_error(exc)


# =====================================================================
# NOVO — Threat Intelligence
# =====================================================================

def _check_safe_browsing(url, api_key):
    if not api_key:
        return {'status': 'unknown', 'detail': 'Safe Browsing não configurado (opcional).'}
    try:
        body = json.dumps({
            'client': {'clientId': 'site-seguro', 'clientVersion': VERSION},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}],
            },
        }).encode()
        req = urllib.request.Request(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}',
            data=body, headers={'Content-Type': 'application/json', 'User-Agent': USER_AGENT},
        )
        data = _api_json(req.full_url, data=body, headers=dict(req.header_items()))
        if not isinstance(data, dict) or 'error' in data or not set(data).issubset({'matches', 'minimumWaitDuration'}):
            return {'status': 'unknown', 'detail': 'Safe Browsing: resposta inconclusiva.'}
        matches = data.get('matches', [])
        if not isinstance(matches, list):
            return {'status': 'unknown', 'detail': 'Safe Browsing: resposta inconclusiva.'}
        valid = [m for m in matches if isinstance(m, dict) and isinstance(m.get('threatType'), str) and m['threatType'].strip()]
        if matches and not valid:
            return {'status': 'unknown', 'detail': 'Safe Browsing: resposta inconclusiva.'}
        if valid:
            threats = sorted({m['threatType'] for m in valid})
            return {'status': 'malicious', 'scope': 'url', 'threatTypes': threats,
                    'detail': 'Safe Browsing: ameaça sinalizada.'}
        return {'status': 'clean', 'detail': 'Safe Browsing: sem alertas.'}
    except Exception as e:
        return {'status': 'unknown', 'detail': 'Safe Browsing: ' + network_error(e)}


def _check_urlhaus(value):
    key = os.environ.get('URLHAUS_AUTH_KEY', '').strip()
    exact = value.startswith(('https://', 'http://'))
    scope = 'url' if exact else 'host'
    if not key:
        return {'status': 'unknown', 'scope': scope, 'detail': 'URLhaus não configurado (opcional).'}
    try:
        body = urllib.parse.urlencode({'url' if exact else 'host': value}).encode()
        data = _api_json('https://urlhaus-api.abuse.ch/v1/' + scope + '/', data=body,
                         headers={'Auth-Key': key, 'Content-Type': 'application/x-www-form-urlencoded'})
        if data.get('query_status') == 'no_results':
            return {'status': 'clean', 'scope': scope, 'detail': 'URLhaus: sem registros.'}
        if data.get('query_status') == 'ok':
            statuses = [data.get('url_status')] if exact else [x.get('url_status') for x in data.get('urls', []) if isinstance(x, dict)]
            active = 'online' in statuses
            status = ('malicious' if exact else 'suspicious') if active else 'historical' if 'offline' in statuses else 'unknown'
            category = ['MALWARE_DOWNLOAD'] if exact and data.get('threat') == 'malware_download' else []
            return {'status': status, 'scope': scope, 'threatTypes': category,
                    'detail': 'URLhaus: registro ativo.' if active else 'URLhaus: atividade atual não confirmada.'}
        return {'status': 'unknown', 'scope': scope, 'detail': 'URLhaus: resposta inconclusiva.'}
    except Exception:
        return {'status': 'unknown', 'scope': scope, 'detail': 'URLhaus: consulta indisponível.'}


def _check_virustotal(url, api_key):
    if not api_key:
        return {'status': 'unknown', 'detail': 'VirusTotal não configurado (opcional).'}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        req = urllib.request.Request(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers={'x-apikey': api_key, 'User-Agent': USER_AGENT},
        )
        data = _api_json(req.full_url, headers=dict(req.header_items()))
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        if not stats or not any(isinstance(v, (int, float)) and v > 0 for v in stats.values()):
            return {'status': 'unknown', 'detail': 'VirusTotal: sem análise disponível.'}
        if not isinstance(stats, dict) or any(k not in stats or not isinstance(stats[k], int) or
                isinstance(stats[k], bool) or stats[k] < 0 for k in ('malicious', 'suspicious')):
            return {'status': 'unknown', 'detail': 'VirusTotal: análise incompleta.'}
        mal = stats.get('malicious', 0)
        sus = stats.get('suspicious', 0)
        if not mal and not sus and not any(isinstance(stats.get(k), int) and not isinstance(stats.get(k), bool)
                                           and stats[k] > 0 for k in ('harmless', 'undetected')):
            return {'status': 'unknown', 'detail': 'VirusTotal: sem motores conclusivos.'}
        stamp = attributes.get('last_analysis_date')
        age = ((time.time() - stamp) / 86400 if isinstance(stamp, (int, float))
               and not isinstance(stamp, bool) and math.isfinite(stamp) and 0 <= stamp <= time.time() else None)
        analyzed_at = datetime.fromtimestamp(stamp, timezone.utc).isoformat() if age is not None else None
        if age is None or age > 90:
            status = 'historical' if mal > 0 or sus > 0 else 'unknown'
        else:
            status = 'malicious' if mal >= 3 else 'suspicious' if mal or sus else 'clean'
        return {'status': status, 'scope': 'url', 'ageDays': math.ceil(age) if age is not None else None,
                'sourceAnalyzedAt': analyzed_at,
                'maliciousEngines': mal, 'suspiciousEngines': sus,
                'detail': f'VirusTotal: {mal} maliciosos, {sus} suspeitos.'}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'status': 'unknown', 'detail': 'VirusTotal: URL ainda não catalogada.'}
        return {'status': 'unknown', 'detail': f'VirusTotal HTTP {e.code}.'}
    except Exception as e:
        return {'status': 'unknown', 'detail': 'VirusTotal: ' + network_error(e)}


def _private_link(url):
    parsed = urlparse(url)
    # Avoid sharing queries, authentication/recovery links and long opaque paths.
    path = parsed.path
    for _ in range(3): path = urllib.parse.unquote(path)
    return bool(parsed.query or parsed.params or re.search(r'reset|recover|token|oauth|callback|magic|session|password|secret', path, re.I)
                or any(len(part) >= 32 for part in path.split('/')))


def _evaluate_threat_intel(final_url, hostname):
    private = _private_link(final_url)
    with ThreadPoolExecutor(max_workers=3) as ex:
        calls = [('URLhaus', ex.submit(contextvars.copy_context().run, _check_urlhaus, hostname if private else final_url))]
        if not private:
            calls += [('Safe Browsing', ex.submit(contextvars.copy_context().run, _check_safe_browsing, final_url, os.environ.get('SAFE_BROWSING_KEY', '').strip())),
                      ('VirusTotal', ex.submit(contextvars.copy_context().run, _check_virustotal, final_url, os.environ.get('VIRUSTOTAL_KEY', '').strip()))]
        sources = [(name, task.result()) for name, task in calls]
    records = _THREAT_RESULTS.get()
    if records is not None:
        for name, res in sources:
            records.append({**res, 'source': name, 'hostname': hostname,
                            'scope': res.get('scope', 'url'), 'checkedAt': datetime.now(timezone.utc).isoformat()})
    malicious = any(res.get('status') == 'malicious' for _, res in sources)
    known = [res for _, res in sources if res.get('status') in ('clean', 'malicious', 'suspicious', 'historical')]
    detail = ' | '.join(res.get('detail', '') for _, res in sources)
    return (0 if malicious else 15 if known else None), detail, malicious, len(known)


# =====================================================================
# NOVO — Análise de conteúdo HTML
# =====================================================================

class _ContentParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.base_seen = False
        self.forms = []
        self.form_ids = {}
        self.passwords = []
        self.submitters = []
        self.findings = []
        self.script_depth = 0
        self.script_parts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'base' and not self.base_seen and attrs.get('href'):
            self.base_seen = True
            self.base_url = urllib.parse.urljoin(self.base_url, attrs['href'])
        elif tag == 'form':
            form = {'action': attrs.get('action', ''), 'overrides': []}
            self.forms.append(form)
            if attrs.get('id'): self.form_ids[attrs['id']] = form
        elif tag in ('button', 'input'):
            form = self.forms[-1] if self.forms else None
            if attrs.get('form'): form = attrs['form']
            if attrs.get('formaction'): self.submitters.append((form,attrs['formaction']))
            if tag == 'input' and attrs.get('type', '').lower() == 'password': self.passwords.append(form)
        elif tag == 'iframe' and ('hidden' in attrs or 'display:none' in attrs.get('style', '').replace(' ', '').lower()):
            self.findings.append('Iframe oculto: pode ter uso legítimo e exige contexto.')
        elif tag == 'script': self.script_depth += 1

    def handle_endtag(self, tag):
        if tag == 'form' and self.forms: self.forms.pop()
        elif tag == 'script': self.script_depth = max(0, self.script_depth - 1)

    def handle_data(self, data):
        if self.script_depth: self.script_parts.append(data)


def _analyze_html(html_bytes, base_hostname):
    try:
        base_url = base_hostname if '://' in base_hostname else 'https://' + base_hostname + '/'
        hostname = urlparse(base_url).hostname
        parser = _ContentParser(base_url)
        parser.feed(html_bytes.decode('utf-8', errors='replace'))
        for owner, action in parser.submitters:
            form = parser.form_ids.get(owner) if isinstance(owner, str) else owner
            if form is not None: form['overrides'].append(action)
        signals = []
        auth_hosts = {'login.microsoftonline.com', 'accounts.google.com', 'appleid.apple.com'}
        for form in parser.passwords:
            if isinstance(form, str): form = parser.form_ids.get(form)
            if not form: continue
            for action in [form['action']] + form['overrides']:
                # Empty action submits to the document URL, not the base element.
                target = urlparse(urllib.parse.urljoin(parser.base_url, action) if action else base_url)
                if target.scheme not in ('http', 'https'):
                    signals.append({'code': 'unsafe_form', 'points': 35, 'detail': 'O formulário usa um destino de envio incomum. Confira a origem.'})
                elif target.scheme == 'http':
                    signals.append({'code': 'insecure_password_form', 'points': 65, 'detail': 'Um formulário envia senha por HTTP, sem proteção na transmissão.'})
                elif target.hostname and _registrable_domain(target.hostname) != _registrable_domain(hostname):
                    if target.hostname in auth_hosts:
                        parser.findings.append('Autenticação direcionada a um provedor conhecido; identidade da página não confirmada.')
                    else:
                        signals.append({'code': 'external_password_form', 'points': 15,
                                        'detail': f'Um formulário de senha envia para outro domínio ({target.hostname}). Pode ser autenticação externa; confira o destino.'})
        signals = list({x['code']: x for x in signals}.values())
        script = ''.join(parser.script_parts)
        if 'eval(' in script and 'atob(' in script:
            parser.findings.append('Script com eval e atob: sinal heurístico, sem confirmação de fraude.')
        findings = [x['detail'] for x in signals] + parser.findings
        critical = sum(x['code'] == 'insecure_password_form' for x in signals)
        detail = '; '.join(findings[:4]) if findings else 'Nenhum dos sinais pesquisados foi encontrado no HTML estático.'
        return {'score': max(0, 10 - 4 * critical), 'detail': detail,
                'critical': critical, 'medium': len(signals)-critical, 'signals': signals}, None
    except Exception:
        return None, 'Não foi possível interpretar o HTML.'


# =====================================================================
# NOVO — E-mail (SPF/DMARC)
# =====================================================================

def _check_email_security(hostname):
    if not DNS_OK:
        return None, 'Não verificado: dnspython opcional não instalado.', {'spf': None, 'dmarc': None}
    domain = _registrable_domain(hostname)
    results = {}
    try:
        for key, name in [('spf', domain), ('dmarc', '_dmarc.' + domain)]:
            records = []
            try:
                records = [r.to_text().replace('"', '') for r in dns.resolver.resolve(name, 'TXT', lifetime=_remaining(4))]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            # A timeout/SERVFAIL is not evidence that the record is absent.
            results[key] = records
        spf = any(txt.lower().startswith('v=spf1') for txt in results['spf'])
        dmarc_records = [txt for txt in results['dmarc'] if txt.lower().startswith('v=dmarc1')]
        dmarc = bool(dmarc_records)
        match = re.search(r'(?:^|;)\s*p\s*=\s*(none|reject|quarantine)\b',
                          dmarc_records[0], re.I) if dmarc else None
        policy = match.group(1).lower() if match else None
        score = (2 if spf else 0) + (2 if dmarc else 0) + (1 if policy in ('reject', 'quarantine') else 0)
        detail = 'SPF: %s · DMARC: %s. Esses registros não garantem a legitimidade do site.' % ('sim' if spf else 'não encontrado', policy or 'não encontrado')
        return score, detail, {'spf': spf, 'dmarc': dmarc, 'dmarcPolicy': policy}
    except Exception:
        return None, 'Consulta SPF/DMARC indisponível; registros não verificados.', {'spf': None, 'dmarc': None}


# =====================================================================
# NOVO — Typosquatting
# =====================================================================

def _levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _normalize_homoglyphs(name):
    return (name.replace('0', 'o').replace('1', 'l').replace('3', 'e')
            .replace('5', 's').replace('7', 't').replace('4', 'a'))


def _check_typosquatting(hostname):
    signal = brand_signal(hostname)
    if signal:
        return 0, signal['detail'], {'suspect': True, 'confidence': 'strong' if signal['code'] == 'brand_lookalike' else 'weak', **signal}
    return 10, 'Nenhum dos sinais de imitação pesquisados foi encontrado; identidade não confirmada.', {'suspect': False}


# =====================================================================
# NOVO — Infraestrutura (geolocalização)
# =====================================================================

def _check_infrastructure(ips):
    # Country/ISP cannot establish whether a website is legitimate.
    return None, 'Geolocalização não entra na nota: país e provedor não comprovam segurança.', {}


# =====================================================================
# Análise completa
# =====================================================================

def analyze_url(raw_url):
    observations_token = _TLS_OBSERVATIONS.set({})
    successes_token = _TLS_SUCCESSES.set({})
    token = _ANALYSIS_DEADLINE.set(time.monotonic() + ANALYSIS_SECONDS)
    threat_token = _THREAT_RESULTS.set([])
    try:
        return _analyze_url(raw_url)
    finally:
        _ANALYSIS_DEADLINE.reset(token)
        _THREAT_RESULTS.reset(threat_token)
        _TLS_OBSERVATIONS.reset(observations_token)
        _TLS_SUCCESSES.reset(successes_token)


def _analyze_url(raw_url):
    raw_url = normalize_url(raw_url)
    parsed = urlparse(raw_url)
    hostname = parsed.hostname
    dns_initial_error = None
    try:
        _public_addresses(hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
    except DestinationError:
        raise  # Private/reserved destinations are still rejected.
    except OSError as exc:
        dns_initial_error = network_error(exc)

    checks = []
    caps = []

    # 1) DNS
    dns = _dns_info(hostname)
    if dns['ok']:
        dns_score = 3
        if len(dns['ips']) >= 2:
            dns_score += 1
        if dns['ipv6']:
            dns_score += 1
        extra = []
        if len(dns['ips']) > 1:
            extra.append(f'{len(dns["ips"])} IPs')
        if dns['ipv6']:
            extra.append('IPv6')
        dns_detail = f'{", ".join(dns["ips"][:3])}' + (f' · {", ".join(extra)}' if extra else '')
    else:
        dns_score = 0
        dns_detail = dns_initial_error or 'DNS não resolveu o domínio.'
    checks.append(_weighted_check('dns', 'Resolução DNS', dns_score, 5, dns_detail, 'DNS'))

    # 2) Redirects
    redirects, final_url, redirect_detail, redirect_failed = _follow_redirects(raw_url)
    redirect_score = None if redirect_failed else 5
    final_parsed = urlparse(final_url)
    final_hostname = (final_parsed.hostname or hostname).lower().rstrip('.')
    try:
        final_port = final_parsed.port or (443 if final_parsed.scheme == 'https' else 80)
    except ValueError:
        final_port = 443
    ordered_chain = [raw_url] + [dest for _,dest in redirects]
    downgrade = any(urlparse(a).scheme == 'https' and urlparse(b).scheme == 'http'
                    for a,b in zip(ordered_chain, ordered_chain[1:]))
    downgrade = downgrade or (parsed.scheme == 'https' and final_parsed.scheme == 'http')
    if downgrade:
        redirect_detail += ' ⚠️ Downgrade HTTPS→HTTP detectado.'
        redirect_score = min(redirect_score, 1) if redirect_score is not None else None
        caps.append(('Downgrade HTTPS→HTTP', 35))
    checks.append(_weighted_check('redirects', 'Redirecionamentos', redirect_score, 5, redirect_detail, 'Navegação'))

    # 3) TLS
    cert_score = None
    tls = {'valid': False, 'error': 'Sem TLS (URL final é HTTP).'}
    if final_parsed.scheme == 'https':
        tls = _check_tls(final_hostname, final_port)
        if tls.get('valid') is True:
            cert_score = 10 if tls.get('version') in ('TLSv1.2', 'TLSv1.3') else 6
            bits = [tls.get('version', '?'), 'emissor ' + tls.get('issuer', '?')]
            if tls.get('daysLeft') is not None:
                bits.append('expira em %dd' % tls['daysLeft'])
            tls_detail = ' · '.join(bits)
        else:
            cert_score = 0 if tls.get('valid') is False else None
            tls_detail = tls.get('error', 'TLS não verificado.')
            if tls.get('valid') is False:
                caps.append(('Certificado inválido', 40))
    else:
        cert_score = 0
        tls_detail = 'A URL final usa HTTP; nenhum certificado foi verificado.'
        caps.append(('URL final sem HTTPS', 55))
    checks.append(_weighted_check('tls', 'Certificado e TLS', cert_score, 10, tls_detail, 'TLS'))

    # 4) HSTS + 5) Cabeçalhos (mesma origem)
    headers, headers_error = _fetch_headers(final_url)

    hsts = _check_hsts(headers or {})
    hsts_score = 0
    if hsts['present']:
        hsts_score += 2
        if hsts['maxAge'] >= 31536000:
            hsts_score += 2
        if hsts['includeSubdomains']:
            hsts_score += 0.5
        if hsts['preload']:
            hsts_score += 0.5
        hsts_detail = f'max-age={hsts["maxAge"]}s' + \
            (', includeSubDomains' if hsts['includeSubdomains'] else '') + \
            (', preload' if hsts['preload'] else '')
    else:
        hsts_detail = 'HSTS não informado na resposta consultada.'
    if headers is None:
        hsts_score, hsts_detail = None, headers_error
    checks.append(_weighted_check('hsts', 'HSTS', min(5, hsts_score) if hsts_score is not None else None, 5, hsts_detail, 'Cabeçalhos'))

    if headers is not None:
        sec_score, present, missing = _evaluate_security_headers(headers)
        sec_detail = f'Presentes: {", ".join(present) or "nenhum"}. Faltando: {", ".join(missing) or "nenhum"}.'
    else:
        sec_score, sec_detail = None, headers_error
    checks.append(_weighted_check('headers', 'Cabeçalhos de segurança', sec_score, 10, sec_detail, 'Cabeçalhos'))

    # 6) URL
    labels = hostname.split('.')
    url_score = 0
    url_flags = []
    if not re.search(r'xn--|[a-z][01357]|[01357][a-z]', hostname, re.I):
        url_score += 2
    else:
        url_flags.append('confusão/punycode')
    if len(labels) <= 3:
        url_score += 2
    else:
        url_flags.append('muitas partes')
    if not parsed.username and not parsed.password:
        url_score += 2
    else:
        url_flags.append('credenciais')
    if hostname not in SHORTENERS:
        url_score += 2
    else:
        url_flags.append('encurtador')
    if not re.search(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        url_score += 2
    else:
        url_flags.append('IP literal')
    checks.append(_weighted_check('url', 'Heurística da URL', url_score, 10,
                              'Sinais: ' + (', '.join(url_flags) if url_flags else 'nenhum'), 'URL'))

    # 7) Idade do domínio
    age_days, created_date, age_source, age_error = get_domain_age(final_hostname)
    if age_error or age_days is None:
        age_score = None
        age_detail = age_error or 'Idade desconhecida.'
    elif age_days < 30:
        age_score = 0
        age_detail = f'Recente: {age_days}d (criado em {created_date}). Precisa de contexto; a idade sozinha não prova fraude.'
    elif age_days < 90:
        age_score = 3
        age_detail = f'Novo: {age_days}d (criado em {created_date}).'
    elif age_days < 365:
        age_score = 7
        age_detail = f'{age_days}d (criado em {created_date}).'
    else:
        anos = age_days // 365
        age_score = 10
        age_detail = f'Estabelecido: {age_days}d (~{anos} ano{"s" if anos != 1 else ""}).'
    age_evidence = age_signal(age_days) if not age_error else None
    age_risk = {'status': 'recent' if age_evidence else 'unverified' if age_days is None else 'not_recent',
                'cap': None, 'points': age_evidence['points'] if age_evidence else 0, 'detail': age_detail}
    age_check = _weighted_check('age', 'Idade do domínio', age_score, 10, age_detail, 'Domínio')
    age_check['riskCap'] = age_risk['cap']
    checks.append(age_check)

    # 8) Threat intel: associate records with the actual hop without exposing its URL.
    actual_chain = list(dict.fromkeys([raw_url] + [dest for _, dest in redirects] + [final_url]))
    records = _THREAT_RESULTS.get()
    def annotate_new_records(start, destination):
        if records is None: return
        index = actual_chain.index(destination)
        position = 'final' if index == len(actual_chain) - 1 else 'initial' if index == 0 else 'intermediate'
        for record in records[start:]:
            record['chainIndex'] = index
            record['chainPosition'] = position

    start = len(records) if records is not None else 0
    ti_score, ti_detail, ti_malicious, ti_count = _evaluate_threat_intel(final_url, final_hostname)
    annotate_new_records(start, final_url)
    if ti_malicious:
        caps.append(('URL em base de ameaças', 5))
    checks.append(_weighted_check('reputation', 'Threat Intelligence', ti_score, 15, ti_detail, 'Reputação', availability=ti_count / 3))

    chain = list(dict.fromkeys([final_url, raw_url] + [dest for _,dest in redirects]))[:MAX_REDIRECTS + 1]
    for destination in chain[1:]:
        if _ANALYSIS_DEADLINE.get() - time.monotonic() < 5: break
        start = len(records) if records is not None else 0
        _evaluate_threat_intel(destination, urlparse(destination).hostname)
        annotate_new_records(start, destination)
    chain_brands = [signal for destination in chain if (signal := brand_signal(urlparse(destination).hostname))]

    # 9) Conteúdo HTML
    content_signals = []
    html_bytes, html_err = _fetch_html(final_url)
    if html_bytes:
        res, err = _analyze_html(html_bytes, final_url)
        if res:
            ct_score, ct_detail = res['score'], res['detail']
            content_signals = res.get('signals', [])
            if res['critical'] > 0:
                caps.append(('Sinais de atenção no conteúdo', 60))
        else:
            ct_score, ct_detail = None, err
    else:
        ct_score, ct_detail = None, html_err or 'Sem HTML para analisar.'
    checks.append(_weighted_check('html', 'Análise de conteúdo', ct_score, 10, ct_detail, 'Conteúdo'))

    # 10) E-mail (SPF/DMARC)
    em_score, em_detail, _ = _check_email_security(final_hostname)
    checks.append(_weighted_check('email', 'Segurança de e-mail (SPF/DMARC)', em_score, 5, em_detail, 'Domínio'))

    # 11) Typosquatting
    tq_score, tq_detail, tq_info = _check_typosquatting(hostname)
    if tq_info.get('suspect'):
        strong = tq_info.get('confidence') == 'strong'
        caps.append(('Imitação por homóglifos' if strong else 'Semelhança de nome a conferir', 40 if strong else 60))
    checks.append(_weighted_check('typosquatting', 'Typosquatting', tq_score, 10, tq_detail, 'Reputação'))

    # 12) Infraestrutura
    inf_score, inf_detail, inf_data = _check_infrastructure(dns['ips'])
    checks.append(_weighted_check('infrastructure', 'Infraestrutura', inf_score, 5, inf_detail, 'Infraestrutura'))

    observed_tls = _observed_tls_failure(final_hostname, final_port)
    if final_parsed.scheme == 'https' and observed_tls:
        tls = observed_tls
        for index, check in enumerate(checks):
            if check['category'] == 'TLS':
                checks[index] = _weighted_check('tls', 'Certificado e TLS', 0, 10,
                                                observed_tls['error'], 'TLS')
        if not any(name == 'Certificado inválido' for name, _ in caps):
            caps.append(('Certificado inválido', 40))
    elif final_parsed.scheme == 'https' and tls.get('valid') is None:
        success = (_TLS_SUCCESSES.get() or {}).get((final_hostname, final_port))
        if success is not None:
            tls = dict(success)
            detail = tls.get('version', '?') + ' · emissor ' + tls.get('issuer', '?')
            value = 10 if tls.get('version') in ('TLSv1.2', 'TLSv1.3') else 6
            for index, check in enumerate(checks):
                if check['category'] == 'TLS':
                    checks[index] = _weighted_check('tls', 'Certificado e TLS', value, 10, detail, 'TLS')

    # ---- observed technical quality, separate reach and threat evidence ----
    technical_caps = [(name,value) for name,value in caps if name in ('Certificado inválido','Downgrade HTTPS→HTTP','URL final sem HTTPS')]
    summary = _summarize_checks(checks, technical_caps)
    technical_score = summary['score']
    reputation_coverage = round(100 * ti_count / 3)
    coverage = round(0.65 * summary['technicalCoverage'] + 25 * ti_count / 3 + (10 if age_days is not None and not age_error else 0))
    summary.update(coverage=coverage, reputationCoverage=reputation_coverage,
                   partial=summary['partial'] or ti_count < 3 or age_days is None or bool(age_error),
                   coverageLevel='alta' if coverage >= 80 else 'média' if coverage >= 40 else 'baixa')
    reputation_results = list(_THREAT_RESULTS.get() or [])
    if not reputation_results and ti_malicious:
        reputation_results = [{'status': 'malicious', 'source': 'Reputação', 'scope': 'url'}]
    risk = decide_risk(technical_coverage=summary['technicalCoverage'], age_days=age_days if not age_error else None,
                       brands=chain_brands, reputation=reputation_results, content=content_signals,
                       tls_invalid=any(name == 'Certificado inválido' for name,_ in caps),
                       http=final_parsed.scheme == 'http', downgrade=downgrade)
    summary['score'], decision, risk = consolidate_score(technical_score, risk, reputation_results)
    level = {'bad': 'baixo', 'medium': 'medio', 'unknown': 'medio', 'good': 'alto'}[risk['band']]
    verdict = risk['reasons'][0]['detail'] if risk['reasons'] else risk['label'] + '. A pontuação não confirma identidade.'

    # Resumo técnico compacto
    tech_parts = []
    if tls.get('valid'):
        tech_parts.append(tls.get('version', '?'))
        if tls.get('alpn') == 'h2':
            tech_parts.append('HTTP/2')
    if dns['ok']:
        tech_parts.append(f'{len(dns["ips"])} IP(s)')
        if dns['ipv6']:
            tech_parts.append('IPv6')
    if inf_data.get('countryCode'):
        tech_parts.append(inf_data['countryCode'])
    tech_summary = ' · '.join(tech_parts)

    return {
        'url': raw_url,
        'hostname': hostname,
        'finalUrl': final_url,
        **summary,
        'technicalScore': technical_score,
        'decision': decision,
        'risk': risk,
        'reputationResults': reputation_results,
        'chainEvaluated': [{'hostname': urlparse(u).hostname, 'brandSignal': brand_signal(urlparse(u).hostname)} for u in chain],
        'reputationVerified': ti_count == 3,
        'reputationStatus': 'alert' if any(x.get('status') == 'malicious' for x in reputation_results) else 'suspicious' if any(x.get('status') in ('suspicious','historical') for x in reputation_results) else 'clear' if ti_count else 'unverified',
        'identityVerified': False,
        'scoreMeaning': 'link_score_with_threat_limits',
        'reputationSourcesChecked': ti_count,
        'reputationSourcesTotal': 3,
        'informationalChecks': sum(c['max'] == 0 for c in checks),
        'weights': dict(WEIGHTS),
        'tlsRevocationChecked': False,
        'scoringMethod': 'consolidated_link_score_v1',
        'version': VERSION,
        'level': level,
        'verdict': verdict,
        'domainAgeDays': age_days,
        'domainAgeRisk': age_risk,
        'domainCreated': created_date,
        'domainAgeSource': age_source,
        'techSummary': tech_summary,
        'capsApplied': [{'name': n, 'value': v} for n, v in technical_caps],
        'checks': checks,
        'redirects': [{'code': c, 'to': u} for (c, u) in redirects],
        'disclaimer': (
            'Pontuação heurística com pesos de engenharia, sem calibração estatística. '
            'DNS, SPF/DMARC e geolocalização são apenas informativos. '
            'Revogação de certificados (OCSP/CRL), execução de JavaScript e identidade empresarial não são confirmadas. '
            'NÃO é probabilidade real de segurança. Sites legítimos podem receber nota baixa '
            'e golpes podem receber nota alta.'
        ),
        'analyzedAt': datetime.now(timezone.utc).isoformat(),
    }


def cached_or_analyze(hostname, url, ttl_seconds=300):
    normalized = normalize_url(url)
    config = '|'.join(os.environ.get(key, '') for key in
                      ('SAFE_BROWSING_KEY', 'VIRUSTOTAL_KEY', 'URLHAUS_AUTH_KEY', 'SSL_CERT_FILE'))
    key = hashlib.sha256((VERSION + normalized + config).encode()).hexdigest()
    now = time.monotonic()
    with LOCK:
        cached = ANALYSIS_CACHE.get(key)
        if cached and now - cached[0] < ttl_seconds:
            return json.loads(cached[1]), True
    result = analyze_url(normalized)
    # A network failure should not persist and obstruct a retry.
    if all(c.get('status') != 'unverified' for c in result.get('checks', [])
           if c.get('category') in ('Navegação', 'TLS', 'Cabeçalhos')):
        with LOCK:
            if len(ANALYSIS_CACHE) >= 100:
                ANALYSIS_CACHE.clear()
            ANALYSIS_CACHE[key] = (now, json.dumps(result, ensure_ascii=False))
    return result, False


# =====================================================================
# Handler HTTP
# =====================================================================

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / 'dist'), **kwargs)

    def parse_request(self):
        if not super().parse_request():
            return False
        try:
            incoming = urlparse('http://' + self.headers.get('Host', ''))
            allowed_hosts = {'localhost', '127.0.0.1', '::1', self.server.server_address[0]}
            external = os.environ.get('SITE_SEGURO_ORIGIN', '')
            if external:
                allowed_hosts.add(urlparse(external).hostname)
            valid = incoming.hostname in allowed_hosts and not incoming.username and not incoming.password
            expected_port = incoming.port or 80
            valid = valid and (expected_port == self.server.server_port or
                              external and incoming.netloc == urlparse(external).netloc)
        except ValueError:
            valid = False
        if not valid:
            self.respond(403, {'error': 'Host não autorizado.'})
            return False
        return True

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header(
            'Content-Security-Policy',
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        super().end_headers()

    def send_head(self):
        # An older install may have left cached HTML/JS with a future timestamp.
        # Always send current static bytes, including on a conditional reload.
        for header in ('If-Modified-Since', 'If-None-Match'):
            if header in self.headers:
                del self.headers[header]
        return super().send_head()

    def respond(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path)
        if path.path == '/api/analyze':
            return self.respond(405, {'error': 'Esta página está desatualizada. Pare o servidor antigo, abra a versão nova em uma pasta separada e recarregue a página sem cache. Consulte LEIA-ME.md.'})

        if path.path == '/api/reviews':
            try:
                try:
                    offset = max(0, min(int(parse_qs(path.query).get('offset', ['0'])[0]), 100000))
                except ValueError:
                    return self.respond(400, {'error': 'Página inválida.'})
                with connect() as con:
                    rows = con.execute(
                        'SELECT name,rating,useful,comment,created_at AS createdAt '
                        'FROM reviews ORDER BY created_ts DESC,id DESC LIMIT 10 OFFSET ?',
                        (offset,)
                    ).fetchall()
                    stats = dict(con.execute(
                        "SELECT COUNT(*) AS total, COALESCE(AVG(rating),0) AS average, "
                        "COALESCE(SUM(CASE WHEN useful='yes' THEN 1 ELSE 0 END),0) AS yes "
                        "FROM reviews"
                    ).fetchone())
                self.respond(200, {'reviews': [dict(r) for r in rows], 'stats': stats})
            except sqlite3.Error:
                self.respond(503, {'error': 'Avaliações indisponíveis. Tente novamente.'})
        elif path.path.startswith('/api/'):
            self.respond(404, {'error': 'Recurso não encontrado.'})
        elif path.path in ('/', '/index.html', '/style.css', '/dark.css', '/analysis.js'):
            super().do_GET()
        else:
            self.send_error(404)

    def do_POST(self):
        endpoint = urlparse(self.path).path
        if endpoint not in ('/api/reviews', '/api/analyze'):
            return self.respond(404, {'error': 'Recurso não encontrado.'})
        origin = self.headers.get('Origin')
        allowed = os.environ.get('SITE_SEGURO_ORIGIN')
        if origin and (origin != allowed if allowed else urlparse(origin).netloc != self.headers.get('Host')):
            return self.respond(403, {'error': 'Origem não autorizada.'})
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            return self.respond(415, {'error': 'Use JSON.'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.respond(400, {'error': 'Corpo inválido.'})
        if not 0 < size <= 4096:
            return self.respond(413, {'error': 'Avaliação acima do limite permitido.'})
        try:
            data = json.loads(self.rfile.read(size))
            if endpoint == '/api/analyze':
                return self.analyze_request(data)
            data = validate(data)
        except (ValueError, UnicodeError):
            return self.respond(400, {
                'error': 'Confira a nota, a utilidade, os limites de texto e a autorização.'
            })
        try:
            with LOCK, connect() as con:
                existing = con.execute(
                    'SELECT name,rating,useful,comment FROM reviews WHERE id=?',
                    (data['id'],)
                ).fetchone()
                if existing:
                    same = all(
                        existing[k] == (data[k] or 'Visitante' if k == 'name' else data[k])
                        for k in ['name', 'rating', 'useful', 'comment']
                    )
                    return self.respond(
                        200 if same else 409,
                        {'saved': True} if same else {'error': 'Identificador já utilizado.'}
                    )
                salt = con.execute("SELECT value FROM settings WHERE key='salt'").fetchone()[0]
                ip = hashlib.sha256((salt + self.client_address[0]).encode()).hexdigest()
                if con.execute(
                    'SELECT 1 FROM reviews WHERE ip_hash=? AND created_ts>?',
                    (ip, time.time() - 60)
                ).fetchone():
                    return self.respond(429, {'error': 'Aguarde um minuto antes de enviar outra avaliação.'})
                con.execute(
                    'INSERT INTO reviews VALUES (?,?,?,?,?,?,?,?)',
                    (data['id'], data['name'] or 'Visitante', data['rating'],
                     data['useful'], data['comment'],
                     datetime.now(timezone.utc).isoformat(), ip, time.time())
                )
            self.respond(201, {'saved': True})
        except sqlite3.Error:
            self.respond(503, {
                'error': 'Não foi possível salvar. Seu texto foi preservado; tente novamente.'
            })

    def analyze_request(self, data):
        if not isinstance(data, dict) or set(data) != {'url'}:
            return self.respond(400, {'error': 'Envie um objeto JSON com o campo url.'})
        if not ANALYSIS_SLOTS.acquire(blocking=False):
            return self.respond(429, {'error': 'Há análises em andamento. Tente novamente em instantes.'})
        try:
            normalized = normalize_url(data['url'])
            result, hit = cached_or_analyze(urlparse(normalized).hostname, normalized)
            result['fromCache'] = hit
            return self.respond(200, result)
        except ValueError as exc:
            return self.respond(400, {'error': str(exc)})
        except Exception:
            return self.respond(502, {'error': 'Análise indisponível. Confira a rede e tente novamente.'})
        finally:
            ANALYSIS_SLOTS.release()

    def do_HEAD(self):
        # Restrict static paths for HEAD as well as GET (no directory listing).
        if urlparse(self.path).path not in ('/', '/index.html', '/style.css', '/dark.css', '/analysis.js'):
            return self.respond(404, {'error': 'Recurso não encontrado.'})
        super().do_HEAD()

    def log_message(self, format, *args):
        pass


def diagnostics():
    print('Site Seguro ' + VERSION)
    print('Python: ' + sys.version.split()[0])
    try:
        context = make_ssl_context()
        print('Certificados CA carregados: %d' % context.cert_store_stats()['x509_ca'])
        print('Validação TLS: ativa (certificado e nome do servidor).')
    except (OSError, ssl.SSLError):
        print('Não foi possível carregar os certificados. Confira SSL_CERT_FILE e LEIA-ME.md.')
        return 1
    for name in ('SAFE_BROWSING_KEY', 'VIRUSTOTAL_KEY', 'URLHAUS_AUTH_KEY'):
        print('%s: %s (opcional)' % (name, 'configurado' if os.environ.get(name) else 'não configurado'))
    print('SPF/DMARC: ' + ('disponível' if DNS_OK else 'não verificado; dnspython opcional ausente'))
    for host in ('example.com', 'rdap.org'):
        result = _check_tls(host)
        print('%s: %s' % (host, 'TLS validado' if result.get('valid') is True else result.get('error', 'indisponível')))
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Site Seguro — protótipo acadêmico local')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--diagnostico', action='store_true', help='Verificar Python, CA e conexões TLS sem mostrar chaves')
    args = parser.parse_args()
    if args.diagnostico:
        raise SystemExit(diagnostics())
    try:
        make_ssl_context()
        init_db()
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    except (OSError, sqlite3.Error, ssl.SSLError):
        print('Não foi possível iniciar. Confira a pasta de dados, certificados e porta. '
              'Se a porta estiver ocupada, use: python3 server.py --port 8766', flush=True)
        raise SystemExit(1)
    print('Site Seguro ' + VERSION, flush=True)
    print('Fontes opcionais sem configuração aparecerão como não verificadas.', flush=True)
    print('Abra no navegador: http://%s:%d' % (args.host, args.port), flush=True)
    print('Encerre com Control+C.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nServidor encerrado.', flush=True)
    finally:
        server.server_close()
