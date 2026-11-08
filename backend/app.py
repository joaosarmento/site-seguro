"""Ponte local da extensão; preserva o motor e a versão web do projeto."""
import argparse
import json
import re
import os
import secrets
import threading
import time
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse
import server as engine

PORTA = int(os.environ.get("PORT", 8765))
IS_RENDER = "PORT" in os.environ
IDENTITY = json.loads(Path(__file__).with_name('extension-identity.json').read_text())['id']
if not re.fullmatch(r'[a-p]{32}', IDENTITY):
    raise ValueError('Identidade da extensão inválida.')
EXTENSION_ORIGIN = 'chrome-extension://' + IDENTITY
EXTENSION_ROUTES = {'/api/extension/start', '/api/extension/status'}


class JobRegistry:
    """Jobs limitados em memória; nenhuma URL é gravada em disco."""
    def __init__(self):
        self._lock = threading.Lock()
        self._jobs = {}

    def _prune(self):
        now = time.monotonic()
        for key in list(self._jobs):
            if now - self._jobs[key]['created'] > 300:
                del self._jobs[key]
        completed = sorted((value['created'], key) for key, value in self._jobs.items()
                           if value['state'] != 'pending')
        while len(self._jobs) >= 50 and completed:
            del self._jobs[completed.pop(0)[1]]

    def submit(self, raw_url):
        normalized = engine.normalize_url(raw_url)
        if not engine.ANALYSIS_SLOTS.acquire(blocking=False):
            return None
        try:
            job_id = secrets.token_urlsafe(24)
            with self._lock:
                self._prune()
                if len(self._jobs) >= 50:
                    engine.ANALYSIS_SLOTS.release()
                    return None
                self._jobs[job_id] = {'state': 'pending', 'created': time.monotonic()}
            worker = threading.Thread(target=self._run, args=(job_id, normalized), daemon=True)
            worker.start()
            return job_id
        except Exception:
            engine.ANALYSIS_SLOTS.release()
            raise

    def _run(self, job_id, normalized):
        try:
            result, hit = engine.cached_or_analyze(urlparse(normalized).hostname, normalized)
            result['fromCache'] = hit
            value = {'state': 'done', 'result': result}
        except engine.DestinationError as exc:
            value = {'state': 'error', 'error': str(exc)}
        except Exception:
            value = {'state': 'error', 'error': 'Não foi possível concluir a análise. Confira a conexão e tente novamente.'}
        finally:
            engine.ANALYSIS_SLOTS.release()
        with self._lock:
            record = self._jobs.get(job_id)
            if record is not None:
                record.update(value)

    def get(self, job_id):
        with self._lock:
            self._prune()
            record = self._jobs.get(job_id)
            return {key: value for key, value in record.items() if key != 'created'} if record else None


class ExtensionHandler(engine.Handler):
    jobs = JobRegistry()

    def do_POST(self):
        endpoint = urlparse(self.path).path
        if endpoint not in EXTENSION_ROUTES:
            return super().do_POST()
        origin = self.headers.get('Origin')
        protocolo = 'https://' if IS_RENDER else 'http://'
        same_origin = protocolo + self.headers.get('Host', '')
        
        # A identidade da extensão é fixa no manifesto de desenvolvimento.
        # Origin é apenas uma verificação de origem, não autenticação.
        if origin and origin not in (EXTENSION_ORIGIN, same_origin):
            return self.respond(403, {'error': 'Origem não autorizada.'})
        
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            return self.respond(415, {'error': 'Use JSON.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4096:
                return self.respond(413, {'error': 'Pedido acima do limite permitido.'})
            data = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeError):
            return self.respond(400, {'error': 'Pedido inválido.'})
        if not isinstance(data, dict):
            return self.respond(400, {'error': 'Pedido inválido.'})
        if endpoint == '/api/extension/start':
            if set(data) != {'url'}:
                return self.respond(400, {'error': 'Informe somente o endereço para análise.'})
            try:
                canonical_url = engine.normalize_url(data['url'])
                job_id = self.jobs.submit(canonical_url)
            except engine.DestinationError as exc:
                return self.respond(400, {'error': str(exc)})
            except Exception:
                return self.respond(503, {'error': 'Não foi possível iniciar a análise.'})
            if job_id is None:
                return self.respond(429, {'error': 'Há análises em andamento. Tente novamente em instantes.'})
            return self.respond(202, {'jobId': job_id, 'url': canonical_url, 'state': 'pending'})
        if set(data) != {'jobId'} or not isinstance(data['jobId'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{32}', data['jobId']):
            return self.respond(400, {'error': 'Identificador de análise inválido.'})
        result = self.jobs.get(data['jobId'])
        if result is None:
            return self.respond(404, {'error': 'A análise expirou. Analise novamente.'})
        return self.respond(200, {'jobId': data['jobId'], **result})


def main():
    parser = argparse.ArgumentParser(description='Site Seguro — servidor local da extensão')
    parser.add_argument('--port', type=int, default=PORTA)
    args = parser.parse_args()
    host = "0.0.0.0" if IS_RENDER else "127.0.0.1"
    # O proxy do Render encaminha o domínio público sem a porta interna.
    # A origem pode ser alterada no painel para um domínio próprio.
    if IS_RENDER and not os.environ.get("SITE_SEGURO_ORIGIN"):
        os.environ["SITE_SEGURO_ORIGIN"] = "https://site-seguro.onrender.com"
    try:
        engine.make_ssl_context()

        engine.init_db()
        httpd = ThreadingHTTPServer((host, args.port), ExtensionHandler)
    except Exception:
        print('Não foi possível iniciar. Confira Python, certificados e se a porta8765 está ocupada.')
        return 1
    print('Site Seguro — extensão 1.4.0 / motor web' + engine.VERSION, flush=True)
    print(f'Servidor ativo em: http://{host}:{args.port}', flush=True)
    print('Mantenha este Terminal aberto. Encerre com Control+C.', flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nServidor encerrado.')
    finally:
        httpd.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
