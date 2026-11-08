'use strict';
// Quando o site estiver publicado, altere somente PUBLIC_SITE_URL.
// Isso muda o link do rodapé. A API permanece local até ser publicada separadamente.
self.SITE_SEGURO_CONFIG = Object.freeze({
  API_BASE_URL: 'http://127.0.0.1:8765',
  PUBLIC_SITE_URL: 'https://site-seguro.onrender.com'
});
