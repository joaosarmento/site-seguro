'use strict';
const $ = id => document.getElementById(id);

const examples = {
  low: 'https://loja-exemplo.test',
  medium: 'http://loja-exemplo.test',
  high: 'http://acesso.login.g00gle.test'
};

const SHORTENERS = ['bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'cutt.ly', 'rb.gy', 'ow.ly', 'buff.ly', 'goo.gl'];

const SUSPICIOUS_WORDS = [
  'login', 'signin', 'secure', 'verify', 'account', 'update', 'wallet',
  'support', 'admin', 'confirm', 'banking', 'password', 'pay', 'billing', 'recovery'
];

const POPULAR_NAMES = [
  'google', 'facebook', 'whatsapp', 'instagram', 'youtube', 'netflix',
  'amazon', 'mercadolivre', 'americanas', 'magazineluiza', 'nubank',
  'itau', 'bradesco', 'santander', 'caixa', 'sicoob', 'picpay', 'inter',
  'c6bank', 'gov', 'serpro', 'receita', 'inss', 'apple', 'microsoft',
  'paypal', 'steam', 'twitch', 'twitter', 'tiktok', 'binance', 'coinbase'
];

// ---------- normalização ----------
function normalize(value) {
  if (typeof value !== 'string' || !value.trim() || value.length > 2048 || /[\s\\]/.test(value.trim()))
    throw Error('Insira um endereço válido, sem espaços, como https://exemplo.com.br.');
  let raw = value.trim();
  if (!/^[a-z][a-z0-9+.-]*:/i.test(raw)) raw = 'https://' + raw;
  let u;
  try { u = new URL(raw); } catch { throw Error('Não foi possível reconhecer esse endereço. Confira o formato.'); }
  if (!['http:', 'https:'].includes(u.protocol) || !u.hostname.includes('.') || u.hostname.length > 253 ||
      u.hostname.split('.').some(p => p.length > 63 || !/^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)$/i.test(p)))
    throw Error('Informe um endereço HTTP ou HTTPS com um domínio válido.');
  return u;
}

// ---------- typosquatting (Levenshtein + homóglifos) ----------
function levenshtein(a, b) {
  if (a.length < b.length) return levenshtein(b, a);
  if (!b) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const curr = [i];
    for (let j = 1; j <= b.length; j++) {
      curr.push(Math.min(
        curr[j - 1] + 1,
        prev[j] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      ));
    }
    prev = curr;
  }
  return prev[b.length];
}

function secondLevelName(hostname) {
  const parts = hostname.split('.');
  if (parts.length < 2) return '';
  if (parts.length >= 3 && ['com', 'net', 'org', 'gov', 'edu', 'co', 'ac', 'mil'].includes(parts[parts.length - 2]))
    return parts[parts.length - 3];
  return parts[parts.length - 2];
}

function normalizeHomoglyphs(name) {
  return name.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
             .replace(/5/g, 's').replace(/7/g, 't').replace(/4/g, 'a');
}

function checkTyposquat(hostname) {
  const name = secondLevelName(hostname).toLowerCase();
  if (!name) return { suspect: false, detail: 'Sem nome de segundo nível.' };
  const normalized = normalizeHomoglyphs(name);
  for (const popular of POPULAR_NAMES) {
    if (name === popular) return { suspect: false, detail: `Corresponde a "${popular}".` };
    if (normalized === popular && name !== popular)
      return { suspect: true, detail: `Imita "${popular}" com homóglifos.` };
    if (levenshtein(name, popular) <= 1)
      return { suspect: true, detail: `Muito parecido com "${popular}".` };
    if (name.includes('-') && name.split('-').includes(popular))
      return { suspect: true, detail: `Contém "${popular}" entre hífens.` };
  }
  return { suspect: false, detail: 'Sem similaridade com domínios populares.' };
}

// ---------- análise local (offline) ----------
function evaluateLocal(value) {
  const u = normalize(value);
  const labels = u.hostname.split('.');
  const isIpLiteral = /^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname);
  const suspiciousHit = SUSPICIOUS_WORDS.find(w => u.hostname.toLowerCase().includes(w));
  const typosquat = checkTyposquat(u.hostname);

  const checks = [
    {
      title: 'Protocolo HTTPS',
      weight: 25,
      ok: u.protocol === 'https:',
      detail: u.protocol === 'https:'
        ? 'O texto indica HTTPS (a conexão não foi verificada offline).'
        : 'O endereço usa HTTP. Confirme o canal oficial antes de informar dados.'
    },
    {
      title: 'Sem usuário ou senha na URL',
      weight: 15,
      ok: !u.username && !u.password,
      detail: u.username || u.password
        ? 'Há credenciais antes do domínio — estrutura que pode enganar.'
        : 'Não há usuário nem senha embutidos.'
    },
    {
      title: 'Grafia sem sinal de confusão',
      weight: 10,
      ok: !(/xn--|[a-z][01357]|[01357][a-z]/i.test(u.hostname)),
      detail: 'Triagem para punycode e letras/números misturados.'
    },
    {
      title: 'Estrutura curta do domínio',
      weight: 5,
      ok: labels.length <= 3,
      detail: labels.length <= 3 ? 'Até três partes no hostname.' : 'Mais de três partes — leitura cuidadosa recomendada.'
    },
    {
      title: 'Sem encurtador da lista local',
      weight: 5,
      ok: !SHORTENERS.some(h => u.hostname === h || u.hostname.endsWith('.' + h)),
      detail: 'Lista fixa pequena; outros encurtadores podem não ser reconhecidos.'
    },
    {
      title: 'Host não é IP literal',
      weight: 5,
      ok: !isIpLiteral,
      detail: isIpLiteral
        ? 'O endereço usa IP numérico — incomum em sites legítimos.'
        : 'Host usa nome de domínio.'
    },
    {
      title: 'Sem palavras suspeitas no host',
      weight: 15,
      ok: !suspiciousHit,
      detail: suspiciousHit
        ? `Palavra "${suspiciousHit}" no hostname — típica de phishing.`
        : 'Nenhuma palavra-chave de phishing no hostname.'
    },
    {
      title: 'Sem typosquatting de domínio popular',
      weight: 15,
      ok: !typosquat.suspect,
      detail: typosquat.detail
    },
    {
      title: 'TLD plausível',
      weight: 5,
      ok: !/\.[a-z]{2,3}$/i.test(u.hostname) || !/\.(tk|ml|ga|cf|gq|xyz|top|work|click)$/i.test(u.hostname),
      detail: 'TLDs gratuitos (.tk, .ml, .ga, .cf, .gq) e alguns genéricos baratos concentram phishing.'
    },
  ];

  const passed = checks.filter(c => c.ok).length;
  const score = checks.filter(c => c.ok).reduce((s, c) => s + c.weight, 0);
  const level = score >= 80 ? 'low' : score >= 50 ? 'medium' : 'high';

  return {
    hostname: u.hostname, checks, passed, total: checks.length,
    score, level,
    example: u.hostname.endsWith('.test'),
    source: 'local'
  };
}

// ---------- análise remota ----------
const apiAvailable = /^https?:$/.test(location.protocol);

async function evaluateRemote(value) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 90000);
  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: value }),
      signal: controller.signal,
      cache: 'no-store'
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw Error(data.error || 'Não foi possível analisar este endereço agora.');
    if (data.scoringMethod !== 'consolidated_link_score_v1' || !data.decision || !data.risk ||
        !['critical','high','attention','none','limited'].includes(data.decision.severity) ||
        !['good','medium','bad','unknown'].includes(data.risk.band) || !Array.isArray(data.risk.reasons) ||
        typeof data.score !== 'number' || !Number.isFinite(data.score) || data.score < 0 || data.score > 100 ||
        typeof data.decision.maxScore !== 'number' || !Number.isFinite(data.decision.maxScore) ||
        data.decision.maxScore < 0 || data.decision.maxScore > 100)
      throw Error('Atualize e reinicie o servidor deste pacote para usar a nova análise.');
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw Error('A consulta demorou demais. Tente novamente ou execute o diagnóstico indicado no LEIA-ME.');
    if (error instanceof TypeError) throw Error('Sem conexão com o servidor. Confira se python3 server.py está em execução.');
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

// ---------- renderização ----------
function esc(v) { return String(v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

function scorePresentation(score, inconclusive = false) {
  if (inconclusive || typeof score !== 'number' || !Number.isFinite(score))
    return { band: 'unknown', level: 'neutral', label: 'Inconclusivo' };
  if (score >= 80) return { band: 'good', level: 'low', label: 'Favorável' };
  if (score >= 50) return { band: 'medium', level: 'medium', label: 'Atenção' };
  return { band: 'bad', level: 'high', label: 'Ruim' };
}

function remoteAlerts(r) {
  if (r.risk && Array.isArray(r.risk.reasons)) return r.risk.reasons.slice(0,5).map(reason => ({
    title: reason.critical || reason.severity === 'high' ? 'Alerta de segurança' : 'Motivo de atenção',
    detail: String(reason.detail || ''), tone: reason.critical || reason.severity === 'high' ||
      (!reason.severity && reason.code !== 'recent_domain' && r.risk.band === 'bad') ? 'danger' : 'warning'
  }));
  const names = new Set((r.capsApplied || []).map(c => c.name));
  const alerts = [];
  if (r.reputationStatus === 'alert' || names.has('URL em base de ameaças'))
    alerts.push({title: 'Possível ameaça identificada', detail: 'Uma base de segurança sinalizou este endereço. Evite informar dados ou baixar arquivos.', tone: 'danger'});
  if (names.has('Certificado inválido'))
    alerts.push({title: 'Problema no certificado', detail: 'O certificado do site não passou na verificação da conexão. Evite enviar dados neste endereço.', tone: 'danger'});
  if (names.has('Downgrade HTTPS→HTTP'))
    alerts.push({title: 'A conexão perdeu a proteção', detail: 'O endereço mudou de HTTPS para HTTP durante o acesso. Evite informar senhas ou dados de pagamento.', tone: 'danger'});
  else if (names.has('URL final sem HTTPS'))
    alerts.push({title: 'Conexão sem HTTPS', detail: 'O site usa HTTP, que não protege os dados durante a transmissão. Evite informar senhas ou dados de pagamento.', tone: 'warning'});
  if (names.has('Sinais de atenção no conteúdo'))
    alerts.push({title: 'Campo de senha aponta para outro site', detail: 'Foi encontrado um campo de senha cujo envio aponta para outro domínio. Confirme o destino antes de continuar.', tone: 'warning'});
  if (r.domainAgeRisk?.cap != null || [...names].some(name => /^Domínio (recente|recém-registrado)/.test(name))) {
    const days = r.domainAgeDays;
    const age = Number.isInteger(days) && days >= 0
      ? days === 0 ? 'há menos de um dia' : `há ${days} ${days === 1 ? 'dia' : 'dias'}`
      : 'recentemente';
    alerts.push({title: 'Domínio recente', detail: `Este domínio foi registrado ${age} e ainda tem pouco histórico. Confira a origem antes de informar dados.`, tone: 'warning'});
  }
  if (names.has('Imitação por homóglifos'))
    alerts.push({title: 'Endereço com grafia enganosa', detail: 'O nome usa trocas de letras e números que imitam uma marca conhecida. Confira o endereço pelo canal oficial.', tone: 'warning'});
  else if (names.has('Semelhança de nome a conferir'))
    alerts.push({title: 'Nome parecido com uma marca conhecida', detail: 'A grafia do domínio pode causar confusão com outro site. Confira o endereço pelo canal oficial.', tone: 'warning'});
  return alerts;
}

function renderAlerts(alerts) {
  if (!alerts.length) return '';
  return `<div class="result-alerts">${alerts.map(alert => `
    <article class="risk-alert ${alert.tone === 'danger' ? 'risk-danger' : 'risk-warning'}">
      <h3>${esc(alert.title)}</h3><p>${esc(alert.detail)}</p>
    </article>`).join('')}</div>`;
}

function coverageValue(value) {
  return typeof value === 'number' && Number.isFinite(value)
    ? `${Math.round(Math.max(0, Math.min(100, value)))}%` : '—';
}

function verifiedTopics(r) {
  const checks = r.checks || [];
  const headersObserved = checks.some(c => c.title === 'Cabeçalhos de segurança' && Number.isFinite(c.score));
  return checks.flatMap(c => {
    let detail = c.detail || '';
    let label = 'Verificado';
    let attention = false;
    if (c.max > 0 && Number.isFinite(c.score)) {
      attention = c.score < (c.availableMax ?? c.max);
      label = attention ? 'Requer atenção' : 'Verificado';
      if (c.title === 'Cabeçalhos de segurança') {
        label = attention ? 'Melhorias possíveis' : 'Verificado';
        detail = detail.replace(/\(\d+(?:\.\d+)?\/4;\s*análise aproximada(?:;\s*([^)]*))?\)/g,
          (_match, reason) => reason ? `(${reason})` : '');
        detail = detail.replace('CSP Report-Only (monitoramento; não bloqueia e não pontua)', 'CSP de monitoramento');
      }
    } else if (c.title === 'Resolução DNS' && /^(?:\d{1,3}(?:\.\d{1,3}){3}|[a-f0-9]{1,4}:)/i.test(detail)) {
      detail = 'O domínio respondeu à consulta de DNS.';
    } else if (c.title === 'HSTS' && (headersObserved || /^max-age=\d+/.test(detail))) {
      label = 'Analisado';
      const maxAge = detail.match(/^max-age=(\d+)/);
      detail = maxAge ? Number(maxAge[1]) > 0
        ? 'O site informa uma política HSTS para priorizar conexões HTTPS.'
        : 'A política HSTS está desativada na resposta consultada.'
        : 'O site não informou HSTS na resposta consultada.';
    } else if (c.title === 'Heurística da URL' && /^Sinais:/.test(detail)) {
      label = 'Analisado';
      detail = detail === 'Sinais: nenhum' ? 'O formato do endereço não apresentou os sinais pesquisados.' : detail;
    } else if (c.title === 'Idade do domínio' && Number.isInteger(r.domainAgeDays) && r.domainAgeDays >= 0) {
      const days = r.domainAgeDays;
      const age = days === 0 ? 'há menos de um dia' : `há ${days} ${days === 1 ? 'dia' : 'dias'}`;
      detail = `Registrado ${age}.` + (r.domainCreated ? ` Criado em ${r.domainCreated}.` : '');
      attention = r.domainAgeRisk?.status === 'recent' || r.domainAgeRisk?.cap != null;
      label = attention ? 'Registro recente' : 'Verificado';
    } else if (c.title === 'Threat Intelligence' && r.reputationSourcesChecked > 0) {
      attention = ['alert','suspicious'].includes(r.reputationStatus);
      label = attention ? 'Requer atenção' : 'Consultado';
      detail = attention ? 'Uma consulta trouxe um registro que merece atenção; confira os motivos acima.' : 'As consultas realizadas não retornaram alertas de ameaça.';
    } else if (c.title === 'Segurança de e-mail (SPF/DMARC)' && /^SPF:/.test(detail)) {
      label = 'Analisado';
      detail = detail.split('. Esses registros')[0];
    } else {
      return [];
    }
    return [{title: c.title === 'Threat Intelligence' ? 'Consulta de ameaças' : c.title, detail, label, attention}];
  });
}

function renderVerifiedTopics(r) {
  const topics = verifiedTopics(r);
  if (!topics.length) return '';
  return `<section class="validated-topics"><h3>Tópicos verificados</h3>
    <ul class="topic-list">${topics.map(topic => `<li class="topic-item">
      <span class="topic-state ${topic.attention ? 'topic-attention' : ''}">${esc(topic.label)}</span>
      <h4>${esc(topic.title)}</h4><p>${esc(topic.detail)}</p>
    </li>`).join('')}</ul></section>`;
}

function renderSourceDetails(r) {
  if (!r.decision || !Array.isArray(r.reputationResults) || !Array.isArray(r.risk?.reasons)) return '';
  const sources = r.risk.reasons.filter(reason => Number.isInteger(reason.evidenceRef)).map(reason => {
    const item = r.reputationResults[reason.evidenceRef];
    if (!item) return '';
    const scope = item.scope === 'host' ? 'Domínio' : 'URL';
    const position = {initial:'endereço inicial', intermediate:'redirecionamento intermediário', final:'destino final'}[item.chainPosition];
    const date = value => {
      if (typeof value !== 'string') return '';
      const parsed = new Date(value);
      return Number.isNaN(parsed.getTime()) ? '' : parsed.toLocaleString('pt-BR');
    };
    const info = [scope, position, date(item.checkedAt) && `Consulta: ${date(item.checkedAt)}`,
      date(item.sourceAnalyzedAt) && `Análise da fonte: ${date(item.sourceAnalyzedAt)}`].filter(Boolean).join(' · ');
    return `<li><strong>${esc(reason.source || item.source)}</strong><p>${esc(reason.detail)}</p><small>${esc(info)}</small></li>`;
  }).filter(Boolean);
  return sources.length ? `<details class="source-evidence"><summary>Detalhes das fontes</summary><ul>${sources.join('')}</ul></details>` : '';
}

function renderRemote(r) {
  const severityLimits = {critical:10, high:39, attention:79, none:100, limited:100};
  const bandLimits = {bad:39, medium:79, good:100, unknown:100};
  const limit = r.decision && typeof r.decision.maxScore === 'number' && Number.isFinite(r.decision.maxScore)
    ? Math.max(0, Math.min(100, r.decision.maxScore, severityLimits[r.decision.severity] ?? 0, bandLimits[r.risk?.band] ?? 0))
    : (bandLimits[r.risk?.band] ?? 100);
  const safeScore = typeof r.score === 'number' && Number.isFinite(r.score) ? Math.min(r.score, limit) : null;
  const presentation = scorePresentation(safeScore, r.level === 'inconclusivo' || r.decision?.severity === 'limited');
  const displayedScore = r.level === 'inconclusivo' ? null : safeScore;
  const alerts = remoteAlerts(r);
  const unavailable = !alerts.length && (displayedScore == null ||
    (typeof r.technicalCoverage === 'number' && r.technicalCoverage < 20));
  $('result').innerHTML = `
    <div class="resulttop compact-resulttop">
      <div><p class="eyebrow">RESULTADO</p><h2>${esc(r.hostname)}</h2>
        ${r.risk && ['good','medium','bad','unknown'].includes(r.risk.band) ? `<p class="risk-verdict risk-${r.risk.band}">${esc(r.risk.label)}</p>` : ''}</div>
    </div>
    ${renderAlerts(alerts)}
    <div class="score-layout compact-score">
      <div class="score-ring score-${presentation.band}" role="img" aria-label="${displayedScore == null ? 'Análise inconclusiva, sem nota' : esc(displayedScore) + ' de 100. ' + (r.decision?.severity === 'limited' ? 'Análise limitada' : presentation.label)}" style="--score:${Math.max(0, Math.min(100, Number(displayedScore) || 0))}">
        <div class="score-core"><strong>${displayedScore == null ? '—' : esc(displayedScore) + '%'}</strong><span>pontuação</span></div>
      </div>
      <div class="score-copy"><h3>Pontuação do link</h3><p class="score-state score-text-${presentation.band}">${r.decision?.severity === 'limited' ? 'Análise limitada' : presentation.label}</p>
        <dl class="coverage-summary">
          <div><dt>Cobertura técnica</dt><dd>${coverageValue(r.technicalCoverage)}</dd></div>
          <div><dt>Cobertura de dados</dt><dd>${coverageValue(r.coverage)}</dd></div>
        </dl>
        <p class="identity-note">A pontuação não confirma que o site é oficial ou legítimo.</p>
        ${unavailable ? '<p class="result-status">Não foi possível acessar o site neste momento. Tente novamente mais tarde.</p>' : ''}
      </div>
    </div>
    ${renderSourceDetails(r)}
    ${renderVerifiedTopics(r)}
  `;
}

function renderLocal(r) {
  const presentation = scorePresentation(r.score);
  const titles = {
    'Protocolo HTTPS': 'Endereço sem HTTPS',
    'Sem usuário ou senha na URL': 'Dados de acesso no endereço',
    'Grafia sem sinal de confusão': 'Grafia que merece atenção',
    'Estrutura curta do domínio': 'Endereço com muitos subdomínios',
    'Sem encurtador da lista local': 'Link encurtado',
    'Host não é IP literal': 'Endereço numérico',
    'Sem palavras suspeitas no host': 'Nome que merece conferência',
    'Sem typosquatting de domínio popular': 'Nome parecido com uma marca conhecida',
    'TLD plausível': 'Extensão que merece atenção'
  };
  const alerts = (r.checks || []).filter(c => !c.ok).map(c => ({
    title: titles[c.title] || c.title, detail: c.detail, tone: 'warning'
  }));
  $('result').innerHTML = `
    <div class="resulttop compact-resulttop"><div><p class="eyebrow">${r.example ? 'EXEMPLO' : 'PRÉVIA OFFLINE'}</p><h2>${esc(r.hostname)}</h2></div></div>
    <div class="score-layout compact-score">
      <div class="score-ring score-${presentation.band}" role="img" aria-label="${esc(r.score)} de 100. ${presentation.label}" style="--score:${Math.max(0, Math.min(100, Number(r.score) || 0))}">
        <div class="score-core"><strong>${esc(r.score)}%</strong><span>leitura da URL</span></div>
      </div>
      <div class="score-copy"><h3>Leitura do endereço</h3><p class="score-state score-text-${presentation.band}">${presentation.label}</p>
        <p class="result-status">${r.example ? 'Demonstração com endereço fictício.' : 'Para verificar o site, abra a versão conectada ao servidor.'}</p>
      </div>
    </div>
    ${renderAlerts(alerts)}`;
}

// ---------- execução ----------
let busy = false;

async function run(value, demo = false) {
  if (busy) return;
  $('error').hidden = true;
  $('url').removeAttribute('aria-invalid');

  busy = true;
  $('submit').disabled = true;
  $('submit').textContent = 'Analisando…';
  $('result').hidden = false;
  $('result').setAttribute('aria-busy', 'true');
  $('result').innerHTML = '<p class="loading">Analisando o endereço…</p>';

  try {
    let payload;
    const normalized = normalize(value);
    if (apiAvailable && !demo && !normalized.hostname.endsWith('.test')) {
      payload = await evaluateRemote(normalized.href);
      renderRemote(payload);
    } else {
      payload = evaluateLocal(value);
      renderLocal(payload);
    }
    $('result').focus({ preventScroll: true });
    $('result').scrollIntoView({
      behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth',
      block: 'start'
    });
  } catch (e) {
    $('error').textContent = e.message || 'Não foi possível analisar este endereço.';
    $('error').hidden = false;
    $('url').setAttribute('aria-invalid', 'true');
    $('result').hidden = true;
  } finally {
    busy = false;
    $('submit').disabled = false;
    $('submit').textContent = 'Analisar link';
    $('result').removeAttribute('aria-busy');
  }
}

$('form').addEventListener('submit', e => { e.preventDefault(); run($('url').value); });
document.querySelectorAll('[data-example]').forEach(b => b.addEventListener('click', () => {
  if (!busy) { $('url').value = examples[b.dataset.example]; run($('url').value, true); }
}));

// ---------- avaliações ----------
let offset = 0, loadingReviews = false, requestId = null;

function reviewCard(r) {
  const article = document.createElement('article');
  article.className = 'review';
  const h = document.createElement('header'), name = document.createElement('strong'), date = document.createElement('time');
  name.textContent = r.name || 'Visitante';
  date.dateTime = r.createdAt;
  date.textContent = new Date(r.createdAt).toLocaleDateString('pt-BR');
  h.append(name, date);
  const stars = document.createElement('p');
  stars.className = 'stars';
  stars.textContent = '★'.repeat(r.rating) + '☆'.repeat(5 - r.rating);
  stars.setAttribute('aria-label', r.rating + ' de 5 estrelas');
  const body = document.createElement('p');
  body.textContent = r.comment || 'Avaliação enviada sem comentário.';
  const useful = document.createElement('small');
  useful.textContent = 'A explicação ajudou: ' + ({ yes: 'Sim', partly: 'Em parte', no: 'Não' }[r.useful]);
  article.append(h, stars, body, useful);
  return article;
}

async function loadReviews(append = false) {
  if (loadingReviews) return;
  loadingReviews = true;
  $('refresh-reviews').disabled = true;
  $('more-reviews').disabled = true;
  try {
    const res = await fetch('/api/reviews?offset=' + (append ? offset : 0), { cache: 'no-store' });
    if (!res.ok) throw Error();
    const data = await res.json();
    if (!Array.isArray(data.reviews) || !data.stats) throw Error();
    if (!append) { $('review-list').replaceChildren(); offset = 0; }
    $('average').textContent = data.stats.total ? data.stats.average.toLocaleString('pt-BR', { maximumFractionDigits: 1 }) : '—';
    $('useful-percent').textContent = data.stats.total ? Math.round(100 * data.stats.yes / data.stats.total) + '%' : '—';
    $('review-total').textContent = data.stats.total + (data.stats.total === 1 ? ' avaliação' : ' avaliações');
    data.reviews.forEach(r => $('review-list').append(reviewCard(r)));
    offset += data.reviews.length;
    $('more-reviews').hidden = offset >= data.stats.total;
    if (!data.stats.total) {
      const p = document.createElement('p');
      p.className = 'empty';
      p.textContent = 'Ainda não há avaliações. Seja a primeira pessoa a contar como foi usar o projeto.';
      $('review-list').append(p);
    }
  } catch {
    if (!append) {
      $('review-total').textContent = 'Avaliações indisponíveis no momento.';
      $('review-list').innerHTML = '<p class="empty">Não foi possível carregar os comentários. Tente atualizar em instantes.</p>';
    } else {
      $('review-message').textContent = 'Não foi possível carregar mais avaliações. Tente novamente.';
    }
  } finally {
    loadingReviews = false;
    $('refresh-reviews').disabled = false;
    $('more-reviews').disabled = false;
  }
}

$('review-comment').addEventListener('input', () => { $('char-count').textContent = $('review-comment').value.length; });
$('feedback-form').addEventListener('input', () => { requestId = null; });

let sendingReview = false;
$('feedback-form').addEventListener('submit', async e => {
  e.preventDefault();
  if (!apiAvailable || sendingReview) return;
  const reviewForm = e.currentTarget;
  const f = new FormData(e.currentTarget);
  requestId = requestId || crypto.randomUUID();
  const payload = {
    id: requestId,
    rating: Number(f.get('rating')),
    useful: f.get('useful'),
    name: String(f.get('name') || '').trim(),
    comment: String(f.get('comment') || '').trim(),
    consent: f.get('consent') === 'on'
  };
  sendingReview = true;
  const controls = Array.from(reviewForm.elements);
  controls.forEach(control => { control.disabled = true; });
  $('review-message').className = '';
  $('review-message').textContent = 'Salvando sua avaliação…';
  try {
    const res = await fetch('/api/reviews', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw Error(data.error || 'Não foi possível salvar.');
    $('review-message').className = 'success';
    $('review-message').textContent = 'Avaliação publicada. Obrigado por contribuir!';
    e.target.reset();
    $('char-count').textContent = '0';
    requestId = null;
    await loadReviews();
  } catch (err) {
    $('review-message').className = 'error';
    $('review-message').textContent =
      err.message === 'Failed to fetch'
        ? 'Sem conexão. Sua avaliação não foi confirmada; tente novamente.'
        : err.message;
  } finally {
    controls.forEach(control => { control.disabled = false; });
    sendingReview = false;
  }
});

$('refresh-reviews').addEventListener('click', () => loadReviews());
$('more-reviews').addEventListener('click', () => loadReviews(true));

if (apiAvailable) {
  loadReviews();
} else {
  $('average').textContent = '—';
  $('review-total').textContent = 'Comentários compartilhados disponíveis na versão conectada.';
  $('review-list').innerHTML = '<p class="empty">Este arquivo é a prévia offline. Abra o site pelo servidor para ler e publicar avaliações compartilhadas.</p>';
  $('send-review').disabled = true;
  $('refresh-reviews').disabled = true;
  $('review-message').textContent = 'O envio fica disponível na versão conectada. Nenhum comentário é salvo apenas neste navegador.';
}
