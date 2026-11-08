'use strict';
importScripts('config.js', 'common.js');

const API = SITE_SEGURO_CONFIG.API_BASE_URL;
const TTL = 300000;
const MODEL = 'consolidated_link_score_v1';
let state = null;
let timer = null;
let writes = Promise.resolve();
const ready = chrome.storage.session.get('analysis').then(async data => {
  const saved = data.analysis;
  if (saved && saved.model === MODEL && (saved.phase !== 'done' || saved.result?.scoringMethod === MODEL) && typeof saved.createdAt === 'number' && Date.now() - saved.createdAt < TTL &&
      ['pending', 'done', 'error'].includes(saved.phase)) {
    try {
      SiteSeguro.normalizeUrl(saved.url);
      state = saved.phase === 'pending' && !saved.jobId
        ? {...saved, phase: 'error', error: 'A análise anterior foi interrompida. Analise novamente.'} : saved;
      if (state !== saved) await chrome.storage.session.set({analysis: state});
    } catch { /* Discard invalid session data. */ }
  }
  if (!state && saved) await chrome.storage.session.set({analysis: null});
});

function persist(next) {
  state = next;
  const snapshot = structuredClone(next);
  writes = writes.catch(() => {}).then(() => chrome.storage.session.set({analysis: snapshot}));
  return writes;
}

async function post(path, body) {
  const abort = new AbortController();
  const timeout = setTimeout(() => abort.abort(), 8000);
  try {
    const response = await fetch(API + path, {method: 'POST', credentials: 'omit', cache: 'no-store',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body), signal: abort.signal});
    const data = await response.json().catch(() => { throw Error('O serviço de análise respondeu de forma inesperada. Tente novamente mais tarde.'); });
    if (!response.ok) {
      if ([404, 405].includes(response.status)) throw Error('A análise pode ter expirado ou o serviço ainda não está atualizado. Tente novamente.');
      if (response.status === 429) throw Error('Há análises em andamento. Tente novamente em instantes.');
      throw Error(typeof data.error === 'string' ? data.error : 'Não foi possível concluir a análise.');
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError' || error instanceof TypeError)
      throw Error('O serviço de análise não respondeu. Confira sua conexão e tente novamente em instantes.');
    throw error;
  } finally { clearTimeout(timeout); }
}

function schedule(requestId, delay = 1200) {
  if (timer !== null) clearTimeout(timer);
  timer = setTimeout(async () => { timer = null; await poll(requestId); }, delay);
}

async function poll(requestId) {
  if (!state || state.requestId !== requestId || state.phase !== 'pending' || !state.jobId) return;
  try {
    const data = await post('/api/extension/status', {jobId: state.jobId});
    if (!state || state.requestId !== requestId || state.phase !== 'pending') return;
    if (data.state === 'pending') {
      if (Date.now() - state.createdAt > 180000) throw Error('A análise demorou demais. Tente novamente.');
      // Session updates retain progress and reset Chrome's worker idle timer.
      await persist({...state, updatedAt: Date.now()});
      if (state?.requestId === requestId) schedule(requestId);
    } else if (data.state === 'done') {
      if (SiteSeguro.normalizeUrl(data.result?.url) !== (state.analysisUrl || state.url)) throw Error('O resultado não corresponde a este endereço. Analise novamente.');
      if (data.result?.scoringMethod !== MODEL || !data.result?.risk || !data.result?.decision)
        throw Error('O serviço de análise precisa ser atualizado. Tente novamente mais tarde.');
      const result = SiteSeguro.presentation(data.result);
      await persist({...state, phase: 'done', result, updatedAt: Date.now()});
    } else if (data.state === 'error') {
      throw Error(typeof data.error === 'string' ? data.error : 'Não foi possível concluir a análise.');
    } else throw Error('O servidor devolveu uma resposta inválida. Tente novamente.');
  } catch (error) {
    if (state?.requestId === requestId && state.phase === 'pending')
      await persist({...state, phase: 'error', error: error.message || 'Não foi possível concluir a análise.', updatedAt: Date.now()});
  }
}

async function handle(message) {
  await ready;
  if (!message || !['GET_STATE', 'START_ANALYSIS'].includes(message.type)) throw Error('Pedido inválido.');
  const url = SiteSeguro.normalizeUrl(message.url);
  if (state && Date.now() - state.createdAt >= TTL) await persist(null);
  if (message.type === 'GET_STATE') {
    if (state?.phase === 'pending' && state.jobId) schedule(state.requestId, 0);
    return {ok: true, state: state?.url === url ? state : null};
  }
  if (state?.url === url && state.phase === 'pending') {
    if (state.jobId) schedule(state.requestId, 0);
    return {ok: true, state};
  }
  const requestId = crypto.randomUUID();
  await persist({model: MODEL, requestId, url, phase: 'pending', createdAt: Date.now(), updatedAt: Date.now()});
  try {
    const job = await post('/api/extension/start', {url});
    if (!/^[A-Za-z0-9_-]{32}$/.test(job.jobId || '')) throw Error('O servidor devolveu uma resposta inválida. Tente novamente.');
    if (state?.requestId === requestId) {
      await persist({...state, jobId: job.jobId, analysisUrl: SiteSeguro.normalizeUrl(job.url || url), updatedAt: Date.now()});
      schedule(requestId);
    }
  } catch (error) {
    if (state?.requestId === requestId && state.phase === 'pending')
      await persist({...state, phase: 'error', error: error.message || 'Não foi possível iniciar a análise.', updatedAt: Date.now()});
  }
  return {ok: true, state: state?.url === url ? state : null};
}

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL('popup.html')) {
    reply({ok: false, error: 'Pedido não autorizado.'});
    return false;
  }
  handle(message).then(reply).catch(() => reply({ok: false, error: 'Não foi possível analisar esta página. Abra um endereço HTTP ou HTTPS e tente novamente.'}));
  return true;
});
