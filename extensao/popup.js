'use strict';
const $ = id => document.getElementById(id);
let currentUrl = null;

function showError(message, unsupported = false) {
  $('result').hidden = true;
  $('status').hidden = false;
  $('status').dataset.error = 'true';
  $('status').dataset.busy = 'false';
  $('status').textContent = String(message || 'Não foi possível analisar o site. Tente novamente.').slice(0, 240);
  $('analyze').disabled = unsupported;
  $('analyze').textContent = 'Tentar novamente';
}

function renderState(state) {
  $('status').hidden = true;
  $('status').textContent = '';
  $('status').dataset.error = 'false';
  $('status').dataset.busy = 'false';
  $('result').hidden = true;
  $('analyze').disabled = false;
  $('analyze').textContent = 'Analisar site';
  if (!state) return;
  if (state.phase === 'pending') {
    $('status').hidden = false;
    $('status').dataset.busy = 'true';
    $('status').textContent = 'Analisando o site…';
    $('analyze').disabled = true;
    $('analyze').textContent = 'Analisando…';
  } else if (state.phase === 'error') {
    showError(state.error);
  } else if (state.phase === 'done') {
    const view = state.result;
    if (!view || typeof view.score !== 'number' || !Number.isFinite(view.score) || view.score < 0 || view.score > 100 ||
        !['good', 'medium', 'bad', 'unknown'].includes(view.band)) return showError('O resultado não está disponível. Analise novamente.');
    $('score').textContent = String(Math.round(view.score));
    $('label').textContent = String(view.label || 'Pontuação do link');
    $('result').dataset.band = view.band;
    $('result').dataset.riskBand = view.riskBand || view.band;
    $('progress').setAttribute('stroke-dashoffset', String(326.73 * (1 - view.score / 100)));
    $('reasons').replaceChildren();
    const reasons = Array.isArray(view.reasons) ? view.reasons.filter(r => typeof r === 'string').slice(0, 2) : [];
    for (const text of reasons) {
      const item = document.createElement('li');
      item.textContent = text.slice(0, 220);
      $('reasons').append(item);
    }
    $('reasons').hidden = !reasons.length;
    $('result').hidden = false;
    $('analyze').textContent = 'Analisar novamente';
  }
}

async function request(type) {
  const reply = await chrome.runtime.sendMessage({type, url: currentUrl});
  if (!reply?.ok) throw Error(reply?.error || 'Não foi possível analisar o site.');
  if (reply.state && reply.state.url !== currentUrl) throw Error('Abra novamente a extensão para analisar esta aba.');
  renderState(reply.state);
}

async function init() {
  const link = SiteSeguro.projectLink(SITE_SEGURO_CONFIG);
  $('project-link').href = link.url;
  $('project-link').textContent = link.label;
  try {
    const tabs = await chrome.tabs.query({active: true, currentWindow: true});
    currentUrl = SiteSeguro.normalizeUrl(tabs[0]?.url);
  } catch (error) {
    $('hostname').textContent = 'Página não compatível';
    showError(error.message || 'Abra uma página HTTP ou HTTPS para analisar.', true);
    return;
  }
  $('hostname').textContent = new URL(currentUrl).hostname;
  $('hostname').setAttribute('title', new URL(currentUrl).hostname);
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'session' || !changes.analysis) return;
    const next = changes.analysis.newValue;
    if (next?.url === currentUrl || next === null) renderState(next);
  });
  $('analyze').addEventListener('click', async () => {
    if (!currentUrl || $('analyze').disabled) return;
    renderState({phase: 'pending'});
    try { await request('START_ANALYSIS'); } catch (error) { showError(error.message); }
  });
  await request('GET_STATE');
}

init().catch(() => showError('Abra novamente a extensão e tente analisar o site.'));
