'use strict';
(() => {
  function normalizeUrl(value) {
    if (typeof value !== 'string' || !value) throw Error('Abra um site HTTP ou HTTPS para analisar.');
    if (value.length > 2048 || /[\s\\\x00-\x1f\x7f]/.test(value))
      throw Error('Não foi possível reconhecer o endereço desta aba.');
    let url;
    try { url = new URL(value); } catch { throw Error('Não foi possível reconhecer o endereço desta aba.'); }
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname)
      throw Error('Abra um site HTTP ou HTTPS para analisar.');
    if (url.username || url.password) throw Error('Não analise endereços com usuário ou senha embutidos.');
    if (url.port && !['80', '443'].includes(url.port)) throw Error('Use um site nas portas web padrão80 ou443.');
    url.hash = '';
    return url.href;
  }

  function presentation(result) {
    if (!result || typeof result.score !== 'number' || !Number.isFinite(result.score) || result.score < 0 || result.score > 100)
      throw Error('O servidor devolveu um resultado inválido. Tente novamente.');
    if (result.risk && ['good','medium','bad','unknown'].includes(result.risk.band)) {
      const risk = result.risk;
      const limits = {critical:10, high:39, attention:79, none:100, limited:100};
      const bandLimits = {bad:39, medium:79, good:100, unknown:100};
      const decision = result.decision;
      if (!decision || !(decision.severity in limits) || typeof decision.maxScore !== 'number' ||
          !Number.isFinite(decision.maxScore) || decision.maxScore < 0 || decision.maxScore > 100)
        throw Error('O serviço de análise precisa ser atualizado. Tente novamente mais tarde.');
      const score = Math.min(result.score, decision.maxScore, limits[decision.severity], bandLimits[risk.band]);
      const band = risk.band === 'unknown' || decision.severity === 'limited' ? 'unknown' : score >= 80 ? 'good' : score >= 50 ? 'medium' : 'bad';
      const shortReasons = {
        brand_lookalike:'O endereço troca caracteres para se parecer com uma marca conhecida.',
        brand_unverified:'O domínio usa o nome de uma marca; o vínculo não foi confirmado.',
        brand_subdomain:'O endereço usa uma marca no subdomínio de outro site.',
        brand_similar:'O nome do domínio é parecido com o de uma marca conhecida.',
        external_password_form:'Um campo de senha envia para outro domínio. Confira o destino.'
      };
      return {score, band, riskBand:band, label:String(risk.label || 'Análise limitada'),
        scoringMethod:'consolidated_link_score_v1',
        reasons:Array.isArray(risk.reasons) ? risk.reasons.map(r => shortReasons[r.code] || r.detail).filter(t => typeof t === 'string').slice(0,2) : []};
    }

    const score = result.score;
    const names = new Set((result.capsApplied || []).map(c => c.name));
    const reasons = [];
    if (result.reputationStatus === 'alert' || names.has('URL em base de ameaças')) reasons.push('Uma base de segurança sinalizou possível ameaça neste link.');
    if (names.has('Certificado inválido')) reasons.push('O certificado de segurança do site não é confiável. Evite enviar dados.');
    if (names.has('Downgrade HTTPS→HTTP')) reasons.push('O acesso mudou de HTTPS para HTTP e perdeu a proteção da conexão.');
    else if (names.has('URL final sem HTTPS')) reasons.push('O site usa HTTP e não protege os dados durante a transmissão.');
    if (names.has('Sinais de atenção no conteúdo')) reasons.push('Um campo de senha aponta para outro domínio. Confira o destino.');
    if (names.has('Imitação por homóglifos')) reasons.push('O endereço troca letras por números para imitar uma marca conhecida.');
    else if (names.has('Semelhança de nome a conferir')) reasons.push('O nome do domínio pode ser confundido com o de uma marca conhecida.');
    if (result.domainAgeRisk?.cap != null || [...names].some(n => /^Domínio (recente|recém-registrado)/.test(n))) {
      const days = result.domainAgeDays;
      const age = Number.isInteger(days) && days >= 0 ? days === 0 ? 'há menos de um dia' : `há ${days} ${days === 1 ? 'dia' : 'dias'}` : 'recentemente';
      reasons.push(`Domínio registrado ${age}. Há pouco histórico para conferir a origem.`);
    }
    let band = score >= 80 ? 'good' : score >= 50 ? 'medium' : 'bad';
    let label = score >= 80 ? 'Favorável' : score >= 50 ? 'Atenção' : 'Ruim';
    if (!reasons.length && typeof result.technicalCoverage === 'number' && result.technicalCoverage < 20) {
      label = 'Análise limitada';
      reasons.push('Não foi possível acessar o site para completar a análise.');
    }
    return {score, band, label, reasons: reasons.slice(0, 2)};
  }

  function projectLink(config) {
    const local = !config.PUBLIC_SITE_URL;
    let url;
    try { url = new URL(config.PUBLIC_SITE_URL || config.API_BASE_URL + '/'); }
    catch { throw Error('O link do projeto precisa ser configurado.'); }
    if (url.username || url.password || !(['https:'].includes(url.protocol) ||
        url.protocol === 'http:' && url.hostname === '127.0.0.1'))
      throw Error('O link do projeto deve usar HTTPS ou o servidor local.');
    return {url: url.href, label: local ? 'Abrir versão web (local) ↗' : 'Abrir site completo ↗'};
  }
  self.SiteSeguro = Object.freeze({normalizeUrl, presentation, projectLink});
})();
