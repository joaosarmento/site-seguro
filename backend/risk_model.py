"""Deterministic evidence model. Points are engineering rules, not probabilities."""
import ipaddress
import math
import re
import unicodedata
from functools import lru_cache
from pathlib import Path

# Known official domains provide context only, never a score bonus or an exemption.
# This deliberately small catalogue is not an exhaustive identity verification service.
OFFICIAL = {
    'google': ('google.com','google.com.br','google.co.uk'),
    'paypal': ('paypal.com',), 'apple': ('apple.com','icloud.com'),
    'microsoft': ('microsoft.com','live.com','office.com'),
    'facebook': ('facebook.com',), 'instagram': ('instagram.com',),
    'whatsapp': ('whatsapp.com',), 'youtube': ('youtube.com',),
    'netflix': ('netflix.com',), 'amazon': ('amazon.com','amazon.com.br'),
    'mercadolivre': ('mercadolivre.com.br',), 'americanas': ('americanas.com.br',),
    'magazineluiza': ('magazineluiza.com.br',), 'nubank': ('nubank.com.br','nu.com.br'),
    'itau': ('itau.com.br',), 'bradesco': ('bradesco.com.br',),
    'santander': ('santander.com.br',), 'caixa': ('caixa.gov.br',),
    'sicoob': ('sicoob.com.br',), 'picpay': ('picpay.com',),
    'inter': ('bancointer.com.br',), 'c6bank': ('c6bank.com.br',),
    'gov': ('gov.br',), 'serpro': ('serpro.gov.br',),
    'receita': ('receita.fazenda.gov.br',), 'inss': ('inss.gov.br',),
    'steam': ('steampowered.com','steamcommunity.com'), 'twitch': ('twitch.tv',),
    'twitter': ('twitter.com','x.com'), 'tiktok': ('tiktok.com',),
    'binance': ('binance.com',), 'coinbase': ('coinbase.com',),
}

def ascii_host(host):
    return host.lower().rstrip('.').encode('idna').decode('ascii')

@lru_cache(maxsize=1)
def _suffix_rules():
    exact, wild, exceptions = set(), set(), set()
    for line in Path(__file__).with_name('data').joinpath('public_suffix_list.dat').read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('//'): continue
        if line.startswith('!'): exceptions.add(ascii_host(line[1:]))
        elif line.startswith('*.'): wild.add(ascii_host(line[2:]))
        else: exact.add(ascii_host(line))
    return frozenset(exact), frozenset(wild), frozenset(exceptions)

def registrable_domain(host):
    host = ascii_host(host)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError: pass
    labels = host.split('.')
    exact, wild, exceptions = _suffix_rules()
    size = 1
    for i in range(len(labels)):
        suffix = '.'.join(labels[i:])
        if suffix in exceptions:
            size = len(labels)-i-1
            break
        if suffix in exact: size = max(size,len(labels)-i)
        if i and suffix in wild: size = max(size,len(labels)-i+1)
    return '.'.join(labels[-(size+1):])

def _skeleton(label):
    try: label = label.encode('ascii').decode('idna')
    except (UnicodeError, ValueError): pass
    table = str.maketrans({'0':'o','1':'l','3':'e','5':'s','7':'t','4':'a',
                          'а':'a','е':'e','о':'o','р':'p','с':'c','у':'y','х':'x',
                          'і':'i','ј':'j','ӏ':'l','α':'a','ο':'o','ρ':'p','ν':'v'})
    return unicodedata.normalize('NFKC',label).lower().translate(table)

def _one_edit(a,b):
    if abs(len(a)-len(b))>1: return False
    if len(a)==len(b): return sum(x!=y for x,y in zip(a,b))==1
    if len(a)>len(b): a,b=b,a
    i=j=miss=0
    while i<len(a) and j<len(b):
        if a[i]==b[j]: i+=1;j+=1
        else:
            miss+=1;j+=1
            if miss>1:return False
    return True

def brand_signal(host):
    host=ascii_host(host)
    if any(host==d or host.endswith('.'+d) for domains in OFFICIAL.values() for d in domains): return None
    domain=registrable_domain(host)
    name=domain.split('.')[0]
    skeleton=_skeleton(name)
    for brand in OFFICIAL:
        code=None
        if skeleton==brand and name!=brand: code='brand_lookalike'
        elif name==brand: code='brand_unverified'
        elif brand in name.split('-'): code='brand_reference'
        elif len(brand)>=5 and len(name)>=5 and _one_edit(name,brand): code='brand_similar'
        elif any(_skeleton(part)==brand for part in host[:-len(domain)].strip('.').split('.')): code='brand_subdomain'
        if code:
            return {'code':code,'points':45 if code=='brand_lookalike' else 25,
                    'brand':brand,'domain':domain,
                    'detail':f'O endereço faz referência a {brand}, mas o domínio responsável é {domain}. Confira o canal oficial.'}
    return None

def age_signal(days):
    if not isinstance(days,int) or isinstance(days,bool) or days<0 or days>=90: return None
    return {'code':'recent_domain','points':round(12*math.exp(-days/30),2),
            'detail':f'Domínio registrado há {days} dia(s). Há pouco histórico para conferir a origem.'}

def decide_risk(*,technical_coverage,age_days,brands,reputation,content,tls_invalid,http,downgrade):
    reasons=[]
    def add(code,points,detail,critical=False):
        if not any(r['code']==code for r in reasons):
            reasons.append({'code':code,'points':points,'detail':detail,'critical':critical})
    for record in reputation:
        status=record.get('status')
        if status=='malicious': add('threat',100,'Uma fonte de segurança identificou ameaça neste link. Evite fornecer dados ou baixar arquivos.',True)
        elif status=='suspicious': add('reputation_suspicion',25,'Uma fonte indicou suspeita que precisa de confirmação. Confira a origem antes de enviar dados.')
        elif status=='historical': add('historical_threat',10,'Há um registro anterior de ameaça; a atividade atual precisa ser confirmada.')
    if tls_invalid: add('invalid_tls',90,'O certificado de segurança não passou na validação. Evite enviar dados.',True)
    if downgrade: add('downgrade',65,'O acesso mudou de HTTPS para HTTP e perdeu a proteção da conexão.',True)
    elif http: add('http',30,'O site usa HTTP e não protege os dados durante a transmissão.')
    for signal in brands+content:
        if signal: add(signal['code'],signal['points'],signal['detail'])
    age=age_signal(age_days)
    if age: add(age['code'],age['points'],age['detail'])
    points=round(min(100,sum(r['points'] for r in reasons)),2)
    codes={r['code'] for r in reasons}
    combined=('brand_lookalike' in codes or bool(codes & {'brand_unverified','brand_subdomain','brand_reference','brand_similar'})) and 'external_password_form' in codes
    band='bad' if any(r['critical'] for r in reasons) or points>=60 or combined else 'medium' if reasons else 'unknown' if technical_coverage<20 else 'good'
    reasons.sort(key=lambda r:(r['critical'],r['points']),reverse=True)
    labels={'bad':'Risco elevado','medium':'Atenção','unknown':'Análise limitada','good':'Sem alertas relevantes'}
    return {'band':band,'label':labels[band],'reasons':reasons,'points':points,
            'method':'evidence_rules_v1','calibrated':False}


def consolidate_score(technical_score, risk, reputation):
    """Combine observed quality with source-specific limits; never add a safety bonus."""
    severity_rank = {'none': 0, 'limited': 0, 'attention': 1, 'high': 2, 'critical': 3}
    translated = {'MALWARE': 'malware', 'SOCIAL_ENGINEERING': 'engenharia social',
                  'UNWANTED_SOFTWARE': 'software indesejado', 'MALWARE_DOWNLOAD': 'distribuição de malware'}
    severity, cap, findings, refs, threat_types = 'none', 100, [], [], []

    def apply(level, limit):
        nonlocal severity, cap
        if severity_rank[level] > severity_rank[severity]: severity = level
        cap = min(cap, limit)

    for index, record in enumerate(reputation):
        source, status = record.get('source', ''), record.get('status', 'unknown')
        if status not in ('malicious', 'suspicious', 'historical'): continue
        display = 'Google Safe Browsing' if source in ('Safe Browsing', 'Google Safe Browsing') else source or 'Fonte de reputação'
        scope = record.get('scope', 'url')
        raw_types = record.get('threatTypes') if isinstance(record.get('threatTypes'), list) else []
        types = [t for t in raw_types if isinstance(t, str) and t in translated]
        for threat in types:
            if threat not in threat_types: threat_types.append(threat)
        where = 'em um redirecionamento' if record.get('chainPosition') == 'intermediate' else 'neste endereço'
        if status == 'historical':
            level, limit = 'attention', 79
            age = record.get('ageDays')
            context = f'análise de {age} dias atrás' if isinstance(age, int) and age > 90 else 'registro sem data de análise confirmada'
            if source == 'VirusTotal':
                mal = record.get('maliciousEngines', 0)
                sus = record.get('suspiciousEngines', 0)
                detail = f'{display}: {context}, com {mal} malicioso(s) e {sus} suspeito(s); a atividade atual precisa ser confirmada.'
            else:
                detail = f'{display}: {context}; a atividade atual precisa ser confirmada.'
        elif source == 'URLhaus' and scope != 'url':
            level, limit = 'attention', 79
            detail = 'URLhaus: registro associado ao domínio; este link específico não foi confirmado.'
        elif source == 'VirusTotal':
            mal = record.get('maliciousEngines', 0)
            sus = record.get('suspiciousEngines', 0)
            age = record.get('ageDays')
            mal = mal if isinstance(mal, int) and not isinstance(mal, bool) and mal >= 0 else 0
            sus = sus if isinstance(sus, int) and not isinstance(sus, bool) and sus >= 0 else 0
            if not isinstance(age, int) or isinstance(age, bool) or age < 0 or age > 90:
                level, limit = 'attention', 79
                detail = f'VirusTotal: {mal} malicioso(s) e {sus} suspeito(s), sem análise recente confirmada.'
            elif mal >= 3:
                level, limit = 'critical', 10
                detail = f'VirusTotal: {mal} mecanismos classificaram a URL como maliciosa. Evite informar dados, pagar ou baixar arquivos.'
            elif mal:
                level, limit = 'high', 39
                engines = '1 mecanismo classificou' if mal == 1 else f'{mal} mecanismos classificaram'
                detail = f'VirusTotal: {engines} a URL como maliciosa. Evite informar dados, pagar ou baixar arquivos.'
            else:
                level, limit = 'attention', 69
                engines = '1 mecanismo sinalizou' if sus == 1 else f'{sus} mecanismos sinalizaram'
                detail = f'VirusTotal: {engines} suspeita. Confira a origem antes de continuar.'
        elif status == 'malicious':
            level, limit = 'critical', 10
            category = ', '.join(translated[t] for t in types)
            place = ' em um redirecionamento' if record.get('chainPosition') == 'intermediate' else ''
            detail = f'{display} sinalizou {category or "uma ameaça"}{place}. Evite informar dados, pagar ou baixar arquivos.'
        else:
            level, limit = 'attention', 69
            detail = f'{display} sinalizou uma suspeita {where}. Confira a origem antes de continuar.'
        apply(level, limit)
        refs.append(index)
        findings.append({'code': 'reputation', 'source': display, 'severity': level,
                         'maxScore': limit, 'critical': level == 'critical', 'detail': detail,
                         'evidenceRef': index})

    nonrep = [r for r in risk.get('reasons', []) if r.get('code') not in ('threat', 'reputation_suspicion', 'historical_threat')]
    codes = {r.get('code') for r in nonrep}
    nonrep_points = sum(r.get('points', 0) for r in nonrep)
    combined = bool(codes & {'brand_lookalike', 'brand_unverified', 'brand_subdomain', 'brand_reference', 'brand_similar'}) and 'external_password_form' in codes
    weak_sources = [r for r in findings if r['severity'] == 'attention']
    weak_points = max((10 if reputation[r['evidenceRef']].get('status') == 'historical' else 25 for r in weak_sources), default=0)
    aggregate_high = nonrep_points >= 60 or combined or bool(nonrep and nonrep_points + weak_points >= 60)
    strong_codes = {'invalid_tls', 'downgrade', 'insecure_password_form'}
    if codes & strong_codes or aggregate_high:
        apply('high', 39)
    elif nonrep:
        apply('attention', 79)
    elif not findings and risk.get('band') == 'unknown':
        severity = 'limited'
    prioritized = []
    for reason in nonrep:
        important = reason.get('code') in strong_codes or reason.get('points', 0) >= 60
        prioritized.append({**reason, 'severity': 'high' if important else 'attention', 'maxScore': 39 if important else 79})
    if aggregate_high and not any(r['severity'] == 'high' for r in prioritized):
        names = {'brand_lookalike':'grafia parecida com uma marca', 'brand_unverified':'nome de uma marca em outro domínio',
                 'brand_subdomain':'marca em um subdomínio', 'brand_reference':'nome de uma marca no endereço',
                 'brand_similar':'grafia parecida com uma marca', 'external_password_form':'senha enviada a outro domínio',
                 'recent_domain':'domínio recente', 'http':'conexão sem HTTPS (HTTP)', 'unsafe_form':'destino incomum no formulário'}
        components = [(r.get('points', 0), names.get(r.get('code'), 'outro sinal de atenção')) for r in nonrep]
        if weak_sources:
            source = max(weak_sources, key=lambda r: 10 if reputation[r['evidenceRef']].get('status') == 'historical' else 25)
            history = reputation[source['evidenceRef']].get('status') == 'historical'
            components.append((weak_points, ('registro histórico de ' if history else 'suspeita de ') + source['source']))
        chosen = [name for _, name in sorted(components, key=lambda item:item[0], reverse=True)[:2]]
        detail = 'A combinação de ' + ' e '.join(chosen) + ' aumenta o risco. Evite informar dados.'
        prioritized.append({'code':'combined_signals', 'severity':'high', 'maxScore':39,
                            'points':nonrep_points + weak_points, 'critical':False, 'detail':detail})
    all_reasons = findings + prioritized
    all_reasons.sort(key=lambda r: (r['maxScore'], not bool(r.get('critical')), -r.get('points', 0)))
    band = {'critical': 'bad', 'high': 'bad', 'attention': 'medium', 'limited': 'unknown', 'none': 'good'}[severity]
    label = {'critical': 'Ameaça identificada', 'high': 'Risco elevado', 'attention': 'Atenção',
             'limited': 'Análise limitada', 'none': 'Sem alertas relevantes'}[severity]
    decision = {'severity': severity, 'maxScore': cap, 'label': label,
                'threatTypes': sorted(threat_types), 'evidenceRefs': refs}
    result_risk = {**risk, 'band': band, 'label': label, 'reasons': all_reasons,
                   'method': 'consolidated_evidence_v1'}
    return min(technical_score, cap), decision, result_risk
