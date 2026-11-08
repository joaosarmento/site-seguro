const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');const vm=require('node:vm');
function api(){const file=path.join(__dirname,'../extensao/common.js');assert.ok(fs.existsSync(file),'Adaptador da extensão ainda não implementado');const c=vm.createContext({URL});c.self=c;vm.runInContext(fs.readFileSync(file,'utf8'),c);return c.SiteSeguro;}
test('normaliza endereço da aba e remove apenas fragmento',()=>{
 assert.equal(api().normalizeUrl('https://www.apple.com/a?x=1#secao'),'https://www.apple.com/a?x=1');
});
for(const url of ['chrome://extensions/','file:///tmp/a','javascript:alert(1)','https://user:pass@example.com/','https://example.com:22/'])test('não analisa destino incompatível '+url,()=>assert.throws(()=>api().normalizeUrl(url)));
for(const [score,band] of [[0,'bad'],[49,'bad'],[50,'medium'],[79,'medium'],[80,'good'],[100,'good']])test('cor do índice '+score,()=>assert.equal(api().presentation({score,capsApplied:[]}).band,band));
test('domínio recente mantém nota do servidor e razão curta',()=>{
 const result=api().presentation({score:60,domainAgeDays:1,domainAgeRisk:{cap:60},capsApplied:[]});
 assert.equal(result.score,60);assert.match(result.reasons.join(' '),/1 dia/);assert.doesNotMatch(JSON.stringify(result),/teto|cobertura|reputação não verificada/i);
});
test('ameaça e certificado têm prioridade sobre motivo de idade',()=>{
 const result=api().presentation({score:5,reputationStatus:'alert',domainAgeDays:1,domainAgeRisk:{cap:60},capsApplied:[{name:'Certificado inválido',value:40}]});
 assert.equal(result.reasons.length,2);assert.match(result.reasons.join(' '),/ameaça/);assert.match(result.reasons.join(' '),/certificado/);
});
test('resultado bom não inventa aprovação nem avisos de configuração',()=>{
 const result=api().presentation({score:97,reputationStatus:'unverified',capsApplied:[]});
 assert.equal(result.label,'Favorável');assert.equal(result.reasons.length,0);
});
test('retorno inválido não vira uma nota inventada',()=>{
 for(const score of [null,undefined,-1,101,'97',NaN])assert.throws(()=>api().presentation({score}));
});
test('ameaça tem pontuação vermelha e preserva a fonte mesmo com dados técnicos perfeitos',()=>{
 const r=api().presentation({score:10,technicalScore:100,decision:{severity:'critical',maxScore:10},risk:{band:'bad',label:'Ameaça identificada',reasons:[{detail:'Google Safe Browsing sinalizou malware.'}]}});
 assert.equal(r.score,10);assert.equal(r.band,'bad');assert.equal(r.riskBand,'bad');assert.match(r.reasons[0],/Google Safe Browsing/);
});
test('dados insuficientes têm classificação neutra sem inventar ameaça',()=>{
 const r=api().presentation({score:50,decision:{severity:'limited',maxScore:100},risk:{band:'unknown',label:'Análise limitada',reasons:[]}});
 assert.equal(r.band,'unknown');assert.equal(r.riskBand,'unknown');assert.equal(r.reasons.length,0);
});
test('contrato inconsistente não mostra pontuação acima do limite de risco',()=>{
 const r=api().presentation({score:100,decision:{severity:'critical',maxScore:10},risk:{band:'bad',label:'Ameaça',reasons:[]}});
 assert.equal(r.score,10);assert.equal(r.band,'bad');
});
test('link funciona localmente e aceita futuro siteHTTPS sem URL da aba',()=>{
 assert.equal(api().projectLink({API_BASE_URL:'http://127.0.0.1:8765',PUBLIC_SITE_URL:null}).url,'http://127.0.0.1:8765/');
 assert.equal(api().projectLink({API_BASE_URL:'http://127.0.0.1:8765',PUBLIC_SITE_URL:'https://projeto.example/site'}).url,'https://projeto.example/site');
});
test('link do projeto rejeita javascript, credenciais eHTTP externo',()=>{
 for(const url of ['javascript:alert(1)','https://user:pass@example.com','http://attacker.example'])assert.throws(()=>api().projectLink({API_BASE_URL:'http://127.0.0.1:8765',PUBLIC_SITE_URL:url}));
});
test('aba semURL disponível orienta abrir um siteHTTPouHTTPS',()=>assert.throws(()=>api().normalizeUrl(undefined),/HTTP ou HTTPS/));
