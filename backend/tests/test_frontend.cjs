'use strict';
const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const test=require('node:test');
const path=require('node:path');
const elements=new Map();
function element(id){
  if(!elements.has(id))elements.set(id,{innerHTML:'',textContent:'',disabled:false,addEventListener(){}});
  return elements.get(id);
}
const context=vm.createContext({
  document:{getElementById:element,querySelectorAll(){return[];}},
  location:{protocol:'file:'},URL,console,setTimeout,clearTimeout
});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../dist/analysis.js'),'utf8'),context);
for(const [value,band] of [[0,'bad'],[40,'bad'],[49,'bad'],[50,'medium'],[79,'medium'],[80,'good'],[100,'good'],[null,'unknown']]){
  test(`faixa visual para ${value}: ${band}`,()=>{
    assert.equal(vm.runInContext(`scorePresentation(${JSON.stringify(value)}).band`,context),band);
  });
}
test('inconclusivo prevalece sobre número antigo em cache',()=>{
  assert.equal(vm.runInContext('scorePresentation(95, true).band',context),'unknown');
});
test('resultado remoto 40 usa a classe vermelha e legenda textual',()=>{
  context.payload={score:40,level:'baixo',hostname:'example.com',coverage:40,verifiedChecks:3,totalScoredChecks:9,checks:[]};
  vm.runInContext('renderRemote(payload)',context);
  assert.match(element('result').innerHTML,/score-ring score-bad/);
  assert.match(element('result').innerHTML,/Ruim/);
});
test('demonstrações geram faixas distintas',()=>{
  assert.equal(vm.runInContext('scorePresentation(evaluateLocal(examples.low).score).band',context),'good');
  assert.equal(vm.runInContext('scorePresentation(evaluateLocal(examples.medium).score).band',context),'medium');
  assert.equal(vm.runInContext('scorePresentation(evaluateLocal(examples.high).score).band',context),'bad');
});

test('resultado inconclusivo não mostra porcentagem de payload antigo',()=>{
  context.payload={score:95,level:'inconclusivo',hostname:'example.com',coverage:70,verifiedChecks:8,totalScoredChecks:9,checks:[]};
  vm.runInContext('renderRemote(payload)',context);
  assert.match(element('result').innerHTML,/score-ring score-unknown/);
  assert.doesNotMatch(element('result').innerHTML,/95%/);
  assert.match(element('result').innerHTML,/<strong>—<\/strong>/);
});
function render(payload){
  context.payload=payload;
  vm.runInContext('renderRemote(payload)',context);
  return element('result').innerHTML;
}
test('ameaça aparece antes da pontuação vermelha e escapa dados das fontes',()=>{
 const html=render({score:10,technicalScore:100,decision:{severity:'critical',maxScore:10,evidenceRefs:[0]},hostname:'example.com',reputationResults:[{source:'<img src=x>',status:'malicious',scope:'url'}],risk:{band:'bad',label:'Ameaça identificada',reasons:[{detail:'<img src=x> Ameaça identificada.',critical:true,evidenceRef:0}]},checks:[]});
 assert.match(html,/10%/);assert.doesNotMatch(html,/100%/);assert.match(html,/score-ring score-bad/);
 assert.match(html,/Pontuação do link/);assert.ok(html.indexOf('risk-alert') < html.indexOf('score-ring'));assert.doesNotMatch(html,/<img/);
});
test('servidor antigo não entrega nota técnica como se fosse pontuação consolidada',async()=>{
 context.AbortController=AbortController;
 context.fetch=async()=>({ok:true,json:async()=>({score:100,scoringMethod:'technical_index_v3_risk_separate',risk:{band:'medium'}})});
 await assert.rejects(vm.runInContext("evaluateRemote('https://example.com/')",context),/servidor deste pacote/i);
});
const internalDetails=/reputação não verificada|fontes indisponíveis|teto|peso total|pontos avaliados|antes dos limites|não comprova|não é probabilidade|cálculo observado|análise parcial/i;

test('resultado favorável mantém índice, coberturas e nota de oficialidade sem alertas internos',()=>{
  const html=render({score:97,measuredScore:97,level:'alto',partial:true,coverage:65,technicalCoverage:100,hostname:'www.apple.com',reputationStatus:'unverified',reputationSourcesChecked:0,domainAgeDays:14504,techSummary:'TLSv1.2 · 3 IPs',verdict:'Reputação não verificada. Nada disso é prova de legitimidade.',checks:[{max:10,score:null,detail:'Fontes indisponíveis ficam fora do cálculo observado.'}],capsApplied:[]});
  assert.match(html,/97%/);
  assert.match(html,/Pontuação do link/);
  assert.doesNotMatch(html,internalDetails);
  assert.doesNotMatch(html,/risk-alert|<details|O que entrou no cálculo/);
  assert.match(html,/Cobertura técnica[\s\S]*100%/);
  assert.match(html,/Cobertura de dados[\s\S]*65%/);
  assert.match(html,/não confirma que o site é oficial/);
  assert.doesNotMatch(html,/site seguro|site confiável|legitimidade confirmada/i);
});

test('domínio recente mostra apenas a razão de cautela e o índice calculado',()=>{
  const html=render({score:60,measuredScore:94,level:'medio',hostname:'example.com',domainAgeDays:1,domainAgeRisk:{status:'very_recent',cap:60,detail:'Teto60; não comprova fraude.'},capsApplied:[{name:'Domínio recém-registrado (menos de 7 dias)',value:60}],checks:[]});
  assert.match(html,/score-ring score-medium/);
  assert.match(html,/Domínio recente/);
  assert.match(html,/1 dia/);
  assert.match(html,/pouco histórico/);
  assert.doesNotMatch(html,/94\/100/);
  assert.doesNotMatch(html,internalDetails);
});

test('alertas reais de ameaça e certificado continuam visíveis sem termos de cálculo',()=>{
  const html=render({score:5,level:'baixo',hostname:'example.com',reputationStatus:'alert',capsApplied:[{name:'URL em base de ameaças',value:5},{name:'Certificado inválido',value:40}],checks:[]});
  assert.match(html,/ameaça/i);
  assert.match(html,/certificado/i);
  assert.match(html,/não passou/i);
  assert.doesNotMatch(html,internalDetails);
});

test('downgrade tem uma explicação sem alerta HTTP duplicado',()=>{
  const html=render({score:35,level:'baixo',hostname:'example.com',capsApplied:[{name:'Downgrade HTTPS→HTTP',value:35},{name:'URL final sem HTTPS',value:55}],checks:[]});
  assert.match(html,/mudou de HTTPS para HTTP/);
  assert.equal((html.match(/class="risk-alert /g)||[]).length,1);
  assert.doesNotMatch(html,internalDetails);
});

test('senha enviada a outro domínio e grafia enganosa mantêm motivos específicos',()=>{
  const html=render({score:40,level:'baixo',hostname:'example.com',capsApplied:[{name:'Sinais de atenção no conteúdo',value:60},{name:'Imitação por homóglifos',value:40}],checks:[]});
  assert.match(html,/senha/i);
  assert.match(html,/outro domínio/i);
  assert.match(html,/letras e números/i);
  assert.doesNotMatch(html,internalDetails);
});

test('impossibilidade de acesso é um estado neutro e não uma suspeita de fraude',()=>{
  const html=render({score:55,level:'medio',hostname:'example.com',technicalCoverage:5,appliedCap:{name:'Poucos dados técnicos',value:55},capsApplied:[],checks:[]});
  assert.match(html,/Não foi possível acessar/);
  assert.doesNotMatch(html,/risk-alert|fraude|ameaça/i);
  assert.doesNotMatch(html,internalDetails);
});

test('hostname e descrições recebidos do servidor continuam escapados',()=>{
  const html=render({score:60,level:'medio',hostname:'<img src=x onerror=alert(1)>',domainAgeDays:'<script>bad()</script>',domainAgeRisk:{cap:60},capsApplied:[],checks:[{title:'<img src=x onerror=alert(1)>',score:1,max:1,detail:'<script>bad()</script>'}]});
  assert.doesNotMatch(html,/<img|<script>/);
  assert.match(html,/&lt;img/);
});

test('tópicos verificados voltam com suas descrições e sem pontos internos',()=>{
  const html=render({score:97,level:'alto',hostname:'example.com',technicalCoverage:100,coverage:65,domainAgeDays:5000,domainCreated:'2010-01-01',checks:[
    {title:'Certificado e TLS',score:55,max:55,detail:'TLSv1.3 · emissor Test CA',category:'TLS'},
    {title:'Cabeçalhos de segurança',score:7,max:10,detail:'Presentes: nosniff. Faltando: CSP.',category:'Cabeçalhos'},
    {title:'Resolução DNS',score:null,max:0,detail:'93.184.215.14',category:'DNS'},
    {title:'HSTS',score:null,max:0,detail:'max-age=31536000s',category:'Cabeçalhos'},
    {title:'Idade do domínio',score:null,max:0,detail:'Teto interno não deve aparecer.',category:'Domínio'},
    {title:'Threat Intelligence',score:null,max:0,detail:'Reputação não verificada.',category:'Reputação'}],capsApplied:[]});
  assert.match(html,/Tópicos verificados/);
  for(const name of ['Certificado e TLS','Cabeçalhos de segurança','Resolução DNS','HSTS','Idade do domínio'])assert.ok(html.includes(name));
  assert.match(html,/Test CA/);
  assert.match(html,/Faltando: CSP/);
  assert.match(html,/5000 dias/);
  assert.doesNotMatch(html,internalDetails);
  assert.doesNotMatch(html,/Threat Intelligence|55 \/ 55/);
});

test('tentativa sem resultado não é apresentada como tópico validado',()=>{
  const html=render({score:55,level:'medio',hostname:'example.com',technicalCoverage:5,coverage:3,checks:[
    {title:'Certificado e TLS',score:null,max:55,detail:'Tempo limite',category:'TLS'},
    {title:'Resolução DNS',score:null,max:0,detail:'Não foi possível resolver o domínio',category:'DNS'},
    {title:'Idade do domínio',score:null,max:0,detail:'Não verificado',category:'Domínio'}],capsApplied:[]});
  assert.doesNotMatch(html,/Tópicos verificados|Certificado e TLS|Resolução DNS|Idade do domínio/);
  assert.match(html,/Cobertura técnica[\s\S]*5%/);
  assert.match(html,/Cobertura de dados[\s\S]*3%/);
});
