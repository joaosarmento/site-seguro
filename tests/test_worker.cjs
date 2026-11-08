const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');const vm=require('node:vm');const crypto=require('node:crypto');
function boot({stored=null,fetcher}={}){
 const file=path.join(__dirname,'../extensao/worker.js');assert.ok(fs.existsSync(file),'Worker ainda não implementado');
 const extensionId=JSON.parse(fs.readFileSync(path.join(__dirname,'../backend/extension-identity.json'))).id;
 let memory=stored;let listener;const timers=new Map();let tick=0;
 const context=vm.createContext({URL,AbortController,Date,structuredClone,crypto:{randomUUID:crypto.randomUUID},setTimeout(fn){timers.set(++tick,fn);return tick},clearTimeout(id){timers.delete(id)},fetch:fetcher||(async()=>{throw Error('rede inesperada')}),chrome:{runtime:{id:extensionId,getURL:p=>'chrome-extension://'+extensionId+'/'+p,onMessage:{addListener:f=>listener=f}},storage:{session:{async get(){return {analysis:memory}},async set(values){memory=structuredClone(values.analysis)}}}}});
 context.self=context;context.importScripts=(...names)=>names.forEach(name=>vm.runInContext(fs.readFileSync(path.join(__dirname,'../extensao',name),'utf8'),context));
 vm.runInContext(fs.readFileSync(file,'utf8'),context);
 return {send(message,sender){return new Promise(resolve=>listener(message,sender||{id:extensionId,url:'chrome-extension://'+extensionId+'/popup.html'},resolve))},async poll(){const pending=[...timers.entries()];timers.clear();for(const [,fn]of pending)await fn();await new Promise(resolve=>setImmediate(resolve));},get state(){return memory},extensionId};
}
const response=(code,data)=>({ok:code>=200&&code<300,status:code,json:async()=>data});
test('abrir popup não inicia análise nem acessa rede',async()=>{
 let calls=0;const w=boot({fetcher:async()=>{calls++;throw Error()}});const reply=await w.send({type:'GET_STATE',url:'https://example.com/'});assert.equal(reply.ok,true);assert.equal(reply.state,null);assert.equal(calls,0);
});
test('job rápido continua sem popup e guarda o resultado na sessão',async()=>{
 let polls=0;const w=boot({fetcher:async(url,init)=>{const body=JSON.parse(init.body);assert.equal(init.method,'POST');assert.equal(init.credentials,'omit');if(url.endsWith('/start')){assert.equal(body.url,'https://example.com/');return response(202,{jobId:'a'.repeat(32),state:'pending'})}polls++;return response(200,{state:'done',result:{scoringMethod:'consolidated_link_score_v1',decision:{severity:'none',maxScore:100},risk:{band:'good',label:'Sem alertas relevantes',reasons:[]},url:'https://example.com/',score:60,domainAgeDays:1,domainAgeRisk:{cap:60},capsApplied:[]}})}});
 const reply=await w.send({type:'START_ANALYSIS',url:'https://example.com/'});assert.equal(reply.state.phase,'pending');await w.poll();assert.equal(polls,1);assert.equal(w.state.phase,'done');assert.equal(w.state.result.score,60);
});
test('reinício do worker recupera job em vez de criar outro',async()=>{
 const previous={model:'consolidated_link_score_v1',requestId:'old',url:'https://example.com/',phase:'pending',jobId:'b'.repeat(32),createdAt:Date.now()-40000,updatedAt:Date.now()-35000};
 const w=boot({stored:previous,fetcher:async(url)=>{assert.ok(url.endsWith('/status'));return response(200,{state:'done',result:{scoringMethod:'consolidated_link_score_v1',decision:{severity:'none',maxScore:100},risk:{band:'good',label:'Sem alertas relevantes',reasons:[]},url:'https://example.com/',score:97,capsApplied:[]}})}});
 await w.send({type:'GET_STATE',url:'https://example.com/'});await w.poll();assert.equal(w.state.phase,'done');assert.equal(w.state.result.score,97);
});
test('resposta para outra URL não vira nota da aba atual',async()=>{
 const w=boot({fetcher:async(url)=>url.endsWith('/start')?response(202,{jobId:'c'.repeat(32)}):response(200,{state:'done',result:{scoringMethod:'consolidated_link_score_v1',decision:{severity:'none',maxScore:100},risk:{band:'good',label:'Sem alertas relevantes',reasons:[]},url:'https://other.example/',score:100}})});
 await w.send({type:'START_ANALYSIS',url:'https://example.com/'});await w.poll();assert.equal(w.state.phase,'error');assert.equal(w.state.result,undefined);
});
test('mensagem de outra origem e página interna não inicia job',async()=>{
 let calls=0;const w=boot({fetcher:async()=>{calls++;throw Error()}});
 assert.equal((await w.send({type:'START_ANALYSIS',url:'https://example.com/'},{id:'other',url:'https://attacker.example/'})).ok,false);
 assert.equal((await w.send({type:'START_ANALYSIS',url:'chrome://extensions/'})).ok,false);assert.equal(calls,0);
});
test('duplo clique durante análise não duplica job',async()=>{
 let starts=0;const w=boot({fetcher:async()=>{starts++;return response(202,{jobId:'d'.repeat(32)})}});
 await w.send({type:'START_ANALYSIS',url:'https://example.com/'});await w.send({type:'START_ANALYSIS',url:'https://example.com/'});assert.equal(starts,1);
});
test('job interrompido antes de receberID não deixa popup preso para sempre',async()=>{
 const w=boot({stored:{model:'consolidated_link_score_v1',requestId:'old',url:'https://example.com/',phase:'pending',createdAt:Date.now(),updatedAt:Date.now()}});
 const reply=await w.send({type:'GET_STATE',url:'https://example.com/'});assert.equal(reply.state.phase,'error');
});
test('aceitaURL canônica do motor sem perder a associação com a aba',async()=>{
 const input='https://example.com/?filter[]=a';const canonical='https://example.com/?filter%5B%5D=a';
 const w=boot({fetcher:async(url)=>url.endsWith('/start')?response(202,{jobId:'e'.repeat(32),url:canonical}):response(200,{state:'done',result:{scoringMethod:'consolidated_link_score_v1',decision:{severity:'none',maxScore:100},risk:{band:'good',label:'Sem alertas relevantes',reasons:[]},url:canonical,score:90,capsApplied:[]}})});
 await w.send({type:'START_ANALYSIS',url:input});await w.poll();assert.equal(w.state.phase,'done');assert.equal(w.state.url,input);assert.equal(w.state.result.score,90);
});
test('outro servidor na porta local gera orientação em vez de erro deparse',async()=>{
 const w=boot({fetcher:async()=>({ok:false,status:501,json:async()=>{throw new SyntaxError('Unexpected token <PRIVATE_DETAIL>')}})});
 await w.send({type:'START_ANALYSIS',url:'https://example.com/'});assert.equal(w.state.phase,'error');assert.match(w.state.error,/servidor deste pacote/);assert.doesNotMatch(w.state.error,/PRIVATE_DETAIL|Unexpected/);
});
test('motor antigo não é apresentado como nova análise de risco',async()=>{
 const w=boot({fetcher:async(url)=>url.endsWith('/start')?response(202,{jobId:'f'.repeat(32)}):response(200,{state:'done',result:{url:'https://example.com/',score:100}})});
 await w.send({type:'START_ANALYSIS',url:'https://example.com/'});await w.poll();assert.equal(w.state.phase,'error');assert.match(w.state.error,/servidor deste pacote/);
});
test('resultado antigo em sessão é descartado após atualização',async()=>{
 const w=boot({stored:{model:'technical_index_v3_risk_separate',url:'https://example.com/',phase:'done',createdAt:Date.now(),result:{score:100,band:'good',riskBand:'bad',label:'Risco elevado',reasons:[]}}});
 assert.equal((await w.send({type:'GET_STATE',url:'https://example.com/'})).state,null);
});
