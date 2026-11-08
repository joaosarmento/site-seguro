const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');const vm=require('node:vm');
async function popup({url='https://www.apple.com/',saved=null}={}){
 const file=path.join(__dirname,'../extensao/popup.js');assert.ok(fs.existsSync(file),'Popup ainda não implementado');
 class Element{constructor(){this.textContent='';this.hidden=false;this.disabled=false;this.dataset={};this.attributes={};this.children=[];this.listeners={};}set innerHTML(v){throw Error('innerHTML proibido no popup')}setAttribute(k,v){this.attributes[k]=String(v)}addEventListener(k,v){this.listeners[k]=v}append(...v){this.children.push(...v)}replaceChildren(...v){this.children=[...v]}}
 const elements=new Map();const element=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id)};
 const sent=[];let storageListener;
 const context=vm.createContext({URL,console,document:{getElementById:element,createElement:()=>new Element()},chrome:{tabs:{query:async()=>[{url}]},runtime:{sendMessage:async msg=>{sent.push(msg);return {ok:true,state:saved}}},storage:{onChanged:{addListener:fn=>storageListener=fn}}}});context.self=context;
 for(const name of ['config.js','common.js','popup.js'])vm.runInContext(fs.readFileSync(path.join(__dirname,'../extensao',name),'utf8'),context);
 await new Promise(resolve=>setImmediate(resolve));
 return {element,sent,async update(state){storageListener({analysis:{newValue:state}},'session');await new Promise(resolve=>setImmediate(resolve))}};
}
test('abrir popup apenas identifica aba e oferece análise manual',async()=>{
 const p=await popup();assert.equal(p.element('hostname').textContent,'www.apple.com');assert.equal(p.element('analyze').disabled,false);assert.equal(p.sent.length,1);assert.equal(p.sent[0].type,'GET_STATE');assert.equal(p.element('project-link').href,'http://127.0.0.1:8765/');
});
test('resultado compacto mostra nota e motivo sem detalhes internos',async()=>{
 const p=await popup({url:'https://example.com/',saved:{url:'https://example.com/',phase:'done',result:{score:60,band:'medium',label:'Atenção',reasons:['Domínio registrado há1dia.']}}});
 assert.equal(p.element('score').textContent,'60');assert.equal(p.element('result').dataset.band,'medium');assert.match(p.element('reasons').children[0].textContent,/1dia/);assert.equal(p.element('status').hidden,true);
});
test('páginas internas doChrome não são enviadas ao motor',async()=>{
 const p=await popup({url:'chrome://extensions/'});assert.equal(p.element('analyze').disabled,true);assert.equal(p.sent.length,0);assert.match(p.element('status').textContent,/HTTP/);
});
test('resultado de outra aba não altera o resultado atual',async()=>{
 const p=await popup();await p.update({url:'https://other.example/',phase:'done',result:{score:5,band:'bad',label:'Ruim',reasons:['ameaça']}});assert.equal(p.element('result').hidden,true);
});
test('texto malicioso é tratado como texto e não criaHTML',async()=>{
 const p=await popup({saved:{url:'https://www.apple.com/',phase:'done',result:{score:5,band:'bad',label:'Ruim',reasons:['<img src=x onerror=alert(1)>']}}});assert.equal(p.element('reasons').children[0].textContent,'<img src=x onerror=alert(1)>');
});
