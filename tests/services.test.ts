import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { Catalog } from '../server/catalog.js';
import { OAuth } from '../server/oauth.js';
import { Services } from '../server/services.js';
import { Inputs } from '../server/inputs.js';
import { HttpExecution } from '../server/http-execution.js';
import { publicAddress, publicUrl } from '../server/transport.js';
import type { Transport, OutboundRequest, OutboundResponse } from '../server/transport.js';
import { ConnectionInput, FunctionDefinition, HttpRequest } from '../shared/contracts.js';
import { encode, decode, seal, open } from '../shared/encryption.js';

class TestTransport implements Transport {
  requests:OutboundRequest[]=[];
  respond:(request:OutboundRequest)=>OutboundResponse|Promise<OutboundResponse> = ()=>({status:200,headers:{'content-type':'application/json'},body:encode('{}')});
  async send(request:OutboundRequest) {this.requests.push(request);return this.respond(request);}
}
async function setup() {
  const base=await fixture(),transport=new TestTransport(),catalog=await Catalog.load(base.resources,base.config),oauth=new OAuth(transport),services=new Services(base.resources,catalog,base.vault,oauth,base.config),inputs=new Inputs(base.resources,services),http=new HttpExecution(base.resources,inputs,transport,base.config.origin);
  return {...base,transport,catalog,oauth,services,inputs,http};
}

test('公開HTTPSの送信先を受け入れ、プライベートアドレスへの送信を拒否する',()=>{
  for(const address of ['8.8.8.8','1.1.1.1','2606:4700:4700::1111']) assert.equal(publicAddress(address),true,address);
  for(const address of ['127.0.0.1','0.0.0.0','10.1.1.1','169.254.169.254','172.16.1.1','192.168.1.1','100.64.0.1','::1','::ffff:127.0.0.1','fc00::1','fe80::1','2001:db8::1']) assert.equal(publicAddress(address),false,address);
  assert.equal(publicUrl('https://example.com/path').hostname,'example.com');
  for(const url of ['http://example.com','https://127.1','https://[::ffff:127.0.0.1]','https://example.com:8443','https://name:password@example.com']) assert.throws(()=>publicUrl(url));
});

test('接続したサービスの値を委任先へ暗号化して渡し、委任解除後の利用を拒否する',async t=>{
  const f=await setup();t.after(()=>f.close());
  const owner=await f.person(),agent=await f.person('Agent');
  await f.principals.relate(owner.actor,agent.actor.id,'agent',owner.actor.id);
  const result=await f.services.begin(owner.actor,owner.actor.id,ConnectionInput.parse({serviceId:'github',scheme:'token',fields:{token:'private-service-value'}}),'browser');
  assert.equal(result.kind,'connected');if(result.kind!=='connected') return;
  const delivered=await f.inputs.deliver(agent.actor,[{name:'GH_TOKEN',source:{kind:'connection',id:result.resource.id,output:'GH_TOKEN'},format:'text'}]);
  const content=JSON.parse(decode(await open(delivered.sealed,agent.keys.privateKey,agent.actor.id,delivered.context)));
  assert.equal(content.environment.GH_TOKEN,'private-service-value');
  const stored=await f.resources.get(result.resource.id);assert.ok(stored.private_data);assert.equal(JSON.stringify(stored.data).includes('private-service-value'),false);
  await f.principals.revoke(owner.actor,owner.actor.id,agent.actor.id);
  await assert.rejects(()=>f.inputs.deliver(agent.actor,[{name:'GH_TOKEN',source:{kind:'connection',id:result.resource.id,output:'GH_TOKEN'},format:'text'}]),{code:'forbidden'});
});

test('シークレットをHTTPヘッダーに渡し、返された秘密値を伏せて実行結果を返す',async t=>{
  const f=await setup();t.after(()=>f.close());const owner=await f.person(),id=randomUUID(),secret='sensitive-http-credential';
  const sealed=await seal(encode(secret),[{id:owner.actor.id,publicKey:owner.keys.publicKey},{id:f.identity.id,publicKey:f.identity.publicKey}],'resource:'+id);
  await f.resources.createSecret(owner.actor,owner.actor.id,{kind:'secret',id,name:'HTTP key',sealed,bytes:secret.length,allowUse:true});
  f.transport.respond=request=>({status:200,headers:{authorization:request.headers!.authorization!},body:encode(JSON.stringify({echo:secret,accepted:true}))});
  const result=await f.http.request(owner.actor,owner.actor.id,HttpRequest.parse({url:'https://api.example.com',headers:{authorization:''},bindings:[{pointer:'/headers/authorization',parts:['Bearer ',{kind:'secret',id}]}]})) as {body:string;headers:Record<string,string>};
  assert.equal(f.transport.requests[0]?.headers?.authorization,'Bearer '+secret);
  assert.deepEqual(JSON.parse(result.body),{echo:'[redacted]',accepted:true});
  assert.equal(result.headers.authorization,'Bearer [redacted]');
  await f.resources.revoke(owner.actor,await f.resources.get(id),f.identity.id);
  await assert.rejects(()=>f.inputs.text(owner.actor,{kind:'secret',id}),{code:'forbidden'});
});

test('共有された関数の実行を許可し、所有者の接続情報の取得を拒否する',async t=>{
  const f=await setup();t.after(()=>f.close());const owner=await f.person(),caller=await f.person('Caller');
  const connection=await f.services.begin(owner.actor,owner.actor.id,ConnectionInput.parse({serviceId:'github',scheme:'token',fields:{token:'function-private-token'}}),'browser');
  assert.equal(connection.kind,'connected');if(connection.kind!=='connected')return;
  const definition=FunctionDefinition.parse({parameters:[{name:'issue',label:'Issue'}],request:{url:'https://api.github.com/repos/example/project/issues/{issue}',headers:{authorization:''},bindings:[{pointer:'/headers/authorization',parts:['Bearer ',{kind:'connection',id:connection.resource.id,output:'GH_TOKEN'}]}]}});
  const fn=await f.http.create(owner.actor,owner.actor.id,'Read issue',definition);
  await f.resources.grant(owner.actor,fn,caller.actor.id,['read','execute']);
  f.transport.respond=request=>({status:200,headers:{},body:encode(JSON.stringify({url:request.url,title:'Hello'}))});
  const result=await f.http.invoke(caller.actor,fn,{issue:'123'}) as {body:string};
  assert.equal(JSON.parse(result.body).url,'https://api.github.com/repos/example/project/issues/123');
  await assert.rejects(()=>f.inputs.text(caller.actor,{kind:'connection',id:connection.resource.id,output:'GH_TOKEN'}),{code:'forbidden'});
  await assert.rejects(()=>f.http.create(owner.actor,owner.actor.id,'Bad destination',FunctionDefinition.parse({...definition,request:{...definition.request,url:'https://{issue}/secret'}})),{code:'variable_origin'});
});

test('OAuthの応答を開始したブラウザーへ結び付け、接続後に更新したトークンを渡す',async t=>{
  const f=await setup();t.after(()=>f.close());const owner=await f.person();
  f.config.oauthApps.google={clientId:'test-client',clientSecret:'test-secret'};
  let exchanges=0;
  f.transport.respond=request=>{
    if(request.url==='https://oauth2.googleapis.com/token') {exchanges++;return {status:200,headers:{},body:encode(JSON.stringify({access_token:exchanges===1?'first-token':'refreshed-token',refresh_token:'refresh-token',expires_in:exchanges===1?30:3600,token_type:'Bearer',scope:'openid https://www.googleapis.com/auth/userinfo.email'}))};}
    return {status:200,headers:{},body:encode(JSON.stringify({sub:'google-account',email:'owner@example.com',email_verified:true}))};
  };
  const started=await f.services.begin(owner.actor,owner.actor.id,ConnectionInput.parse({serviceId:'google',scheme:'oauth'}),'right-browser');
  assert.equal(started.kind,'authorize');if(started.kind!=='authorize')return;
  const state=new URL(started.url).searchParams.get('state')!;
  await assert.rejects(()=>f.services.callback(state,'authorization-code','other-browser'),{code:'invalid_state'});
  const complete=await f.services.callback(state,'authorization-code','right-browser');
  assert.equal(complete.kind,'connected');if(complete.kind!=='connected')return;
  assert.equal(await f.inputs.text(owner.actor,{kind:'connection',id:complete.resource.id,output:'GOOGLE_OAUTH_ACCESS_TOKEN'}),'refreshed-token');
  assert.equal(exchanges,2);
  await assert.rejects(()=>f.services.callback(state,'authorization-code','right-browser'),{code:'invalid_state'});
});

test('同時に届いた利用要求に同じ更新済みトークンを渡す',async t=>{
  const f=await setup();t.after(()=>f.close());const owner=await f.person();f.config.oauthApps.google={clientId:'test-client',clientSecret:'test-secret'};
  let exchanges=0;
  f.transport.respond=async request=>{
    if(request.url==='https://oauth2.googleapis.com/token') {exchanges++;await new Promise(resolve=>setTimeout(resolve,20));return {status:200,headers:{},body:encode(JSON.stringify({access_token:'token-'+exchanges,refresh_token:'refresh-'+exchanges,expires_in:exchanges===1?30:3600,token_type:'Bearer'}))};}
    return {status:200,headers:{},body:encode(JSON.stringify({sub:'same-account',email:'owner@example.com',email_verified:true}))};
  };
  const begin=await f.services.begin(owner.actor,owner.actor.id,ConnectionInput.parse({serviceId:'google',scheme:'oauth'}),'browser');if(begin.kind!=='authorize')throw new Error('Expected consent');
  const connected=await f.services.callback(new URL(begin.url).searchParams.get('state')!,'code','browser');if(connected.kind!=='connected')throw new Error('Expected connection');
  const values=await Promise.all(Array.from({length:4},()=>f.inputs.text(owner.actor,{kind:'connection',id:connected.resource.id,output:'GOOGLE_OAUTH_ACCESS_TOKEN'})));
  assert.deepEqual(values,['token-2','token-2','token-2','token-2']);assert.equal(exchanges,2);
});
