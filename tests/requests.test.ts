import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { encode } from '../shared/encryption.js';

test('確認コードで端末を引き受け、承認者の権限で利用を委任する',async t=>{
  const f=await fixture(),context=await createContext(f.config,{db:f.db,mailer:f.mailer}),app=await buildApp(context);t.after(async()=>{await app.close();await f.close();});
  const person=await f.person('Person'),device=await f.person('Device'),headers={authorization:'Bearer '+device.token};
  const request=await app.inject({method:'POST',url:'/api/requests',headers,payload:{operations:[{method:'POST',path:'/api/relations',body:{relation:'agent',principalId:'$approver',subjectId:device.actor.id}}]}});
  assert.equal(request.statusCode,201,request.body);const pending=request.json();assert.match(pending.code,/^[A-Z2-9]{8}$/);
  const wrong=await app.inject({method:'POST',url:'/api/requests/'+pending.id+'/approve',headers:{authorization:'Bearer '+person.token},payload:{code:'WRONG'}});assert.equal(wrong.statusCode,400,wrong.body);
  const answer=await app.inject({method:'POST',url:'/api/requests/'+pending.id+'/approve',headers:{authorization:'Bearer '+person.token},payload:{code:pending.code}});assert.equal(answer.statusCode,200,answer.body);assert.equal(answer.json().state,'approved');
  assert.equal(await context.authorization.uses(device.actor.id,person.actor.id),true);
  assert.equal(await context.authorization.principal(person.actor,device.actor.id,'credentials'),true);
  const polled=await app.inject({url:'/api/requests/'+pending.id,headers});assert.equal(polled.json().state,'approved');
});

test('依頼に入力された秘密値でサービスへ接続し、結果を依頼元へ返す',async t=>{
  const f=await fixture(),context=await createContext(f.config,{db:f.db,mailer:f.mailer}),app=await buildApp(context);t.after(async()=>{await app.close();await f.close();});
  const owner=await f.person('Owner'),agent=await f.person('Agent');await f.principals.relate(owner.actor,agent.actor.id,'agent',owner.actor.id);
  const asked=await app.inject({method:'POST',url:'/api/requests',headers:{authorization:'Bearer '+agent.token},payload:{to:owner.actor.id,message:'Connect GitHub',operations:[{method:'POST',path:'/api/principals/'+owner.actor.id+'/connections',body:{serviceId:'github',scheme:'token',fields:{token:''}},inputs:[{pointer:'/fields/token',label:'GitHub token',secret:true}]}]}});
  assert.equal(asked.statusCode,201,asked.body);
  const answered=await app.inject({method:'POST',url:'/api/requests/'+asked.json().id+'/approve',headers:{authorization:'Bearer '+owner.token},payload:{values:[{'/fields/token':'secret-from-person'}]}});
  assert.equal(answered.statusCode,200,answered.body);assert.equal(answered.json().state,'approved');
  const connection=answered.json().results[0].resource;assert.equal(connection.ownerId,owner.actor.id);
  assert.equal(await context.inputs.text(agent.actor,{kind:'connection',id:connection.id,output:'GH_TOKEN'}),'secret-from-person');
  assert.equal((await context.requests.get(agent.actor,asked.json().id)).operations[0]!.body&&JSON.stringify((await context.requests.get(agent.actor,asked.json().id)).operations).includes('secret-from-person'),false);
});

test('依頼専用リンクでその依頼を承認し、通常のAPI操作を拒否する',async t=>{
  const f=await fixture(),context=await createContext(f.config,{db:f.db,mailer:f.mailer}),app=await buildApp(context);t.after(async()=>{await app.close();await f.close();});
  const owner=await f.person('Owner'),sender=await f.person('Sender');
  const asked=await app.inject({method:'POST',url:'/api/requests',headers:{authorization:'Bearer '+sender.token},payload:{to:owner.actor.id,operations:[{method:'POST',path:'/api/principals',body:{name:'New group',ownerId:owner.actor.id}}]}});assert.equal(asked.statusCode,201,asked.body);
  const link=await context.requests.link(owner.actor,asked.json().id),secret=new URLSearchParams(new URL(link.url).hash.slice(1)).get('token')!;
  const redeemed=await app.inject({method:'POST',url:'/api/requests/'+asked.json().id+'/redeem',payload:{token:secret}});assert.equal(redeemed.statusCode,200,redeemed.body);
  const cookie=redeemed.cookies.find(value=>value.name==='foundation_request')!,headers={cookie:cookie.name+'='+cookie.value,origin:f.config.origin};
  const direct=await app.inject({method:'PATCH',url:'/api/principals/'+owner.actor.id,headers,payload:{name:'Unrelated change'}});assert.equal(direct.statusCode,403,direct.body);
  const answer=await app.inject({method:'POST',url:'/api/requests/'+asked.json().id+'/approve',headers,payload:{}});assert.equal(answer.statusCode,200,answer.body);assert.equal(answer.json().state,'approved');
  const repeated=await app.inject({method:'POST',url:'/api/requests/'+asked.json().id+'/redeem',payload:{token:secret}});assert.equal(repeated.statusCode,400,repeated.body);
});

test('OAuthの完了後に依頼を再開し、取り消された依頼の接続を拒否する',async t=>{
  const f=await fixture();f.config.oauthApps.google={clientId:'test-client',clientSecret:'test-secret'};
  const context=await createContext(f.config,{db:f.db,mailer:f.mailer,transport:{async send(input){return {status:200,headers:{},body:encode(JSON.stringify(input.url.includes('/token')?{access_token:'oauth-token',refresh_token:'refresh-token',expires_in:3600,token_type:'Bearer'}:{sub:'account',email:'owner@example.com',email_verified:true}))};}}}),app=await buildApp(context);t.after(async()=>{await app.close();await f.close();});
  const owner=await f.person('Owner'),sender=await f.person('Sender'),headers={authorization:'Bearer '+owner.token,cookie:'foundation_browser=approval-browser'};
  async function ask(name:string) {
    const request=await app.inject({method:'POST',url:'/api/requests',headers:{authorization:'Bearer '+sender.token},payload:{to:owner.actor.id,operations:[{method:'POST',path:'/api/principals/'+owner.actor.id+'/connections',body:{serviceId:'google',scheme:'oauth',name}},{method:'PATCH',path:'/api/principals/'+owner.actor.id,body:{name:'Connected owner'}}]}});assert.equal(request.statusCode,201,request.body);
    const approval=await app.inject({method:'POST',url:'/api/requests/'+request.json().id+'/approve',headers,payload:{}});assert.equal(approval.statusCode,200,approval.body);assert.equal(approval.json().state,'running');return approval.json();
  }
  const first=await ask('Allowed connection'),state=new URL(first.continueUrl).searchParams.get('state');
  const callback=await app.inject({url:'/api/connections/callback?state='+state+'&code=authorization-code',headers});assert.equal(callback.statusCode,302,callback.body);
  assert.equal((await context.requests.get(owner.actor,first.id)).state,'approved');assert.equal((await context.principals.get(owner.actor.id)).name,'Connected owner');
  const second=await ask('Cancelled connection');await context.requests.decline(owner.actor,second.id);
  await app.inject({url:'/api/connections/callback?state='+new URL(second.continueUrl).searchParams.get('state')+'&code=authorization-code',headers});
  assert.equal((await context.resources.list(owner.actor,owner.actor.id,{kind:'connection'})).items.length,1);
});
