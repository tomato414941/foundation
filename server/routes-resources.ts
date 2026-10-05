import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { fail,required } from './errors.js';
import * as C from '../shared/contracts.js';
import { Injection } from '../shared/session.js';

const connectionResult=z.discriminatedUnion('kind',[
  z.object({kind:z.literal('connected'),resource:C.Resource,returnTo:z.string()}),
  z.object({kind:z.literal('authorize'),url:z.url()}),
  z.object({kind:z.literal('role'),id:C.Id,externalId:z.string(),principalArn:z.string()}),
  z.object({kind:z.literal('review'),id:C.Id,before:C.JsonObject,after:C.JsonObject,returnTo:z.string()}),
]);
export async function routesResources(app:ApiApp,context:Context) {
  const {resources,authorization,services,catalog,http,objects,environments,runs,billing}=context;
  app.get('/api/catalog',{schema:{response:{200:C.listOf(C.CatalogEntry)}}},async request=>({items:await catalog.list(actor(request)),next:null}));
  app.get('/api/identities/:id',{schema:{params:C.IdParams,response:{200:z.object({id:C.Id,name:C.Name,publicKey:C.PublicKey.nullable()})}}},async request=>{actor(request);const row=await context.principals.get(request.params.id);return {id:row.id,name:row.name,publicKey:row.public_key};});
  app.get('/api/principals/:id/resources',{schema:{params:C.IdParams,querystring:C.PageQuery.extend({kind:C.ResourceKind.optional(),query:z.string().max(200).optional()}),response:{200:C.listOf(C.Resource)}}},request=>resources.list(actor(request),request.params.id,request.query));
  app.get('/api/resources/shared',{schema:{response:{200:C.listOf(C.Resource)}}},request=>resources.shared(actor(request)));
  app.get('/api/principals/:id/recipients',{schema:{params:C.IdParams,response:{200:C.listOf(C.Recipient)}}},async request=>{await authorization.requirePrincipal(actor(request),request.params.id,'read');return {items:await resources.recipients(request.params.id),next:null};});
  app.post('/api/principals/:id/resources',{config:{approval:true},schema:{params:C.IdParams,body:C.NewResource,response:{201:C.Resource}}},async(request,reply)=>{
    const who=actor(request),body=request.body,owner=request.params.id;
    const row=body.kind==='secret'?await resources.createSecret(who,owner,body):body.kind==='service'||body.kind==='app'?await services.createDefinition(who,owner,body):body.kind==='environment'?await environments.create(who,owner,body.options,body.name):await http.create(who,owner,body.name,body.definition);
    return reply.code(201).send(await resources.view(who,row));
  });
  app.get('/api/resources/:id',{schema:{params:C.IdParams,response:{200:C.Resource}}},async request=>{const who=actor(request),row=await resources.get(request.params.id);await authorization.requireResource(who,row,'read');return resources.view(who,row);});
  app.patch('/api/resources/:id',{config:{approval:true},schema:{params:C.IdParams,body:C.UpdateResource,response:{200:C.Resource}}},async request=>{
    const who=actor(request),body=request.body;let row=await resources.get(request.params.id);
    await authorization.requireResource(who,row,'update');
    if(body.version!==row.version)fail(409,'changed','This item changed. Reload it before saving.');
    if(body.name&&body.name!==row.name&&!await authorization.stands(who.id,row.owner_id))await authorization.requireResource(who,row,'share');
    if(body.sealed||body.allowUse!==undefined) {
      if(row.kind!=='secret'||!body.sealed||body.bytes===undefined)fail(400,'invalid_secret','Provide the encrypted content and its size.');
      row=await resources.updateSecret(who,row,body.sealed,body.bytes,body.allowUse);
    }
    if(body.definition) {
      if(row.kind==='function') {
        const spec=await http.validateFunction(who,C.FunctionDefinition.parse(body.definition));
        await http.validateFunction({id:row.owner_id},spec);
        row=await resources.db.transaction(async connection=>{const updated=await resources.update(row,{data:spec as unknown as Record<string,C.JsonValue>,...(body.name?{name:body.name}:{})},connection);await resources.references(row.id,http.references(spec.request),connection);return updated;});
      } else if(row.kind==='service') {
        const reference=await resources.db.one('SELECT 1 FROM resource_references WHERE referenced_id=$1 LIMIT 1',[row.id]);if(reference)fail(409,'in_use','Disconnect items using this service before changing its definition.');
        row=await resources.update(row,{data:C.ServiceDefinition.parse(body.definition) as unknown as Record<string,C.JsonValue>,...(body.name?{name:body.name}:{})});
      } else fail(400,'wrong_kind','This item does not have an editable definition.');
    }
    if(body.clientId!==undefined||body.clientSecret!==undefined||body.fields!==undefined) {
      if(row.kind!=='app')fail(400,'wrong_kind','This item is not an OAuth application.');
      const old=await context.vault.decrypt<{clientSecret?:string}>(required(row.private_data),'resource:'+row.id);
      row=await resources.db.transaction(async connection=>{
        const updated=await resources.update(row,{data:{...row.data,...(body.clientId!==undefined?{clientId:body.clientId}:{}),...(body.fields?{fields:body.fields}:{})},privateData:await context.vault.encrypt({...old,...(body.clientSecret!==undefined?{clientSecret:body.clientSecret}:{})},'resource:'+row.id)},connection);
        await connection.query("UPDATE resources SET data=jsonb_set(data,'{state}','\"reconnect\"'),version=version+1 WHERE kind='connection' AND data->>'appId'=$1",[row.id]);return updated;
      });
    }
    if(body.name&&body.name!==row.name)row=await resources.rename(who,row,body.name);
    return resources.view(who,row);
  });
  app.delete('/api/resources/:id',{config:{approval:true},schema:{params:C.IdParams,querystring:z.object({revoke:z.enum(['true','false']).default('true').transform(value=>value==='true')}),response:{200:C.Ok}}},async request=>{
    const who=actor(request),row=await resources.get(request.params.id);
    if(row.kind==='connection')await services.remove(who,row,request.query.revoke);
    else if(row.kind==='environment')await environments.remove(who,row);
    else if(row.kind==='object')await objects.remove(who,row);
    else await resources.delete(who,row);
    return {ok:true as const};
  });
  app.get('/api/resources/:id/secret',{schema:{params:C.IdParams,response:{200:z.object({sealed:C.Sealed,context:z.string()})}}},request=>resources.secretContent(actor(request),request.params.id));
  app.get('/api/resources/:id/grants',{schema:{params:C.IdParams,response:{200:C.listOf(C.Grant)}}},async request=>({items:await resources.grants(actor(request),await resources.get(request.params.id)),next:null}));
  app.put('/api/resources/:id/grants/:principalId',{config:{approval:true},schema:{params:z.object({id:C.Id,principalId:C.Id}),body:z.object({actions:z.array(C.Action).min(1)}).strict(),response:{200:C.Ok}}},async request=>{await resources.grant(actor(request),await resources.get(request.params.id),request.params.principalId,request.body.actions);return {ok:true as const};});
  app.delete('/api/resources/:id/grants/:principalId',{config:{approval:true},schema:{params:z.object({id:C.Id,principalId:C.Id}),response:{200:C.Ok}}},async request=>{await resources.revoke(actor(request),await resources.get(request.params.id),request.params.principalId);return {ok:true as const};});
  app.post('/api/resources/:id/transfer',{config:{approval:true},schema:{params:C.IdParams,body:z.object({to:C.Id,sealed:C.Sealed.optional()}).strict(),response:{200:C.Ok}}},async request=>{await resources.transfer(actor(request),await resources.get(request.params.id),request.body.to,request.body.sealed);return {ok:true as const};});
  app.post('/api/inputs',{schema:{body:z.object({inputs:z.array(C.Input).max(32)}).strict(),response:{200:Injection}}},request=>context.inputs.deliver(actor(request),request.body.inputs));
  app.post('/api/principals/:id/connections',{config:{approval:true},schema:{params:C.IdParams,body:C.ConnectionInput,response:{200:connectionResult}}},request=>services.begin(actor(request),request.params.id,request.body,request.browser));
  app.get('/api/connections/callback',{schema:{querystring:z.object({state:C.Id,code:z.string().max(16384).optional(),error:z.string().max(200).optional()}).passthrough(),hide:true}},async(request,reply)=>{
    if(request.query.error||!request.query.code)return reply.redirect(await services.cancel(request.query.state,request.browser).catch(()=>'/services?connection=cancelled'));
    try {
      const result=await services.callback(request.query.state,request.query.code,request.browser);
      if(result.kind==='review')return reply.redirect('/services/review/'+result.id);
      const path='returnTo' in result?result.returnTo:'/services';return reply.redirect(path);
    } catch(error) {const code=typeof error==='object'&&error&&'code' in error?String(error.code):'connection_failed';return reply.redirect('/services?error='+encodeURIComponent(code));}
  });
  app.post('/api/connections/:id/review',{schema:{params:C.IdParams,body:z.object({accept:z.boolean()}).strict(),response:{200:z.union([connectionResult,z.object({kind:z.literal('cancelled'),returnTo:z.string()})])}}},request=>services.review(actor(request),request.params.id,request.browser,request.body.accept));
  app.get('/api/connections/:id/review',{schema:{params:C.IdParams,response:{200:z.object({id:C.Id,before:C.JsonObject,after:C.JsonObject})}}},request=>services.pendingReview(actor(request),request.params.id,request.browser));
  app.post('/api/connections/:id/role',{schema:{params:C.IdParams,body:z.object({arn:z.string().max(600),region:z.string().max(50)}).strict(),response:{200:connectionResult}}},request=>services.completeRole(actor(request),request.params.id,request.browser,request.body.arn,request.body.region));
  app.post('/api/resources/:id/stop',{config:{approval:true},schema:{params:C.IdParams,body:z.object({}).strict(),response:{200:C.Resource}}},async request=>resources.view(actor(request),await environments.stop(actor(request),await resources.get(request.params.id))));
  app.post('/api/principals/:id/runs',{config:{approval:true},schema:{params:C.IdParams,body:C.RunInput,response:{202:C.Run}}},async(request,reply)=>reply.code(202).send(await runs.create(actor(request),request.params.id,request.body)));
  app.get('/api/principals/:id/runs',{schema:{params:C.IdParams,querystring:C.PageQuery,response:{200:C.listOf(C.Run)}}},request=>runs.list(actor(request),request.params.id,request.query.limit,request.query.after));
  app.get('/api/runs/:id',{schema:{params:C.IdParams,response:{200:C.Run}}},request=>runs.get(actor(request),request.params.id));
  app.post('/api/runs/:id/cancel',{schema:{params:C.IdParams,body:z.object({}).strict(),response:{200:C.Run}}},request=>runs.cancel(actor(request),request.params.id));
  app.addContentTypeParser('application/octet-stream',{parseAs:'buffer',bodyLimit:25*1024*1024},(_request,body,done)=>done(null,body));
  app.post('/api/principals/:id/objects',{bodyLimit:25*1024*1024,schema:{params:C.IdParams,querystring:z.object({name:C.Name,contentType:z.string().max(200).default('application/octet-stream')}),response:{201:C.Resource}}},async(request,reply)=>{if(!Buffer.isBuffer(request.body))fail(400,'binary_required','Upload the file as application/octet-stream.');return reply.code(201).send(await resources.view(actor(request),await objects.upload(actor(request),request.params.id,request.query.name,request.body,request.query.contentType)));});
  app.put('/api/resources/:id/content',{bodyLimit:25*1024*1024,schema:{params:C.IdParams,querystring:z.object({version:z.coerce.number().int().positive(),contentType:z.string().max(200).default('application/octet-stream')}),response:{200:C.Resource}}},async request=>{const row=await resources.get(request.params.id);if(row.version!==request.query.version)fail(409,'changed','This file changed. Reload it before saving.');if(!Buffer.isBuffer(request.body))fail(400,'binary_required','Upload the file as application/octet-stream.');return resources.view(actor(request),await objects.upload(actor(request),row.owner_id,row.name,request.body,request.query.contentType,row));});
  app.get('/api/resources/:id/content',{schema:{params:C.IdParams}},async(request,reply)=>{const row=await resources.get(request.params.id),bytes=await objects.content(actor(request),row);return reply.header('content-type','application/octet-stream').header('content-disposition',"attachment; filename*=UTF-8''"+encodeURIComponent(row.name)).send(Buffer.from(bytes));});
  app.post('/api/resources/:id/link',{schema:{params:C.IdParams,body:z.object({minutes:z.number().int().min(1).max(1440).default(15)}).strict(),response:{200:z.object({url:z.url(),expiresAt:C.Time})}}},request=>resources.get(request.params.id).then(row=>objects.link(actor(request),row,request.body.minutes)));
  app.get('/api/principals/:id/payment',{schema:{params:C.IdParams,response:{200:C.Payment}}},request=>billing.payment(actor(request),request.params.id));
  app.get('/api/principals/:id/usage',{schema:{params:C.IdParams,response:{200:C.Usage}}},async request=>{await authorization.requirePrincipal(actor(request),request.params.id,'read');return billing.usage(request.params.id);});
  app.put('/api/principals/:id/limits',{schema:{params:C.IdParams,body:z.object({storageBytes:z.number().int().min(1).max(1_000_000_000_000),computeSeconds:z.number().int().min(1).max(10_000_000)}).strict(),response:{200:C.Ok}}},async request=>{await billing.limits(actor(request),request.params.id,request.body.storageBytes,request.body.computeSeconds);return {ok:true as const};});
  app.post('/api/principals/:id/payment/checkout',{schema:{params:C.IdParams,body:z.object({}).strict(),response:{200:z.object({url:z.url()})}}},request=>billing.checkout(actor(request),request.params.id));
  app.post('/api/principals/:id/payment/portal',{schema:{params:C.IdParams,body:z.object({}).strict(),response:{200:z.object({url:z.url()})}}},request=>billing.portal(actor(request),request.params.id));
  await app.register(async scope=>{
    scope.removeContentTypeParser('application/json');scope.addContentTypeParser('application/json',{parseAs:'buffer'},(_request,body,done)=>done(null,body));
    scope.post('/api/webhooks/stripe',{schema:{hide:true}},async(request,reply)=>{if(!Buffer.isBuffer(request.body)||typeof request.headers['stripe-signature']!=='string')fail(400,'invalid_signature','The webhook signature could not be verified.');await billing.webhook(request.body,request.headers['stripe-signature']);return reply.send({ok:true});});
  });
}
