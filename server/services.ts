import { randomUUID } from 'node:crypto';
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { z } from 'zod';
import safeRegex from 'safe-regex2';
import type { Resources, ResourceRow } from './resources.js';
import type { Actor } from './authorization.js';
import type { Catalog } from './catalog.js';
import type { Configuration } from './config.js';
import type { Queryable } from './database.js';
import { Vault, token, digest } from './vault.js';
import { OAuth } from './oauth.js';
import type { OAuthApp, OAuthToken, OAuthSpec } from './oauth.js';
import { ConnectionResource, ServiceDefinition } from '../shared/contracts.js';
import type { ConnectInput, ServiceDescription, SourceReference, NewResourceInput, JsonValue } from '../shared/contracts.js';
import { atPointer, textValue } from '../shared/values.js';
import { DomainError, fail, required } from './errors.js';

interface ConnectionState { service:ServiceDescription; app:OAuthApp; oauth?:OAuthToken; fields?:Record<string,string>; role?:{arn:string;externalId:string;region:string}; appVersion?:number }
interface Consent { actor:Actor; ownerId:string; input:ConnectInput; service:ServiceDescription; app:OAuthApp; verifier:string; connectionVersion?:number; result?:OAuthToken; externalId?:string }
export type ConnectionResult = {kind:'connected';resource:Awaited<ReturnType<Resources['view']>>;returnTo:string} | {kind:'authorize';url:string} | {kind:'review';id:string;before:Record<string,JsonValue>;after:Record<string,JsonValue>;returnTo:string} | {kind:'role';id:string;externalId:string;principalArn:string};
export interface RoleCredentials extends Record<string,string> { AWS_ACCESS_KEY_ID:string;AWS_SECRET_ACCESS_KEY:string;AWS_SESSION_TOKEN:string;AWS_DEFAULT_REGION:string }
export interface RoleProvider { obtain(arn:string,externalId:string,region:string):Promise<RoleCredentials> }
export class AwsRoles implements RoleProvider {
  async obtain(arn:string,externalId:string,region:string) {
    const sts=new STSClient({region});
    try {
      const response=await sts.send(new AssumeRoleCommand({RoleArn:arn,RoleSessionName:'foundation-'+randomUUID().slice(0,8),ExternalId:externalId,DurationSeconds:3600}));
      const key=response.Credentials;
      if(!key?.AccessKeyId||!key.SecretAccessKey||!key.SessionToken) fail(502,'invalid_response','AWS did not return credentials.');
      const client=new STSClient({region,credentials:{accessKeyId:key.AccessKeyId,secretAccessKey:key.SecretAccessKey,sessionToken:key.SessionToken}});
      try { const identity=await client.send(new GetCallerIdentityCommand({})); if(identity.Account!==arn.split(':')[4]) fail(502,'account_changed','The AWS account could not be verified.'); } finally {client.destroy();}
      return {AWS_ACCESS_KEY_ID:key.AccessKeyId,AWS_SECRET_ACCESS_KEY:key.SecretAccessKey,AWS_SESSION_TOKEN:key.SessionToken,AWS_DEFAULT_REGION:region};
    } catch(error) { if(error instanceof DomainError) throw error; fail(502,'role_denied','Check the IAM role and its trust policy.'); } finally {sts.destroy();}
  }
}
export class Services {
  resolve?: (actor:Actor,source:SourceReference)=>Promise<string>;
  checkApproval?: (actor:Actor,connection?:Queryable)=>Promise<void>;
  completed?: (actor:Actor,result:JsonValue)=>Promise<void>;
  cancelled?: (actor:Actor)=>Promise<void>;
  constructor(readonly resources:Resources,readonly catalog:Catalog,readonly vault:Vault,readonly oauth:OAuth,readonly config:Configuration,readonly roles:RoleProvider=new AwsRoles()) {}
  private async allowed(actor:Actor,ownerId:string,input:ConnectInput) {
    if(input.connectionId) {
      const row=await this.resources.get(input.connectionId);
      if(row.kind!=='connection'||row.owner_id!==ownerId||row.data.serviceId!==input.serviceId||row.data.scheme!==input.scheme) fail(400,'wrong_connection','Choose a connection for this service.');
      await this.resources.authorization.requireResource(actor,row,'update'); return row;
    }
    if(!await this.resources.authorization.canCreate(actor,ownerId,'connection')) fail(403,'forbidden','You cannot connect services for this principal.');
    return null;
  }
  private fields(definitions:Array<{name:string;required?:boolean;pattern?:string}>,input:Record<string,string>,defaults:Record<string,string>={}) {
    const values={...defaults,...input};
    for(const field of definitions) {
      if(field.required!==false && !values[field.name] && !Object.hasOwn(defaults,field.name)) fail(400,'missing_field','Complete the required service fields.');
      if(values[field.name] && (values[field.name]!.length>16384 || /\u0000/.test(values[field.name]!))) fail(400,'invalid_field','Check the service fields.');
      if(field.pattern && (!safeRegex(field.pattern) || field.pattern.length>200)) fail(400,'invalid_pattern','Use a simple field validation pattern.');
      if(field.pattern && values[field.name] && !new RegExp(field.pattern,'u').test(values[field.name]!.slice(0,1000))) fail(400,'invalid_field','Check the service fields.');
    }
    if(Object.keys(input).some(key=>!definitions.some(field=>field.name===key))) fail(400,'invalid_field','Remove unrecognized service fields.');
    return values;
  }
  private async app(actor:Actor,id:string,serviceId:string,spec:OAuthSpec):Promise<OAuthApp> {
    if(id==='foundation') {
      const app=this.config.oauthApps[serviceId];
      if(!app && spec.adapter!=='openrouter') fail(409,'app_required','Add an OAuth application to connect this service.');
      return {clientId:app?.clientId ?? '',...(app?.clientSecret?{clientSecret:app.clientSecret}:{}),fields:this.fields(spec.fields,app?.fields ?? {},spec.defaults)};
    }
    const row=await this.resources.get(id);
    if(row.kind!=='app'||row.data.serviceId!==serviceId) fail(400,'wrong_app','Choose an application for this service.');
    await this.resources.authorization.requireResource(actor,row,'use');
    const privateData=await this.vault.decrypt<{clientSecret?:string}>(required(row.private_data),'resource:'+id);
    return {clientId:String(row.data.clientId),...privateData,fields:this.fields(spec.fields,row.data.fields as Record<string,string>,spec.defaults),version:row.version};
  }
  async createDefinition(actor:Actor,ownerId:string,input:Extract<NewResourceInput,{kind:'app'|'service'}>) {
    if(!await this.resources.authorization.canCreate(actor,ownerId,input.kind)) fail(403,'forbidden','You cannot create this item for this principal.');
    if(input.kind==='service') {
      if(!Object.keys(input.definition.auth).length) fail(400,'scheme_required','Add at least one connection method.');
      return this.resources.insert(ownerId,'service',input.name,ServiceDefinition.parse(input.definition) as unknown as Record<string,JsonValue>);
    }
    const service=await this.catalog.get(actor,input.serviceId);
    if(!service.auth.oauth) fail(400,'oauth_unavailable','This service does not use OAuth applications.');
    const fields=this.fields(service.auth.oauth.fields,input.fields,service.auth.oauth.defaults),id=randomUUID();
    return this.resources.db.transaction(async connection=>this.resources.insert(ownerId,'app',input.name,{serviceId:input.serviceId,clientId:input.clientId,fields},{id,privateData:await this.vault.encrypt({clientSecret:input.clientSecret},'resource:'+id),references:this.catalog.definitions.has(input.serviceId)?[]:[input.serviceId]},connection));
  }
  async begin(actor:Actor,ownerId:string,input:ConnectInput,browser:string):Promise<ConnectionResult> {
    if(actor.approvalId)input={...input,returnTo:'/requests/'+actor.approvalId};
    const previous=await this.allowed(actor,ownerId,input),service=await this.catalog.get(actor,input.serviceId);
    if(!service.auth[input.scheme]) fail(400,'scheme_unavailable','Choose an available connection method.');
    if(!input.returnTo.startsWith('/')||input.returnTo.startsWith('//')||/[\\\u0000-\u001f]/.test(input.returnTo)) fail(400,'invalid_return','Choose a page within Foundation.');
    if(input.scheme==='token') {
      const fields:Record<string,string>={};
      for(const [key,value] of Object.entries(input.fields)) fields[key]=typeof value==='string'?value:await required(this.resolve)(actor,value);
      const data=this.fields(service.auth.token!.fields,fields);
      return this.store(actor,ownerId,input,{service,app:{clientId:'',fields:{}},fields:data},previous);
    }
    const id=randomUUID(),app=input.scheme==='oauth'?await this.app(actor,input.appId,input.serviceId,service.auth.oauth!):{clientId:'',fields:{}};
    const consent:Consent={actor,ownerId,input,service,app,verifier:token(),...(previous?{connectionVersion:previous.version}:{})};
    if(input.scheme==='role') {
      if(!this.config.FOUNDATION_AWS_PRINCIPAL_ARN) fail(503,'role_unavailable','AWS role connections are not configured.');
      consent.externalId=token();
    }
    await this.resources.db.pool.query("INSERT INTO challenges(id,kind,principal_id,browser_hash,data,expires_at) VALUES($1,'service',$2,$3,$4,now()+interval '15 minutes')",[id,actor.id,digest(browser),JSON.stringify({sealed:await this.vault.encrypt(consent,'consent:'+id)})]);
    if(input.scheme==='role') return {kind:'role',id,externalId:consent.externalId!,principalArn:this.config.FOUNDATION_AWS_PRINCIPAL_ARN};
    const spec=service.auth.oauth!,scopes=[...new Set([...spec.scopes.default,...(input.scopes ?? [])])];
    return {kind:'authorize',url:this.oauth.authorize(spec,app,id,consent.verifier,this.config.origin+'/api/connections/callback',scopes)};
  }
  private async consent(id:string,browser:string,kind='service'):Promise<Consent> {
    const row=await this.resources.db.one<{data:{sealed:string}}>('DELETE FROM challenges WHERE id=$1 AND kind=$2 AND browser_hash=$3 AND expires_at>now() RETURNING data',[id,kind,digest(browser)]);
    if(!row) fail(400,'invalid_state','Start the connection again.');
    const value=await this.vault.decrypt<Consent>(row.data.sealed,'consent:'+id);
    await this.resources.authorization.active(value.actor);
    await this.checkApproval?.(value.actor);
    const previous=await this.allowed(value.actor,value.ownerId,value.input);
    if(previous && previous.version!==value.connectionVersion) fail(409,'changed','This connection changed. Start again.');
    if(value.input.appId!=='foundation'&&value.input.scheme==='oauth') {
      const current=await this.app(value.actor,value.input.appId,value.input.serviceId,value.service.auth.oauth!);
      if(current.version!==value.app.version) fail(409,'changed','The OAuth application changed. Start again.');
    }
    return value;
  }
  async callback(id:string,code:string,browser:string):Promise<ConnectionResult> {
    const consent=await this.consent(id,browser);
    if(consent.input.scheme!=='oauth') fail(400,'invalid_state','Start the connection again.');
    const previous=consent.input.connectionId?await this.resources.get(consent.input.connectionId):null;
    const old=previous?await this.vault.decrypt<ConnectionState>(required(previous.private_data),'resource:'+previous.id):undefined;
    const spec=consent.service.auth.oauth!,scopes=[...new Set([...spec.scopes.default,...(consent.input.scopes ?? [])])];
    const result=await this.oauth.exchange(spec,consent.app,code,consent.verifier,this.config.origin+'/api/connections/callback',scopes,old?.oauth);
    if(previous && (JSON.stringify([...result.scopes].sort())!==JSON.stringify([...(old?.oauth?.scopes??[])].sort()) || previous.data.appId!==(consent.input.appId==='foundation'?null:consent.input.appId))) {
      consent.result=result;
      await this.resources.db.pool.query("INSERT INTO challenges(id,kind,principal_id,browser_hash,data,expires_at) VALUES($1,'service-review',$2,$3,$4,now()+interval '15 minutes')",[id,consent.actor.id,digest(browser),JSON.stringify({sealed:await this.vault.encrypt(consent,'consent:'+id)})]);
      return {kind:'review',id,before:{account:String(previous.data.account),scopes:previous.data.scopes ?? []},after:{account:result.accountName,scopes:result.scopes},returnTo:consent.input.returnTo};
    }
    const connected=await this.store(consent.actor,consent.ownerId,consent.input,{service:consent.service,app:consent.app,oauth:result},previous);
    await this.completed?.(consent.actor,connected as unknown as JsonValue);return connected;
  }
  async review(actor:Actor,id:string,browser:string,accept:boolean) {
    const consent=await this.consent(id,browser,'service-review');
    if(actor.id!==consent.actor.id) fail(403,'forbidden','Use the account that started this connection.');
    if(!accept) {await this.cancelled?.(consent.actor);return {kind:'cancelled' as const,returnTo:consent.input.returnTo};}
    const connected=await this.store(consent.actor,consent.ownerId,consent.input,{service:consent.service,app:consent.app,oauth:required(consent.result)},consent.input.connectionId?await this.resources.get(consent.input.connectionId):null);
    await this.completed?.(consent.actor,connected as unknown as JsonValue);return connected;
  }
  async cancel(id:string,browser:string) {
    const consent=await this.consent(id,browser);await this.cancelled?.(consent.actor);return consent.input.returnTo;
  }
  async pendingReview(actor:Actor,id:string,browser:string) {
    const row=await this.resources.db.one<{data:{sealed:string}}>("SELECT data FROM challenges WHERE id=$1 AND kind='service-review' AND browser_hash=$2 AND expires_at>now()",[id,digest(browser)]);
    if(!row)fail(400,'invalid_state','Start the connection again.');
    const consent=await this.vault.decrypt<Consent>(row.data.sealed,'consent:'+id);
    if(actor.id!==consent.actor.id)fail(403,'forbidden','Use the account that started this connection.');
    const previous=await this.resources.get(required(consent.input.connectionId));
    return {id,before:{account:String(previous.data.account),scopes:previous.data.scopes??[]},after:{account:consent.result!.accountName,scopes:consent.result!.scopes}};
  }
  async completeRole(actor:Actor,id:string,browser:string,arn:string,region:string) {
    const consent=await this.consent(id,browser);
    if(actor.id!==consent.actor.id||consent.input.scheme!=='role') fail(403,'forbidden','Use the account that started this connection.');
    z.string().regex(/^arn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@_/-]{1,512}$/).parse(arn);
    z.string().regex(/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/).parse(region);
    const role={arn,region,externalId:required(consent.externalId)};
    await this.roles.obtain(arn,role.externalId,region);
    const connected=await this.store(consent.actor,consent.ownerId,consent.input,{service:consent.service,app:consent.app,role},consent.input.connectionId?await this.resources.get(consent.input.connectionId):null);
    await this.completed?.(consent.actor,connected as unknown as JsonValue);return connected;
  }
  private async store(actor:Actor,ownerId:string,input:ConnectInput,state:ConnectionState,previous:ResourceRow|null):Promise<ConnectionResult> {
    await this.allowed(actor,ownerId,input);
    const outputs=state.oauth?Object.keys(state.service.auth.oauth!.outputs):state.role?['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_DEFAULT_REGION']:Object.keys(state.service.auth.token!.outputs);
    const account=state.oauth?.accountName ?? state.role?.arn.split(':')[4] ?? input.name ?? state.service.name;
    const data={serviceId:input.serviceId,scheme:input.scheme,account,scopes:state.oauth?.scopes ?? [],outputs,state:'ready',appId:input.scheme==='oauth'&&input.appId!=='foundation'?input.appId:null};
    const id=previous?.id ?? randomUUID(),privateData=await this.vault.encrypt(state,'resource:'+id);
    const references=[...(this.catalog.definitions.has(input.serviceId)?[]:[input.serviceId]),...(data.appId?[data.appId]:[])];
    const row=await this.resources.db.transaction(async connection=>{
      await this.checkApproval?.(actor,connection);
      const row=previous?await this.resources.update(previous,{name:input.name ?? previous.name,data,privateData},connection):await this.resources.insert(ownerId,'connection',input.name ?? state.service.name+' · '+account,data,{id,privateData},connection);
      await this.resources.references(id,references,connection);
      await this.resources.audit.record(ownerId,actor.id,'connection.connect',id,{serviceId:input.serviceId},connection);
      return row;
    });
    return {kind:'connected',resource:await this.resources.view(actor,row),returnTo:input.returnTo};
  }
  async outputs(actor:Actor,row:ResourceRow):Promise<Record<string,string>> {
    if(row.kind!=='connection') fail(400,'wrong_kind','This item is not a connection.');
    await this.resources.authorization.requireResource(actor,row,'use');
    if(row.data.state!=='ready') fail(409,'reconnect_required','Reconnect this service to renew access.');
    try {
      return await this.resources.db.transaction(async connection=>{
        const locked=required(await this.resources.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1 FOR UPDATE',[row.id],connection));
        await this.resources.authorization.requireResource(actor,locked,'use',connection);
        if(locked.data.state!=='ready') fail(409,'reconnect_required','Reconnect this service to renew access.');
        const state=await this.vault.decrypt<ConnectionState>(required(locked.private_data),'resource:'+locked.id);
        if(state.role) return this.roles.obtain(state.role.arn,state.role.externalId,state.role.region);
        if(state.fields) return Object.fromEntries(Object.entries(state.service.auth.token!.outputs).map(([name,pointer])=>[name,textValue(atPointer(state.fields,pointer))]));
        if(!state.oauth) fail(409,'reconnect_required','Reconnect this service to renew access.');
        state.oauth=await this.oauth.refresh(state.service.auth.oauth!,state.app,state.oauth);
        await this.resources.update(locked,{privateData:await this.vault.encrypt(state,'resource:'+locked.id),data:{...locked.data,scopes:state.oauth.scopes}},connection);
        return this.oauth.outputs(state.service.auth.oauth!,state.app,state.oauth);
      });
    } catch(error) {
      if(error instanceof DomainError && ['reconnect_required','account_changed'].includes(error.code)) await this.resources.db.pool.query("UPDATE resources SET data=jsonb_set(data,'{state}','\"reconnect\"'),version=version+1 WHERE id=$1",[row.id]);
      throw error;
    }
  }
  async remove(actor:Actor,row:ResourceRow,revoke=true) {
    await this.resources.authorization.requireResource(actor,row,'delete');
    if(revoke && row.kind==='connection') {
      const state=await this.vault.decrypt<ConnectionState>(required(row.private_data),'resource:'+row.id);
      if(state.oauth) await this.oauth.revoke(state.service.auth.oauth!,state.app,state.oauth);
    }
    await this.resources.delete(actor,row);
  }
}
