import { createHash } from 'node:crypto';
import { Template } from '@fedify/uri-template';
import type { z } from 'zod';
import type { OAuthDefinition } from '../shared/contracts.js';
import { atPointer, textValue } from '../shared/values.js';
import { publicUrl, responseJson } from './transport.js';
import type { Transport } from './transport.js';
import { fail } from './errors.js';
import { digest } from './vault.js';

export type OAuthSpec = z.infer<typeof OAuthDefinition>;
export interface OAuthApp { clientId: string; clientSecret?: string; fields: Record<string,string>; version?: number }
export interface OAuthToken {
  accessToken: string; refreshToken?: string; expiresAt: number | null; refreshExpiresAt?: number;
  scopes: string[]; account: string; accountName: string; extra: Record<string,string>; facts: Record<string,unknown>;
}
export function expandUrl(template: string, values: Record<string,string>): string {
  try { return publicUrl(new Template(template).expand(values)).href; } catch { fail(400,'invalid_service_url','Check the service URL and its required fields.'); }
}
const strings = (value: unknown, separator = ' ') => typeof value === 'string' ? [...new Set(value.split(separator).filter(Boolean))].sort() : [];
export class OAuth {
  constructor(readonly transport: Transport) {}
  authorize(spec: OAuthSpec, app: OAuthApp, state: string, verifier: string, redirectUri: string, scopes: string[]) {
    const url = new URL(expandUrl(spec.authorizeUrl, app.fields));
    const params: Record<string,string> = {...spec.authorizeParams,response_type:'code',client_id:app.clientId,redirect_uri:spec.adapter === 'ebay' ? app.fields.ruName! : redirectUri,state};
    if(scopes.length) params.scope = scopes.join(spec.scopes.separator);
    if(spec.pkce) { params.code_challenge = createHash('sha256').update(verifier).digest('base64url'); params.code_challenge_method = 'S256'; }
    if(spec.adapter === 'openrouter') {
      delete params.response_type; delete params.client_id; delete params.redirect_uri;
      params.callback_url = redirectUri; params.key_label = 'Foundation';
    }
    for(const [key,value] of Object.entries(params)) url.searchParams.set(key,value);
    return url.href;
  }
  private async call(spec: OAuthSpec, app: OAuthApp, values: Record<string,string>, refresh = false) {
    const params = {...spec.tokenParams,...values}, headers: Record<string,string> = {accept:'application/json'};
    if(spec.clientAuth === 'basic') headers.authorization = 'Basic '+Buffer.from(encodeURIComponent(app.clientId)+':'+encodeURIComponent(app.clientSecret ?? '')).toString('base64');
    if(spec.clientAuth === 'body') { params.client_id = app.clientId; if(app.clientSecret) params.client_secret = app.clientSecret; }
    if(spec.clientAuth === 'none' && app.clientId) params.client_id = app.clientId;
    headers['content-type'] = spec.tokenFormat === 'json' ? 'application/json' : 'application/x-www-form-urlencoded';
    const response = await this.transport.send({url:expandUrl(spec.tokenUrl,app.fields),method:'POST',headers,body:spec.tokenFormat === 'json' ? JSON.stringify(params) : new URLSearchParams(params).toString()});
    const data = responseJson(response);
    if(response.status >= 400 || data.error || spec.okPointer && atPointer(data,spec.okPointer) !== true) {
      if(refresh && (data.error === 'invalid_grant' || data.error === 'invalid_token')) fail(409,'reconnect_required','Reconnect this service to renew access.');
      if(response.status === 429) fail(503,'service_rate_limit','The service is busy. Try again later.');
      fail(502,'authorization_failed','The service did not authorize this connection.');
    }
    return data;
  }
  private token(spec: OAuthSpec, data: Record<string,unknown>, scopes: string[], previous?: OAuthToken): OAuthToken {
    const accessToken = spec.adapter === 'openrouter' ? data.key : data.access_token;
    if(typeof accessToken !== 'string' || !accessToken || accessToken.length>16384 || /[\s\u0000-\u001f]/.test(accessToken)) fail(502,'invalid_response','The service did not return a valid access token.');
    if(data.token_type !== undefined && !['bearer','user access token'].includes(String(data.token_type).toLowerCase())) fail(502,'invalid_response','The service returned an unsupported token.');
    let expiresAt: number | null = null;
    if(data.expires_in !== undefined) {
      const seconds = Number(data.expires_in);
      if(!Number.isSafeInteger(seconds) || seconds <= 0 || seconds>315_576_000) fail(502,'invalid_response','The service returned an invalid expiry.');
      expiresAt = Date.now()+seconds*1000;
    }
    const refreshToken = data.refresh_token ?? previous?.refreshToken;
    if(refreshToken !== undefined && (typeof refreshToken !== 'string' || !refreshToken || refreshToken.length>16384)) fail(502,'invalid_response','The service returned an invalid refresh token.');
    const extra = {...previous?.extra};
    for(const key of spec.keep) if(typeof data[key] === 'string') extra[key] = data[key];
    const result: OAuthToken = {accessToken,...(refreshToken ? {refreshToken:String(refreshToken)} : {}),expiresAt,scopes: data.scope !== undefined ? strings(data.scope,spec.scopes.separator) : previous?.scopes ?? scopes,account:previous?.account ?? '',accountName:previous?.accountName ?? '',extra,facts:{}};
    if(data.refresh_token_expires_in !== undefined) {
      const seconds=Number(data.refresh_token_expires_in); if(!Number.isSafeInteger(seconds)||seconds<=0||seconds>315_576_000) fail(502,'invalid_response','The service returned an invalid expiry.');
      result.refreshExpiresAt=Date.now()+seconds*1000;
    }
    if(previous?.refreshExpiresAt && refreshToken === previous.refreshToken) result.refreshExpiresAt=Math.min(result.refreshExpiresAt ?? Infinity,previous.refreshExpiresAt);
    return result;
  }
  async exchange(spec: OAuthSpec, app: OAuthApp, code: string, verifier: string, redirectUri: string, scopes: string[], previous?: OAuthToken) {
    const values:Record<string,string> = spec.adapter === 'openrouter' ? {code,code_verifier:verifier,code_challenge_method:'S256'} : {grant_type:'authorization_code',code,redirect_uri:spec.adapter === 'ebay' ? app.fields.ruName! : redirectUri,...(spec.pkce ? {code_verifier:verifier} : {})};
    const data = await this.call(spec,app,values);
    const result = await this.inspect(spec,app,this.token(spec,data,scopes,previous),data);
    if(previous && result.account !== previous.account && spec.adapter !== 'openrouter') fail(409,'account_changed','Reconnect using the same service account.');
    return result;
  }
  async refresh(spec: OAuthSpec, app: OAuthApp, previous: OAuthToken): Promise<OAuthToken> {
    let current = previous;
    if(previous.expiresAt !== null && previous.expiresAt < Date.now()+60_000) {
      if(!previous.refreshToken || previous.refreshExpiresAt && previous.refreshExpiresAt <= Date.now()) fail(409,'reconnect_required','Reconnect this service to renew access.');
      const data = await this.call(spec,app,{grant_type:'refresh_token',refresh_token:previous.refreshToken},true);
      current = this.token(spec,data,previous.scopes,previous);
    }
    if(spec.identity?.url || spec.adapter === 'ebay' || spec.adapter === 'openrouter') current = await this.inspect(spec,app,current);
    if(current.account !== previous.account) fail(409,'account_changed','Reconnect using the same service account.');
    return current;
  }
  private async inspect(spec: OAuthSpec, app: OAuthApp, current: OAuthToken, tokenResponse?: Record<string,unknown>): Promise<OAuthToken> {
    let data: Record<string,unknown> = tokenResponse ?? {};
    if(spec.adapter === 'ebay') {
      const response = await this.transport.send({url:expandUrl(spec.tokenUrl,app.fields)+'/introspect',method:'POST',headers:{authorization:'Basic '+Buffer.from(app.clientId+':'+app.clientSecret).toString('base64'),'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({token:current.accessToken,token_type_hint:'access_token'}).toString()});
      data = responseJson(response);
      if(response.status!==200 || data.active!==true || data.client_id!==app.clientId || typeof data.sub!=='string' || !data.sub || typeof data.exp!=='number' || data.exp*1000<=Date.now()) fail(409,'reconnect_required','Reconnect this service to renew access.');
      return {...current,account:data.sub,accountName:typeof data.username==='string' ? data.username : data.sub,scopes:strings(data.scope),expiresAt:Math.min(current.expiresAt ?? Infinity,data.exp*1000)};
    }
    if(spec.adapter === 'openrouter') {
      const response=await this.transport.send({url:'https://openrouter.ai/api/v1/key',headers:{authorization:'Bearer '+current.accessToken}});
      data=responseJson(response);
      if(response.status!==200 || !data.data || typeof data.data!=='object') fail(409,'reconnect_required','Reconnect this service to renew access.');
      const info=data.data as Record<string,unknown>;
      return {...current,account:digest(current.accessToken),accountName:typeof info.label==='string'? info.label:'OpenRouter',facts:info};
    }
    if(spec.identity?.url) {
      const response=await this.transport.send({url:expandUrl(spec.identity.url,{...app.fields,...current.extra,accessToken:current.accessToken,refreshToken:current.refreshToken ?? ''}),method:spec.identity.method,headers:{...spec.identity.headers,authorization:'Bearer '+current.accessToken}});
      data=responseJson(response);
      if(response.status===401 || response.status===403) fail(409,'reconnect_required','Reconnect this service to renew access.');
      if(response.status>=400) fail(502,'invalid_response','The service account could not be verified.');
      if(spec.adapter==='github' && response.headers['x-oauth-scopes']!==undefined) current.scopes=strings(response.headers['x-oauth-scopes'].replaceAll(',',' '));
      if(spec.adapter==='google' && data.email_verified!==true) fail(502,'invalid_response','The service account could not be verified.');
    } else if(spec.identity?.from==='app') data=app.fields;
    const first=(pointers:string|string[]) => {
      for(const pointer of Array.isArray(pointers)?pointers:[pointers]) { const value=atPointer(data,pointer); if(typeof value==='string' && value || typeof value==='number') return String(value); }
      return '';
    };
    const id=spec.identity?.id;
    const account=id ? (Array.isArray(id) ? id.map(pointer=>first(pointer)).filter(Boolean).join(':') : first(id)) : current.account || app.fields.domain || app.fields.shop || digest(current.accessToken);
    if(!account || account.length>1000) fail(502,'invalid_response','The service account could not be verified.');
    return {...current,account,accountName:spec.identity ? first(spec.identity.name)||account : account};
  }
  async revoke(spec: OAuthSpec, app: OAuthApp, current: OAuthToken) {
    if(!spec.revoke) fail(409,'manual_revoke','Remove access in the service settings, then remove this connection.');
    const headers:Record<string,string>={},values:Record<string,string>={token:current.refreshToken ?? current.accessToken};
    const auth=spec.revoke.auth ?? spec.clientAuth;
    if(auth==='basic'||spec.revoke.style==='github') headers.authorization='Basic '+Buffer.from(app.clientId+':'+(app.clientSecret ?? '')).toString('base64');
    else if(auth==='body') { values.client_id=app.clientId; if(app.clientSecret) values.client_secret=app.clientSecret; }
    let method='POST',body:string|undefined;
    if(spec.revoke.style==='github') { method='DELETE';headers['content-type']='application/json';body=JSON.stringify({access_token:current.accessToken}); }
    else if(spec.revoke.style==='delete') method='DELETE';
    else if(spec.revoke.style==='bearer') headers.authorization='Bearer '+current.accessToken;
    else { headers['content-type']='application/x-www-form-urlencoded';body=new URLSearchParams(values).toString(); }
    const response=await this.transport.send({url:expandUrl(spec.revoke.url,{...app.fields,clientId:app.clientId,accessToken:current.accessToken,refreshToken:current.refreshToken ?? ''}),method,headers,...(body?{body}:{})});
    if(response.status>=300) fail(502,'revoke_failed','Access could not be removed at the service. Try again.');
  }
  outputs(spec: OAuthSpec, app: OAuthApp, value: OAuthToken): Record<string,string> {
    const data={...app.fields,...value.extra,...value,expiresAt:value.expiresAt===null?'':String(value.expiresAt)};
    return Object.fromEntries(Object.entries(spec.outputs).map(([name,pointer]) => [name,textValue(atPointer(data,pointer))]));
  }
}
