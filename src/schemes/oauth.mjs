import { createHash, randomUUID } from 'node:crypto';
import { fail } from '../errors.mjs';
import { destination, prepare, send } from '../fetch.mjs';
import { valueAt } from '../json-pointer.mjs';
import { uriTemplate, templateVariables } from '../uri-template.mjs';

// OAuth 2.0 as services actually speak it. Most follow RFC 6749; where one departs, the departure is a setting of the
// service's definition (catalog/*.json, or one a holder wrote) rather than code of its own:
//   authorize, token          RFC 6570 URL templates for consent and token exchange
//   authorize_params          anything else the consent screen needs (Dropbox: token_access_type=offline)
//   scope_separator           how scopes are joined (Slack, Linear, Shopify: ",")
//   pkce                      whether to send a code challenge (default: yes; services that do not know it ignore it)
//   client_auth               'basic' (the standard's) or 'body' (client_id and client_secret in the request)
//   token_format              'form' (the standard's) or 'json'
//   ok_field                  a service that says success in the body rather than the status (Slack: "ok")
//   keep                      what else of the token answer to keep and show (Salesforce: instance_url)
//   identity                  who authorized: { url, method, headers, json, token_header, id, label, optional } fetched
//                             with the token, { from: 'token', id, label } read from the token answer, or
//                             { from: 'app', id } a value of the app itself (a Shopify shop)
//   subject_prefix            what kind of account the identity names (default "user:"; Slack: "team:")
//   revoke                    { url, style: 'rfc7009' | 'bearer' | 'delete', auth } how a grant is taken back
//
// Foundation talks to these addresses itself, so each must be an https:// URL of a host on the public internet; the
// address a name resolves to is checked, and the request goes to that address (fetch.mjs).
export const OAUTH2_DOCS = 'https://oauth.net/2/';
const invalidResponse = () => fail(502, 'service_response', '接続先からの認証応答を確認できませんでした。');
const reconnect = () => fail(409, 'reconnect_required', '接続先の許可が失効しています。接続し直してください。');
const validToken = value => typeof value === 'string' && value.length > 0 && value.length <= 8192 && !/[^\x20-\x7e]/.test(value);
const validId = value => (typeof value === 'string' && value.length > 0 && value.length <= 255 && !/[\x00-\x1f]/.test(value)) || Number.isSafeInteger(value);
const camel = name => name.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
// Codes services give when a grant is gone for good, when the code or redirect was wrong, and when the app was refused.
const GONE = ['invalid_grant', 'invalid_refresh_token', 'token_revoked', 'token_expired', 'account_inactive', 'invalid_auth', 'not_authed'];
const RETRY = ['invalid_code', 'code_already_used', 'bad_redirect_uri'];
const REFUSED = ['invalid_client', 'unauthorized_client', 'invalid_client_id', 'bad_client_secret'];
export const httpsUrl = value => { destination(value); return value; };

// The one way out: public https hosts only, pinned to the address that was checked, redirects handed back.
export async function publicFetch(url, { method = 'GET', headers = {}, body } = {}) {
  const answer = await send(prepare({ url, method, headers, ...(body === undefined ? {} : { body }) }), new Map());
  return { ok: answer.status >= 200 && answer.status < 300, status: answer.status, text: answer.body_encoding === 'utf8' ? answer.body : '' };
}

export class OAuth2Client {
  // settings: the app's values, camelCased (clientId, clientSecret, and whatever else the app holds).
  // profile: how the service speaks - an object, or a function of the client for a service named by its app.
  constructor(settings = {}, { fetcher = publicFetch, profile = {} } = {}) {
    Object.assign(this, settings);
    this.enabled = Boolean(this.clientId && this.clientSecret);
    this.fetcher = fetcher; this.profile = profile;
  }
  spec() { return typeof this.profile === 'function' ? this.profile(this) : this.profile; }
  // An app value by its field name, or the profile's default for it.
  value(name) { return this[camel(name)] ?? this.spec().defaults?.[name]; }
  // Required URL variables come only from declared app values and the operation's token fields.
  expand(template, extra = {}) {
    const parsed = uriTemplate(template), values = Object.fromEntries(['client_id', ...(this.spec().app_fields ?? []).map(field => field.name)]
      .map(name => [name, this.value(name)]));
    Object.assign(values, extra);
    for (const name of templateVariables(parsed)) if (!Object.hasOwn(values, name) || values[name] === undefined || values[name] === null || values[name] === '') {
      fail(400, 'app_required', 'URLの組み立てに必要な設定が足りません。');
    }
    return parsed.expand(values);
  }
  check() {
    const spec = this.spec();
    if (!this.enabled || !this.clientId || !this.clientSecret) {
      const [status, message] = spec.unavailable ?? [400, 'この接続先には、自分のOAuthアプリを選んでください。'];
      fail(status, 'app_required', message);
    }
    for (const url of [spec.authorize, spec.token]) destination(this.expand(url));
  }
  clientAuth(spec = this.spec()) {
    return spec.client_auth === 'body' ? { headers: {}, values: { client_id: this.clientId, client_secret: this.clientSecret } }
      : { headers: { authorization: 'Basic ' + Buffer.from(encodeURIComponent(this.clientId) + ':' + encodeURIComponent(this.clientSecret)).toString('base64') }, values: {} };
  }
  authorize({ state, verifier, redirectUri, scopes }) {
    this.check();
    scopes ??= [];
    const spec = this.spec(), url = new URL(this.expand(spec.authorize));
    for (const [key, value] of Object.entries({ response_type: 'code', client_id: this.clientId, redirect_uri: redirectUri, state, ...(spec.authorize_params ?? {}),
      ...(spec.pkce === false || !verifier ? {} : { code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }),
      ...(scopes.length ? { scope: scopes.join(spec.scope_separator ?? ' ') } : {}) })) url.searchParams.set(key, value);
    return url.href;
  }
  async call(url, options) {
    destination(url);
    let answer;
    try { answer = await this.fetcher(url, options); }
    catch (error) { if (error?.status) throw error; fail(502, 'service_unavailable', '接続先に接続できませんでした。時間をおいて再度お試しください。'); }
    if (typeof Response === 'function' && answer instanceof Response) answer = { ok: answer.ok, status: answer.status, text: await answer.text() };
    if (answer.status === 429) fail(503, 'service_rate_limit', '接続先の利用上限に達しました。時間をおいて再度お試しください。');
    return answer;
  }
  parse(answer) {
    let data;
    try { data = JSON.parse(answer.text); } catch { data = Object.fromEntries(new URLSearchParams(answer.text)); }
    return data && typeof data === 'object' ? data : {};
  }
  errorOf(data) { return typeof data.error === 'string' ? data.error : typeof data.error?.code === 'string' ? data.error.code : ''; }
  // The token endpoint, with the client's credentials as the service takes them.
  async tokenRequest(values) {
    const spec = this.spec(), auth = this.clientAuth(spec), all = { ...values, ...auth.values }, json = spec.token_format === 'json';
    const answer = await this.call(this.expand(spec.token), { method: 'POST', headers: { accept: 'application/json', 'content-type': json ? 'application/json' : 'application/x-www-form-urlencoded', ...auth.headers },
      body: json ? JSON.stringify(all) : new URLSearchParams(all).toString() });
    const data = this.parse(answer), error = this.errorOf(data);
    if (!answer.ok || (spec.ok_field ? valueAt(data, spec.ok_field) !== true : Boolean(data.error))) {
      if (values.grant_type === 'refresh_token' && GONE.includes(error)) reconnect();
      if (error === 'invalid_grant' || RETRY.includes(error)) fail(400, 'invalid_state', '接続をやり直してください。');
      if (answer.status === 401 || REFUSED.includes(error)) fail(400, 'invalid_app', '接続先がアプリのIDかシークレットを受け付けませんでした。アプリの設定を確認してください。');
      fail(502, 'service_unavailable', '接続先で処理を完了できませんでした。');
    }
    return data;
  }
  grant(data, previous) {
    const spec = this.spec();
    if (!validToken(data.access_token) || (data.token_type !== undefined && typeof data.token_type !== 'string')) invalidResponse();
    const expiresIn = data.expires_in === undefined || data.expires_in === null ? null : Number(data.expires_in);
    if (expiresIn !== null && !(Number.isFinite(expiresIn) && expiresIn > 0)) invalidResponse();
    const refresh = data.refresh_token === undefined || data.refresh_token === null ? previous?.refresh_token ?? null : data.refresh_token;
    if (refresh !== null && !validToken(refresh)) invalidResponse();
    const scopes = typeof data.scope === 'string' ? [...new Set(data.scope.split(/[ ,+]+/).filter(Boolean))].sort() : previous?.scopes ?? null;
    const kept = {};
    for (const name of spec.keep ?? []) {
      const value = typeof data[name] === 'string' && data[name].length <= 2048 ? data[name] : previous?.kept?.[name];
      if (value !== undefined) kept[name] = value;
    }
    return { access_token: data.access_token, token_type: /^bearer$/i.test(data.token_type || 'Bearer') ? 'Bearer' : data.token_type, refresh_token: refresh, scopes,
      expires_at: expiresIn === null ? null : Date.now() + expiresIn * 1000, client_id: this.clientId, kept };
  }
  // Who an answer names: the paths the profile gives, or else the first stable identifier it carries.
  pick(body, { id, label } = {}) {
    const inner = body.data && typeof body.data === 'object' && !Array.isArray(body.data) ? { ...body.data, ...body } : body;
    const ids = id ? [].concat(id).map(pointer => valueAt(body, pointer)) : [['sub', 'id', 'user_id', 'uid', 'email', 'login', 'username'].map(key => inner[key]).find(validId)];
    if (!ids.every(validId)) return null;
    const named = (label ? [].concat(label).map(pointer => valueAt(body, pointer)) : ['email', 'name', 'login', 'username'].map(key => inner[key]))
      .find(value => typeof value === 'string' && value && value.length <= 200 && !/[\x00-\x1f]/.test(value));
    const joined = ids.map(String).join(':');
    return { id: joined, label: named || joined, checked_at: Date.now() };
  }
  // Who authorized, when the service can say: asked with the token, read from the token answer, or the app's own.
  async identity(grant, data) {
    const spec = this.spec(), how = spec.identity;
    if (!how) return null;
    if (how.from === 'app') return this.pick(Object.fromEntries((spec.app_fields ?? []).map(field => [field.name, this.value(field.name)])), how) ?? invalidResponse();
    if (how.from === 'token') return this.pick(data, how) ?? invalidResponse();
    const json = 'json' in how;
    const answer = await this.call(this.expand(how.url, { access_token: grant.access_token, ...grant.kept }), { method: how.method || 'GET',
      headers: { accept: 'application/json', ...(json ? { 'content-type': 'application/json' } : {}), ...(how.headers ?? {}),
        ...(how.token_header ? { [how.token_header]: grant.access_token } : { authorization: 'Bearer ' + grant.access_token }) },
      ...(json ? { body: JSON.stringify(how.json) } : {}) });
    if (answer.status === 401) reconnect();
    const body = this.parse(answer);
    const okField = how.ok_field ?? spec.ok_field;
    if (okField && valueAt(body, okField) !== true) { if (GONE.includes(this.errorOf(body))) reconnect(); invalidResponse(); }
    if (!answer.ok) return how.optional ? null : invalidResponse();
    return this.pick(body, how) ?? (how.optional ? null : invalidResponse());
  }
  subject(identity) { return (this.spec().subject_prefix ?? 'user:') + identity.id; }
  async exchange({ code, verifier, redirectUri }, previous) {
    this.check();
    const spec = this.spec();
    const data = await this.tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, ...(spec.pkce === false || !verifier ? {} : { code_verifier: verifier }) });
    const grant = this.grant(data), identity = await this.identity(grant, data);
    // Without a way to ask who it is, each connection is its own account, and connecting again keeps it.
    const subject = identity ? this.subject(identity) : previous?.subject ?? 'connection:' + randomUUID();
    if (identity && previous && previous.subject !== subject) fail(409, 'account_changed', '接続し直すには同じアカウントを選んでください。');
    return { subject, secret: { ...grant, identity } };
  }
  async token(existing, { subject }) {
    this.check();
    if (existing.client_id !== this.clientId) reconnect();
    if (existing.expires_at === null || existing.expires_at > Date.now() + 60_000) return existing;
    if (!existing.refresh_token) reconnect();
    const data = await this.tokenRequest({ grant_type: 'refresh_token', refresh_token: existing.refresh_token });
    const next = this.grant(data, existing), how = this.spec().identity;
    // Asked again when it can be asked; a token answer that no longer names the account keeps the one it did.
    const identity = !existing.identity || !how || how.from === 'app' ? existing.identity
      : how.from === 'token' ? this.pick(data, how) ?? existing.identity : await this.identity(next, data);
    if (identity && this.subject(identity) !== subject) fail(409, 'account_changed', '接続先のアカウントが変わりました。接続し直してください。');
    return { ...next, identity: identity ?? existing.identity };
  }
  get revocable() { return Boolean(this.spec().revoke?.url); }
  async revoke(secret) {
    const spec = this.spec(), how = spec.revoke, url = this.expand(how.url, { access_token: secret.access_token, refresh_token: secret.refresh_token ?? secret.access_token });
    let options;
    if (how.style === 'bearer') options = { method: 'POST', headers: { authorization: 'Bearer ' + secret.access_token } };
    else if (how.style === 'delete') options = { method: 'DELETE', headers: {} };
    else {
      const auth = how.auth === 'none' ? { headers: {}, values: {} } : this.clientAuth(spec);
      options = { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...auth.headers },
        body: new URLSearchParams({ token: secret.refresh_token || secret.access_token, ...auth.values }).toString() };
    }
    const answer = await this.call(url, options), body = this.parse(answer), gone = GONE.includes(this.errorOf(body));
    if (!gone && (!answer.ok || (spec.ok_field && valueAt(body, spec.ok_field) !== true))) fail(502, 'revoke_failed', '接続先の許可を取り消せませんでした。');
  }
  facts(secret) {
    return { label: secret.identity?.label || this.serviceName || this.spec().name, account: secret.identity?.id ?? null, client_id: secret.client_id,
      ...(secret.scopes ? { scopes: secret.scopes } : {}), ...(secret.kept ?? {}), expiry_known: secret.expires_at !== null };
  }
}

// Only declared scalar output values can be selected. Optional facts (such as expiry) may be absent.
export function inject(injection, values) {
  return Object.fromEntries(Object.entries(injection).flatMap(([name, pointer]) => {
    const value = valueAt(values, pointer);
    if (value === undefined || value === null || value === '') return [];
    if (!['string', 'number', 'boolean'].includes(typeof value)) invalidResponse();
    return [[name, String(value)]];
  }));
}

// Foundation's own app for a service, when its configuration holds FOUNDATION_<ID>_CLIENT_ID and _SECRET. A service
// whose addresses are the holder's own site (a kintone domain, a Shopify shop) has none: only the holder's app can
// name the site.
export function oauthSettings(definition, env = {}) {
  const prefix = 'FOUNDATION_' + definition.id.toUpperCase().replace(/-/g, '_') + '_';
  return { clientId: env[prefix + 'CLIENT_ID'] || '', clientSecret: env[prefix + 'CLIENT_SECRET'] || '' };
}
export function oauthClient(definition, settings = {}, options = {}) {
  if (Boolean(settings.clientId) !== Boolean(settings.clientSecret)) throw new Error(`Both Foundation ${definition.name} client ID and client secret are required`);
  const spec = definition.auth_schemes.oauth, ownSiteOnly = (spec.app_fields ?? []).some(field => field.required);
  return new OAuth2Client(ownSiteOnly ? {} : settings, { ...options, profile: { ...spec, name: definition.name,
    unavailable: [503, `現在Foundationの${definition.name}アプリは使えません。自分のOAuthアプリを選んでください。`] } });
}

// The OAuth scheme of a service described as data: connecting through an app, renewing, revoking, and what an AI is
// handed - the definition's injection, filled from the token, the account and the app's values.
export function oauthScheme(definition, client) {
  const spec = definition.auth_schemes.oauth;
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret), expiresAt: secret.expires_at,
    credentials: { environment: inject(spec.injection, { ...Object.fromEntries((spec.app_fields ?? []).map(field => [field.name, client.value(field.name)])), ...(secret.kept ?? {}),
      access_token: secret.access_token, account: secret.identity?.id, expires_at: secret.expires_at === null ? undefined : secret.expires_at }) } });
  return {
    kind: 'oauth', available: client.enabled, variables: Object.keys(spec.injection),
    ...(spec.scopes ? { scopes: { base: spec.scopes.base ?? [], documentationUrl: spec.scopes.docs || '' } } : {}),
    oauthClient: client, withClient: other => oauthScheme(definition, other),
    authorization: {
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    ...(client.revocable ? { revoke: privateState => client.revoke(privateState) } : {}),
  };
}
