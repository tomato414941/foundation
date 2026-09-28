import { createHash, randomUUID } from 'node:crypto';
import { fail } from '../../errors.mjs';
import { destination, prepare, send } from '../../fetch.mjs';

// Any service that speaks OAuth 2.0 as RFC 6749 describes it, known only through the app someone registered for it:
// where its consent screen is, where it hands out tokens, and - when it has them - where it says who authorized and
// where it takes a token back. Nothing here is particular to a service; a service that departs from the standard
// needs a connector of its own.
//
// Foundation talks to these addresses itself, so each must be an https:// URL of a host on the public internet; the
// address a name resolves to is checked, and the request goes to that address (fetch.mjs).
export const OAUTH2_DOCS = 'https://oauth.net/2/';
const invalidResponse = () => fail(502, 'service_response', '接続先からの認証応答を確認できませんでした。');
const reconnect = () => fail(409, 'reconnect_required', '接続先の許可が失効しています。接続し直してください。');
const validToken = value => typeof value === 'string' && value.length > 0 && value.length <= 8192 && !/[^\x20-\x7e]/.test(value);
export const httpsUrl = value => { destination(value); return value; };

// The one way out: public https hosts only, pinned to the address that was checked, redirects handed back.
export async function publicFetch(url, { method = 'GET', headers = {}, body } = {}) {
  const answer = await send(prepare({ url, method, headers, ...(body === undefined ? {} : { body }) }), new Map());
  return { ok: answer.status >= 200 && answer.status < 300, status: answer.status, text: answer.body_encoding === 'utf8' ? answer.body : '' };
}

export class OAuth2Client {
  constructor(settings = {}, { fetcher = publicFetch } = {}) {
    Object.assign(this, settings);
    this.enabled = false;
    this.fetcher = fetcher;
  }
  check() {
    if (!this.enabled || !this.clientId || !this.clientSecret || !this.authorizeUrl || !this.tokenUrl) fail(400, 'app_required', 'この接続先には、自分のOAuthアプリを選んでください。');
  }
  authorize({ state, verifier, redirectUri, scopes }) {
    this.check();
    const url = new URL(this.authorizeUrl);
    for (const [key, value] of Object.entries({ response_type: 'code', client_id: this.clientId, redirect_uri: redirectUri, state,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', ...(scopes.length ? { scope: scopes.join(' ') } : {}) })) url.searchParams.set(key, value);
    return url.href;
  }
  async call(url, options) {
    let answer;
    try { answer = await this.fetcher(url, options); }
    catch (error) { if (error?.status) throw error; fail(502, 'service_unavailable', '接続先に接続できませんでした。時間をおいて再度お試しください。'); }
    return answer;
  }
  // The token endpoint, with the client's own credentials (HTTP Basic, as the standard asks every server to accept).
  async tokenRequest(values) {
    const answer = await this.call(this.tokenUrl, { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded',
      authorization: 'Basic ' + Buffer.from(encodeURIComponent(this.clientId) + ':' + encodeURIComponent(this.clientSecret)).toString('base64') },
      body: new URLSearchParams(values).toString() });
    let data;
    try { data = JSON.parse(answer.text); } catch { data = Object.fromEntries(new URLSearchParams(answer.text)); }
    if (!answer.ok || data?.error) {
      if (data?.error === 'invalid_grant' && values.grant_type === 'refresh_token') reconnect();
      if (data?.error === 'invalid_grant') fail(400, 'invalid_state', '接続をやり直してください。');
      if (answer.status === 401 || data?.error === 'invalid_client') fail(400, 'invalid_app', '接続先がアプリのIDかシークレットを受け付けませんでした。アプリの設定を確認してください。');
      fail(502, 'service_unavailable', '接続先で処理を完了できませんでした。');
    }
    return data;
  }
  grant(data, previous) {
    if (!data || typeof data !== 'object' || !validToken(data.access_token) || (data.token_type !== undefined && typeof data.token_type !== 'string')) invalidResponse();
    const expiresIn = data.expires_in === undefined ? null : Number(data.expires_in);
    if (expiresIn !== null && !(Number.isFinite(expiresIn) && expiresIn > 0)) invalidResponse();
    const refresh = data.refresh_token === undefined ? previous?.refresh_token ?? null : data.refresh_token;
    if (refresh !== null && !validToken(refresh)) invalidResponse();
    const scope = typeof data.scope === 'string' ? [...new Set(data.scope.split(/[ ,]+/).filter(Boolean))].sort() : previous?.scopes ?? null;
    return { access_token: data.access_token, token_type: data.token_type || 'Bearer', refresh_token: refresh, scopes: scope,
      expires_at: expiresIn === null ? null : Date.now() + expiresIn * 1000, client_id: this.clientId };
  }
  // Who authorized, when the service says so: the first stable identifier its answer carries.
  async identity(accessToken) {
    if (!this.userinfoUrl) return null;
    const answer = await this.call(this.userinfoUrl, { headers: { accept: 'application/json', authorization: 'Bearer ' + accessToken } });
    if (answer.status === 401) reconnect();
    let data;
    try { data = JSON.parse(answer.text); } catch { invalidResponse(); }
    if (!answer.ok || !data || typeof data !== 'object') invalidResponse();
    const body = data.data && typeof data.data === 'object' && !Array.isArray(data.data) ? { ...data.data, ...data } : data;
    const id = ['sub', 'id', 'user_id', 'uid', 'email', 'login', 'username'].map(key => body[key]).find(value => (typeof value === 'string' && value) || Number.isSafeInteger(value));
    if (id === undefined || String(id).length > 255 || /[\x00-\x1f]/.test(String(id))) invalidResponse();
    const label = ['email', 'name', 'login', 'username'].map(key => body[key]).find(value => typeof value === 'string' && value && value.length <= 200) || String(id);
    return { id: String(id), label, checked_at: Date.now() };
  }
  async exchange({ code, verifier, redirectUri }, previous) {
    this.check();
    const grant = this.grant(await this.tokenRequest({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirectUri }));
    const identity = await this.identity(grant.access_token);
    // Without a way to ask who it is, each connection is its own account, and connecting again keeps it.
    const subject = identity ? 'user:' + identity.id : previous?.subject ?? 'connection:' + randomUUID();
    if (identity && previous && previous.subject !== subject) fail(409, 'account_changed', '接続し直すには同じアカウントを選んでください。');
    return { subject, secret: { ...grant, identity } };
  }
  async token(existing, { subject }) {
    this.check();
    if (existing.client_id !== this.clientId) reconnect();
    if (existing.expires_at === null || existing.expires_at > Date.now() + 60_000) return existing;
    if (!existing.refresh_token) reconnect();
    const next = this.grant(await this.tokenRequest({ grant_type: 'refresh_token', refresh_token: existing.refresh_token }), existing);
    const identity = existing.identity ? await this.identity(next.access_token) : null;
    if (identity && 'user:' + identity.id !== subject) fail(409, 'account_changed', '接続先のアカウントが変わりました。接続し直してください。');
    return { ...next, identity: identity ?? existing.identity };
  }
  // RFC 7009, for an app that says where.
  async revoke(secret) {
    const answer = await this.call(this.revokeUrl, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded',
      authorization: 'Basic ' + Buffer.from(encodeURIComponent(this.clientId) + ':' + encodeURIComponent(this.clientSecret)).toString('base64') },
      body: new URLSearchParams({ token: secret.refresh_token || secret.access_token }).toString() });
    if (!answer.ok) fail(502, 'revoke_failed', '接続先の許可を取り消せませんでした。');
  }
  facts(secret) {
    return { label: secret.identity?.label || this.serviceName, account: secret.identity?.id ?? null, client_id: secret.client_id,
      ...(secret.scopes ? { scopes: secret.scopes } : {}), expiry_known: secret.expires_at !== null };
  }
}
