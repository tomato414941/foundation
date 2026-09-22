import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createApp } from '../src/app.mjs';
import { fail } from '../src/errors.mjs';
import { GmailClient, METADATA_SCOPE, READONLY_SCOPE } from '../src/services/gmail.mjs';
import { gmailReadonly, gmailMetadata } from '../src/adapters.mjs';

export const KEY = Buffer.alloc(32, 7);
export const USER_A = '10000000-0000-4000-8000-000000000001';
export const USER_B = '10000000-0000-4000-8000-000000000002';
export const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
export class FakeAuth {
  constructor() { this.enabled = true; this.refreshes = 0; this.revoked = false; this.links = new Map(); this.codeFactory = () => randomUUID(); }
  value(email = 'owner@example.test') { return { access_token: 'supabase-access-' + email, refresh_token: 'supabase-refresh-' + email, expires_at: Date.now() + 3600_000, user: { id: email === 'owner@example.test' ? USER_A : USER_B, email } }; }
  async sendLink(email, redirectUri, storage) {
    if (!this.enabled) fail(503, 'auth_unavailable', '現在ログインを利用できません。');
    if (this.sendHandler) await this.sendHandler(email);
    const code = this.codeFactory(email), verifier = randomUUID();
    storage.set('test-verifier', verifier);
    this.links.set(email, { email, code, verifier, url: redirectUri + '?code=' + code });
  }
  async exchangeLink(code, storage) {
    const link = [...this.links.values()].find(value => value.code === code);
    if (this.verifyHandler) await this.verifyHandler(code, storage);
    if (!link || storage.get('test-verifier') !== link.verifier) fail(401, 'invalid_link', 'リンクが無効か、有効期限が切れています。');
    if (this.links.get(link.email) === link) this.links.delete(link.email);
    return this.value(link.email);
  }
  async user(token) { if (this.revoked || !token.startsWith('supabase-access-')) fail(401, 'login_required', 'ログインしてください。'); return this.value(token.slice('supabase-access-'.length)).user; }
  async refresh(token) { this.refreshes++; if (this.refreshHandler) await this.refreshHandler(); return this.value(token.slice('supabase-refresh-'.length)); }
  async logout() {}
}
export class FakeGmail extends GmailClient {
  constructor() {
    super({ clientId: 'test-google-client', clientSecret: 'test-google-secret' }, { fetcher: async (url, options) => this.fetch(url, options) });
    this.calls = []; this.exchangeCount = 0;
  }
  async fetch(url, options) {
    this.calls.push({ url: String(url), options });
    if (String(url).endsWith('/revoke')) {
      if (this.revokeHandler) return this.revokeHandler();
      return new Response('', { status: 200 });
    }
    if (String(url).endsWith('/token')) {
      const params = options.body, exchange = params.get('grant_type') === 'authorization_code';
      const code = exchange ? params.get('code') : params.get('refresh_token').replace('refresh-', '');
      if (exchange) { this.exchangeCount++; if (this.exchangeHandler) await this.exchangeHandler(); }
      else if (this.refreshHandler) { const result = await this.refreshHandler(); if (result) return result; }
      const mode = code.endsWith('-metadata') ? 'metadata' : 'readonly';
      return json({ access_token: 'google-access-' + code, refresh_token: 'refresh-' + code, expires_in: 3600, scope: mode === 'metadata' ? METADATA_SCOPE : READONLY_SCOPE, token_type: 'Bearer' });
    }
    if (String(url).includes('/profile?')) {
      const code = options.headers.authorization.replace('Bearer google-access-', '');
      const email = code.replace(/-(readonly|metadata)$/, '') + '@example.test';
      return json({ emailAddress: email });
    }
    throw new Error('Unexpected provider request');
  }
}
export async function fixture(t, options = {}) {
  const { gmail = new FakeGmail(), adapters = [gmailReadonly(gmail), gmailMetadata(gmail)], ...rest } = options, auth = options.auth || new FakeAuth();
  const app = createApp({ encryptionKey: KEY, ...rest, auth, adapters });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => app.close());
  const base = 'http://127.0.0.1:' + app.server.address().port;
  let cookie;
  async function request(path, { method = 'GET', data, token, anonymous = false, headers = {} } = {}) {
    const response = await fetch(base + path, { method, redirect: 'manual', headers: { ...(!anonymous && cookie ? { cookie } : {}), ...(method !== 'GET' ? { origin: options.publicOrigin || base } : {}), ...(data !== undefined ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: 'Bearer ' + token } : {}), ...headers }, ...(data !== undefined ? { body: JSON.stringify(data) } : {}) });
    const text = await response.text();
    let json; try { json = JSON.parse(text); } catch {}
    return { status: response.status, json, text, headers: response.headers };
  }
  async function login(email = 'owner@example.test') {
    const sent = await request('/api/auth/link', { method: 'POST', data: { email } });
    assert.equal(sent.status, 202, sent.text);
    const challenge = sent.headers.getSetCookie().find(value => value.startsWith('fdn_login=')).split(';')[0];
    const url = new URL(auth.links.get(email).url);
    const response = await request(url.pathname + url.search, { headers: { cookie: [cookie, challenge].filter(Boolean).join('; '), 'sec-fetch-site': 'cross-site' } });
    assert.equal(response.status, 303, response.text);
    assert.equal(response.headers.get('location'), '/');
    cookie = response.headers.getSetCookie().find(value => value.startsWith('fdn_session=')).split(';')[0];
    return response;
  }
  // Gmail's read range is its adapter: gmail.readonly or gmail.metadata.
  async function start({ name = '個人用', range = 'readonly', purpose = 'サービス登録', credentialId } = {}) {
    const result = await request('/api/adapters/gmail.' + range + '/connect', { method: 'POST', data: { name, purpose, credentialId } });
    assert.equal(result.status, 200, result.text);
    return new URL(result.json.url);
  }
  // Returns to the callback the authorization named, as Google would.
  async function callback(url, code = 'personal-readonly', extra = {}) {
    return request(new URL(url.searchParams.get('redirect_uri')).pathname + '?state=' + url.searchParams.get('state') + '&code=' + code, extra);
  }
  async function credential(code = 'personal', range = 'readonly') {
    const url = await start({ name: code, range });
    const response = await callback(url, code + '-' + range);
    assert.equal(response.headers.get('location'), '/?connection=connected&adapter=gmail.' + range, response.text);
    return (await request('/api/state')).json.credentials.find((item) => item.subject === code + '@example.test');
  }
  async function agent(name = 'dev-us') {
    const result = await request('/api/agents', { method: 'POST', data: { name } });
    assert.equal(result.status, 201, result.text);
    return result.json.agent;
  }
  function expire(credentialId, owner = USER_A) {
    const credential = app.store.credential(owner, credentialId);
    app.store.saveSecret(credential, { ...app.store.secret(credential), expires_at: Date.now() - 1 });
  }
  if (options.login !== false) await login();
  return { app, auth, gmail, base, request, login, start, callback, credential, agent, expire, cookie: () => cookie };
}
