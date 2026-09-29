import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createApp } from '../src/app.mjs';
import { fail } from '../src/errors.mjs';
import { FakeGoogle } from '../src/adapters/google/fixture.mjs';
export { FakeGoogle } from '../src/adapters/google/fixture.mjs';
import { googleOauth } from '../src/adapters/google/index.mjs';
import { entry } from '../src/catalog.mjs';
export { entry } from '../src/catalog.mjs';
import { Credentials } from '../src/credentials.mjs';
import { Services } from '../src/services.mjs';
import { Apps } from '../src/apps.mjs';
import { Resources } from '../src/resources.mjs';
import { Principals } from '../src/principals.mjs';
import { Authorization } from '../src/authorization.mjs';
import { Sessions, OAuthFlows } from '../src/sessions.mjs';

// Gmail scopes the tests ask Google for.
const GMAIL_SCOPE = 'https://www.googleapis.com/auth/gmail.';
export const GMAIL = { readonly: [GMAIL_SCOPE + 'readonly'], metadata: [GMAIL_SCOPE + 'metadata'], 'read-send': [GMAIL_SCOPE + 'readonly', GMAIL_SCOPE + 'send'] };

// The modules a server is made of, over one store, with the services given (each an entry of the catalog).
export function modules(store, entries = []) {
  const principals = new Principals(store), authorization = new Authorization(principals);
  const resources = new Resources(store), services = new Services(store, resources, entries, { authorization }), apps = new Apps(store, resources, services);
  return { resources, services, apps, credentials: new Credentials(store, resources, services, apps), principals, authorization, sessions: new Sessions(store), flows: new OAuthFlows(store) };
}

export const KEY = Buffer.alloc(32, 7);
export const USER_A = '10000000-0000-4000-8000-000000000001';
export const USER_B = '10000000-0000-4000-8000-000000000002';
export const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
export class FakeAuth {
  constructor() { this.enabled = true; this.refreshes = 0; this.revoked = false; this.links = new Map(); this.codeFactory = () => randomUUID(); this.now = Date.now; }
  value(email = 'owner@example.test') { return { access_token: 'supabase-access-' + email, refresh_token: 'supabase-refresh-' + email, expires_at: Date.now() + 3600_000, user: { id: email === 'owner@example.test' ? USER_A : USER_B, email } }; }
  async sendLink(email, redirectUri) {
    if (!this.enabled) fail(503, 'auth_unavailable', '現在ログインを利用できません。');
    if (this.sendHandler) await this.sendHandler(email);
    const code = this.codeFactory(email);
    this.links.set(email, { email, code, expires_at: this.now() + 900_000, url: redirectUri + '#' + new URLSearchParams({ token_hash: code, email }) });
  }
  async verifyLink(code) {
    const link = [...this.links.values()].find(value => value.code === code);
    if (!link || link.expires_at <= this.now()) fail(401, 'invalid_link', 'リンクが無効か、有効期限が切れています。');
    this.links.delete(link.email);
    if (this.verifyHandler) await this.verifyHandler(code);
    return this.value(link.email);
  }
  async user(token) { if (this.revoked || !token.startsWith('supabase-access-')) fail(401, 'login_required', 'ログインしてください。'); return this.value(token.slice('supabase-access-'.length)).user; }
  async refresh(token) { this.refreshes++; if (this.refreshHandler) await this.refreshHandler(); return this.value(token.slice('supabase-refresh-'.length)); }
  async logout() {}
}

// Seed a credential for a service, including already-expired fixture tokens.
export function acquired(store, entries, service, { subject, secret }, scheme = 'oauth') {
  const { credentials } = modules(store, entries);
  const saved = credentials.keep(USER_A, { service, scheme, subject, label: subject,
    state: { private_state: secret, facts: {}, expires_at: secret.expires_at } });
  const row = () => credentials.held(USER_A, saved.id);
  const state = () => credentials.state(row());
  const run = () => credentials.obtain(row());
  return { credentials, row, run, state };
}
export async function fixture(t, options = {}) {
  const { google = new FakeGoogle(), services = [entry('google', { oauth: googleOauth(google) })], ...rest } = options, auth = options.auth || new FakeAuth();
  const app = createApp({ encryptionKey: KEY, ...rest, auth, services });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  let closed = false;
  const close = async () => { if (!closed) { closed = true; await app.close(); } };
  t.after(close);
  const base = 'http://127.0.0.1:' + app.server.address().port;
  let cookie;
  // `data` is sent as JSON; `raw` is sent as given, with `type` as its content type.
  // A token that acts for exactly one principal names them on every call, as the CLI and the MCP tool do.
  const actsFor = new Map();
  async function request(path, { method = 'GET', data, raw, type = 'application/octet-stream', token, anonymous = false, headers = {}, as } = {}) {
    const holder = as ?? (token && actsFor.get(token));
    if (holder && !/[?&]as=/.test(path)) path += (path.includes('?') ? '&' : '?') + 'as=' + holder;
    const body = raw !== undefined ? raw : data !== undefined ? JSON.stringify(data) : undefined;
    const response = await fetch(base + path, { method, redirect: 'manual', headers: { ...(!anonymous && cookie ? { cookie } : {}), ...(method !== 'GET' ? { origin: options.publicOrigin || base } : {}), ...(body !== undefined ? { 'content-type': raw !== undefined ? type : 'application/json' } : {}), ...(token ? { authorization: 'Bearer ' + token } : {}), ...headers }, ...(body !== undefined ? { body } : {}) });
    const text = await response.text();
    let json; try { json = JSON.parse(text); } catch {}
    return { status: response.status, json, text, headers: response.headers };
  }
  async function login(email = 'owner@example.test') {
    // The other tests need a verified identity, not a real email delivery or its resend cooldown.
    await auth.sendLink(email, base + '/login/confirm');
    const response = await request('/v1/login/verify', { method: 'POST', data: { email, token_hash: auth.links.get(email).code } });
    assert.equal(response.status, 200, response.text);
    assert.equal(response.json.return_to, '/');
    cookie = response.headers.getSetCookie().find(value => value.startsWith('fdn_session=')).split(';')[0];
    return response;
  }
  // Connecting Google, asking to read Gmail unless other scopes are given.
  async function start({ credential_id, scopes = GMAIL.readonly } = {}) {
    const result = await request('/v1/credentials', { method: 'POST', data: { service: 'google', credential_id, scopes } });
    assert.equal(result.status, 200, result.text);
    return new URL(result.json.url);
  }
  // Returns to the callback the authorization named, as Google would.
  async function callback(url, code = 'personal', extra = {}) {
    return request(new URL(url.searchParams.get('redirect_uri')).pathname + '?state=' + url.searchParams.get('state') + '&code=' + code, extra);
  }
  // Connects one Google account, named by the code, and returns its own credential.
  async function credential(code = 'personal', scopes = GMAIL.readonly) {
    const url = await start({ scopes });
    const response = await callback(url, code);
    assert.equal(response.headers.get('location'), '/services?result=connected&service=google', response.text);
    return (await request('/v1/overview')).json.credentials.find((item) => item.subject === code + '@example.test');
  }
  // Injecting a credential for a service derives what it yields now; nothing else reaches the service.
  async function inject(credential, options = {}) {
    return request('/v1/injections', { method: 'POST', data: { names: [{ name: credential.id }] }, ...options });
  }
  async function credentialFacts(credential, options = {}) {
    const listed = await request('/v1/resources?kind=credential&secret=false', options);
    assert.equal(listed.status, 200, listed.text);
    const found = listed.json.resources.find(item => item.id === credential.id);
    assert.ok(found, '接続の一覧から対象を取得する');
    return found.facts;
  }
  // Makes a key known to the owner: the key asks to act for whoever opens its request, and the owner types its code.
  // A machine becomes a principal with no credential, is issued a key, asks to act for the person, and is approved.
  async function become(name = 'laptop') {
    const made = await request('/v1/principals', { method: 'POST', anonymous: true, data: { name } });
    assert.equal(made.status, 201, made.text);
    return { id: made.json.principal.id, token: made.json.token };
  }
  async function approveKey(name = 'laptop') {
    const made = await become(name);
    const asked = await request('/v1/requests', { method: 'POST', anonymous: true, token: made.token, data: { kind: 'actor', input: { name } } });
    assert.equal(asked.status, 201, asked.text);
    const done = await request('/v1/requests/' + asked.json.request.id + '/done', { method: 'POST', data: { confirmation_code: asked.json.request.confirmation_code } });
    assert.equal(done.status, 200, done.text);
    actsFor.set(made.token, done.json.request.to);
    return { ...asked.json.request, token: made.token, principal_id: made.id };
  }
  // A key the owner makes from the dashboard: a principal that acts for them, carrying a key.
  // Resources by name: the holder's name finds the id, and the id reaches the thing.
  const lookup = (kind, name, options = {}) => request('/v1/resources?' + new URLSearchParams({ kind, name }), options);
  async function read(kind, name, options = {}) {
    const found = await lookup(kind, name, options);
    return found.status === 200 ? request('/v1/resources/' + found.json.resource.id + '/content', options) : found;
  }
  const keep = (kind, name, raw, options = {}) => request('/v1/resources?' + new URLSearchParams({ kind, name }), { method: 'PUT', raw, type: 'text/plain', ...options });
  async function drop(kind, name, options = {}) {
    const found = await lookup(kind, name, options);
    return found.status === 200 ? request('/v1/resources/' + found.json.resource.id, { method: 'DELETE', data: {}, ...options }) : found;
  }
  async function issueKey(name = 'laptop') {
    const result = await request('/v1/principals', { method: 'POST', data: { name, actor: true, key: true } });
    assert.equal(result.status, 201, result.text);
    actsFor.set(result.json.token, result.json.principal.acts_for[0]);
    return { ...result.json.principal, token: result.json.token, key_id: result.json.key.id };
  }
  // Ages a credential past its expiry in both the envelope and the scheme's private state.
  function expire(id, owner = USER_A) {
    const credential = app.credentials.held(owner, id);
    const state = app.credentials.state(credential), expires_at = Date.now() - 1;
    app.credentials.saveState(credential, { ...state, expires_at, private_state: { ...state.private_state, expires_at } });
  }
  if (options.login !== false) await login();
  return { app, auth, google, base, request, lookup, read, keep, drop, become, login, start, callback, credential, inject, credentialFacts, issueKey, approveKey, expire, close, cookie: () => cookie };
}
