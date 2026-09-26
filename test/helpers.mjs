import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createApp } from '../src/app.mjs';
import { fail } from '../src/errors.mjs';
import { FakeGmail } from '../src/connectors/gmail/fixture.mjs';
export { FakeGmail } from '../src/connectors/gmail/fixture.mjs';
import { Connectors } from '../src/connectors.mjs';
import { gmailReadonly, gmailMetadata } from '../src/connectors/gmail/index.mjs';
import { Grants } from '../src/grants.mjs';
import { Holdings } from '../src/holdings.mjs';
import { Principals } from '../src/principals.mjs';
import { Sessions, OAuthFlows } from '../src/sessions.mjs';

export function resources(store, connectors = []) {
  const holdings = new Holdings(store);
  return { holdings, grants: new Grants(store, holdings, new Connectors(connectors)), principals: new Principals(store), sessions: new Sessions(store), flows: new OAuthFlows(store) };
}

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

// Seed a stored credential, including already-expired fixture tokens.
export function acquired(store, connectors, connectorId, { subject, secret }) {
  const grants = new Grants(store, new Holdings(store), new Connectors(connectors));
  const saved = grants.writeConnection(USER_A, { connector: connectorId, method: 'authorized', provider: connectorId.split('.')[0], subject, label: subject,
    state: { private_state: secret, facts: {}, expires_at: secret.expires_at } });
  const row = () => grants.held(USER_A, saved.id);
  const state = () => grants.state(row());
  const run = () => grants.obtain(row());
  return { grants, row, run, state };
}
export async function fixture(t, options = {}) {
  const { gmail = new FakeGmail(), connectors = [gmailReadonly(gmail), gmailMetadata(gmail)], ...rest } = options, auth = options.auth || new FakeAuth();
  const app = createApp({ encryptionKey: KEY, ...rest, auth, connectors });
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
    const sent = await request('/v1/login', { method: 'POST', data: { email } });
    assert.equal(sent.status, 202, sent.text);
    const challenge = sent.headers.getSetCookie().find(value => value.startsWith('fdn_login=')).split(';')[0];
    const url = new URL(auth.links.get(email).url);
    const response = await request(url.pathname + url.search, { headers: { cookie: [cookie, challenge].filter(Boolean).join('; '), 'sec-fetch-site': 'cross-site' } });
    assert.equal(response.status, 303, response.text);
    assert.equal(response.headers.get('location'), '/');
    cookie = response.headers.getSetCookie().find(value => value.startsWith('fdn_session=')).split(';')[0];
    return response;
  }
  // Gmail's read range is its connector: gmail.readonly or gmail.metadata.
  async function start({ range = 'readonly', connection_id } = {}) {
    const result = await request('/v1/connections', { method: 'POST', data: { connector: 'gmail.' + range, connection_id } });
    assert.equal(result.status, 200, result.text);
    return new URL(result.json.url);
  }
  // Returns to the callback the authorization named, as Google would.
  async function callback(url, code = 'personal-readonly', extra = {}) {
    return request(new URL(url.searchParams.get('redirect_uri')).pathname + '?state=' + url.searchParams.get('state') + '&code=' + code, extra);
  }
  // Connects one Gmail account and returns its independent connection.
  async function credential(code = 'personal', range = 'readonly') {
    const url = await start({ range });
    const response = await callback(url, code + '-' + range);
    assert.equal(response.headers.get('location'), '/?connection=connected&connector=gmail.' + range, response.text);
    return (await request('/v1/overview')).json.grants.find((item) => item.subject === code + '@example.test');
  }
  // Delivering a connected grant derives what it yields now; nothing else reaches the provider.
  async function deliver(connection, options = {}) {
    return request('/v1/deliveries', { method: 'POST', data: { names: [{ name: connection.id }] }, ...options });
  }
  // Makes a key known to the owner: the key asks to act for whoever opens its request, and the owner types its code.
  // A machine becomes a principal with no credential, is issued a key, asks to act for the person, and is approved.
  async function become(name = 'dev-us') {
    const made = await request('/v1/principals', { method: 'POST', anonymous: true, data: { name } });
    assert.equal(made.status, 201, made.text);
    return { id: made.json.principal.id, token: made.json.token };
  }
  async function approveKey(name = 'dev-us') {
    const made = await become(name);
    const asked = await request('/v1/requests', { method: 'POST', anonymous: true, token: made.token, data: { kind: 'actor', input: { name } } });
    assert.equal(asked.status, 201, asked.text);
    const done = await request('/v1/requests/' + asked.json.request.id + '/done', { method: 'POST', data: { confirmation_code: asked.json.request.confirmation_code } });
    assert.equal(done.status, 200, done.text);
    actsFor.set(made.token, done.json.request.to);
    return { ...asked.json.request, token: made.token, principal_id: made.id };
  }
  // A key the owner makes from the dashboard: a principal that acts for them, carrying a key.
  // Held things by name: the holder's name finds the id, and the id reaches the thing.
  const lookup = (kind, name, options = {}) => request('/v1/holdings?' + new URLSearchParams({ kind, name }), options);
  async function read(kind, name, options = {}) {
    const found = await lookup(kind, name, options);
    return found.status === 200 ? request('/v1/holdings/' + found.json.holding.id + '/content', options) : found;
  }
  const keep = (kind, name, raw, options = {}) => request('/v1/holdings?' + new URLSearchParams({ kind, name }), { method: 'PUT', raw, type: 'text/plain', ...options });
  async function drop(kind, name, options = {}) {
    const found = await lookup(kind, name, options);
    return found.status === 200 ? request('/v1/holdings/' + found.json.holding.id, { method: 'DELETE', data: {}, ...options }) : found;
  }
  async function issueKey(name = 'dev-us') {
    const result = await request('/v1/principals', { method: 'POST', data: { name, actor: true, credential: 'key' } });
    assert.equal(result.status, 201, result.text);
    actsFor.set(result.json.token, result.json.principal.acts_for[0].id);
    return { ...result.json.principal, token: result.json.token, credential_id: result.json.credential.id };
  }
  // Ages a connection past its expiry in both the envelope and the connector's private state.
  function expire(id, owner = USER_A) {
    const connection = app.grants.held(owner, id);
    const state = app.grants.state(connection), expires_at = Date.now() - 1;
    app.grants.saveState(connection, { ...state, expires_at, private_state: { ...state.private_state, expires_at } });
  }
  if (options.login !== false) await login();
  return { app, auth, gmail, base, request, lookup, read, keep, drop, become, login, start, callback, credential, deliver, issueKey, approveKey, expire, close, cookie: () => cookie };
}
