import assert from 'node:assert/strict';
import { createApp } from '../src/app.mjs';
import { Stripe } from '../src/payments.mjs';
import { fail } from '../src/errors.mjs';
import { FakeGoogle } from '../src/adapters/google/fixture.mjs';
export { FakeGoogle } from '../src/adapters/google/fixture.mjs';
import { googleOauth } from '../src/adapters/google/index.mjs';
import { entry } from '../src/catalog.mjs';
export { entry } from '../src/catalog.mjs';
import { Connections } from '../src/connections.mjs';
import { Secrets } from '../src/secrets.mjs';
import { Inputs } from '../src/inputs.mjs';
import { Keys } from '../src/keys.mjs';
import { generateKey, newContentKey, sealContent, openContent, seal, open } from '../cli/envelope.mjs';
// One private key per principal for the whole run, as a client keeps its own: a second fixture over the same database still opens with it.
const privateKeys = new Map();
import { Services } from '../src/services.mjs';
import { Apps } from '../src/apps.mjs';
import { Resources } from '../src/resources.mjs';
import { Principals } from '../src/principals.mjs';
import { Authorization } from '../src/authorization.mjs';
import { Sessions, OAuthFlows } from '../src/sessions.mjs';
import { matchRoute, validateSchema } from '../src/api.mjs';

// Gmail scopes the tests ask Google for.
const GMAIL_SCOPE = 'https://www.googleapis.com/auth/gmail.';
export const GMAIL = { readonly: [GMAIL_SCOPE + 'readonly'], metadata: [GMAIL_SCOPE + 'metadata'], 'read-send': [GMAIL_SCOPE + 'readonly', GMAIL_SCOPE + 'send'] };

// The modules a server is made of, over one store, with the services given (each an entry of the catalog).
export function modules(store, entries = []) {
  const principals = new Principals(store), resources = new Resources(store), authorization = new Authorization(principals, resources);
  const services = new Services(store, resources, entries, { authorization }), apps = new Apps(store, resources, services);
  const keys = new Keys(store), secrets = new Secrets(store, resources, keys), connections = new Connections(store, resources, services, apps, authorization, keys, (ownerId, id) => { const row = secrets.get(id); if (!row || !authorization.can(ownerId, 'content', 'secret', { id: row.id, owner: row.owner_id })) throw new Error('not found'); return secrets.open(row).toString('utf8'); });
  return { resources, services, apps, secrets, keys, connections, inputs: new Inputs(secrets, connections, row => secrets.open(row)), principals, authorization, sessions: new Sessions(store), flows: new OAuthFlows(store) };
}

export const KEY = Buffer.alloc(32, 7);
export const USER_A = '10000000-0000-4000-8000-000000000001';
export const USER_B = '10000000-0000-4000-8000-000000000002';
export const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
// Email that is never sent: what would have gone out is kept, and the link in it can be followed.
export class FakeMailer {
  constructor() { this.enabled = true; this.sent = []; }
  async send(message) {
    if (!this.enabled) fail(503, 'email_unavailable', '現在サインインを利用できません。');
    if (this.sendHandler) await this.sendHandler(message);
    this.sent.push(message);
  }
  // The newest link sent to an address: where it goes, and the token and address it carries.
  link(email) {
    const message = this.sent.findLast(item => item.to === email);
    if (!message) return;
    const url = new URL(message.text.match(/https?:\/\/\S+/)[0]), fragment = new URLSearchParams(url.hash.slice(1));
    return { url: url.href, token: fragment.get('token'), email: fragment.get('email') };
  }
}
// Stripe as far as Foundation uses it: customers, a setup page, subscriptions and meter events, with every call kept.
export function fakeStripe({ sessionStatus = 'complete', otherCustomer = false } = {}) {
  const calls = [], meterEvents = new Map();
  const answer = body => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  const fetcher = async (url, options) => {
    const target = new URL(url), body = Object.fromEntries(new URLSearchParams(options.body ?? ''));
    calls.push({ method: options.method, path: target.pathname, body, idempotency: options.headers['idempotency-key'] });
    if (target.pathname === '/v1/customers') return answer({ id: 'cus_1' });
    if (target.pathname === '/v1/checkout/sessions') return answer({ id: 'cs_test_1', url: 'https://checkout.stripe.com/c/pay/cs_test_1' });
    if (target.pathname === '/v1/checkout/sessions/cs_test_1') return answer({ id: 'cs_test_1', mode: 'setup', status: sessionStatus, customer: otherCustomer ? 'cus_other' : 'cus_1', setup_intent: { payment_method: 'pm_1' } });
    if (target.pathname === '/v1/customers/cus_1') return answer({ id: 'cus_1' });
    if (target.pathname === '/v1/subscriptions') return answer({ id: 'sub_1', status: 'active' });
    if (target.pathname === '/v1/billing/meter_events') { meterEvents.set(body.identifier, body); return answer({ identifier: body.identifier }); }
    return new Response('{}', { status: 404 });
  };
  return { stripe: new Stripe({ key: 'sk_test_x', computePrice: 'price_compute', storagePrice: 'price_storage', webhookSecret: 'whsec_test', fetcher }), calls, meterEvents };
}

// Who an address is in these tests: the owner is USER_A and anyone else USER_B, as if they had signed in before.
export const PEOPLE = email => email === 'owner@example.test' ? USER_A : USER_B;

// Seed a connection for a service, including already-expired fixture tokens.
export function acquired(store, entries, service, { subject, secret }, scheme = 'oauth') {
  const { connections } = modules(store, entries);
  const saved = connections.keep(USER_A, { service, scheme, subject, label: subject,
    state: { private_state: secret, facts: {}, expires_at: secret.expires_at } });
  const row = () => connections.held(USER_A, saved.id);
  const state = () => connections.state(row());
  const run = () => connections.obtain(row());
  return { connections, row, run, state };
}
export async function fixture(t, options = {}) {
  const { google = new FakeGoogle(), services = [entry('google', { oauth: googleOauth(google) })], payers = true, ...rest } = options, mailer = options.mailer || new FakeMailer();
  // Tests look at a request again at once; the interval between looks is a test of its own.
  const app = createApp({ encryptionKey: KEY, requestInterval: 0, ...rest, mailer, services });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  let closed = false;
  const close = async () => { if (!closed) { closed = true; await app.close(); } };
  t.after(close);
  const base = 'http://127.0.0.1:' + app.server.address().port;
  let cookie;
  // `data` is sent as JSON; `raw` is sent as given, with `type` as its content type.
  // A token that acts for exactly one principal names them on every call, as the CLI and the MCP tool do.
  const actsFor = new Map();
  // Secrets are sealed by the client: a test that places one as `raw` has it sealed here, for the owner's
  // recipients and the caller, with a key the caller publishes on first use; one that reads a secret gets its
  // bytes opened with that key, as a client would.
  const subjects = new Map(), published = new Set();
  const b64 = buffer => Buffer.from(buffer).toString('base64url');
  async function subjectOf(options) {
    const who = options.token ?? options.headers?.cookie ?? (options.anonymous ? null : cookie);
    if (!who) return null;
    if (!subjects.has(who)) { const me = await request('/v1/principals/me', { ...options, method: 'GET', data: undefined, raw: undefined }); subjects.set(who, me.json?.principal?.id ?? null); }
    return subjects.get(who);
  }
  async function keyOf(options) {
    const id = await subjectOf(options);
    if (!id) return null;
    if (!privateKeys.has(id)) privateKeys.set(id, generateKey());
    if (!published.has(id)) {
      const response = await request('/v1/principals/me/key', { ...options, method: 'PUT', data: { public_key: b64(privateKeys.get(id).publicKey) }, raw: undefined });
      if (response.status !== 200 && response.json?.error?.code !== 'key_exists') return null;
      published.add(id);
    }
    return { id, ...privateKeys.get(id) };
  }
  async function sealed(content, options, recipients, also = []) {
    const own = await keyOf(options);
    if (!recipients) { const listed = await request('/v1/recipients', { ...options, method: 'GET', data: undefined, raw: undefined }); recipients = listed.status === 200 ? listed.json.recipients : []; }
    recipients = [...recipients, ...also.filter(one => !recipients.some(item => item.principal_id === one.principal_id))];
    // The placer is a recipient too: placing something new for another makes it the thing's editor.
    if (own && !recipients.some(item => item.principal_id === own.id)) recipients.push({ principal_id: own.id, public_key: b64(own.publicKey) });
    const contentKey = newContentKey();
    return { content: b64(sealContent(contentKey, Buffer.from(content))), envelopes: Object.fromEntries(recipients.map(item => [item.principal_id, b64(seal(contentKey, Buffer.from(item.public_key, 'base64url')))])) };
  }
  const secretPath = path => /^\/v1\/resources\?.*kind=secret/.test(path) || (path.match(/^\/v1\/resources\/([^/?]+)\/content/) && app.resources.get(RegExp.$1)?.kind === 'secret');
  async function request(path, { method = 'GET', data, raw, type = 'application/octet-stream', token, anonymous = false, headers = {}, as } = {}) {
    // Making a principal and giving it a key are two calls; a test that wants both at once gets them joined here.
    if (method === 'POST' && /^\/v1\/principals(\?|$)/.test(path) && data?.key === true) {
      const { key: _, ...rest } = data;
      const made = await request(path, { method, data: rest, token, anonymous, headers, as });
      if (made.status !== 201) return made;
      const issued = await request('/v1/principals/' + encodeURIComponent(made.json.principal.id) + '/credentials', { method: 'POST', data: { kind: 'key' }, token, anonymous, headers });
      if (issued.status !== 201) return issued;
      const json = { principal: { ...made.json.principal, keys: [{ id: issued.json.credential.id, created_at: issued.json.credential.created_at, last_used_at: null }] }, token: issued.json.token, key: { id: issued.json.credential.id, kind: 'key' } };
      return { status: 201, json, text: JSON.stringify(json), headers: issued.headers };
    }
    const owner = as ?? (token && actsFor.get(token)) ?? new URL(path, base).searchParams.get('as') ?? undefined;
    if (owner && !/[?&]as=/.test(path)) path += (path.includes('?') ? '&' : '?') + 'as=' + owner;
    if (method === 'PUT' && raw !== undefined && secretPath(path)) {
      // Over what is there, the new key goes to everyone who had the old one.
      let existing = null;
      try { existing = path.match(/^\/v1\/resources\/([^/?]+)\/content/) ? app.resources.get(RegExp.$1) : app.secrets.find(owner ?? await subjectOf({ token, anonymous }), new URL(path, base).searchParams.get('name')); } catch {}
      data = await sealed(raw, { token, anonymous, as: owner }, undefined, existing ? app.keys.recipientKeys(existing.id) : []); raw = undefined;
    }
    // Answering a store request: each entry sealed for whom the request says.
    if (method === 'POST' && data?.entries && /^\/v1\/requests\/[^/]+\/grant/.test(path)) {
      const shown = await request(path.replace(/\/grant.*$/, ''), { method: 'GET', token, anonymous, headers });
      data = { ...data, entries: await Promise.all(data.entries.map(async entry => typeof entry.content === 'string' && entry.envelopes === undefined ? { ...entry, ...await sealed(entry.content, { token, anonymous, headers }, shown.json?.request?.recipients ?? []) } : entry)) };
    }
    const body = raw !== undefined ? raw : data !== undefined ? JSON.stringify(data) : undefined;
    const response = await fetch(base + path, { method, redirect: 'manual', headers: { ...(!anonymous && cookie ? { cookie } : {}), ...(method !== 'GET' ? { origin: options.publicOrigin || base } : {}), ...(body !== undefined ? { 'content-type': raw !== undefined ? type : 'application/json' } : {}), ...(token ? { authorization: 'Bearer ' + token } : {}), ...headers }, ...(body !== undefined ? { body } : {}) });
    let text = await response.text();
    let json; try { json = JSON.parse(text); } catch {}
    if (method === 'GET' && response.ok && json?.envelope && secretPath(path)) {
      const own = await keyOf({ token, anonymous, headers });
      if (own) text = openContent(open(Buffer.from(json.envelope, 'base64url'), own.privateKey), Buffer.from(json.content, 'base64url')).toString('utf8');
    }
    const operation = matchRoute(new URL(path, base).pathname, method)?.operation;
    const described = operation?.responses[response.status] ?? operation?.responses.default;
    const schema = described?.content?.['application/json']?.schema;
    if (schema && json !== undefined) {
      const checked = validateSchema(schema, json);
      assert.ok(checked.valid, `${method} ${new URL(path, base).pathname} ${response.status}: response must match OpenAPI: ` +
        JSON.stringify(checked.errors.map(({ instancePath, keyword, message }) => ({ instancePath, keyword, message }))));
    }
    return { status: response.status, json, text, headers: response.headers };
  }
  // An address someone has signed in with before, so it is the same principal each time.
  // A principal that has registered a payment method, as people who use what is metered have: a payer, whether or
  // not it is being charged now.
  const bind = id => app.store.db.prepare("INSERT INTO payment_accounts (principal_id,customer_id,subscription_id,status,created_at) VALUES (?,?,?,'canceled',0) ON CONFLICT(principal_id) DO NOTHING").run(id, 'cus_fixture_' + id, 'sub_fixture_' + id);
  function known(email) {
    if (app.emails.principalOf(email)) return;
    app.principals.ensure(PEOPLE(email));
    app.emails.add(PEOPLE(email), email);
    if (payers) bind(PEOPLE(email));
  }
  async function signin(email = 'owner@example.test') {
    // The other tests need a verified identity, not a real email delivery or its resend cooldown.
    known(email);
    const token = app.challenges.issue('email', email, { ttl: 900_000 });
    const response = await request('/v1/session', { method: 'PUT', data: { kind: 'email', email, token } });
    assert.equal(response.status, 200, response.text);
    assert.equal(response.json.return_to, '/');
    cookie = response.headers.getSetCookie().find(value => value.startsWith('fdn_session=')).split(';')[0];
    await allowFoundation();
    await keyOf({});
    return response;
  }
  // The caller's envelope for a secret, sealed by Foundation's principal from its own: for a line drawn without one.
  async function handEnvelope(resourceId, options = {}) {
    const own = await keyOf(options);
    const handed = await request('/v1/resources/' + resourceId + '/envelopes/' + own.id, { method: 'POST', data: {} });
    assert.equal(handed.status, 200, handed.text);
  }
  // Foundation's principal made the owner's agent: what the owner keeps is sealed for it too, and injected by it.
  async function allowFoundation(options = {}) {
    const owner = options.as ?? (options.token && actsFor.get(options.token)) ?? await subjectOf(options);
    const drawn = await request('/v1/principals/' + app.keys.agentId + '/relations', { ...options, method: 'POST', data: { relation: 'agent', object_type: 'principal', object_id: owner } });
    assert.equal(drawn.status, 201, drawn.text);
  }
  // Connecting Google, asking to read Gmail unless other scopes are given.
  async function start({ connection_id, scopes = GMAIL.readonly } = {}) {
    const result = await request('/v1/connections', { method: 'POST', data: { service: 'google', connection_id, scopes } });
    assert.equal(result.status, 200, result.text);
    return new URL(result.json.url);
  }
  // Returns to the callback the authorization named, as Google would.
  async function callback(url, code = 'personal', extra = {}) {
    return request(new URL(url.searchParams.get('redirect_uri')).pathname + '?state=' + url.searchParams.get('state') + '&code=' + code, extra);
  }
  // Connects one Google account, named by the code, and returns its own connection.
  async function connection(code = 'personal', scopes = GMAIL.readonly) {
    const url = await start({ scopes });
    const response = await callback(url, code);
    assert.equal(response.headers.get('location'), '/services?result=connected&service=google', response.text);
    return (await request('/v1/resources?kind=connection')).json.resources.find((item) => item.subject === code + '@example.test');
  }
  // Injecting a connection for a service derives what it yields now; nothing else reaches the service.
  async function inject(connection, options = {}) {
    return request('/v1/injections', { method: 'POST', data: { names: [{ id: connection.id }] }, ...options });
  }
  async function connectionFacts(connection, options = {}) {
    const listed = await request('/v1/resources?kind=connection', options);
    assert.equal(listed.status, 200, listed.text);
    const found = listed.json.resources.find(item => item.id === connection.id);
    assert.ok(found, '接続の一覧から対象を取得する');
    return found.facts;
  }
  // Makes a key known to the owner: the key asks to act for whoever opens its request, and the owner types its code.
  // A machine becomes a principal with no connection, is issued a key, asks to act for the person, and is approved.
  // All that a principal is shown of what it has, across the API: for checking that something kept in confidence
  // appears nowhere in it.
  async function visible(options = {}) {
    const paths = ['/v1/principals/me', '/v1/principals/me/credentials', '/v1/resources', '/v1/principals/me/relations', '/v1/requests?to=me', '/v1/services'];
    return JSON.stringify(await Promise.all(paths.map(async path => (await request(path, options)).json)));
  }
  async function become(name = 'laptop') {
    const made = await request('/v1/principals', { method: 'POST', anonymous: true, data: { kind: 'key', name } });
    assert.equal(made.status, 201, made.text);
    // A machine publishes its key as soon as it has a credential, as the CLI does.
    await keyOf({ token: made.json.token, anonymous: true });
    return { id: made.json.principal.id, token: made.json.token };
  }
  async function approveKey(name = 'laptop') {
    const made = await become(name);
    const asked = await request('/v1/requests', { method: 'POST', anonymous: true, token: made.token, data: { authorization_details: [{ type: 'relation', relation: 'agent' }] } });
    assert.equal(asked.status, 201, asked.text);
    const done = await request('/v1/requests/' + asked.json.request.id + '/grant', { method: 'POST', data: { user_code: asked.json.request.user_code } });
    assert.equal(done.status, 200, done.text);
    actsFor.set(made.token, done.json.request.to);
    return { ...asked.json.request, token: made.token, principal_id: made.id };
  }
  // A key the owner makes from the dashboard: a principal that acts for them, carrying a key.
  // Resources by name: the owner's name finds the id, and the id reaches the thing.
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
    const result = await request('/v1/principals', { method: 'POST', data: { name, agent: true, key: true } });
    assert.equal(result.status, 201, result.text);
    actsFor.set(result.json.token, result.json.principal.acts_for[0]);
    await keyOf({ token: result.json.token, anonymous: true });
    return { ...result.json.principal, token: result.json.token, key_id: result.json.key.id };
  }
  // Ages a connection past its expiry in both the envelope and the scheme's private state.
  function expire(id, owner = USER_A) {
    const connection = app.connections.held(owner, id);
    const state = app.connections.state(connection), expires_at = Date.now() - 1;
    app.connections.saveState(connection, { ...state, expires_at, private_state: { ...state.private_state, expires_at } });
  }
  if (options.signin !== false) await signin();
  return { app, mailer, known, bind, visible, google, base, request, lookup, read, keep, drop, become, signin, start, callback, connection, inject, connectionFacts, issueKey, approveKey, expire, close, allowFoundation, handEnvelope, keyOf, sealed, cookie: () => cookie };
}
