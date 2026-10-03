import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { FakeOAuth2Service, SERVICE } from '../src/schemes/oauth.fixture.mjs';
import { fixture, FakeGoogle, USER_A, USER_B } from './helpers.mjs';
import { googleOauth } from '../src/adapters/google/index.mjs';
const READONLY = 'https://www.googleapis.com/auth/gmail.readonly', SEND = 'https://www.googleapis.com/auth/gmail.send';

const key = () => 'fdn_' + randomBytes(32).toString('base64url');
// A key nobody knows asks to act for whoever opens its request; a key that acts for someone asks them for a registration.
const asking = { authorization_details: [{ type: 'relation', relation: 'agent' }] };
const registration = { authorization_details: [{ type: 'connection', service: 'google' }], binding_message: '届いたメールの確認' };
const askingWith = ({ name, ...rest } = {}) => ({ ...asking, ...rest });
async function create(f, token = null, overrides = {}, base = asking) {
  token ??= (await f.become(overrides.name ?? 'laptop のAI')).token;
  const response = await f.request('/v1/requests', { method: 'POST', anonymous: true, token, data: base === asking ? askingWith(overrides) : { ...base, ...overrides } });
  assert.equal(response.status, 201, response.text);
  return { token, row: response.json.request };
}
// A registration request comes from a key the owner already approved.
async function register(f, overrides = {}, agent = null) {
  const key = agent || await f.issueKey();
  return { ...(await create(f, key.token, { to: USER_A, ...overrides }, registration)), agent: key };
}
const approve = (f, row, overrides = {}) => f.request('/v1/requests/' + row.id + '/grant', { method: 'POST', data: { user_code: row.user_code, ...overrides } });
// Once approved, a machine names the person it acts for on every call, as the CLI does.
const usable = (f, token) => f.request('/v1/resources?kind=connection', { token, anonymous: true, as: USER_A });
const cancel = (f, token) => f.request('/v1/principals/me', { method: 'DELETE', token, anonymous: true, data: {} });
const rowStatus = (f, id) => f.app.store.db.prepare('SELECT status FROM requests WHERE id=?').get(id)?.status;

test('A new key asks only to be approved: no access before approval, the same private key after it', async t => {
  const f = await fixture(t, { signin: false });
  const { token, row } = await create(f);
  assert.equal(row.requester_name, 'laptop のAI'); assert.equal(row.status, 'pending');
  assert.equal(row.verification_uri, f.base + '/requests/' + row.id);
  assert.match(row.user_code, /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/, 'consonants a person reads without mistaking one for another');
  assert.doesNotMatch(JSON.stringify(row), /fdn_|token_hash|refresh_token/);
  assert.equal((await f.request('/requests/' + row.id, { anonymous: true, headers: { 'sec-fetch-site': 'cross-site' } })).status, 200);
  assert.equal((await f.request('/v1/requests/' + row.id, { anonymous: true })).status, 401);
  assert.deepEqual((await f.request('/v1/resources?kind=connection', { token, anonymous: true })).json.resources, [], 'a key nobody has accepted holds nothing but itself');
  assert.equal((await cancel(f, row.id)).status, 401);
  assert.equal((await cancel(f, key())).status, 401);
  assert.equal((await f.request('/v1/principals/me', { token, anonymous: true })).json.requests[0].id, row.id, 'a runtime may read its own request');
  await f.signin();
  const saved = await f.connection();
  const approved = await approve(f, row);
  assert.equal(approved.status, 200, approved.text);
  assert.equal(approved.json.request.status, 'granted');
  assert.doesNotMatch(approved.text, /fdn_|google-access|refresh_token|token_hash/);
  const listed = await usable(f, token);
  assert.deepEqual(listed.json.resources.map(a => a.id), [saved.id]);
  assert.deepEqual(listed.json.resources[0].variables, ['GOOGLE_OAUTH_ACCESS_TOKEN', 'CLOUDSDK_AUTH_ACCESS_TOKEN', 'GOOGLE_ACCOUNT_EMAIL', 'GOOGLE_OAUTH_EXPIRES_AT']);
  const delivered = await f.inject(saved, { token, anonymous: true, as: USER_A });
  assert.equal(delivered.status, 200);
  assert.equal(delivered.json.injection.environment.GOOGLE_OAUTH_ACCESS_TOKEN, 'google-access-personal');

  assert.equal((await approve(f, row)).status, 409);
  assert.equal(f.app.principals.agentsOf(USER_A).length, 2);
  assert.ok(!JSON.stringify(f.app.store.db.prepare('SELECT * FROM requests').all()).includes(token));
});

test('A key not yet approved cannot ask for a registration, an approval request registers nothing, and an approved key names an adapter', async t => {
  const f = await fixture(t);
  const refused = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: key(), data: registration });
  assert.equal(refused.status, 401); assert.equal(refused.json.error.code, 'not_approved');
  const { row } = await create(f);
  const attempt = await f.request('/v1/connections', { method: 'POST', data: { service: 'google', request_id: row.id } });
  assert.equal(attempt.status, 409); assert.equal(attempt.json.error.code, 'approval_only');
  assert.equal(f.app.connections.list(USER_A).length, 0);
  const approved = await f.issueKey();
  const bare = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: approved.token, data: { binding_message: '何もない' } });
  assert.equal(bare.status, 400); assert.equal(bare.json.error.code, 'invalid_authorization_details');
  // A key that already acts for someone may still ask to act for another; that is a new request, not a repeat.
  const again = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: approved.token, data: asking });
  assert.equal(again.status, 201, again.text); assert.equal(again.json.request.authorization_details[0].relation, 'agent'); assert.equal(again.json.request.to, null);
});

test('Request creation is idempotent, and asking for something else makes a new request rather than changing a shared one', async t => {
  const f = await fixture(t), { token, row } = await create(f);
  assert.equal((await create(f, token)).row.id, row.id);
  const first = await register(f);
  assert.equal((await create(f, first.token, {}, registration)).row.id, first.row.id);
  const changed = await f.request('/v1/requests', { method: 'POST', token: first.token, data: { ...registration, authorization_details: [{ type: 'connection', service: 'google', scopes: [SEND] }] } });
  assert.equal(changed.status, 201); assert.notEqual(changed.json.request.id, first.row.id);
  assert.deepEqual((await f.request('/v1/requests/' + first.row.id, { token: first.token })).json.request.authorization_details, [{ ...registration.authorization_details[0], auth_scheme: 'oauth' }]);
});

test('メール認証後は依頼のページへ戻し、外部への転送を拒否する', async t => {
  const f = await fixture(t, { signin: false }), { row } = await create(f);
  for (const return_to of ['https://evil.test/', '//evil.test/', '/keys/x', '/requests/' + row.id + '?next=evil', '/requests/' + row.id + '/..', 42]) {
    const response = await f.request('/v1/signin', { method: 'POST', data: { email: 'owner@example.test', return_to } });
    assert.equal(response.status, 400, String(return_to));
  }
  const sent = await f.request('/v1/signin', { method: 'POST', data: { email: 'owner@example.test', return_to: '/requests/' + row.id } });
  assert.equal(sent.status, 202);
  const url = new URL(f.mailer.link('owner@example.test').url);
  const keys = new URLSearchParams(url.hash.slice(1));
  const result = await f.request('/v1/signin/verify', { method: 'POST', data: {
    email: keys.get('email'), token: keys.get('token'), return_to: url.searchParams.get('return_to'),
  } });
  assert.equal(result.status, 200);
  assert.equal(result.json.return_to, '/requests/' + row.id);
});

test('Approval requires the confirmation code; a registration asks the service for the requested scopes only and needs no code', async t => {
  const f = await fixture(t);
  const { row } = await create(f);
  assert.equal((await approve(f, row, { user_code: '' })).status, 400);
  const asked = await register(f, { authorization_details: [{ type: 'connection', service: 'google', scopes: [READONLY] }] });
  assert.equal(asked.row.authorization_details[0].type, 'connection'); assert.equal(asked.row.user_code, undefined);
  const escalation = await f.request('/v1/connections', { method: 'POST', data: { service: 'google', request_id: asked.row.id, scopes: [SEND] } });
  assert.equal(escalation.status, 200, escalation.text);
  const scope = new URL(escalation.json.url).searchParams.get('scope').split(' ');
  assert.ok(scope.includes(READONLY)); assert.ok(!scope.includes(SEND), 'the page asks for what the request showed, not more');
  assert.equal((await approve(f, asked.row)).status, 409, 'a registration request is not approved with a code');
});

test('A registration request stays with its owner, completes by registering, and a revoked key cannot be revived through it', async t => {
  const f = await fixture(t);
  await f.connection();
  const { row, agent: runtime } = await register(f, { authorization_details: [{ type: 'connection', service: 'google' }] });
  assert.equal(row.requester_name, 'laptop');
  const ownerCookie = 'fdn_session=' + f.app.sessions.create(USER_A, { proof: 'email', ref: 'owner@example.test' });
  await f.signin('other@example.test');
  assert.equal((await f.request('/v1/requests/' + row.id)).status, 404);
  const flow = new URL((await f.request('/v1/connections', { method: 'POST', headers: { cookie: ownerCookie }, data: { service: 'google', request_id: row.id } })).json.url);
  await f.callback(flow, 'second', { headers: { cookie: ownerCookie } });
  const done = (await f.request('/v1/requests/' + row.id, { headers: { cookie: ownerCookie } })).json.request;
  assert.equal(done.status, 'granted'); assert.equal(f.app.connections.held(USER_A, done.result.connection_id).subject, 'second@example.test');
  assert.equal((await usable(f, runtime.token)).json.resources.length, 2);
  const next = await create(f, runtime.token, {}, registration);
  f.app.requestActions.removePrincipal(USER_A, runtime.id);
  assert.equal((await usable(f, runtime.token)).status, 401);
  assert.equal((await f.request('/v1/requests/' + next.row.id, { headers: { cookie: ownerCookie } })).json.request.status, 'cancelled');
  const blocked = await f.request('/v1/connections', { method: 'POST', headers: { cookie: ownerCookie }, data: { service: 'google', request_id: next.row.id } });
  assert.equal(blocked.status, 409);
  assert.equal(f.app.principals.agentsOf(USER_A).length, 1, 'Foundation alone acts for the owner');
  assert.equal(f.app.principals.agentsOf(USER_B).length, 1);
  assert.equal(f.app.connections.list(USER_A).length, 2);
});

test('An approval request belongs to the owner who approves it', async t => {
  const f = await fixture(t), { row } = await create(f);
  assert.equal((await approve(f, row)).status, 200);
  await f.signin('other@example.test');
  assert.equal((await f.request('/v1/requests/' + row.id)).status, 404);
  assert.equal((await f.request('/v1/requests/' + row.id + '/deny', { method: 'POST', data: {} })).status, 404);
});

for (const end of ['deny', 'cancel', 'expire']) test(`A ${end} registration request cannot finish an in-flight Google exchange`, async t => {
  const f = await fixture(t);
  await f.connection();
  const { token, row } = await register(f);
  let entered, release;
  const started = new Promise(resolve => { entered = resolve; });
  f.google.exchangeHandler = () => { entered(); return new Promise(resolve => { release = resolve; }); };
  const start = await f.request('/v1/connections', { method: 'POST', data: { service: 'google', request_id: row.id } });
  const callback = f.callback(new URL(start.json.url), 'new');
  await started;
  if (end === 'deny') assert.equal((await f.request('/v1/requests/' + row.id + '/deny', { method: 'POST', data: {} })).status, 200);
  if (end === 'cancel') assert.equal((await f.request('/v1/requests/' + row.id, { method: 'DELETE', token, data: {} })).status, 200);
  if (end === 'expire') f.app.store.db.prepare('UPDATE requests SET expires_at=0 WHERE id=?').run(row.id);
  release();
  const result = await callback;
  assert.equal(result.headers.get('location'), '/requests/' + row.id + '?result=failed');
  assert.equal(f.app.connections.list(USER_A).length, 1);
  if (end === 'expire') {
    assert.equal(rowStatus(f, row.id), 'pending');
    f.app.store.sweep();
    assert.equal(f.app.store.db.prepare('SELECT count(*) n FROM requests').get().n, 0);
  } else assert.equal(rowStatus(f, row.id), end === 'deny' ? 'denied' : 'cancelled');
});

test('Cross-site creation, invalid names and cross-origin approval are rejected', async t => {
  const f = await fixture(t); let token;
  for (const headers of [{ origin: 'https://evil.test' }, { 'sec-fetch-site': 'cross-site' }]) {
    assert.equal((await f.request('/v1/requests', { method: 'POST', token, data: asking, headers })).status, 403);
  }
  const agent = await f.issueKey();
  assert.equal((await f.request('/v1/requests', { method: 'POST', token: agent.token, data: { ...registration, authorization_details: [{ type: 'connection', connector: 'unknown' }] } })).status, 400);
  const { row } = await create(f, token);
  const response = await f.request('/v1/requests/' + row.id + '/grant', { method: 'POST', headers: { origin: 'https://evil.test' }, data: { user_code: row.user_code } });
  assert.equal(response.status, 403);
  assert.equal(rowStatus(f, row.id), 'pending'); assert.equal((await usable(f, token)).status, 401, 'nothing of the person\'s before approval');
});

test('What a key sees reflects a connection needing attention, one removed, and its own key revoked', async t => {
  const f = await fixture(t), saved = await f.connection(), { token, row } = await create(f);
  await approve(f, row);
  f.app.connections.reconnectRequired(f.app.connections.held(USER_A, saved.id));
  assert.equal((await usable(f, token)).json.resources[0].status, 'reconnect_required');
  f.app.connections.disconnect(USER_A, saved.id);
  assert.deepEqual((await usable(f, token)).json.resources, []);
  f.app.requestActions.removePrincipal(USER_A, f.app.principals.agentsOf(USER_A).find(item => item.name !== 'Foundation').id);
  assert.equal((await usable(f, token)).status, 401);
});

test('Unavailable services cannot register through a request; expired request records are deleted without revoking the key', async t => {
  const f = await fixture(t), saved = await f.connection(), { token, row } = await register(f);
  f.google.enabled = false;
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { service: 'google', request_id: row.id } })).status, 503);
  f.google.enabled = true;
  f.app.store.db.prepare('UPDATE requests SET expires_at=0 WHERE id=?').run(row.id);
  f.app.store.sweep();
  assert.equal(rowStatus(f, row.id), undefined);
  assert.equal((await usable(f, token)).json.resources[0].id, saved.id);
});

test('利用者が定義したサービスも、共通の依頼・認証・受け渡しの動線を利用する', async t => {
  const notes = new FakeOAuth2Service();
  const f = await fixture(t, { serviceFetcher: notes.fetch });
  const defined = await f.request('/v1/resources?kind=service&name=Notes', { method: 'PUT', data: { name: 'Notes', api: 'https://service.example/api',
    auth_schemes: { oauth: { authorize: SERVICE.authorize_url, token: SERVICE.token_url, identity: { url: SERVICE.userinfo_url }, injection: { NOTES_TOKEN: '/access_token' } } } } });
  assert.equal(defined.status, 200, defined.text);
  const service = defined.json.resource.id;
  const app = (await f.request('/v1/resources?kind=app&name=' + encodeURIComponent('Notesのアプリ'), { method: 'PUT', data: { service, client_id: 'notes-client', client_secret: 'notes-secret' } })).json.resource;
  const { row, token } = await register(f, { authorization_details: [{ type: 'connection', service, app: app.id }] });
  assert.equal(row.service.name, 'Notes');
  assert.deepEqual(row.app, { id: app.id, name: 'Notesのアプリ', foundation: false });
  const start = await f.request('/v1/connections', { method: 'POST', data: { request_id: row.id } });
  assert.equal(start.status, 200, start.text);
  const callback = await f.callback(new URL(start.json.url), 'personal');
  assert.equal(callback.headers.get('location'), '/requests/' + row.id + '?result=connected');
  const saved = f.app.connections.list(USER_A)[0];
  assert.equal(saved.service, service); assert.equal(saved.subject, 'user:id-personal');
  const injected = await f.inject(saved, { token });
  assert.deepEqual(injected.json.injection.environment, { NOTES_TOKEN: 'access-personal-0' });
  const listed = (await f.request('/v1/resources?kind=connection', { token })).json.resources[0];
  assert.deepEqual(listed.variables, ['NOTES_TOKEN']); assert.equal(listed.service.name, 'Notes');
});

test('The approval page never receives the confirmation code; entry is normalized and locked after repeated mistakes', async t => {
  const f = await fixture(t);
  const { row } = await create(f);
  const page = await f.request('/v1/requests/' + row.id);
  assert.equal(page.status, 200);
  assert.equal(page.json.request.user_code, undefined);
  assert.doesNotMatch(page.text, new RegExp(row.user_code));
  for (const wrong of ['', 'ZZZZ-ZZZZ', row.user_code.slice(0, 7)]) {
    const response = await approve(f, row, { user_code: wrong });
    assert.equal(response.status, 400); assert.equal(response.json.error.code, 'confirmation_required');
    assert.doesNotMatch(response.text, new RegExp(row.user_code));
  }
  assert.equal(rowStatus(f, row.id), 'pending');
  const relaxed = await approve(f, row, { user_code: ' ' + row.user_code.toLowerCase().replace('-', '') + ' ' });
  assert.equal(relaxed.status, 200, relaxed.text);
  assert.equal(relaxed.json.request.status, 'granted');
  assert.equal(relaxed.json.request.user_code, undefined);
  const second = await create(f);
  for (let attempt = 1; attempt <= 4; attempt++) assert.equal((await approve(f, second.row, { user_code: '0000-0000' })).json.error.code, 'confirmation_required');
  const locked = await approve(f, second.row, { user_code: '0000-0000' });
  assert.equal(locked.status, 400); assert.equal(locked.json.error.code, 'confirmation_locked');
  assert.equal(rowStatus(f, second.row.id), 'denied');
  assert.equal((await approve(f, second.row)).status, 409);
  assert.equal(f.app.principals.agentsOf(USER_A).length, 2);
});

test('An access key introduces itself: whoami, the owner can rename it, it can rename itself, and it can leave', async t => {
  const f = await fixture(t), saved = await f.connection();
  const { token, row } = await create(f, null, { name: 'laptop の claude' });
  const before = await f.request('/v1/principals/me', { token, anonymous: true });
  assert.equal(before.status, 200); assert.equal(before.json.requests[0].status, 'pending'); assert.deepEqual(before.json.acts_for, [], 'nobody to act for yet');
  assert.equal((await approve(f, row)).status, 200);
  const me = await f.request('/v1/principals/me', { token, anonymous: true });
  assert.equal(me.status, 200, me.text);
  assert.equal(me.json.principal.name, 'laptop の claude');
  assert.deepEqual((await usable(f, token)).json.resources.map(item => item.id), [saved.id]);
  assert.doesNotMatch(me.text, /token_hash|fdn_/);
  // A later request from the same key is shown under the registered name, whatever the runtime calls itself.
  const next = await create(f, token, { to: USER_A, name: 'laptop の Claude Code' }, registration);
  const page = (await f.request('/v1/requests/' + next.row.id)).json.request;
  assert.equal(page.requester_name, 'laptop の claude');
  const agentId = me.json.principal.id;
  assert.equal((await f.request('/v1/principals/' + agentId, { method: 'PATCH', data: { name: '' } })).status, 400);
  assert.equal((await f.request('/v1/principals/' + agentId, { method: 'PATCH', data: { name: '作業用' } })).status, 200);
  assert.equal(f.app.principals.agentsOf(USER_A).find(item => item.id === agentId).name, '作業用');
  assert.equal((await f.request('/v1/principals/' + agentId, { method: 'PATCH', headers: { origin: 'https://evil.test' }, data: { name: 'x' } })).status, 403);
  const renamed = await f.request('/v1/principals/me', { method: 'PATCH', token, anonymous: true, data: { name: '作業用 Claude' } });
  assert.equal(renamed.status, 200, renamed.text); assert.equal(renamed.json.principal.name, '作業用 Claude');
  assert.equal((await f.request('/v1/principals/me', { method: 'PATCH', token, anonymous: true, data: { name: '' } })).status, 400);
  assert.equal(f.app.principals.agentsOf(USER_A).find(item => item.id === agentId).name, '作業用 Claude');
  // Leaving revokes the key but keeps the connections.
  assert.equal((await f.request('/v1/principals/me', { method: 'DELETE', token, anonymous: true, data: {} })).status, 200);
  assert.equal((await f.request('/v1/resources?kind=connection', { token, anonymous: true })).status, 401);
  assert.equal(f.app.principals.agentsOf(USER_A).length, 1, 'Foundation stays');
  assert.equal(f.app.connections.list(USER_A).length, 1);
});

test('依頼元が認証失敗と再試行の経過を機密入力なしで確認する', async t => {
  const f = await fixture(t, { signin: false }), { token, row } = await create(f);
  const approval = async () => (await f.request('/v1/requests/' + row.id, { token, anonymous: true })).json.request;
  assert.deepEqual((await approval()).events, []);
  assert.equal((await approval()).user_code, row.user_code, 'the runtime created the request and already knows the code');
  assert.equal((await f.request('/requests/' + row.id, { anonymous: true })).status, 200);
  await f.signin();
  await f.request('/v1/requests/' + row.id);
  assert.equal((await approve(f, row, { user_code: 'ZZZZ-ZZZZ' })).status, 400);
  assert.equal((await approve(f, row)).status, 200);
  let events = (await approval()).events;
  assert.deepEqual(events.map(item => item.event), ['page_opened', 'page_viewed', 'connect_failed', 'granted']);
  assert.equal(events[2].code, 'confirmation_required');
  // The same key, now approved, asks for a registration; its events are the registration's own.
  const asked = await create(f, token, { to: USER_A }, registration);
  const view = async (id = asked.row.id, as = token) => (await f.request('/v1/requests/' + id, { token: as, anonymous: true })).json.request;
  await f.request('/v1/requests/' + asked.row.id);
  const start = await f.request('/v1/connections', { method: 'POST', data: { service: 'google', request_id: asked.row.id } });
  const authorization = new URL(start.json.url), callback = new URL(authorization.searchParams.get('redirect_uri'));
  await f.request(callback.pathname + '?state=' + authorization.searchParams.get('state') + '&error=access_denied');
  const again = await f.request('/v1/connections', { method: 'POST', data: { service: 'google', request_id: asked.row.id } });
  await f.callback(new URL(again.json.url), 'personal');
  events = (await view()).events;
  assert.deepEqual(events.map(item => item.event), ['page_viewed', 'connect_started', 'connect_failed', 'connect_started', 'connected']);
  assert.equal(events[2].code, 'authorization_denied'); assert.match(events[2].message, /認証は許可されません/); assert.equal(events[2].service, 'google');
  assert.ok(events.every(item => Number.isFinite(item.at)));
  assert.doesNotMatch(JSON.stringify(events), /headers|personal-example|google-access|refresh_token|fdn_|ZZZZ/);
  assert.equal((await view()).status, 'granted');
  // Another key never sees this request; a cancelled request records it.
  const other = await f.issueKey('other');
  assert.equal((await f.request('/v1/requests/' + asked.row.id, { token: other.token, anonymous: true })).status, 404);
  const next = await create(f, token, { authorization_details: [{ type: 'connection', service: 'google' }] }, registration);
  assert.equal((await f.request('/v1/requests/' + next.row.id, { method: 'DELETE', token, anonymous: true, data: {} })).status, 200);
  assert.deepEqual((await view(next.row.id)).events.map(item => item.event), ['cancelled']);
});

test('The runtime chooses how long the link stays open, within a day', async t => {
  const f = await fixture(t);
  const { token, row } = await create(f, null, { valid_minutes: 120 });
  assert.equal(row.expires_at - row.created_at, 120 * 60_000);
  const other = await f.request('/v1/requests', { method: 'POST', anonymous: true, token, data: { ...asking, valid_minutes: 30 } });
  assert.equal(other.status, 201); assert.notEqual(other.json.request.id, row.id, 'a different validity is a different request');
  const plain = (await create(f)).row;
  assert.equal(plain.expires_at - plain.created_at, 30 * 60_000, 'the default stays 30 minutes');
  for (const bad of [0, 1441, 1.5, '120']) assert.equal((await f.request('/v1/requests', { method: 'POST', anonymous: true, token: (await f.become()).token, data: { ...asking, valid_minutes: bad } })).json.error.code, 'invalid_validity', String(bad));
});

test('The runtime writes the steps its owner follows as a list; Foundation keeps them as written and bounds them', async t => {
  const f = await fixture(t), issued = await f.issueKey();
  const steps = ['定義ファイルをダウンロードします', 'スタック名は foundation-admin にします', '出力の値を貼ります'];
  const created = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: issued.token, data: { ...registration, steps: steps.map(step => ' ' + step + ' ') } });
  assert.equal(created.status, 201, created.text);
  assert.deepEqual(created.json.request.steps, steps);
  assert.deepEqual((await f.request('/v1/requests/' + created.json.request.id)).json.request.steps, steps);
  for (const bad of ['1. 一つの文字列', ['改行\nあり'], ['x'.repeat(501)], [''], Array(21).fill('多すぎる'), [42]]) {
    const refused = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: issued.token, data: { ...registration, steps: bad } });
    assert.equal(refused.json.error.code, 'invalid_steps', JSON.stringify(bad).slice(0, 40));
  }
});

test('A key may have several requests open at once, each at its own address, and lists its own', async t => {
  const f = await fixture(t), issued = await f.issueKey(), other = await f.issueKey('other');
  const asks = [];
  for (const scopes of [[READONLY], [SEND]]) {
    const made = await f.request('/v1/requests', { method: 'POST', token: issued.token, data: { authorization_details: [{ type: 'connection', service: 'google', scopes }], binding_message: scopes[0] } });
    assert.equal(made.status, 201, made.text); asks.push(made.json.request);
  }
  assert.notEqual(asks[0].id, asks[1].id);
  assert.equal(asks[1].verification_uri, f.base + '/requests/' + asks[1].id);
  const again = await f.request('/v1/requests', { method: 'POST', token: issued.token, data: { authorization_details: [{ type: 'connection', service: 'google', scopes: [READONLY] }], binding_message: READONLY } });
  assert.equal(again.json.request.id, asks[0].id, 'asking again for the same thing is the same request');
  assert.deepEqual((await f.request('/v1/requests?status=pending', { token: issued.token })).json.requests.map(row => row.id), asks.map(row => row.id));
  assert.deepEqual((await f.request('/v1/requests', { token: other.token })).json.requests, []);
  for (let n = 2; n < 10; n++) assert.equal((await f.request('/v1/requests', { method: 'POST', token: issued.token, data: { authorization_details: [{ type: 'connection', service: 'google' }], binding_message: 'more ' + n } })).status, 201);
  const full = await f.request('/v1/requests', { method: 'POST', token: issued.token, data: { authorization_details: [{ type: 'connection', service: 'google' }], binding_message: 'one too many' } });
  assert.equal(full.status, 409); assert.equal(full.json.error.code, 'too_many_pending');
  assert.equal((await f.request('/v1/requests?status=nope', { token: issued.token })).json.error.code, 'invalid_status');
});

test('依頼元は interval 秒をあけて確認し、急ぎすぎると slow_down を受け、決まった依頼はいつでも読める', async t => {
  const f = await fixture(t, { signin: false, requestInterval: 5 }), { token, row } = await create(f);
  assert.equal(row.interval, 5);
  const look = () => f.request('/v1/requests/' + row.id, { token, anonymous: true });
  assert.equal((await look()).status, 200);
  const hurried = await look();
  assert.equal(hurried.status, 429); assert.equal(hurried.json.error.code, 'slow_down');
  await f.signin();
  assert.equal((await approve(f, row)).status, 200);
  assert.equal((await look()).json.request.status, 'granted');
  assert.equal((await look()).json.request.status, 'granted', 'what is decided is read again at once');
});

test('代わりに動く AI は持ち主に追加の関係を頼み、持ち主が許可すると関係が引かれ、見知らぬ相手には頼めない', async t => {
  const f = await fixture(t), agent = await f.issueKey(), stranger = await f.become('stranger');
  const connected = await f.connection();
  const detail = { type: 'relation', relation: 'disconnect_grant', object_type: 'resource', object_id: connected.id };
  const asked = await f.request('/v1/requests', { method: 'POST', token: agent.token, anonymous: true, data: { authorization_details: [detail], binding_message: '重複した接続を片付ける' } });
  assert.equal(asked.status, 201, asked.text);
  assert.equal(asked.json.request.to, USER_A); assert.equal(asked.json.request.user_code, undefined, 'a request from one already known needs no code');
  assert.equal(asked.json.request.object.name, connected.label);
  const refused = await f.request('/v1/requests', { method: 'POST', token: stranger.token, anonymous: true, data: { authorization_details: [detail] } });
  assert.equal(refused.status, 400, 'a stranger may ask only to act for someone');
  const granted = await f.request('/v1/requests/' + asked.json.request.id + '/grant', { method: 'POST', data: {} });
  assert.equal(granted.status, 200, granted.text);
  assert.deepEqual(granted.json.request.result, { relation: 'disconnect_grant', object_type: 'resource', object_id: connected.id });
  assert.equal((await f.request('/v1/resources/' + connected.id, { method: 'DELETE', data: { revoke: false }, token: agent.token, anonymous: true, as: USER_A })).status, 200);
});
