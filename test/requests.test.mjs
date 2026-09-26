import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { fixture, FakeGmail, USER_A, USER_B } from './helpers.mjs';
import { gmailReadonly, gmailMetadata } from '../src/connectors/gmail/index.mjs';

const key = () => 'fdn_' + randomBytes(32).toString('base64url');
// A key nobody knows asks to act for whoever opens its request; a key that acts for someone asks them for a registration.
const asking = { kind: 'actor', input: { name: 'dev-us のAI' } };
const registration = { kind: 'connect', input: { connector: 'gmail.readonly' }, purpose: '届いたメールの確認' };
const askingWith = ({ name, ...rest } = {}) => ({ ...asking, ...(name === undefined ? {} : { input: { name } }), ...rest });
async function create(f, token = null, overrides = {}, base = asking) {
  token ??= (await f.become(overrides.name ?? 'dev-us のAI')).token;
  const response = await f.request('/v1/requests', { method: 'POST', anonymous: true, token, data: base === asking ? askingWith(overrides) : { ...base, ...overrides } });
  assert.equal(response.status, 201, response.text);
  return { token, row: response.json.request };
}
// A registration request comes from a key the owner already approved.
async function register(f, overrides = {}, agent = null) {
  const key = agent || await f.issueKey();
  return { ...(await create(f, key.token, { to: USER_A, ...overrides }, registration)), agent: key };
}
const approve = (f, row, overrides = {}) => f.request('/v1/requests/' + row.id + '/done', { method: 'POST', data: { confirmation_code: row.confirmation_code, ...overrides } });
// Once approved, a machine names the person it acts for on every call, as the CLI does.
const usable = (f, token) => f.request('/v1/connections', { token, anonymous: true, as: USER_A });
const cancel = (f, token) => f.request('/v1/principals/me', { method: 'DELETE', token, anonymous: true, data: {} });
const rowStatus = (f, id) => f.app.store.db.prepare('SELECT status FROM requests WHERE id=?').get(id)?.status;

test('A new key asks only to be approved: no access before approval, the same private key after it', async t => {
  const f = await fixture(t, { login: false });
  const { token, row } = await create(f);
  assert.equal(row.requester_name, 'dev-us のAI'); assert.equal(row.status, 'pending');
  assert.equal(row.verification_uri, f.base + '/requests/' + row.id);
  assert.match(row.confirmation_code, /^[A-F0-9]{4}-[A-F0-9]{4}$/);
  assert.doesNotMatch(JSON.stringify(row), /fdn_|token_hash|refresh_token/);
  assert.equal((await f.request('/requests/' + row.id, { anonymous: true, headers: { 'sec-fetch-site': 'cross-site' } })).status, 200);
  assert.equal((await f.request('/v1/requests/' + row.id, { anonymous: true })).status, 401);
  assert.deepEqual((await f.request('/v1/connections', { token, anonymous: true })).json.connections, [], 'a key nobody has accepted holds nothing but itself');
  assert.equal((await cancel(f, row.id)).status, 401);
  assert.equal((await cancel(f, key())).status, 401);
  assert.equal((await f.request('/v1/principals/me', { token, anonymous: true })).json.requests[0].id, row.id, 'a runtime may read its own request');
  await f.login();
  const saved = await f.credential();
  const approved = await approve(f, row);
  assert.equal(approved.status, 200, approved.text);
  assert.equal(approved.json.request.status, 'done');
  assert.doesNotMatch(approved.text, /fdn_|google-access|refresh_token|token_hash/);
  const listed = await usable(f, token);
  assert.deepEqual(listed.json.connections.map(a => a.id), [saved.id]);
  assert.deepEqual(listed.json.connections[0].outputs, ['GOOGLE_OAUTH_ACCESS_TOKEN', 'GMAIL_ACCOUNT_EMAIL', 'GOOGLE_OAUTH_EXPIRES_AT']);
  const delivered = await f.deliver(saved, { token, anonymous: true, as: USER_A });
  assert.equal(delivered.status, 200);
  assert.equal(delivered.json.delivery.environment.GOOGLE_OAUTH_ACCESS_TOKEN, 'google-access-personal-readonly');

  assert.equal((await approve(f, row)).status, 409);
  assert.equal(f.app.principals.actorsOf(USER_A).length, 1);
  assert.ok(!JSON.stringify(f.app.store.db.prepare('SELECT * FROM requests').all()).includes(token));
});

test('A key not yet approved cannot ask for a registration, an approval request registers nothing, and an approved key names an adapter', async t => {
  const f = await fixture(t);
  const refused = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: key(), data: registration });
  assert.equal(refused.status, 401); assert.equal(refused.json.error.code, 'not_approved');
  const { row } = await create(f);
  const attempt = await f.request('/v1/connections', { method: 'POST', data: { connector: 'gmail.readonly', request_id: row.id } });
  assert.equal(attempt.status, 409); assert.equal(attempt.json.error.code, 'approval_only');
  assert.equal(f.app.grants.connections(USER_A).length, 0);
  const approved = await f.issueKey();
  const bare = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: approved.token, data: { purpose: '何もない' } });
  assert.equal(bare.status, 400); assert.equal(bare.json.error.code, 'nothing_requested');
  // A key that already acts for someone may still ask to act for another; that is a new request, not a repeat.
  const again = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: approved.token, data: asking });
  assert.equal(again.status, 201, again.text); assert.equal(again.json.request.kind, 'actor'); assert.equal(again.json.request.to, null);
});

test('Request creation is idempotent, and asking for something else makes a new request rather than changing a shared one', async t => {
  const f = await fixture(t), { token, row } = await create(f);
  assert.equal((await create(f, token)).row.id, row.id);
  assert.equal((await f.request('/v1/requests', { method: 'POST', token, data: askingWith({ name: 'someone else' }) })).status, 409);
  const first = await register(f);
  assert.equal((await create(f, first.token, {}, registration)).row.id, first.row.id);
  const changed = await f.request('/v1/requests', { method: 'POST', token: first.token, data: { ...registration, input: { connector: 'gmail.metadata' } } });
  assert.equal(changed.status, 201); assert.notEqual(changed.json.request.id, first.row.id);
  assert.deepEqual((await f.request('/v1/requests/' + first.row.id, { token: first.token })).json.request.input, { connector: 'gmail.readonly' });
});

test('Email login returns to the exact request page and rejects open redirects', async t => {
  const f = await fixture(t, { login: false }), { row } = await create(f);
  for (const return_to of ['https://evil.test/', '//evil.test/', '/keys/x', '/requests/' + row.id + '?next=evil', '/requests/' + row.id + '/..', 42]) {
    const response = await f.request('/v1/login', { method: 'POST', data: { email: 'owner@example.test', return_to } });
    assert.equal(response.status, 400, String(return_to));
  }
  const sent = await f.request('/v1/login', { method: 'POST', data: { email: 'owner@example.test', return_to: '/requests/' + row.id } });
  assert.equal(sent.status, 202);
  const cookie = sent.headers.getSetCookie().find(value => value.startsWith('fdn_login=')).split(';')[0];
  const url = new URL(f.auth.links.get('owner@example.test').url);
  const callback = await f.request(url.pathname + url.search, { headers: { cookie, 'sec-fetch-site': 'cross-site' } });
  assert.equal(callback.status, 303);
  assert.equal(callback.headers.get('location'), '/requests/' + row.id);
});

test('Approval requires the confirmation code; a registration keeps to the requested adapter and needs no code', async t => {
  const f = await fixture(t);
  const { row } = await create(f);
  assert.equal((await approve(f, row, { confirmation_code: '' })).status, 400);
  const asked = await register(f, { input: { connector: 'gmail.metadata' } });
  assert.equal(asked.row.kind, 'connect'); assert.equal(asked.row.confirmation_code, undefined);
  const escalation = await f.request('/v1/connections', { method: 'POST', data: { connector: 'gmail.readonly', request_id: asked.row.id } });
  assert.equal(escalation.status, 400); assert.equal(escalation.json.error.code, 'scope_mismatch');
  assert.equal((await approve(f, asked.row)).status, 409, 'a registration request is not approved with a code');
});

test('A registration request stays with its owner, completes by registering, and a revoked key cannot be revived through it', async t => {
  const f = await fixture(t);
  await f.credential();
  const { row, agent: runtime } = await register(f, { input: { connector: 'gmail.metadata' } });
  assert.equal(row.requester_name, 'dev-us');
  const ownerCookie = 'fdn_session=' + f.app.sessions.create(f.auth.value());
  await f.login('other@example.test');
  assert.equal((await f.request('/v1/requests/' + row.id)).status, 404);
  const flow = new URL((await f.request('/v1/connections', { method: 'POST', headers: { cookie: ownerCookie }, data: { connector: 'gmail.metadata', request_id: row.id } })).json.url);
  await f.callback(flow, 'second-metadata', { headers: { cookie: ownerCookie } });
  const done = (await f.request('/v1/requests/' + row.id, { headers: { cookie: ownerCookie } })).json.request;
  assert.equal(done.status, 'done'); assert.equal(f.app.grants.held(USER_A, done.result.connection_id).subject, 'second@example.test');
  assert.equal((await usable(f, runtime.token)).json.connections.length, 2);
  const next = await create(f, runtime.token, {}, registration);
  f.app.requestActions.removePrincipal(USER_A, runtime.id);
  assert.equal((await usable(f, runtime.token)).status, 401);
  assert.equal((await f.request('/v1/requests/' + next.row.id, { headers: { cookie: ownerCookie } })).json.request.status, 'cancelled');
  const blocked = await f.request('/v1/connections', { method: 'POST', headers: { cookie: ownerCookie }, data: { connector: 'gmail.readonly', request_id: next.row.id } });
  assert.equal(blocked.status, 409);
  assert.equal(f.app.principals.actorsOf(USER_A).length, 0);
  assert.equal(f.app.principals.actorsOf(USER_B).length, 0);
  assert.equal(f.app.grants.connections(USER_A).length, 2);
});

test('An approval request belongs to the owner who approves it', async t => {
  const f = await fixture(t), { row } = await create(f);
  assert.equal((await approve(f, row)).status, 200);
  await f.login('other@example.test');
  assert.equal((await f.request('/v1/requests/' + row.id)).status, 404);
  assert.equal((await f.request('/v1/requests/' + row.id + '/deny', { method: 'POST', data: {} })).status, 404);
});

for (const end of ['deny', 'cancel', 'expire']) test(`A ${end} registration request cannot finish an in-flight Google exchange`, async t => {
  const f = await fixture(t);
  await f.credential();
  const { token, row } = await register(f);
  let entered, release;
  const started = new Promise(resolve => { entered = resolve; });
  f.gmail.exchangeHandler = () => { entered(); return new Promise(resolve => { release = resolve; }); };
  const start = await f.request('/v1/connections', { method: 'POST', data: { connector: 'gmail.readonly', request_id: row.id } });
  const callback = f.callback(new URL(start.json.url), 'new-readonly');
  await started;
  if (end === 'deny') assert.equal((await f.request('/v1/requests/' + row.id + '/deny', { method: 'POST', data: {} })).status, 200);
  if (end === 'cancel') assert.equal((await f.request('/v1/requests/' + row.id, { method: 'DELETE', token, data: {} })).status, 200);
  if (end === 'expire') f.app.store.db.prepare('UPDATE requests SET expires_at=0 WHERE id=?').run(row.id);
  release();
  const result = await callback;
  assert.equal(result.headers.get('location'), '/requests/' + row.id + '?connection=failed');
  assert.equal(f.app.grants.connections(USER_A).length, 1);
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
  assert.equal((await f.request('/v1/requests', { method: 'POST', token, data: askingWith({ name: '' }) })).status, 400);
  const agent = await f.issueKey();
  assert.equal((await f.request('/v1/requests', { method: 'POST', token: agent.token, data: { ...registration, input: { connector: 'unknown' } } })).status, 400);
  const { row } = await create(f, token);
  const response = await f.request('/v1/requests/' + row.id + '/done', { method: 'POST', headers: { origin: 'https://evil.test' }, data: { confirmation_code: row.confirmation_code } });
  assert.equal(response.status, 403);
  assert.equal(rowStatus(f, row.id), 'pending'); assert.equal((await usable(f, token)).status, 401, 'nothing of the person\'s before approval');
});

test('What a key sees reflects a connection needing attention, one removed, and its own key revoked', async t => {
  const f = await fixture(t), saved = await f.credential(), { token, row } = await create(f);
  await approve(f, row);
  f.app.grants.reconnectRequired(f.app.grants.held(USER_A, saved.id));
  assert.equal((await usable(f, token)).json.connections[0].status, 'reconnect_required');
  f.app.grants.disconnect(USER_A, saved.id);
  assert.deepEqual((await usable(f, token)).json.connections, []);
  f.app.requestActions.removePrincipal(USER_A, f.app.principals.actorsOf(USER_A)[0].id);
  assert.equal((await usable(f, token)).status, 401);
});

test('Unavailable services cannot register through a request; expired request records are deleted without revoking the key', async t => {
  const f = await fixture(t), saved = await f.credential(), { token, row } = await register(f);
  f.gmail.enabled = false;
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { connector: 'gmail.readonly', request_id: row.id } })).status, 503);
  f.gmail.enabled = true;
  f.app.store.db.prepare('UPDATE requests SET expires_at=0 WHERE id=?').run(row.id);
  f.app.store.sweep();
  assert.equal(rowStatus(f, row.id), undefined);
  assert.equal((await usable(f, token)).json.connections[0].id, saved.id);
});

test('独自の接続も共通の依頼・認証・受け渡し・解除の動線を利用する', async t => {
  const gmail = new FakeGmail();
  const notes = {
    id: 'notes.oauth', service: { name: 'Notes', icon: 'key', management_url: 'https://notes.example.test/keys', api: { base_url: 'https://notes.example.test/api', documentation_url: 'https://notes.example.test/docs' } },
    label: 'Notesで接続', register: 'oauth', available: true,
    access: { name: 'ノートの読み取り', description: '保存済みノート', restrictions: '変更は許可しません。' },
    variables: ['NOTES_TOKEN'],
    authorization: { kind: 'oauth', begin: ({ state, redirectUri }) => 'https://notes.example.test/auth?' + new URLSearchParams({ state, redirect_uri: redirectUri }),
      async complete() { return { subject: 'notes-user', privateState: 'notes-private', facts: { scopes: ['notes.read'] }, expiresAt: null }; },
    },
    async obtain({ subject, privateState }) {
      assert.equal(privateState, 'notes-private');
      return { subject, privateState, facts: { scopes: ['notes.read'] }, expiresAt: null, credentials: { environment: { NOTES_TOKEN: 'notes-access' } } };
    },
  };
  const f = await fixture(t, { gmail, connectors: [gmailReadonly(gmail), gmailMetadata(gmail), notes] });
  const catalog = (await f.request('/v1/connectors', { anonymous: true })).json.connectors;
  assert.equal(catalog[2].access.name, 'ノートの読み取り'); assert.deepEqual(catalog[2].variables, ['NOTES_TOKEN']);
  assert.ok(!JSON.stringify(catalog).includes('client'));
  const { row, token } = await register(f, { input: { connector: 'notes.oauth' } });
  assert.equal(row.connector.label, 'Notesで接続');
  assert.equal(row.connector.service.name, 'Notes');
  const start = await f.request('/v1/connections', { method: 'POST', data: { connector: 'notes.oauth', request_id: row.id } });
  assert.equal(start.status, 200, start.text);
  const callback = await f.request('/oauth/notes.oauth/callback?state=' + new URL(start.json.url).searchParams.get('state') + '&code=notes-code');
  assert.equal(callback.headers.get('location'), '/requests/' + row.id + '?connection=connected');
  const saved = f.app.grants.connections(USER_A)[0];
  assert.equal(saved.connector, 'notes.oauth'); assert.equal(saved.subject, 'notes-user');
  const delivered = await f.deliver(saved, { token });
  assert.deepEqual(delivered.json.delivery.environment, { NOTES_TOKEN: 'notes-access' });
  const listed = (await f.request('/v1/connections', { token })).json.connections[0];
  assert.deepEqual(listed.outputs, ['NOTES_TOKEN']); assert.equal(listed.api.documentation_url, 'https://notes.example.test/docs');
});

test('The approval page never receives the confirmation code; entry is normalized and locked after repeated mistakes', async t => {
  const f = await fixture(t);
  const { row } = await create(f);
  const page = await f.request('/v1/requests/' + row.id);
  assert.equal(page.status, 200);
  assert.equal(page.json.request.confirmation_code, undefined);
  assert.doesNotMatch(page.text, new RegExp(row.confirmation_code));
  for (const wrong of ['', 'ZZZZ-ZZZZ', row.confirmation_code.slice(0, 7)]) {
    const response = await approve(f, row, { confirmation_code: wrong });
    assert.equal(response.status, 400); assert.equal(response.json.error.code, 'confirmation_required');
    assert.doesNotMatch(response.text, new RegExp(row.confirmation_code));
  }
  assert.equal(rowStatus(f, row.id), 'pending');
  const relaxed = await approve(f, row, { confirmation_code: ' ' + row.confirmation_code.toLowerCase().replace('-', '') + ' ' });
  assert.equal(relaxed.status, 200, relaxed.text);
  assert.equal(relaxed.json.request.status, 'done');
  assert.equal(relaxed.json.request.confirmation_code, undefined);
  const second = await create(f);
  for (let attempt = 1; attempt <= 4; attempt++) assert.equal((await approve(f, second.row, { confirmation_code: '0000-0000' })).json.error.code, 'confirmation_required');
  const locked = await approve(f, second.row, { confirmation_code: '0000-0000' });
  assert.equal(locked.status, 400); assert.equal(locked.json.error.code, 'confirmation_locked');
  assert.equal(rowStatus(f, second.row.id), 'denied');
  assert.equal((await approve(f, second.row)).status, 409);
  assert.equal(f.app.principals.actorsOf(USER_A).length, 1);
});

test('An access key introduces itself: whoami, the owner can rename it, it can rename itself, and it can leave', async t => {
  const f = await fixture(t), saved = await f.credential();
  const { token, row } = await create(f, null, { name: 'dev-us の claude' });
  const before = await f.request('/v1/principals/me', { token, anonymous: true });
  assert.equal(before.status, 200); assert.equal(before.json.requests[0].status, 'pending'); assert.deepEqual(before.json.acts_for, [], 'nobody to act for yet');
  assert.equal((await approve(f, row)).status, 200);
  const me = await f.request('/v1/principals/me', { token, anonymous: true });
  assert.equal(me.status, 200, me.text);
  assert.equal(me.json.principal.name, 'dev-us の claude');
  assert.deepEqual((await usable(f, token)).json.connections.map(item => item.id), [saved.id]);
  assert.doesNotMatch(me.text, /token_hash|fdn_/);
  // A later request from the same key is shown under the registered name, whatever the runtime calls itself.
  const next = await create(f, token, { to: USER_A, name: 'dev-us の Claude Code' }, registration);
  const page = (await f.request('/v1/requests/' + next.row.id)).json.request;
  assert.equal(page.requester_name, 'dev-us の claude');
  const agentId = me.json.principal.id;
  assert.equal((await f.request('/v1/principals/' + agentId, { method: 'PATCH', data: { name: '' } })).status, 400);
  assert.equal((await f.request('/v1/principals/' + agentId, { method: 'PATCH', data: { name: '作業用' } })).status, 200);
  assert.equal(f.app.principals.actorsOf(USER_A)[0].name, '作業用');
  assert.equal((await f.request('/v1/principals/' + agentId, { method: 'PATCH', headers: { origin: 'https://evil.test' }, data: { name: 'x' } })).status, 403);
  const renamed = await f.request('/v1/principals/me', { method: 'PATCH', token, anonymous: true, data: { name: '作業用 Claude' } });
  assert.equal(renamed.status, 200, renamed.text); assert.equal(renamed.json.principal.name, '作業用 Claude');
  assert.equal((await f.request('/v1/principals/me', { method: 'PATCH', token, anonymous: true, data: { name: '' } })).status, 400);
  assert.equal(f.app.principals.actorsOf(USER_A)[0].name, '作業用 Claude');
  // Leaving revokes the key but keeps the credentials.
  assert.equal((await f.request('/v1/principals/me', { method: 'DELETE', token, anonymous: true, data: {} })).status, 200);
  assert.equal((await f.request('/v1/connections', { token, anonymous: true })).status, 401);
  assert.equal(f.app.principals.actorsOf(USER_A).length, 0);
  assert.equal(f.app.grants.connections(USER_A).length, 1);
});

test('依頼元が認証失敗と再試行の経過を機密入力なしで確認する', async t => {
  const f = await fixture(t, { login: false }), { token, row } = await create(f);
  const approval = async () => (await f.request('/v1/requests/' + row.id, { token, anonymous: true })).json.request;
  assert.deepEqual((await approval()).events, []);
  assert.equal((await approval()).confirmation_code, row.confirmation_code, 'the runtime created the request and already knows the code');
  assert.equal((await f.request('/requests/' + row.id, { anonymous: true })).status, 200);
  await f.login();
  await f.request('/v1/requests/' + row.id);
  assert.equal((await approve(f, row, { confirmation_code: 'ZZZZ-ZZZZ' })).status, 400);
  assert.equal((await approve(f, row)).status, 200);
  let events = (await approval()).events;
  assert.deepEqual(events.map(item => item.event), ['page_opened', 'page_viewed', 'connect_failed', 'approved']);
  assert.equal(events[2].code, 'confirmation_required');
  // The same key, now approved, asks for a registration; its events are the registration's own.
  const asked = await create(f, token, { to: USER_A }, registration);
  const view = async (id = asked.row.id, as = token) => (await f.request('/v1/requests/' + id, { token: as, anonymous: true })).json.request;
  await f.request('/v1/requests/' + asked.row.id);
  const start = await f.request('/v1/connections', { method: 'POST', data: { connector: 'gmail.readonly', request_id: asked.row.id } });
  const authorization = new URL(start.json.url), callback = new URL(authorization.searchParams.get('redirect_uri'));
  await f.request(callback.pathname + '?state=' + authorization.searchParams.get('state') + '&error=access_denied');
  const again = await f.request('/v1/connections', { method: 'POST', data: { connector: 'gmail.readonly', request_id: asked.row.id } });
  await f.callback(new URL(again.json.url), 'personal-readonly');
  events = (await view()).events;
  assert.deepEqual(events.map(item => item.event), ['page_viewed', 'connect_started', 'connect_failed', 'connect_started', 'connected']);
  assert.equal(events[2].code, 'authorization_denied'); assert.match(events[2].message, /認証は許可されません/); assert.equal(events[2].connector, 'gmail.readonly');
  assert.ok(events.every(item => Number.isFinite(item.at)));
  assert.doesNotMatch(JSON.stringify(events), /headers-metadata|personal-readonly|google-access|refresh_token|fdn_|ZZZZ/);
  assert.equal((await view()).status, 'done');
  // Another key never sees this request; a cancelled request records it.
  const other = await f.issueKey('other');
  assert.equal((await f.request('/v1/requests/' + asked.row.id, { token: other.token, anonymous: true })).status, 404);
  const next = await create(f, token, { kind: 'connect', input: { connector: 'gmail.metadata' } }, registration);
  assert.equal((await f.request('/v1/requests/' + next.row.id, { method: 'DELETE', token, anonymous: true, data: {} })).status, 200);
  assert.deepEqual((await view(next.row.id)).events.map(item => item.event), ['cancelled']);
});

test('The runtime chooses how long the link stays open, within a day', async t => {
  const f = await fixture(t);
  const { token, row } = await create(f, null, { valid_minutes: 120 });
  assert.equal(row.expires_at - row.created_at, 120 * 60_000);
  assert.equal((await f.request('/v1/requests', { method: 'POST', anonymous: true, token, data: { ...asking, valid_minutes: 30 } })).status, 409, 'a different validity is a different request');
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
  for (const adapter of ['gmail.readonly', 'gmail.metadata']) {
    const made = await f.request('/v1/requests', { method: 'POST', token: issued.token, data: { kind: 'connect', input: { connector: adapter }, purpose: adapter } });
    assert.equal(made.status, 201, made.text); asks.push(made.json.request);
  }
  assert.notEqual(asks[0].id, asks[1].id);
  assert.equal(asks[1].verification_uri, f.base + '/requests/' + asks[1].id);
  const again = await f.request('/v1/requests', { method: 'POST', token: issued.token, data: { kind: 'connect', input: { connector: 'gmail.readonly' }, purpose: 'gmail.readonly' } });
  assert.equal(again.json.request.id, asks[0].id, 'asking again for the same thing is the same request');
  assert.deepEqual((await f.request('/v1/requests?status=pending', { token: issued.token })).json.requests.map(row => row.id), asks.map(row => row.id));
  assert.deepEqual((await f.request('/v1/requests', { token: other.token })).json.requests, []);
  for (let n = 2; n < 10; n++) assert.equal((await f.request('/v1/requests', { method: 'POST', token: issued.token, data: { kind: 'connect', input: { connector: 'gmail.readonly' }, purpose: 'more ' + n } })).status, 201);
  const full = await f.request('/v1/requests', { method: 'POST', token: issued.token, data: { kind: 'connect', input: { connector: 'gmail.readonly' }, purpose: 'one too many' } });
  assert.equal(full.status, 409); assert.equal(full.json.error.code, 'too_many_pending');
  assert.equal((await f.request('/v1/requests?status=nope', { token: issued.token })).json.error.code, 'invalid_status');
});
