import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { fixture, FakeGmail, USER_A, USER_B } from './helpers.mjs';
import { gmailConnection } from '../src/providers/catalog.mjs';

const key = () => 'fdn_' + randomBytes(32).toString('base64url');
const input = { provider: 'gmail', name: 'dev-us のAI', purpose: '届いたメールの確認', mode: 'readonly' };
async function create(f, token = key(), overrides = {}) {
  const response = await f.request('/v1/access-requests', { method: 'POST', anonymous: true, token, data: { ...input, ...overrides } });
  assert.equal(response.status, 201, response.text);
  return { token, row: response.json.request };
}
const approve = (f, row, overrides = {}) => f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { confirmationCode: row.confirmation_code, ...overrides } });
const usable = (f, token) => f.request('/v1/accounts', { token, anonymous: true });
const cancel = (f, token) => f.request('/v1/access-requests/current', { method: 'DELETE', token, anonymous: true, data: {} });
const rowStatus = (f, id) => f.app.store.db.prepare('SELECT status FROM access_requests WHERE id=?').get(id)?.status;

test('A fresh runtime requests access, receives no access before approval, and uses the same private key after approval', async t => {
  const f = await fixture(t, { login: false });
  const { token, row } = await create(f);
  assert.equal(row.status, 'pending');
  assert.equal(row.verification_uri, f.base + '/connect/' + row.id);
  assert.match(row.confirmation_code, /^[A-F0-9]{4}-[A-F0-9]{4}$/);
  assert.doesNotMatch(JSON.stringify(row), /fdn_|token_hash|refresh_token/);
  assert.equal((await f.request('/connect/' + row.id, { anonymous: true, headers: { 'sec-fetch-site': 'cross-site' } })).status, 200);
  assert.equal((await f.request('/api/access-requests/' + row.id, { anonymous: true })).status, 401);
  assert.equal((await f.request('/v1/accounts', { token, anonymous: true })).status, 401);
  assert.equal((await cancel(f, row.id)).status, 401);
  assert.equal((await cancel(f, key())).status, 410);
  assert.equal((await f.request('/v1/access-requests/current', { token, anonymous: true })).json.request.id, row.id, 'a runtime may read its own request');
  await f.login();
  const account = await f.account();
  const info = await f.request('/api/access-requests/' + row.id);
  assert.equal(info.json.request.agent_name, undefined, 'the key is not yet the owner\'s');
  const approved = await approve(f, row);
  assert.equal(approved.status, 200, approved.text);
  assert.equal(approved.json.request.status, 'approved');
  assert.doesNotMatch(approved.text, /fdn_|google-access|refresh_token|token_hash/);
  assert.equal((await usable(f, token)).json.accounts[0].id, account.id);
  const listed = await f.request('/v1/accounts', { token, anonymous: true });
  assert.deepEqual(listed.json.accounts.map(a => a.id), [account.id]);
  const credential = await f.request('/v1/accounts/' + account.id + '/credentials', { method: 'POST', token, anonymous: true, data: {} });
  assert.equal(credential.status, 200);
  assert.equal(credential.json.access_token, 'google-access-personal-readonly');
  assert.equal(credential.json.account.provider, 'gmail');
  assert.equal((await approve(f, row)).status, 409);
  assert.equal(f.app.store.agents(USER_A).length, 1);
  assert.ok(!JSON.stringify(f.app.store.db.prepare('SELECT * FROM access_requests').all()).includes(token));
});

test('Request creation is idempotent and cannot silently change the permissions in a shared URL', async t => {
  const f = await fixture(t), { token, row } = await create(f);
  const again = await create(f, token);
  assert.equal(again.row.id, row.id);
  const changed = await f.request('/v1/access-requests', { method: 'POST', token, data: { ...input, mode: 'metadata' } });
  assert.equal(changed.status, 409);
  assert.equal(f.app.store.db.prepare('SELECT mode FROM access_requests WHERE id=?').get(row.id).mode, 'readonly');
});

test('Email login returns to the exact approval page and rejects open redirects', async t => {
  const f = await fixture(t, { login: false }), { row } = await create(f);
  for (const returnTo of ['https://evil.test/', '//evil.test/', '/connect/x', '/connect/' + row.id + '?next=evil', '/connect/' + row.id + '/..', 42]) {
    const response = await f.request('/api/auth/link', { method: 'POST', data: { email: 'owner@example.test', returnTo } });
    assert.equal(response.status, 400, String(returnTo));
  }
  const sent = await f.request('/api/auth/link', { method: 'POST', data: { email: 'owner@example.test', returnTo: '/connect/' + row.id } });
  assert.equal(sent.status, 202);
  const cookie = sent.headers.getSetCookie().find(value => value.startsWith('fdn_login=')).split(';')[0];
  const url = new URL(f.auth.links.get('owner@example.test').url);
  const callback = await f.request(url.pathname + url.search, { headers: { cookie, 'sec-fetch-site': 'cross-site' } });
  assert.equal(callback.status, 303);
  assert.equal(callback.headers.get('location'), '/connect/' + row.id);
});

test('Google OAuth preserves the request but connecting alone never approves the runtime', async t => {
  const f = await fixture(t), { token, row } = await create(f);
  const start = await f.request('/api/connections/gmail/connect', { method: 'POST', data: { name: '個人用', mode: 'readonly', accessRequestId: row.id } });
  assert.equal(start.status, 200, start.text);
  const response = await f.callback(new URL(start.json.url));
  assert.equal(response.headers.get('location'), '/connect/' + row.id + '?connection=connected');
  assert.equal((await f.request('/v1/accounts', { token, anonymous: true })).status, 401);
  assert.equal(f.app.store.accounts(USER_A).length, 1);
  assert.equal(f.app.store.agents(USER_A).length, 0);
});

test('Approval requires the confirmation code; a registration through the request keeps to the requested permission', async t => {
  const f = await fixture(t);
  const { token, row } = await create(f, key(), { mode: 'metadata' });
  assert.equal((await approve(f, row, { confirmationCode: '' })).status, 400);
  const escalation = await f.request('/api/connections/gmail/connect', { method: 'POST', data: { name: 'Gmail', mode: 'readonly', accessRequestId: row.id } });
  assert.equal(escalation.status, 400);
  const readonly = await f.account(), metadata = await f.account('headers', 'metadata');
  assert.equal((await approve(f, row)).status, 200);
  // An approved key uses every account its owner registered, whatever the request named.
  assert.deepEqual((await usable(f, token)).json.accounts.map(a => a.id).sort(), [readonly.id, metadata.id].sort());
});

test('A request from an approved key stays with its owner, completes by registering, and a revoked key cannot be revived through it', async t => {
  const f = await fixture(t), first = await f.account();
  const runtime = await f.agent();
  const { row } = await create(f, runtime.token, { mode: 'metadata' });
  assert.equal(row.agent_name, 'dev-us');
  const ownerCookie = 'fdn_session=' + f.app.store.createSession(f.auth.value());
  await f.login('other@example.test');
  assert.equal((await f.request('/api/access-requests/' + row.id)).status, 404);
  assert.equal((await approve(f, row)).status, 404);
  // The owner registers the account the key asked for; that completes the request without a code.
  const flow = new URL((await f.request('/api/connections/gmail/connect', { method: 'POST', headers: { cookie: ownerCookie }, data: { name: 'Gmail', mode: 'metadata', accessRequestId: row.id } })).json.url);
  await f.callback(flow, 'second-metadata', { headers: { cookie: ownerCookie } });
  const done = (await f.request('/api/access-requests/' + row.id, { headers: { cookie: ownerCookie } })).json.request;
  assert.equal(done.status, 'approved'); assert.equal(done.account.email, 'second@example.test');
  assert.equal(f.app.store.agents(USER_A).length, 1);
  assert.equal((await usable(f, runtime.token)).json.accounts.length, 2);
  const next = await create(f, runtime.token);
  f.app.store.removeAgent(USER_A, runtime.id);
  assert.equal((await usable(f, runtime.token)).status, 401);
  assert.equal((await f.request('/api/access-requests/' + next.row.id, { headers: { cookie: ownerCookie } })).json.request.status, 'revoked');
  const blocked = await f.request('/api/access-requests/' + next.row.id + '/approve', { method: 'POST', headers: { cookie: ownerCookie }, data: { confirmationCode: next.row.confirmation_code } });
  assert.equal(blocked.status, 409);
  assert.equal(f.app.store.agents(USER_A).length, 0);
  assert.equal(f.app.store.agents(USER_B).length, 0);
  assert.equal(f.app.store.accounts(USER_A).length, 2);
});

test('The first connection action binds an unregistered request to that user', async t => {
  const f = await fixture(t), { row } = await create(f);
  await f.request('/api/connections/gmail/connect', { method: 'POST', data: { name: 'Gmail', mode: 'readonly', accessRequestId: row.id } });
  await f.login('other@example.test');
  assert.equal((await f.request('/api/access-requests/' + row.id)).status, 404);
  assert.equal((await f.request('/api/access-requests/' + row.id + '/deny', { method: 'POST', data: {} })).status, 404);
});

for (const end of ['deny', 'cancel', 'expire']) test(`A ${end} request cannot grant access or finish an in-flight Google exchange`, async t => {
  const f = await fixture(t), existing = await f.account(), { token, row } = await create(f);
  let entered, release;
  const started = new Promise(resolve => { entered = resolve; });
  f.gmail.exchangeHandler = () => { entered(); return new Promise(resolve => { release = resolve; }); };
  const start = await f.request('/api/connections/gmail/connect', { method: 'POST', data: { name: 'new', mode: 'readonly', accessRequestId: row.id } });
  const callback = f.callback(new URL(start.json.url), 'new-readonly');
  await started;
  if (end === 'deny') assert.equal((await f.request('/api/access-requests/' + row.id + '/deny', { method: 'POST', data: {} })).status, 200);
  if (end === 'cancel') assert.equal((await f.request('/v1/access-requests/current', { method: 'DELETE', token, data: {} })).status, 200);
  if (end === 'expire') f.app.store.db.prepare('UPDATE access_requests SET expires_at=0 WHERE id=?').run(row.id);
  release();
  const result = await callback;
  assert.equal(result.headers.get('location'), '/connect/' + row.id + '?connection=failed');
  assert.equal(f.app.store.accounts(USER_A).length, 1);
  assert.notEqual((await approve(f, row)).status, 200);
  assert.equal(f.app.store.agents(USER_A).length, 0);
  if (end === 'expire') {
    assert.equal(rowStatus(f, row.id), 'pending');
    f.app.store.sweep();
    assert.equal(f.app.store.db.prepare('SELECT count(*) n FROM access_requests').get().n, 0);
  } else assert.equal(rowStatus(f, row.id), end === 'deny' ? 'denied' : 'cancelled');
});

test('Cross-site creation, forged providers and cross-origin approval are rejected', async t => {
  const f = await fixture(t), token = key();
  for (const headers of [{ origin: 'https://evil.test' }, { 'sec-fetch-site': 'cross-site' }]) {
    assert.equal((await f.request('/v1/access-requests', { method: 'POST', token, data: input, headers })).status, 403);
  }
  for (const data of [{ ...input, provider: 'unknown' }, { ...input, mode: 'send' }, { ...input, name: '' }]) {
    assert.equal((await f.request('/v1/access-requests', { method: 'POST', token, data })).status, 400);
  }
  const { row } = await create(f, token), account = await f.account();
  const response = await f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', headers: { origin: 'https://evil.test' }, data: { accountId: account.id, confirmationCode: row.confirmation_code } });
  assert.equal(response.status, 403);
  assert.equal(rowStatus(f, row.id), 'pending'); assert.equal((await usable(f, token)).status, 401);
});

test('What the runtime sees reflects a reconnect-required account, a disconnected account, and a revoked key', async t => {
  const f = await fixture(t), account = await f.account(), { token, row } = await create(f);
  await approve(f, row);
  f.app.store.reconnectRequired(f.app.store.account(USER_A, account.id));
  assert.equal((await usable(f, token)).json.accounts[0].status, 'reconnect_required');
  f.app.store.disconnect(USER_A, account.id);
  assert.deepEqual((await usable(f, token)).json.accounts, []);
  f.app.store.removeAgent(USER_A, f.app.store.agents(USER_A)[0].id);
  assert.equal((await usable(f, token)).status, 401);
});

test('Unavailable integrations cannot register through a request; expired request records are deleted without revoking the key', async t => {
  const f = await fixture(t), account = await f.account(), { token, row } = await create(f);
  f.gmail.enabled = false;
  assert.equal((await f.request('/api/connections/gmail/connect', { method: 'POST', data: { name: 'Gmail', mode: 'readonly', accessRequestId: row.id } })).status, 503);
  f.gmail.enabled = true;
  assert.equal((await approve(f, row)).status, 200);
  f.app.store.db.prepare('UPDATE access_requests SET expires_at=0 WHERE id=?').run(row.id);
  f.app.store.sweep();
  assert.equal(rowStatus(f, row.id), undefined);
  assert.equal((await f.request('/v1/accounts', { token })).json.accounts[0].id, account.id);
});

test('A second integration uses the same request, approval and credential APIs without Gmail-specific permission logic', async t => {
  const gmail = new FakeGmail();
  const notes = {
    id: 'notes', name: 'Notes', connectLabel: 'Notesで接続', api: { base_url: 'https://notes.example.test/api', documentation_url: 'https://notes.example.test/docs' },
    permissions: [{ id: 'notes.read', name: 'ノートの読み取り', description: '保存済みノート', restrictions: '変更は許可しません。' }],
    matches: (mode, account) => mode === 'notes.read' && account.scopes.includes('notes.read'),
    client: { enabled: true, check() {}, authorize: ({ state, redirectUri }) => 'https://notes.example.test/auth?' + new URLSearchParams({ state, redirect_uri: redirectUri }),
      async exchange() { return { email: 'notes-user', credentials: { access_token: 'notes-access', refresh_token: 'notes-refresh', expires_at: Date.now() + 3600_000, scopes: ['notes.read'] } }; },
      async token(store, account) { return store.secrets(account); }, async revoke() {},
    },
  };
  const f = await fixture(t, { gmail, integrations: [gmailConnection(gmail), notes] });
  const catalog = (await f.request('/v1/providers', { anonymous: true })).json.providers;
  assert.equal(catalog[1].permissions[0].id, 'notes.read');
  assert.ok(!JSON.stringify(catalog).includes('client'));
  const { row, token } = await create(f, key(), { provider: 'notes', mode: 'notes.read' });
  assert.equal(row.service.name, 'Notes');
  assert.equal(row.permission.name, 'ノートの読み取り');
  const start = await f.request('/api/connections/notes/connect', { method: 'POST', data: { name: 'Notes', mode: 'notes.read', accessRequestId: row.id } });
  assert.equal(start.status, 200, start.text);
  const callback = await f.request('/oauth/notes/callback?state=' + new URL(start.json.url).searchParams.get('state') + '&code=notes-code');
  assert.equal(callback.headers.get('location'), '/connect/' + row.id + '?connection=connected');
  const account = f.app.store.accounts(USER_A)[0];
  assert.equal(account.provider, 'notes');
  assert.equal((await approve(f, row)).status, 200);
  const credentials = await f.request('/v1/accounts/' + account.id + '/credentials', { method: 'POST', token, data: {} });
  assert.equal(credentials.json.access_token, 'notes-access');
  assert.equal(credentials.json.api_base_url, notes.api.base_url);
  assert.equal((await f.request('/v1/accounts', { token })).json.accounts[0].api.documentation_url, notes.api.documentation_url);
});

test('The approval page never receives the confirmation code; entry is normalized and locked after repeated mistakes', async t => {
  const f = await fixture(t), account = await f.account();
  const { token, row } = await create(f);
  const page = await f.request('/api/access-requests/' + row.id);
  assert.equal(page.status, 200);
  assert.equal(page.json.request.confirmation_code, undefined);
  assert.doesNotMatch(page.text, new RegExp(row.confirmation_code));
  for (const wrong of ['', 'ZZZZ-ZZZZ', row.confirmation_code.slice(0, 7)]) {
    const response = await approve(f, row, { confirmationCode: wrong });
    assert.equal(response.status, 400); assert.equal(response.json.error.code, 'confirmation_required');
    assert.doesNotMatch(response.text, new RegExp(row.confirmation_code));
  }
  assert.equal(rowStatus(f, row.id), 'pending');
  const relaxed = await approve(f, row, { confirmationCode: ' ' + row.confirmation_code.toLowerCase().replace('-', '') + ' ' });
  assert.equal(relaxed.status, 200, relaxed.text);
  assert.equal(relaxed.json.request.status, 'approved');
  assert.equal(relaxed.json.request.confirmation_code, undefined);

  const second = await create(f, key());
  for (let attempt = 1; attempt <= 4; attempt++) assert.equal((await approve(f, second.row, { confirmationCode: '0000-0000' })).json.error.code, 'confirmation_required');
  const locked = await approve(f, second.row, { confirmationCode: '0000-0000' });
  assert.equal(locked.status, 400); assert.equal(locked.json.error.code, 'confirmation_locked');
  assert.equal(rowStatus(f, second.row.id), 'denied');
  assert.equal((await approve(f, second.row)).status, 409);
  assert.equal(f.app.store.agents(USER_A).length, 1);
});

test('An access key introduces itself: whoami, approval renames it, the owner can rename it, and it can leave', async t => {
  const f = await fixture(t), account = await f.account();
  const { token, row } = await create(f, key(), { name: 'dev-us の claude' });
  const before = await f.request('/v1/me', { token, anonymous: true });
  assert.equal(before.status, 401); assert.equal(before.json.error.code, 'not_approved');
  assert.equal((await f.request('/api/access-requests/' + row.id)).json.request.agent_name, undefined);
  assert.equal((await approve(f, row)).status, 200);
  const me = await f.request('/v1/me', { token, anonymous: true });
  assert.equal(me.status, 200, me.text);
  assert.equal(me.json.agent.name, 'dev-us の claude');
  assert.deepEqual((await usable(f, token)).json.accounts.map(item => item.id), [account.id]);
  assert.doesNotMatch(me.text, /token_hash|fdn_/);
  // A later request from the same key is shown under the registered name, whatever the runtime calls itself.
  const next = await create(f, token, { name: 'dev-us の Claude Code', mode: 'readonly' });
  const page = (await f.request('/api/access-requests/' + next.row.id)).json.request;
  assert.equal(page.requester_name, 'dev-us の claude'); assert.equal(page.agent_name, 'dev-us の claude');
  assert.equal((await approve(f, next.row)).status, 409, 'an approved key is not approved twice');
  assert.equal((await f.request('/v1/me', { token, anonymous: true })).json.agent.name, 'dev-us の claude');
  const agentId = me.json.agent.id;
  assert.equal((await f.request('/api/agents/' + agentId, { method: 'PATCH', data: { name: '' } })).status, 400);
  assert.equal((await f.request('/api/agents/' + agentId, { method: 'PATCH', data: { name: '作業用' } })).status, 200);
  assert.equal(f.app.store.agents(USER_A)[0].name, '作業用');
  assert.equal((await f.request('/api/agents/' + agentId, { method: 'PATCH', headers: { origin: 'https://evil.test' }, data: { name: 'x' } })).status, 403);
  // The key may rename itself; the owner's later rename wins just the same.
  const renamed = await f.request('/v1/me', { method: 'PATCH', token, anonymous: true, data: { name: '作業用 Claude' } });
  assert.equal(renamed.status, 200, renamed.text); assert.equal(renamed.json.agent.name, '作業用 Claude');
  assert.equal((await f.request('/v1/me', { method: 'PATCH', token, anonymous: true, data: { name: '' } })).status, 400);
  assert.equal(f.app.store.agents(USER_A)[0].name, '作業用 Claude');
  // Leaving revokes the key but keeps the connection.
  assert.equal((await f.request('/v1/me', { method: 'DELETE', token, anonymous: true, data: {} })).status, 200);
  assert.equal((await f.request('/v1/accounts', { token, anonymous: true })).status, 401);
  assert.equal(f.app.store.agents(USER_A).length, 0);
  assert.equal(f.app.store.accounts(USER_A).length, 1);
});

test('A runtime can read its own request raw: what it asked for, and what happened at the approval URL, never an input', async t => {
  const f = await fixture(t, { login: false }), { token, row } = await create(f);
  const view = async () => (await f.request('/v1/access-requests/current', { token, anonymous: true })).json.request;
  assert.deepEqual((await view()).events, []);
  assert.equal((await view()).confirmation_code, row.confirmation_code, 'the runtime created the request and already knows the code');
  assert.equal((await f.request('/connect/' + row.id, { anonymous: true })).status, 200);
  await f.login();
  await f.request('/api/access-requests/' + row.id);
  const start = await f.request('/api/connections/gmail/connect', { method: 'POST', data: { name: 'Gmail', mode: 'readonly', accessRequestId: row.id } });
  await f.callback(new URL(start.json.url), 'headers-metadata');
  const again = await f.request('/api/connections/gmail/connect', { method: 'POST', data: { name: 'Gmail', mode: 'readonly', accessRequestId: row.id } });
  await f.callback(new URL(again.json.url), 'personal-readonly');
  const account = f.app.store.accounts(USER_A)[0];
  assert.equal((await approve(f, row, { confirmationCode: 'ZZZZ-ZZZZ' })).status, 400);
  assert.equal((await approve(f, row)).status, 200);
  const events = (await view()).events;
  assert.deepEqual(events.map(item => item.event), ['page_opened', 'page_viewed', 'connect_started', 'connect_failed', 'connect_started', 'connected', 'connect_failed', 'approved']);
  assert.equal(events[3].code, 'scope_mismatch'); assert.match(events[3].message, /読み取り範囲/); assert.equal(events[3].provider, 'gmail');
  assert.equal(events[6].code, 'confirmation_required');
  assert.ok(events.every(item => Number.isFinite(item.at)));
  assert.doesNotMatch(JSON.stringify(events), /headers-metadata|personal-readonly|google-access|refresh_token|fdn_|ZZZZ/);
  assert.equal((await view()).status, 'approved');
  // Another key never sees this request; a cancelled request records it.
  assert.equal((await f.request('/v1/access-requests/current', { token: key(), anonymous: true })).status, 410);
  const next = await create(f, token, { mode: 'metadata' });
  assert.equal((await f.request('/v1/access-requests/current', { method: 'DELETE', token, anonymous: true, data: {} })).status, 200);
  assert.deepEqual((await view()).events.map(item => item.event), ['cancelled']);
  assert.equal((await view()).id, next.row.id);
});

test('The runtime chooses how long the link stays open, within a day', async t => {
  const f = await fixture(t), token = key();
  const { row } = await create(f, token, { valid_minutes: 120 });
  assert.equal(row.expires_at - row.created_at, 120 * 60_000);
  assert.equal((await f.request('/v1/access-requests', { method: 'POST', anonymous: true, token, data: { ...input, valid_minutes: 30 } })).status, 409, 'a different validity is a different request');
  const plain = (await create(f, key())).row;
  assert.equal(plain.expires_at - plain.created_at, 30 * 60_000, 'the default stays 30 minutes');
  for (const bad of [0, 1441, 1.5, '120']) assert.equal((await f.request('/v1/access-requests', { method: 'POST', anonymous: true, token: key(), data: { ...input, valid_minutes: bad } })).json.error.code, 'invalid_validity', String(bad));
});

test('The runtime writes the guidance its owner reads on the approval page; Foundation frames it and bounds it', async t => {
  const f = await fixture(t), token = key();
  const guidance = '1. 定義ファイルをダウンロード\n2. スタック名は foundation-admin\n\n出力の値を貼る';
  const created = await f.request('/v1/access-requests', { method: 'POST', anonymous: true, token, data: { ...input, guidance: guidance + '\r\n' } });
  assert.equal(created.status, 201, created.text);
  assert.equal(created.json.request.guidance, guidance);
  assert.equal((await f.request('/api/access-requests/' + created.json.request.id)).json.request.guidance, guidance);
  assert.equal((await f.request('/v1/access-requests', { method: 'POST', anonymous: true, token, data: { ...input, guidance: 'different' } })).status, 409, 'different guidance is a different request');
  assert.equal((await f.request('/v1/access-requests', { method: 'POST', anonymous: true, token: key(), data: { ...input, guidance: 'x'.repeat(2001) } })).json.error.code, 'invalid_guidance');
  assert.equal((await f.request('/v1/access-requests', { method: 'POST', anonymous: true, token: key(), data: { ...input, guidance: 'bad\u0007' } })).json.error.code, 'invalid_guidance');
});
