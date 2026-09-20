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
const approve = (f, row, accountId, overrides = {}) => f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { accountId, confirmationCode: row.confirmation_code, ...overrides } });
const status = (f, token) => f.request('/v1/access-requests/current', { token, anonymous: true });

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
  assert.equal((await status(f, row.id)).status, 401);
  assert.equal((await status(f, key())).status, 410);
  await f.login();
  const account = await f.account();
  const info = await f.request('/api/access-requests/' + row.id);
  assert.deepEqual(info.json.request.eligible_account_ids, [account.id]);
  const approved = await approve(f, row, account.id);
  assert.equal(approved.status, 200, approved.text);
  assert.equal(approved.json.request.status, 'approved');
  assert.doesNotMatch(approved.text, /fdn_|google-access|refresh_token|token_hash/);
  assert.equal((await status(f, token)).json.request.account.id, account.id);
  const listed = await f.request('/v1/accounts', { token, anonymous: true });
  assert.deepEqual(listed.json.accounts.map(a => a.id), [account.id]);
  const credential = await f.request('/v1/accounts/' + account.id + '/credentials', { method: 'POST', token, anonymous: true, data: {} });
  assert.equal(credential.status, 200);
  assert.equal(credential.json.access_token, 'google-access-personal-readonly');
  assert.equal(credential.json.account.provider, 'gmail');
  assert.equal((await approve(f, row, account.id)).status, 409);
  assert.equal(f.app.store.agents(USER_A).length, 1);
  assert.ok(!JSON.stringify(f.app.store.db.prepare('SELECT * FROM access_requests').all()).includes(token));
});

test('Request creation is idempotent and cannot silently change the permissions in a shared URL', async t => {
  const f = await fixture(t), { token, row } = await create(f);
  const again = await create(f, token);
  assert.equal(again.row.id, row.id);
  const changed = await f.request('/v1/access-requests', { method: 'POST', token, data: { ...input, mode: 'metadata' } });
  assert.equal(changed.status, 409);
  assert.equal((await status(f, token)).json.request.mode, 'readonly');
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
  assert.equal((await status(f, token)).json.request.status, 'pending');
  assert.equal((await f.request('/v1/accounts', { token, anonymous: true })).status, 401);
  assert.equal(f.app.store.accounts(USER_A).length, 1);
  assert.equal(f.app.store.agents(USER_A).length, 0);
});

test('Approval requires the confirmation code and cannot exceed the requested permission', async t => {
  const f = await fixture(t), readonly = await f.account(), metadata = await f.account('headers', 'metadata');
  const { row } = await create(f, key(), { mode: 'metadata' });
  assert.deepEqual((await f.request('/api/access-requests/' + row.id)).json.request.eligible_account_ids, [metadata.id]);
  assert.equal((await approve(f, row, readonly.id)).status, 409);
  assert.equal((await approve(f, row, metadata.id, { confirmationCode: '' })).status, 400);
  const escalation = await f.request('/api/connections/gmail/connect', { method: 'POST', data: { name: 'Gmail', mode: 'readonly', accessRequestId: row.id } });
  assert.equal(escalation.status, 400);
  assert.equal((await approve(f, row, metadata.id)).status, 200);
});

test('Existing runtime requests stay with their owner, preserve old grants, and cannot revive a revoked runtime', async t => {
  const f = await fixture(t), first = await f.account(), second = await f.account('second');
  const runtime = await f.agent([first.id]);
  const { row } = await create(f, runtime.token);
  const ownerCookie = 'fdn_session=' + f.app.store.createSession(f.auth.value());
  await f.login('other@example.test');
  assert.equal((await f.request('/api/access-requests/' + row.id)).status, 404);
  assert.equal((await approve(f, row, first.id)).status, 404);
  const approved = await f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', headers: { cookie: ownerCookie }, data: { accountId: second.id, confirmationCode: row.confirmation_code } });
  assert.equal(approved.status, 200);
  assert.equal(f.app.store.agents(USER_A).length, 1);
  assert.deepEqual(new Set(f.app.store.agents(USER_A)[0].accountIds), new Set([first.id, second.id]));
  const next = await create(f, runtime.token);
  f.app.store.removeAgent(USER_A, runtime.id);
  assert.equal((await status(f, runtime.token)).json.request.status, 'revoked');
  const blocked = await f.request('/api/access-requests/' + next.row.id + '/approve', { method: 'POST', headers: { cookie: ownerCookie }, data: { accountId: second.id, confirmationCode: next.row.confirmation_code } });
  assert.equal(blocked.status, 409);
  assert.equal(f.app.store.agents(USER_A).length, 0);
  assert.equal(f.app.store.agents(USER_B).length, 0);
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
  assert.notEqual((await approve(f, row, existing.id)).status, 200);
  assert.equal(f.app.store.agents(USER_A).length, 0);
  if (end === 'expire') {
    assert.equal((await status(f, token)).status, 410);
    f.app.store.sweep();
    assert.equal(f.app.store.db.prepare('SELECT count(*) n FROM access_requests').get().n, 0);
  } else assert.equal((await status(f, token)).json.request.status, end === 'deny' ? 'denied' : 'cancelled');
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
  assert.equal((await status(f, token)).json.request.status, 'pending');
});

test('Request status reflects later grant revocation and a disconnected account', async t => {
  const f = await fixture(t), account = await f.account(), { token, row } = await create(f);
  await approve(f, row, account.id);
  f.app.store.reconnectRequired(f.app.store.account(USER_A, account.id));
  assert.equal((await status(f, token)).json.request.status, 'reconnect_required');
  const agent = f.app.store.agents(USER_A)[0];
  f.app.store.setGrants(USER_A, agent.id, []);
  assert.equal((await status(f, token)).json.request.status, 'revoked');
});

test('Unavailable integrations cannot claim approval success; expired request records are deleted without revoking existing grants', async t => {
  const f = await fixture(t), account = await f.account(), { token, row } = await create(f);
  f.gmail.enabled = false;
  assert.equal((await approve(f, row, account.id)).status, 503);
  assert.equal(f.app.store.agents(USER_A).length, 0);
  f.gmail.enabled = true;
  assert.equal((await approve(f, row, account.id)).status, 200);
  f.app.store.db.prepare('UPDATE access_requests SET expires_at=0 WHERE id=?').run(row.id);
  f.app.store.sweep();
  assert.equal((await status(f, token)).status, 410);
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
  assert.equal((await approve(f, row, account.id)).status, 200);
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
  assert.equal((await status(f, token)).json.request.confirmation_code, row.confirmation_code);
  for (const wrong of ['', 'ZZZZ-ZZZZ', row.confirmation_code.slice(0, 7)]) {
    const response = await approve(f, row, account.id, { confirmationCode: wrong });
    assert.equal(response.status, 400); assert.equal(response.json.error.code, 'confirmation_required');
    assert.doesNotMatch(response.text, new RegExp(row.confirmation_code));
  }
  assert.equal((await status(f, token)).json.request.status, 'pending');
  const relaxed = await approve(f, row, account.id, { confirmationCode: ' ' + row.confirmation_code.toLowerCase().replace('-', '') + ' ' });
  assert.equal(relaxed.status, 200, relaxed.text);
  assert.equal(relaxed.json.request.status, 'approved');
  assert.equal(relaxed.json.request.confirmation_code, undefined);

  const second = await create(f, key());
  for (let attempt = 1; attempt <= 4; attempt++) assert.equal((await approve(f, second.row, account.id, { confirmationCode: '0000-0000' })).json.error.code, 'confirmation_required');
  const locked = await approve(f, second.row, account.id, { confirmationCode: '0000-0000' });
  assert.equal(locked.status, 400); assert.equal(locked.json.error.code, 'confirmation_locked');
  assert.equal((await status(f, second.token)).json.request.status, 'denied');
  assert.equal((await approve(f, second.row, account.id)).status, 409);
  assert.equal(f.app.store.agents(USER_A).length, 1);
});

test('An access key introduces itself: whoami, approval renames it, the owner can rename it, and it can leave', async t => {
  const f = await fixture(t), account = await f.account();
  const { token, row } = await create(f, key(), { name: 'dev-us の claude' });
  const before = await f.request('/v1/me', { token, anonymous: true });
  assert.equal(before.status, 401); assert.equal(before.json.error.code, 'not_approved');
  assert.equal((await f.request('/api/access-requests/' + row.id)).json.request.agent_name, undefined);
  assert.equal((await approve(f, row, account.id)).status, 200);
  const me = await f.request('/v1/me', { token, anonymous: true });
  assert.equal(me.status, 200, me.text);
  assert.equal(me.json.agent.name, 'dev-us の claude');
  assert.deepEqual(me.json.agent.accounts.map(item => item.id), [account.id]);
  assert.doesNotMatch(me.text, /token_hash|fdn_/);
  // A later request from the same key carries its own name; the page shows the registered one; approval keeps the owner's name.
  const next = await create(f, token, { name: 'dev-us の Claude Code', mode: 'readonly' });
  const page = (await f.request('/api/access-requests/' + next.row.id)).json.request;
  assert.equal(page.requester_name, 'dev-us の Claude Code'); assert.equal(page.agent_name, 'dev-us の claude');
  assert.equal((await approve(f, next.row, account.id)).status, 200);
  assert.equal((await f.request('/v1/me', { token, anonymous: true })).json.agent.name, 'dev-us の claude');
  const agentId = me.json.agent.id;
  assert.equal((await f.request('/api/agents/' + agentId, { method: 'PATCH', data: { name: '' } })).status, 400);
  assert.equal((await f.request('/api/agents/' + agentId, { method: 'PATCH', data: { name: '作業用' } })).status, 200);
  assert.equal(f.app.store.agents(USER_A)[0].name, '作業用');
  assert.equal((await f.request('/api/agents/' + agentId, { method: 'PATCH', headers: { origin: 'https://evil.test' }, data: { name: 'x' } })).status, 403);
  // Leaving revokes the key and its grants but keeps the connection.
  assert.equal((await f.request('/v1/me', { method: 'DELETE', token, anonymous: true, data: {} })).status, 200);
  assert.equal((await f.request('/v1/accounts', { token, anonymous: true })).status, 401);
  assert.equal(f.app.store.agents(USER_A).length, 0);
  assert.equal(f.app.store.accounts(USER_A).length, 1);
});
