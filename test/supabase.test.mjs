import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { SUPABASE_TOKENS } from '../src/providers/supabase.mjs';
import { FakeSupabase, supabaseFixture, SUPABASE_TOKEN } from './supabase-helper.mjs';
import { json, USER_A } from './helpers.mjs';

const credential = (f, id, token) => f.request('/v1/accounts/' + id + '/credentials', { method: 'POST', anonymous: true, token, data: {} });
const createRequest = async (f, token) => (await f.request('/v1/access-requests', { method: 'POST', token, anonymous: true, data: { provider: 'supabase', mode: 'access-token', name: 'dev-us', purpose: 'プロジェクト一覧の確認' } })).json.request;

test('Supabase import verifies the token against the Management API and shows who it belongs to', async t => {
  const f = await supabaseFixture(t), account = await f.supabaseAccount();
  const state = await f.request('/api/state'), provider = state.json.providers.find(item => item.id === 'supabase');
  assert.equal(provider.connection_method, 'token');
  assert.equal(provider.token_setup.url, SUPABASE_TOKENS);
  assert.equal(provider.can_revoke, false);
  assert.equal(account.label, 'owner@example.test');
  assert.deepEqual(account.organizations, [{ slug: 'ttgx', name: 'Owner Org' }]);
  assert.equal(account.credential_type, 'api_key'); assert.equal(account.expires_at, null);
  assert.equal(account.verified, undefined);
  assert.ok(!state.text.includes(SUPABASE_TOKEN));
  assert.deepEqual(f.supabase.calls.map(call => call.url.split('/v1/')[1]), ['profile', 'organizations']);
  assert.equal(f.supabase.calls[0].options.headers.authorization, 'Bearer ' + SUPABASE_TOKEN);
});

test('Supabase rejects malformed, unauthorized or inconsistent tokens without storing anything', async t => {
  const f = await supabaseFixture(t);
  for (const [token, code] of [['not-a-token', 'invalid_credential'], ['sbp_short', 'invalid_credential'], ['sbp_' + 'z'.repeat(40), 'reconnect_required']]) {
    const response = await f.importSupabase({ token });
    assert.equal(response.status, token.startsWith('sbp_') && token.length > 20 ? 409 : 400, token); assert.equal(response.json.error.code, code, token);
  }
  f.supabase.handler = () => json({ username: 'x' });
  assert.equal((await f.importSupabase()).json.error.code, 'provider_response');
  f.supabase.handler = () => json({ message: 'slow down' }, 429);
  assert.equal((await f.importSupabase()).status, 503);
  f.supabase.handler = () => { throw new TypeError('network'); };
  assert.equal((await f.importSupabase()).json.error.code, 'provider_unavailable');
  f.supabase.handler = null;
  assert.equal((await f.importSupabase({ mode: 'admin' })).status, 400);
  assert.equal(f.app.store.accounts(USER_A).length, 0);
  assert.equal((await f.importSupabase()).status, 200);
  assert.equal((await f.importSupabase()).status, 409, 'same token twice');
});

test('Supabase approval delivers SUPABASE_ACCESS_TOKEN to the runtime and stops when the token is revoked upstream', async t => {
  const f = await supabaseFixture(t), token = 'fdn_' + randomBytes(32).toString('base64url');
  const row = await createRequest(f, token), account = await f.supabaseAccount({ accessRequestId: row.id });
  assert.equal(account.permission.id, 'access-token');
  const approved = await f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { accountId: account.id, confirmationCode: row.confirmation_code } });
  assert.equal(approved.status, 200, approved.text);
  const listed = await f.request('/v1/accounts', { token, anonymous: true });
  assert.equal(listed.json.accounts[0].token_env, 'SUPABASE_ACCESS_TOKEN');
  const issued = await credential(f, account.id, token);
  assert.equal(issued.status, 200, issued.text);
  assert.equal(issued.json.access_token, SUPABASE_TOKEN);
  assert.equal(issued.json.token_env, 'SUPABASE_ACCESS_TOKEN');
  assert.equal(issued.json.account.label, 'owner@example.test');
  // Token revoked on Supabase: delivery stops and the connection asks for a new token.
  f.supabase.valid.clear();
  const revoked = await credential(f, account.id, token);
  assert.equal(revoked.status, 409); assert.equal(revoked.json.error.code, 'reconnect_required');
  assert.equal((await f.request('/api/state')).json.accounts[0].status, 'reconnect_required');
  assert.equal((await f.request('/api/accounts/' + account.id, { method: 'DELETE', data: { revoke: true } })).json.error.code, 'manual_revocation_required');
  assert.equal((await f.request('/api/accounts/' + account.id, { method: 'DELETE', data: { revoke: false } })).status, 200);
});

test('A generic key request may not borrow the Supabase variable name', async t => {
  const f = await supabaseFixture(t);
  const { apikeyConnection } = await import('../src/providers/catalog.mjs');
  const { ApiKeyProvider } = await import('../src/providers/apikey.mjs');
  assert.throws(() => new ApiKeyProvider().details({ service: 'Supabase', site: SUPABASE_TOKENS, env: 'SUPABASE_ACCESS_TOKEN' }), /invalid_env|環境変数名/);
  assert.ok(apikeyConnection(new ApiKeyProvider()).id);
});
