import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { SUPABASE_TOKENS } from '../src/services/supabase.mjs';
import { FakeSupabase, supabaseFixture, SUPABASE_TOKEN } from './supabase-helper.mjs';
import { json, USER_A } from './helpers.mjs';

const credential = (f, id, token) => f.request('/v1/credentials/' + id + '/deliver', { method: 'POST', anonymous: true, token, data: {} });
// A registration request comes from a key the owner has approved.
const createRequest = async (f, token) => { await f.approveKey(token); return (await f.request('/v1/access-requests', { method: 'POST', token, anonymous: true, data: { adapter: 'supabase.access-token', purpose: 'プロジェクト一覧の確認' } })).json.request; };

test('Supabase import verifies the token against the Management API and shows who it belongs to', async t => {
  const f = await supabaseFixture(t), account = await f.supabaseAccount();
  const state = await f.request('/api/state'), adapter = state.json.adapters.find(item => item.id === 'supabase.access-token');
  assert.equal(adapter.register, 'paste');
  assert.equal(adapter.form.links[0].href, SUPABASE_TOKENS);
  assert.equal(adapter.can_revoke, false);
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
  assert.equal((await f.importSupabase()).json.error.code, 'service_response');
  f.supabase.handler = () => json({ message: 'slow down' }, 429);
  assert.equal((await f.importSupabase()).status, 503);
  f.supabase.handler = () => { throw new TypeError('network'); };
  assert.equal((await f.importSupabase()).json.error.code, 'service_unavailable');
  f.supabase.handler = null;
  assert.equal(f.app.store.credentials(USER_A).length, 0);
  assert.equal((await f.importSupabase()).status, 200);
  assert.equal((await f.importSupabase()).status, 409, 'same token twice');
});

test('Supabase approval delivers SUPABASE_ACCESS_TOKEN to the runtime and stops when the token is revoked upstream', async t => {
  const f = await supabaseFixture(t), token = 'fdn_' + randomBytes(32).toString('base64url');
  const row = await createRequest(f, token), account = await f.supabaseAccount({ accessRequestId: row.id });
  assert.match(account.access.name, /Supabase/);
  assert.equal((await f.request('/api/access-requests/' + row.id)).json.request.status, 'approved', 'registering completes the request');
  const listed = await f.request('/v1/credentials', { token, anonymous: true });
  assert.deepEqual(listed.json.credentials[0].variables, ['SUPABASE_ACCESS_TOKEN']);
  const issued = await credential(f, account.id, token);
  assert.equal(issued.status, 200, issued.text);
  assert.deepEqual(issued.json.delivery.environment, { SUPABASE_ACCESS_TOKEN: SUPABASE_TOKEN });
  assert.equal(issued.json.credential.label, 'owner@example.test');
  // Token revoked on Supabase: delivery stops and the connection asks for a new token.
  f.supabase.valid.clear();
  const revoked = await credential(f, account.id, token);
  assert.equal(revoked.status, 409); assert.equal(revoked.json.error.code, 'reconnect_required');
  assert.equal((await f.request('/api/state')).json.credentials[0].status, 'reconnect_required');
  const removed = await f.request('/api/credentials/' + account.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.status, 200); assert.equal(removed.json.service_revoked, null);
});

test('A generic key request may not borrow the Supabase variable name', async t => {
  const f = await supabaseFixture(t);
  const { Adapters, generic, supabaseAccessToken } = await import('../src/adapters.mjs');
  const { GenericClient } = await import('../src/generic.mjs');
  const adapters = new Adapters([supabaseAccessToken(f.supabase), generic(new GenericClient())]);
  assert.throws(() => adapters.details('generic', { service: 'Supabase', site: SUPABASE_TOKENS, fields: [{ id: 'SUPABASE_ACCESS_TOKEN' }] }), /環境変数名/);
});
