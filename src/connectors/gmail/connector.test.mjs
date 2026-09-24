import test from 'node:test';
import assert from 'node:assert/strict';
import { GmailClient, METADATA_SCOPE, READONLY_SCOPE } from './client.mjs';
import { json, FakeGmail, KEY, USER_A, acquired, fixture } from '../../../test/helpers.mjs';
import { Store } from '../../store.mjs';
import { gmailReadonly, gmailMetadata } from './index.mjs';

function setup(t, mode = 'readonly') {
  const store = new Store(':memory:', KEY), gmail = new FakeGmail();
  t.after(() => store.close());
  const scopes = [mode === 'metadata' ? METADATA_SCOPE : READONLY_SCOPE];
  const credentials = { access_token: 'google-access-personal-' + mode, refresh_token: 'refresh-personal-' + mode, scopes, expires_at: Date.now() - 1 };
  const held = acquired(store, [gmailReadonly(gmail), gmailMetadata(gmail)], 'gmail.' + mode, { subject: 'personal@example.test', secret: credentials });
  return { run: held.run, gmail, account: held.row, credentials, state: () => store.acquisitionState(held.row()) };
}

test('Google exchange and refresh keep tokens server-side and preserve actual read scopes', async (t) => {
  const { gmail, run, account, state } = setup(t);
  const result = await gmail.exchange({ code: 'personal-readonly', verifier: 'test-pkce-verifier', redirectUri: 'https://app.test/oauth/gmail.readonly/callback', range: 'readonly' });
  assert.equal(result.subject, 'personal@example.test');
  const request = gmail.calls[0];
  assert.equal(request.options.body.get('grant_type'), 'authorization_code');
  assert.equal(request.options.body.get('code_verifier'), 'test-pkce-verifier');
  assert.equal(request.options.body.get('redirect_uri'), 'https://app.test/oauth/gmail.readonly/callback');
  await run();
  const calls = gmail.calls.length;
  await run();
  assert.equal(gmail.calls.length, calls);
  for (const call of gmail.calls) { assert.equal(call.options.redirect, 'error'); assert.ok(call.options.signal); }
  assert.ok(gmail.calls.every((call) => !call.url.includes('/messages')));
});

for (const scope of ['https://mail.google.com/', 'https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/drive']) test('追加されたGoogle権限を確認結果として返す: ' + scope, async (t) => {
  const { run, gmail, account, state } = setup(t);
  gmail.refreshHandler = () => json({ access_token: 'google-access-personal-readonly', refresh_token: 'secret-broad-refresh', expires_in: 3600, scope: READONLY_SCOPE + ' ' + scope });
  const result = await run();
  assert.deepEqual(result.state.facts.additional_scopes, [scope]);
  assert.deepEqual(result.state.facts.missing_scopes, []);
  assert.equal(account().status, 'connected');
  assert.equal(result.values.get('GOOGLE_OAUTH_ACCESS_TOKEN').content.toString(), 'google-access-personal-readonly');
  assert.doesNotMatch(JSON.stringify(result.state.facts), /google-access|secret-broad/);
});

test('件名のみの接続に本文権限が加わったことを報告する', async (t) => {
  const { run, gmail, account, state } = setup(t, 'metadata');
  gmail.refreshHandler = () => json({ access_token: 'google-access-personal-metadata', expires_in: 3600, scope: METADATA_SCOPE + ' ' + READONLY_SCOPE });
  assert.deepEqual((await run()).state.facts.additional_scopes, [READONLY_SCOPE]);
});

test('不足するGmail権限を依頼元が接続一覧と認証情報の取得結果で確認する', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  const request = await f.request('/v1/requests', { method: 'POST', token: agent.token, data: { connector: 'gmail.readonly' } });
  const start = await f.request('/v1/connections', { method: 'POST', data: { connector: 'gmail.readonly', request_id: request.json.request.id } });
  const done = await f.callback(new URL(start.json.url), 'personal-metadata');
  assert.match(done.headers.get('location'), /connection=connected/);
  const completed = await f.request('/v1/requests/' + request.json.request.id, { token: agent.token });
  assert.equal(completed.json.request.status, 'done');
  const connection = (await f.request('/v1/connections', { token: agent.token })).json.connections[0];
  assert.deepEqual(connection.facts.missing_scopes, [READONLY_SCOPE]);
  assert.deepEqual(connection.facts.scopes, [METADATA_SCOPE]);
  const delivered = await f.deliver(connection, { token: agent.token });
  assert.equal(delivered.status, 200, delivered.text);
  assert.deepEqual(delivered.json.facts.missing_scopes, [READONLY_SCOPE]);
  assert.equal(delivered.json.delivery.environment.GMAIL_ACCOUNT_EMAIL, 'personal@example.test');
});

test('初回の許可範囲や継続利用のトークンを確認できない応答を拒否する', () => {
  const gmail = new FakeGmail();
  assert.throws(() => gmail.grant({ access_token: 'a', refresh_token: 'r', expires_in: 3600 }), { code: 'service_response' });
  assert.throws(() => gmail.grant({ access_token: 'a', scope: READONLY_SCOPE, expires_in: 3600 }), { code: 'refresh_missing' });
});

test('Refresh may omit unchanged scopes and refresh token under OAuth specification', async (t) => {
  const { run, gmail, account, state } = setup(t);
  gmail.refreshHandler = () => json({ access_token: 'google-access-personal-readonly', expires_in: 3600 });
  await run();
  assert.equal(state().private_state.refresh_token, 'refresh-personal-readonly');
  assert.deepEqual(state().private_state.scopes, [READONLY_SCOPE]);
});

test('Changed Gmail identity is never delivered to existing runtime grants', async (t) => {
  const { run, gmail, account, state } = setup(t);
  gmail.refreshHandler = () => json({ access_token: 'google-access-work-readonly', expires_in: 3600, scope: READONLY_SCOPE });
  await assert.rejects(run(), { code: 'account_changed' });
  assert.equal(account().subject, 'personal@example.test');
  assert.equal(account().status, 'reconnect_required');
});

test('Provider failures are redacted and transient errors do not delete credentials', async (t) => {
  const { run, gmail, account, state } = setup(t);
  for (const status of [403, 429, 500]) {
    gmail.refreshHandler = () => json({ error: 'secret-refresh-token', error_description: 'private body' }, status);
    await assert.rejects(run(), (error) => !error.message.includes('secret') && !error.message.includes('private'));
    assert.equal(account().status, 'connected');
  }
});

test('Revocation is form POST, no token in URL; already invalid token counts as revoked', async () => {
  const calls = [];
  const gmail = new GmailClient({ clientId: 'id', clientSecret: 'secret' }, { fetcher: async (url, options) => { calls.push({ url, options }); return json({ error: 'invalid_token' }, 400); } });
  await gmail.revoke({ refresh_token: 'test-refresh-sensitive' });
  assert.equal(calls[0].url, 'https://oauth2.googleapis.com/revoke');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.body.get('token'), 'test-refresh-sensitive');
});

test('Malformed token lifetimes, bearer types and identity are rejected', () => {
  const gmail = new FakeGmail();
  for (const change of [{ expires_in: -1 }, { expires_in: 900000 }, { expires_in: '3600' }, { access_token: '' }, { access_token: 'a\r\nb' }, { token_type: 'unknown' }]) assert.throws(() => gmail.grant({ access_token: 'a', refresh_token: 'r', scope: READONLY_SCOPE, expires_in: 3600, ...change }), { code: 'service_response' });
});
