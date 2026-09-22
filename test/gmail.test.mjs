import test from 'node:test';
import assert from 'node:assert/strict';
import { GmailClient, METADATA_SCOPE, READONLY_SCOPE } from '../src/services/gmail.mjs';
import { json, FakeGmail, KEY, USER_A } from './helpers.mjs';
import { Store } from '../src/store.mjs';

function setup(t, mode = 'readonly') {
  const store = new Store(':memory:', KEY), gmail = new FakeGmail();
  t.after(() => store.close());
  const scopes = [mode === 'metadata' ? METADATA_SCOPE : READONLY_SCOPE];
  const credentials = { access_token: 'google-access-personal-' + mode, refresh_token: 'refresh-personal-' + mode, scopes, expires_at: Date.now() - 1 };
  const id = store.connect(USER_A, { adapter: 'gmail.oauth', name: '個人用', purpose: '', subject: 'personal@example.test', scopes }, credentials);
  return { store, gmail, account: () => store.account(USER_A, id), credentials };
}

test('Google exchange and refresh keep tokens server-side and preserve actual read scopes', async (t) => {
  const { gmail, store, account } = setup(t);
  const result = await gmail.exchange({ code: 'personal-readonly', verifier: 'test-pkce-verifier', redirectUri: 'https://app.test/oauth/gmail.oauth/callback', permission: 'readonly' });
  assert.equal(result.subject, 'personal@example.test');
  const request = gmail.calls[0];
  assert.equal(request.options.body.get('grant_type'), 'authorization_code');
  assert.equal(request.options.body.get('code_verifier'), 'test-pkce-verifier');
  assert.equal(request.options.body.get('redirect_uri'), 'https://app.test/oauth/gmail.oauth/callback');
  await gmail.token(store, account());
  const calls = gmail.calls.length;
  await gmail.token(store, account());
  assert.equal(gmail.calls.length, calls);
  for (const call of gmail.calls) { assert.equal(call.options.redirect, 'error'); assert.ok(call.options.signal); }
  assert.ok(gmail.calls.every((call) => !call.url.includes('/messages')));
});

for (const scope of ['https://mail.google.com/', 'https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/drive']) test('Broad or unrelated Google scope rejected: ' + scope, async (t) => {
  const { store, gmail, account } = setup(t);
  gmail.refreshHandler = () => json({ access_token: 'secret-broad-access', refresh_token: 'secret-broad-refresh', expires_in: 3600, scope: READONLY_SCOPE + ' ' + scope });
  await assert.rejects(gmail.token(store, account()), (error) => error.code === 'scope_mismatch' && !error.message.includes('secret-broad'));
  assert.equal(account().status, 'reconnect_required');
  assert.notEqual(store.secrets(account()).access_token, 'secret-broad-access');
});

test('Metadata-only grant cannot be silently expanded to body access', async (t) => {
  const { store, gmail, account } = setup(t, 'metadata');
  gmail.refreshHandler = () => json({ access_token: 'extra-scope', expires_in: 3600, scope: METADATA_SCOPE + ' ' + READONLY_SCOPE });
  await assert.rejects(gmail.token(store, account()), { code: 'scope_mismatch' });
});

test('Missing scope on initial exchange and missing refresh token are rejected', () => {
  const gmail = new FakeGmail();
  assert.throws(() => gmail.credentials({ access_token: 'a', refresh_token: 'r', expires_in: 3600 }, 'readonly'), { code: 'scope_mismatch' });
  assert.throws(() => gmail.credentials({ access_token: 'a', scope: READONLY_SCOPE, expires_in: 3600 }, 'readonly'), { code: 'refresh_missing' });
});

test('Refresh may omit unchanged scopes and refresh token under OAuth specification', async (t) => {
  const { store, gmail, account } = setup(t);
  gmail.refreshHandler = () => json({ access_token: 'google-access-personal-readonly', expires_in: 3600 });
  await gmail.token(store, account());
  assert.equal(store.secrets(account()).refresh_token, 'refresh-personal-readonly');
  assert.deepEqual(account().scopes, [READONLY_SCOPE]);
});

test('Changed Gmail identity is never delivered to existing runtime grants', async (t) => {
  const { store, gmail, account } = setup(t);
  gmail.refreshHandler = () => json({ access_token: 'google-access-work-readonly', expires_in: 3600, scope: READONLY_SCOPE });
  await assert.rejects(gmail.token(store, account()), { code: 'account_changed' });
  assert.equal(account().subject, 'personal@example.test');
  assert.equal(account().status, 'reconnect_required');
});

test('Provider failures are redacted and transient errors do not delete credentials', async (t) => {
  const { store, gmail, account } = setup(t);
  for (const status of [403, 429, 500]) {
    gmail.refreshHandler = () => json({ error: 'secret-refresh-token', error_description: 'private body' }, status);
    await assert.rejects(gmail.token(store, account()), (error) => !error.message.includes('secret') && !error.message.includes('private'));
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
  for (const change of [{ expires_in: -1 }, { expires_in: 900000 }, { expires_in: '3600' }, { access_token: '' }, { access_token: 'a\r\nb' }, { token_type: 'unknown' }]) assert.throws(() => gmail.credentials({ access_token: 'a', refresh_token: 'r', scope: READONLY_SCOPE, expires_in: 3600, ...change }, 'readonly'), { code: 'service_response' });
});
