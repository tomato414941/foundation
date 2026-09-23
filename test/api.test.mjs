import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { fixture, USER_A } from './helpers.mjs';

test('Login gives a private state behind a safe session cookie', async (t) => {
  const f = await fixture(t);
  assert.equal((await f.request('/api/state', { anonymous: true })).status, 401);
  const login = await f.login();
  assert.match(login.headers.get('set-cookie'), /HttpOnly; SameSite=Lax/);
  const result = await f.request('/api/state');
  assert.equal(result.json.user.id, USER_A);
  assert.deepEqual(result.json.secrets, []);
  assert.deepEqual(result.json.acquisitions, []);
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.doesNotMatch(result.text, /supabase-access|refresh_token|"secret"|token_hash/);
});

test('OAuth uses state, PKCE, offline consent, native Google URL; callback is one-use', async (t) => {
  const f = await fixture(t);
  const url = await f.start();
  assert.equal(url.origin, 'https://accounts.google.com');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('access_type'), 'offline');
  assert.equal(url.searchParams.get('include_granted_scopes'), 'false');
  assert.ok(url.searchParams.get('prompt').includes('consent'));
  assert.equal(url.searchParams.get('redirect_uri'), f.base + '/oauth/gmail.readonly/callback');
  const complete = await f.callback(url, 'personal-readonly', { headers: { 'sec-fetch-site': 'cross-site' } });
  assert.equal(complete.headers.get('location'), '/?connection=connected&adapter=gmail.readonly');
  assert.equal((await f.callback(url)).headers.get('location'), '/?connection=expired&adapter=gmail.readonly');
  assert.equal(f.gmail.exchangeCount, 1);
  assert.equal((await f.request('/api/state')).json.acquisitions.length, 1);
});

test('OAuth state is browser-bound and expires; cancel and forged callbacks cannot connect', async (t) => {
  const f = await fixture(t);
  const url = await f.start();
  assert.equal((await f.callback(url, 'personal-readonly', { anonymous: true })).headers.get('location'), '/?connection=expired&adapter=gmail.readonly');
  await f.login('second@example.test');
  assert.equal((await f.callback(url)).headers.get('location'), '/?connection=expired&adapter=gmail.readonly');
  const second = await f.start();
  f.app.store.db.prepare('UPDATE oauth_flows SET expires_at=0').run();
  assert.equal((await f.callback(second)).headers.get('location'), '/?connection=expired&adapter=gmail.readonly');
  const cancel = await f.start();
  const cancelled = await f.request('/oauth/gmail.readonly/callback?state=' + cancel.searchParams.get('state') + '&error=access_denied&error_description=secret-provider-value');
  assert.equal(cancelled.headers.get('location'), '/?connection=denied&adapter=gmail.readonly');
  assert.doesNotMatch(cancelled.text, /secret-provider/);
  assert.equal(f.gmail.exchangeCount, 0);
});

test('Connections expose explicit credential outputs independently of saved names', async (t) => {
  const f = await fixture(t), a = await f.credential(), b = await f.credential('work', 'metadata');
  const agent = await f.issueKey();
  assert.notEqual(a.id, b.id);
  assert.equal(a.label, 'personal@example.test');
  assert.equal(b.label, 'work@example.test');
  const saved = await f.request('/api/secrets?name=gmail%2Fpersonal-example-test', { method: 'PUT', raw: 'independent-value' });
  assert.equal(saved.status, 200);
  assert.deepEqual((await f.request('/v1/secrets', { token: agent.token })).json.secrets.map(row => row.name), ['gmail/personal-example-test']);
  const connections = await f.request('/v1/acquisitions', { token: agent.token });
  assert.deepEqual(connections.json.acquisitions.map(item => item.id), [a.id, b.id]);
  assert.equal(connections.json.acquisitions[0].service.api.base_url, 'https://gmail.googleapis.com/gmail/v1');
  assert.doesNotMatch(connections.text, /refresh_token|google-access-|"state":/);

  const result = await f.deliver(a, { token: agent.token });
  assert.equal(result.status, 200, result.text);
  assert.equal(result.json.delivery.environment.GOOGLE_OAUTH_ACCESS_TOKEN, 'google-access-personal-readonly');
  assert.equal(result.json.delivery.environment.GMAIL_ACCOUNT_EMAIL, 'personal@example.test');
  assert.ok(result.json.expires_in > 3500);
  assert.doesNotMatch(result.text, /refresh_token/);
  assert.equal((await f.deliver(b, { token: agent.token })).json.delivery.environment.GOOGLE_OAUTH_ACCESS_TOKEN, 'google-access-work-metadata');

  // Credential processing leaves existing saved values unchanged.
  assert.equal((await f.request('/api/secrets?name=gmail%2Fpersonal-example-test')).text, 'independent-value');
  assert.ok(!f.gmail.calls.some((call) => call.url.includes('/messages')));
});

test('Owners cannot see, disconnect or reach each other\'s connections', async (t) => {
  const f = await fixture(t), first = await f.credential(), runtime = await f.issueKey();
  await f.login('second@example.test');
  const state = await f.request('/api/state');
  assert.deepEqual(state.json.acquisitions, []);
  assert.deepEqual(state.json.secrets, []);
  assert.deepEqual(state.json.keys, []);
  assert.equal((await f.request('/api/acquisitions/' + encodeURIComponent(first.id), { method: 'DELETE', data: { revoke: true } })).status, 404);
  const intruder = (await f.request('/api/keys', { method: 'POST', data: { name: 'intruder' } })).json.key;
  assert.deepEqual((await f.request('/v1/acquisitions', { token: intruder.token })).json.acquisitions, []);
  assert.equal((await f.deliver(first, { token: intruder.token })).status, 404);
  await f.request('/api/keys/' + runtime.id, { method: 'DELETE' });
  assert.equal((await f.request('/v1/acquisitions', { token: runtime.token })).json.acquisitions.length, 1, 'the owner keeps it when one key is revoked');
  const second = await f.credential();
  assert.notEqual(second.id, first.id);
  assert.equal((await f.request('/api/state')).json.acquisitions.length, 1);
});

test('Connecting again pins the Google account and stays within the same adapter', async (t) => {
  const f = await fixture(t), a = await f.credential('personal', 'metadata'), agent = await f.issueKey();
  assert.equal((await f.request('/api/adapters/gmail.readonly/connect', { method: 'POST', data: { connection_id: a.id } })).json.error.code, 'invalid_adapter');
  let flow = await f.start({ range: 'metadata', connection_id: a.id });
  assert.equal(flow.searchParams.get('login_hint'), 'personal@example.test');
  assert.equal((await f.callback(flow, 'work-metadata')).headers.get('location'), '/?connection=wrong_account&adapter=gmail.metadata');
  assert.equal((await f.request('/v1/acquisitions', { token: agent.token })).json.acquisitions.length, 1);
  flow = await f.start({ range: 'metadata', connection_id: a.id });
  assert.equal((await f.callback(flow, 'personal-metadata')).headers.get('location'), '/?connection=connected&adapter=gmail.metadata');
  const seen = (await f.request('/v1/acquisitions', { token: agent.token })).json.acquisitions;
  assert.equal(seen.length, 1); assert.equal(seen[0].id, a.id);
});

test('The same account connected twice does not become two of them', async (t) => {
  const f = await fixture(t), a = await f.credential(), agent = await f.issueKey();
  const flow = await f.start();
  assert.equal((await f.callback(flow, 'personal-readonly')).headers.get('location'), '/?connection=already_connected&adapter=gmail.readonly');
  assert.equal((await f.request('/api/state')).json.acquisitions[0].id, a.id);
  assert.equal((await f.request('/v1/acquisitions', { token: agent.token })).json.acquisitions.length, 1);
});

for (const change of ['agent', 'account']) test('In-flight token withheld after ' + change, async (t) => {
  const f = await fixture(t), a = await f.credential(), runtime = await f.issueKey(); f.expire(a.id);
  let began, finish;
  const started = new Promise((resolve) => { began = resolve; });
  f.gmail.refreshHandler = () => { began(); return new Promise((resolve) => { finish = resolve; }); };
  const pending = f.deliver(a, { token: runtime.token });
  await started;
  if (change === 'agent') await f.request('/api/keys/' + runtime.id, { method: 'DELETE' });
  if (change === 'account') await f.request('/api/acquisitions/' + encodeURIComponent(a.id), { method: 'DELETE', data: { revoke: false } });
  finish();
  const result = await pending;
  assert.ok([401, 403, 404, 409].includes(result.status), result.text);
  assert.doesNotMatch(result.text, /google-access|refresh-personal/);
});

test('Refreshing is coalesced, and an invalid grant asks the owner to connect again', async (t) => {
  const f = await fixture(t), a = await f.credential(), agent = await f.issueKey(); f.expire(a.id);
  let calls = 0, finish;
  f.gmail.refreshHandler = () => { calls++; return new Promise((resolve) => { finish = resolve; }); };
  const one = f.deliver(a, { token: agent.token }), two = f.deliver(a, { token: agent.token });
  while (!finish) await new Promise((resolve) => setTimeout(resolve, 5));
  await new Promise((resolve) => setTimeout(resolve, 20)); finish();
  assert.equal((await one).status, 200); assert.equal((await two).status, 200); assert.equal(calls, 1);
  f.expire(a.id);
  f.gmail.refreshHandler = () => new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'secret-provider-detail' }), { status: 400 });
  const response = await f.deliver(a, { token: agent.token });
  assert.equal(response.status, 409);
  assert.doesNotMatch(response.text, /secret-provider/);
  assert.equal((await f.request('/api/state')).json.acquisitions[0].status, 'reconnect_required');
});

test('Disconnecting preserves saved values even when service revocation fails, and reports the failure', async (t) => {
  const f = await fixture(t), a = await f.credential(), agent = await f.issueKey();
  await f.request('/api/secrets?name=gmail%2Fpersonal-example-test%2Ftoken', { method: 'PUT', raw: 'independent-copy' });
  f.gmail.revokeHandler = () => new Response('{}', { status: 503 });
  const removed = await f.request('/api/acquisitions/' + encodeURIComponent(a.id), { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.status, 200);
  assert.equal(removed.json.service_revoked, false, 'the owner learns the grant is still at Google');
  const state = await f.request('/api/state');
  assert.deepEqual(state.json.acquisitions, []);
  assert.deepEqual(state.json.secrets.map(row => row.name), ['gmail/personal-example-test/token']);
  assert.equal((await f.request('/api/secrets?name=gmail%2Fpersonal-example-test%2Ftoken')).text, 'independent-copy');
  assert.equal((await f.deliver(a, { token: agent.token })).status, 404);
  assert.deepEqual((await f.request('/v1/acquisitions', { token: agent.token })).json.acquisitions, []);
});

test('Where the owners are named, nobody else can make themselves one', async t => {
  const f = await fixture(t, { owners: ['Owner@Example.test'], login: false });
  const refused = await f.request('/api/auth/link', { method: 'POST', data: { email: 'stranger@example.test' } });
  assert.equal(refused.status, 403);
  assert.equal(refused.json.error.code, 'not_invited');
  assert.equal(f.auth.links.size, 0, 'no link is sent to an address that may not be here');
  await f.login();
  assert.equal((await f.request('/api/state')).json.user.email, 'owner@example.test', 'the named owner logs in as before');
});
