import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { fixture, USER_A, GMAIL } from './helpers.mjs';

test('Signin gives a private state behind a safe session cookie', async (t) => {
  const f = await fixture(t);
  assert.equal((await f.request('/v1/overview', { anonymous: true })).status, 401);
  const signin = await f.signin();
  assert.match(signin.headers.get('set-cookie'), /HttpOnly; SameSite=Lax/);
  const result = await f.request('/v1/overview');
  assert.equal(result.json.user.id, USER_A);
  assert.deepEqual(result.json.secrets, []);
  assert.deepEqual(result.json.connections.filter(row => row.service !== null), []);
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.doesNotMatch(result.text, /refresh_token|"secret"|"token"/);
});

test('OAuth uses state, PKCE, offline consent, native Google URL; callback is one-use', async (t) => {
  const f = await fixture(t);
  const url = await f.start();
  assert.equal(url.origin, 'https://accounts.google.com');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('access_type'), 'offline');
  assert.equal(url.searchParams.get('include_granted_scopes'), 'false');
  assert.ok(url.searchParams.get('prompt').includes('consent'));
  assert.equal(url.searchParams.get('redirect_uri'), f.base + '/oauth/callback');
  const complete = await f.callback(url, 'personal', { headers: { 'sec-fetch-site': 'cross-site' } });
  assert.equal(complete.headers.get('location'), '/services?result=connected&service=google');
  assert.equal((await f.callback(url)).headers.get('location'), '/services?result=expired');
  assert.equal(f.google.exchanges, 1);
  assert.equal((await f.request('/v1/overview')).json.connections.filter(row => row.service !== null).length, 1);
});

test('OAuth state is browser-bound and expires; cancel and forged callbacks cannot connect', async (t) => {
  const f = await fixture(t);
  const url = await f.start();
  assert.equal((await f.callback(url, 'personal', { anonymous: true })).headers.get('location'), '/services?result=expired');
  await f.signin('second@example.test');
  assert.equal((await f.callback(url)).headers.get('location'), '/services?result=expired');
  const second = await f.start();
  f.app.store.db.prepare('UPDATE oauth_flows SET expires_at=0').run();
  assert.equal((await f.callback(second)).headers.get('location'), '/services?result=expired');
  const cancel = await f.start();
  const cancelled = await f.request('/oauth/callback?state=' + cancel.searchParams.get('state') + '&error=access_denied&error_description=secret-provider-value');
  assert.equal(cancelled.headers.get('location'), '/services?result=denied&service=google');
  assert.doesNotMatch(cancelled.text, /secret-provider/);
  assert.equal(f.google.exchanges, 0);
});

test('Connections expose explicit connection outputs independently of saved names', async (t) => {
  const f = await fixture(t), a = await f.connection(), b = await f.connection('work', GMAIL.metadata);
  const agent = await f.issueKey();
  assert.notEqual(a.id, b.id);
  assert.equal(a.label, 'personal@example.test');
  assert.equal(b.label, 'work@example.test');
  const saved = await f.request('/v1/resources?kind=secret&name=gmail%2Fpersonal-example-test', { method: 'PUT', raw: 'independent-value' });
  assert.equal(saved.status, 200);
  assert.deepEqual((await f.request('/v1/resources?kind=secret', { token: agent.token })).json.resources.map(row => row.name), ['gmail/personal-example-test']);
  assert.deepEqual((await f.request('/v1/resources?kind=connection', { token: agent.token })).json.resources.map(row => row.auth_scheme), ['oauth', 'oauth'], 'managed authorizations are listed independently of secrets');
  const connections = await f.request('/v1/resources?kind=connection', { token: agent.token });
  assert.deepEqual(connections.json.resources.map(item => item.id), [a.id, b.id]);
  assert.deepEqual(connections.json.resources[0].service, { id: 'google', name: 'Google', catalog: true });
  assert.doesNotMatch(connections.text, /refresh_token|google-access-|"state":/);

  const result = await f.inject(a, { token: agent.token });
  assert.equal(result.status, 200, result.text);
  assert.equal(result.json.injection.environment.GOOGLE_OAUTH_ACCESS_TOKEN, 'google-access-personal');
  assert.equal(result.json.injection.environment.GOOGLE_ACCOUNT_EMAIL, 'personal@example.test');
  assert.ok(result.json.expires_in > 3500);
  assert.doesNotMatch(result.text, /refresh_token/);
  assert.equal((await f.inject(b, { token: agent.token })).json.injection.environment.GOOGLE_OAUTH_ACCESS_TOKEN, 'google-access-work');

  // Connection processing leaves existing saved values unchanged.
  assert.equal((await f.read('secret', 'gmail/personal-example-test')).text, 'independent-value');
  assert.ok(!f.google.calls.some((call) => call.url.includes('/messages')));
});

test('Owners cannot see, disconnect or reach each other\'s connections', async (t) => {
  const f = await fixture(t), first = await f.connection(), runtime = await f.issueKey();
  await f.signin('second@example.test');
  const state = await f.request('/v1/overview');
  assert.deepEqual(state.json.connections.filter(row => row.service !== null), []);
  assert.deepEqual(state.json.secrets, []);
  assert.deepEqual(state.json.agents.map(item => item.name), ['Foundation']);
  assert.equal((await f.request('/v1/resources/' + encodeURIComponent(first.id), { method: 'DELETE', data: { revoke: true } })).status, 403);
  const intruder = await f.issueKey('intruder');
  assert.deepEqual((await f.request('/v1/resources?kind=connection', { token: intruder.token })).json.resources, []);
  assert.equal((await f.inject(first, { token: intruder.token })).status, 404);
  await f.request('/v1/principals/' + runtime.id, { method: 'DELETE', data: {} });
  assert.equal((await f.request('/v1/resources?kind=connection', { token: runtime.token })).json.resources.length, 1, 'the owner keeps it when one key is revoked');
  const second = await f.connection();
  assert.notEqual(second.id, first.id);
  assert.equal((await f.request('/v1/overview')).json.connections.filter(row => row.service !== null).length, 1);
});

test('Connecting again pins the Google account', async (t) => {
  const f = await fixture(t), a = await f.connection('personal', GMAIL.metadata), agent = await f.issueKey();
  let flow = await f.start({ scopes: GMAIL.metadata, connection_id: a.id });
  assert.equal(flow.searchParams.get('login_hint'), 'personal@example.test');
  assert.equal((await f.callback(flow, 'work')).headers.get('location'), '/services?result=wrong_account&service=google');
  assert.equal((await f.request('/v1/resources?kind=connection', { token: agent.token })).json.resources.length, 1);
  flow = await f.start({ scopes: GMAIL.metadata, connection_id: a.id });
  assert.equal((await f.callback(flow, 'personal')).headers.get('location'), '/services?result=connected&service=google');
  const seen = (await f.request('/v1/resources?kind=connection', { token: agent.token })).json.resources;
  assert.equal(seen.length, 1); assert.equal(seen[0].id, a.id);
});

test('同じGmailユーザーの新たな認可を別の接続として保存する', async (t) => {
  const f = await fixture(t), a = await f.connection(), agent = await f.issueKey();
  const flow = await f.start();
  assert.equal((await f.callback(flow, 'personal')).headers.get('location'), '/services?result=connected&service=google');
  assert.equal((await f.request('/v1/overview')).json.connections.filter(row => row.service !== null)[0].id, a.id);
  const connections = (await f.request('/v1/resources?kind=connection', { token: agent.token })).json.resources;
  assert.equal(connections.length, 2);
  assert.equal(new Set(connections.map(item => item.id)).size, 2);
});

for (const change of ['agent', 'account']) test('In-flight token withheld after ' + change, async (t) => {
  const f = await fixture(t), a = await f.connection(), runtime = await f.issueKey(); f.expire(a.id);
  let began, finish;
  const started = new Promise((resolve) => { began = resolve; });
  f.google.refreshHandler = () => { began(); return new Promise((resolve) => { finish = resolve; }); };
  const pending = f.inject(a, { token: runtime.token });
  await started;
  if (change === 'agent') await f.request('/v1/principals/' + runtime.id, { method: 'DELETE', data: {} });
  if (change === 'account') await f.request('/v1/resources/' + encodeURIComponent(a.id), { method: 'DELETE', data: { revoke: false } });
  finish();
  const result = await pending;
  assert.ok([401, 403, 404, 409].includes(result.status), result.text);
  assert.doesNotMatch(result.text, /google-access|refresh-personal/);
});

test('Refreshing is coalesced, and an invalid grant asks the owner to connect again', async (t) => {
  const f = await fixture(t), a = await f.connection(), agent = await f.issueKey(); f.expire(a.id);
  let calls = 0, finish;
  f.google.refreshHandler = () => { calls++; return new Promise((resolve) => { finish = resolve; }); };
  const one = f.inject(a, { token: agent.token }), two = f.inject(a, { token: agent.token });
  while (!finish) await new Promise((resolve) => setTimeout(resolve, 5));
  await new Promise((resolve) => setTimeout(resolve, 20)); finish();
  assert.equal((await one).status, 200); assert.equal((await two).status, 200); assert.equal(calls, 1);
  f.expire(a.id);
  f.google.refreshHandler = () => new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'secret-provider-detail' }), { status: 400 });
  const response = await f.inject(a, { token: agent.token });
  assert.equal(response.status, 409);
  assert.doesNotMatch(response.text, /secret-provider/);
  assert.equal((await f.request('/v1/overview')).json.connections.filter(row => row.service !== null)[0].status, 'reconnect_required');
});

test('Disconnecting preserves saved values even when service revocation fails, and reports the failure', async (t) => {
  const f = await fixture(t), a = await f.connection(), agent = await f.issueKey();
  await f.request('/v1/resources?kind=secret&name=gmail%2Fpersonal-example-test%2Ftoken', { method: 'PUT', raw: 'independent-copy' });
  f.google.revokeHandler = () => new Response('{}', { status: 503 });
  const removed = await f.request('/v1/resources/' + encodeURIComponent(a.id), { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.status, 200);
  assert.equal(removed.json.service_revoked, false, 'the owner learns the grant is still at Google');
  const state = await f.request('/v1/overview');
  assert.deepEqual(state.json.connections.filter(row => row.service !== null), []);
  assert.deepEqual(state.json.secrets.map(row => row.name), ['gmail/personal-example-test/token']);
  assert.equal((await f.read('secret', 'gmail/personal-example-test/token')).text, 'independent-copy');
  assert.equal((await f.inject(a, { token: agent.token })).status, 404);
  assert.deepEqual((await f.request('/v1/resources?kind=connection', { token: agent.token })).json.resources, []);
});

