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
  assert.deepEqual(result.json.credentials, []);
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
  assert.equal((await f.request('/api/state')).json.credentials.length, 1);
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

test('Multiple accounts carry who registered them, actual scopes and native API discovery, and an approved key reaches all of them', async (t) => {
  const f = await fixture(t), a = await f.credential(), b = await f.credential('work', 'metadata');
  const agent = await f.agent();
  const list = await f.request('/v1/credentials', { token: agent.token });
  assert.deepEqual(list.json.credentials.map(item => item.id), [a.id, b.id]);
  assert.equal(list.json.credentials[0].requested_by, '', 'registered from the dashboard, through no request');
  assert.equal(list.json.credentials[0].api.base_url, 'https://gmail.googleapis.com/gmail/v1');
  assert.equal(list.json.credentials[0].delivery.method, 'POST');
  assert.doesNotMatch(list.text, /refresh_token|google-access-|"secret":/);
  const result = await f.request('/v1/credentials/' + a.id + '/deliver', { method: 'POST', data: {}, token: agent.token });
  assert.equal(result.status, 200);
  assert.equal(result.json.delivery.environment.GOOGLE_OAUTH_ACCESS_TOKEN, 'google-access-personal-readonly');
  assert.equal(result.json.credential.id, a.id);
  assert.ok(result.json.expires_in > 3500);
  assert.doesNotMatch(result.text, /refresh_token/);
  assert.equal((await f.request('/v1/credentials/' + b.id + '/deliver', { method: 'POST', data: {}, token: agent.token })).json.delivery.environment.GOOGLE_OAUTH_ACCESS_TOKEN, 'google-access-work-metadata');
  assert.equal((await f.request('/v1/credentials/' + a.id + '/deliver', { token: agent.token })).status, 404);
  assert.equal((await f.request('/v1/credentials/' + a.id + '/messages', { token: agent.token })).status, 404);
  assert.equal((await f.request('/api/credentials/' + a.id + '/messages')).status, 404);
  assert.ok(!f.gmail.calls.some((call) => call.url.includes('/messages')));
});

test('Supabase users cannot see, edit, disconnect or reach each other\'s connections', async (t) => {
  const f = await fixture(t), first = await f.credential(), runtime = await f.agent();
  await f.login('second@example.test');
  const state = await f.request('/api/state');
  assert.deepEqual(state.json.credentials, []);
  assert.deepEqual(state.json.agents, []);
  for (const [method, data] of [['PATCH', { name: 'takeover' }], ['DELETE', { revoke: true }]]) assert.equal((await f.request('/api/credentials/' + first.id, { method, data })).status, 404);
  const intruder = (await f.request('/api/agents', { method: 'POST', data: { name: 'intruder' } })).json.agent;
  assert.deepEqual((await f.request('/v1/credentials', { token: intruder.token })).json.credentials, []);
  assert.equal((await f.request('/v1/credentials/' + first.id + '/deliver', { method: 'POST', data: {}, token: intruder.token })).status, 403);
  await f.request('/api/agents/' + runtime.id, { method: 'DELETE' });
  assert.equal((await f.request('/v1/credentials', { token: runtime.token })).json.credentials.length, 1);
  const second = await f.credential();
  assert.notEqual(first.id, second.id);
  assert.equal((await f.request('/api/state')).json.credentials.length, 1);
});

test('Registering again pins the Google account and stays within the same adapter', async (t) => {
  const f = await fixture(t), a = await f.credential('personal', 'metadata'), agent = await f.agent();
  assert.equal((await f.request('/api/adapters/gmail.readonly/connect', { method: 'POST', data: { credentialId: a.id } })).json.error.code, 'invalid_adapter');
  let flow = await f.start({ range: 'metadata', credentialId: a.id });
  assert.equal(flow.searchParams.get('login_hint'), 'personal@example.test');
  assert.equal((await f.callback(flow, 'work-metadata')).headers.get('location'), '/?connection=wrong_account&adapter=gmail.metadata');
  assert.equal((await f.request('/v1/credentials', { token: agent.token })).json.credentials.length, 1);
  flow = await f.start({ range: 'metadata', credentialId: a.id });
  assert.equal((await f.callback(flow, 'personal-metadata')).headers.get('location'), '/?connection=connected&adapter=gmail.metadata');
  const seen = (await f.request('/v1/credentials', { token: agent.token })).json.credentials;
  assert.equal(seen.length, 1); assert.equal(seen[0].id, a.id);
});

test('Duplicate connection cannot overwrite identity, name or existing grants', async (t) => {
  const f = await fixture(t), a = await f.credential(), agent = await f.agent();
  const flow = await f.start({ name: 'replacement' });
  assert.equal((await f.callback(flow, 'personal-readonly')).headers.get('location'), '/?connection=already_connected&adapter=gmail.readonly');
  assert.equal((await f.request('/api/state')).json.credentials[0].name, 'personal');
  assert.equal((await f.request('/v1/credentials', { token: agent.token })).json.credentials.length, 1);
});

for (const change of ['agent', 'account']) test('In-flight token withheld after ' + change, async (t) => {
  const f = await fixture(t), a = await f.credential(), runtime = await f.agent(); f.expire(a.id);
  let began, finish;
  const started = new Promise((resolve) => { began = resolve; });
  f.gmail.refreshHandler = () => { began(); return new Promise((resolve) => { finish = resolve; }); };
  const pending = f.request('/v1/credentials/' + a.id + '/deliver', { method: 'POST', data: {}, token: runtime.token });
  await started;
  if (change === 'agent') await f.request('/api/agents/' + runtime.id, { method: 'DELETE' });
  if (change === 'account') await f.request('/api/credentials/' + a.id, { method: 'DELETE', data: { revoke: false } });
  finish();
  const result = await pending;
  assert.ok([401, 403, 404, 409].includes(result.status), result.text);
  assert.doesNotMatch(result.text, /google-access|refresh-personal/);
});

test('Token refresh is coalesced and invalid grants become reconnect_required', async (t) => {
  const f = await fixture(t), a = await f.credential(), agent = await f.agent(); f.expire(a.id);
  let calls = 0, finish;
  f.gmail.refreshHandler = () => { calls++; return new Promise((resolve) => { finish = resolve; }); };
  const path = '/v1/credentials/' + a.id + '/deliver', opts = { method: 'POST', data: {}, token: agent.token };
  const one = f.request(path, opts), two = f.request(path, opts);
  while (!finish) await new Promise((resolve) => setTimeout(resolve, 5));
  await new Promise((resolve) => setTimeout(resolve, 20)); finish();
  assert.equal((await one).status, 200); assert.equal((await two).status, 200); assert.equal(calls, 1);
  f.expire(a.id);
  f.gmail.refreshHandler = () => new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'secret-provider-detail' }), { status: 400 });
  const response = await f.request(path, opts);
  assert.equal(response.status, 409);
  assert.doesNotMatch(response.text, /secret-provider/);
  assert.equal((await f.request('/api/state')).json.credentials[0].status, 'reconnect_required');
});

test('Disconnect failure stops issuance, keeps retryable secret, and allows explicit local-only removal', async (t) => {
  const f = await fixture(t), a = await f.credential(), agent = await f.agent();
  f.gmail.revokeHandler = () => new Response('{}', { status: 503 });
  const path = '/api/credentials/' + a.id;
  assert.equal((await f.request(path, { method: 'DELETE', data: { revoke: true } })).status, 502);
  assert.equal((await f.request('/api/state')).json.credentials[0].status, 'disconnecting');
  assert.equal((await f.request('/v1/credentials', { token: agent.token })).json.credentials.length, 0);
  assert.equal((await f.request(path, { method: 'DELETE', data: { revoke: false } })).status, 200);
  assert.equal((await f.request('/api/state')).json.credentials.length, 0);
});

test('Cross-origin, cross-site, rebinding, invalid input and unexpected paths are denied', async (t) => {
  const f = await fixture(t);
  assert.equal((await f.request('/api/session', { method: 'POST', data: { code: 'obsolete' }, headers: { origin: 'https://evil.test' } })).status, 403);
  assert.equal((await f.request('/api/state', { headers: { 'sec-fetch-site': 'cross-site' } })).status, 403);
  assert.equal((await f.request('/api/adapters/gmail.readonly/connect', { method: 'POST', data: {}, headers: { 'content-type': 'text/plain' } })).status, 415);
  assert.equal((await f.request('/api/adapters/gmail.readonly/connect', { method: 'POST', data: { name: 'x'.repeat(15000) } })).status, 413);
  const status = await new Promise((resolve, reject) => {
    const request = httpRequest(f.base + '/api/state', { headers: { host: 'evil.test' } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    request.on('error', reject); request.end();
  });
  assert.equal(status, 403);
});

test('Logout deletes local session even on upstream failure; Supabase revocation blocks access', async (t) => {
  const f = await fixture(t);
  f.auth.logout = () => { throw new Error('upstream token secret'); };
  assert.equal((await f.request('/api/session', { method: 'DELETE' })).json.authLogout, false);
  assert.equal((await f.request('/api/state')).status, 401);
  await f.login();
  f.auth.revoked = true;
  assert.equal((await f.request('/api/state')).status, 401);
});

test('Session refresh cannot resurrect a logged-out session', async (t) => {
  const f = await fixture(t);
  const session = f.app.store.session(f.cookie().slice(12));
  f.app.store.updateSession(session.id, { ...session.value, expires_at: 0 });
  let finish, began;
  const started = new Promise((resolve) => { began = resolve; });
  f.auth.refreshHandler = () => { began(); return new Promise((resolve) => { finish = resolve; }); };
  const pending = f.request('/api/state'); await started;
  await f.request('/api/session', { method: 'DELETE' }); finish();
  assert.equal((await pending).status, 401);
  assert.equal(f.app.store.db.prepare('SELECT count(*) n FROM sessions').get().n, 0);
});

test('Secure cookies are based on configured origin, including callbacks without Origin header', async (t) => {
  const f = await fixture(t, { publicOrigin: 'https://foundation.example.test:8443' });
  const login = await f.login();
  assert.match(login.headers.get('set-cookie'), /; Secure/);
  const url = await f.start();
  assert.equal(url.searchParams.get('redirect_uri'), 'https://foundation.example.test:8443/oauth/gmail.readonly/callback');
});

test('Login attempts are bounded; provider error text is never exposed', async (t) => {
  const f = await fixture(t);
  let result;
  for (let i = 0; i < 31; i++) result = await f.request('/auth/callback?code=invalid-authorization-code');
  assert.equal(result.headers.get('location'), '/?login=limited');
  f.gmail.exchangeHandler = () => { throw new Error('secret-token'); };
  assert.equal((await f.callback(await f.start())).headers.get('location'), '/?connection=failed&adapter=gmail.readonly');
});

test('Behind a named proxy the client address comes from X-Forwarded-For; an unnamed proxy cannot spoof it; HSTS only on the public origin', async t => {
  const { fixture } = await import('./helpers.mjs');
  const { randomBytes } = await import('node:crypto');
  const create = (f, forwarded) => f.request('/v1/access-requests', { method: 'POST', anonymous: true, token: 'fdn_' + randomBytes(32).toString('base64url'), headers: forwarded ? { 'x-forwarded-for': forwarded } : {}, data: { name: 'x' } });
  const trusting = await fixture(t, { login: false, trustedProxies: ['127.0.0.1', '::ffff:127.0.0.1', '::1'] });
  for (let i = 0; i < 12; i++) assert.equal((await create(trusting, '203.0.113.10, 10.0.0.2')).status, 201);
  assert.equal((await create(trusting, '203.0.113.10, 10.0.0.2')).status, 429, 'the last hop is the client');
  assert.equal((await create(trusting, '203.0.113.10, 10.0.0.3')).status, 201, 'another client is not affected');
  const plain = await fixture(t, { login: false });
  for (let i = 0; i < 12; i++) assert.equal((await create(plain, '10.0.0.' + i)).status, 201);
  assert.equal((await create(plain, '10.0.0.99')).status, 429, 'without a trusted proxy the header is ignored');
  assert.equal((await plain.request('/health', { anonymous: true })).headers.get('strict-transport-security'), null);
  const external = await fixture(t, { login: false, publicOrigin: 'https://foundation.example.test' });
  assert.equal((await external.request('/health', { anonymous: true, headers: { host: 'foundation.example.test' } })).headers.get('strict-transport-security'), 'max-age=31536000; includeSubDomains');
});
