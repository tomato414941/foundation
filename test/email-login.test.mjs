import test from 'node:test';
import assert from 'node:assert/strict';
import { EmailLogins, LOGIN_TTL } from '../src/email-login.mjs';
import { fixture, USER_B } from './helpers.mjs';

const challengeCookie = response => response.headers.getSetCookie().find(value => value.startsWith('fdn_login=')).split(';')[0];
const sessionCookie = response => response.headers.getSetCookie().find(value => value.startsWith('fdn_session=')).split(';')[0];
const send = (f, email = 'new@example.test', cookie) => f.request('/v1/login', { method: 'POST', data: { email }, headers: cookie ? { cookie } : {} });
const callback = (f, cookie, code = f.auth.links.get('new@example.test')?.code) => f.request('/login/callback?code=' + encodeURIComponent(code || ''), { headers: { ...(cookie ? { cookie } : {}), 'sec-fetch-site': 'cross-site' } });
const location = response => response.headers.get('location');

test('Browser challenges hide PKCE state and expire without retaining authentication data', () => {
  let now = 1000;
  const logins = new EmailLogins({ now: () => now });
  const { token, row } = logins.reserve('new@example.test');
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(logins.pending.has(token), false);
  assert.equal(logins.summary(token), null);
  row.storage.set('code-verifier', 'test-secret');
  logins.sent(token);
  assert.deepEqual(logins.summary(token), { email: row.email, expires_at: now + LOGIN_TTL, resend_at: now + 60_000 });
  assert.doesNotMatch(JSON.stringify(logins.summary(token)), /test-secret|verifier|storage/);
  assert.throws(() => logins.reserve(row.email), { status: 429, code: 'link_cooldown' });
  now += LOGIN_TTL;
  assert.equal(logins.summary(token), null);
  assert.equal(logins.consume(token, row), false);
  logins.sweep();
  assert.equal(logins.pending.size, 0);
  assert.equal(logins.cooldowns.size, 0);
});

test('Challenges serialize verification, limit attempts and cannot be consumed twice', () => {
  const logins = new EmailLogins();
  const { token } = logins.reserve('new@example.test');
  logins.sent(token);
  for (let attempt = 1; attempt <= 5; attempt++) {
    const row = logins.begin(token);
    assert.equal(row.attempts, attempt);
    assert.throws(() => logins.begin(token), { status: 409 });
    logins.release(token, row);
  }
  assert.throws(() => logins.begin(token), { status: 401, code: 'login_expired' });
  const second = logins.reserve('second@example.test');
  logins.sent(second.token);
  const row = logins.begin(second.token);
  assert.equal(logins.consume(second.token, row), true);
  assert.equal(logins.consume(second.token, row), false);
});

test('Pending challenge and cooldown storage is bounded and swept', () => {
  let now = 0;
  const logins = new EmailLogins({ now: () => now });
  for (let i = 0; i < 1000; i++) logins.reserve(`user-${i}@example.test`);
  assert.throws(() => logins.reserve('overflow@example.test'), { status: 429 });
  now = LOGIN_TTL;
  logins.reserve('later@example.test');
  assert.equal(logins.pending.size, 1);
  assert.equal(logins.cooldowns.size, 1);
});

test('Default email-link signup/login uses secure HttpOnly cookies and a fixed callback', async (t) => {
  const f = await fixture(t, { login: false, publicOrigin: 'https://foundation.example.test' });
  const sent = await send(f, ' New@Example.Test ');
  assert.equal(sent.status, 202, sent.text);
  assert.match(sent.headers.get('set-cookie'), /HttpOnly; SameSite=Lax; Path=\/; Max-Age=3600; Secure/);
  assert.equal(sent.json.pending.email, 'new@example.test');
  assert.doesNotMatch(sent.text, /verifier|access_token|refresh_token/);
  const cookie = challengeCookie(sent), link = f.auth.links.get('new@example.test');
  assert.equal(new URL(link.url).origin, 'https://foundation.example.test');
  assert.equal(new URL(link.url).pathname, '/login/callback');
  const config = await f.request('/v1/login', { headers: { cookie } });
  assert.equal(config.json.method, 'email_link');
  assert.equal('code_length' in config.json, false);
  assert.deepEqual(config.json.pending, sent.json.pending);
  assert.equal((await f.request('/v1/login')).json.pending, null);
  assert.equal(location(await callback(f, undefined, link.code)), '/?login=expired');
  const result = await callback(f, cookie, link.code);
  assert.equal(result.status, 303);
  assert.equal(location(result), '/');
  assert.doesNotMatch(result.text, /access_token|refresh_token|verifier/);
  assert.match(result.headers.get('referrer-policy'), /no-referrer/);
  assert.match(result.headers.getSetCookie().find(value => value.startsWith('fdn_login=')), /Max-Age=0/);
  const state = await f.request('/v1/state', { headers: { cookie: sessionCookie(result) } });
  assert.equal(state.status, 200);
  assert.equal(state.json.user.id, USER_B);
  assert.equal(state.json.user.email, 'new@example.test');
  assert.equal(location(await callback(f, cookie, link.code)), '/?login=expired');
});

test('Password/code login and malformed or ambiguous callback URLs cannot authenticate', async (t) => {
  const f = await fixture(t, { login: false });
  const cookie = challengeCookie(await send(f));
  for (const data of [{ code: '123456' }, { email: 'new@example.test', password: 'obsolete' }, { access_token: 'forged', refresh_token: 'forged' }]) {
    assert.equal((await f.request('/v1/session', { method: 'POST', data, headers: { cookie } })).status, 401);
  }
  for (const suffix of ['', '?code=123456', '?error=access_denied&error_description=secret-value', '?code=valid-looking-code-000&code=duplicate']) {
    const result = await f.request('/login/callback' + suffix, { headers: { cookie } });
    assert.equal(location(result), '/?login=invalid');
    assert.doesNotMatch(result.text, /secret-value/);
  }
  assert.equal(location(await callback(f, cookie)), '/');
});

test('Resending has a cooldown and invalidates the previous browser challenge', async (t) => {
  let now = Date.now();
  const f = await fixture(t, { login: false, loginClock: () => now });
  const oldCookie = challengeCookie(await send(f)), oldCode = f.auth.links.get('new@example.test').code;
  assert.equal((await send(f, 'new@example.test', oldCookie)).status, 429);
  now += 60_001;
  const sent = await send(f, 'new@example.test', oldCookie);
  assert.equal(sent.status, 202, sent.text);
  const newCookie = challengeCookie(sent);
  assert.notEqual(newCookie, oldCookie);
  assert.equal(location(await callback(f, oldCookie, oldCode)), '/?login=expired');
  assert.equal(location(await callback(f, newCookie, oldCode)), '/?login=invalid');
  assert.equal(location(await callback(f, newCookie)), '/');
});

test('A link opened in the wrong browser cannot exchange another login challenge', async (t) => {
  const f = await fixture(t, { login: false });
  const first = challengeCookie(await send(f)), firstCode = f.auth.links.get('new@example.test').code;
  const second = challengeCookie(await send(f, 'second@example.test'));
  assert.equal(location(await callback(f, second, firstCode)), '/?login=invalid');
  assert.equal(location(await callback(f, first, firstCode)), '/');
});

test('Five failed exchanges expire the challenge before further provider verification', async (t) => {
  const f = await fixture(t, { login: false });
  let calls = 0;
  f.auth.verifyHandler = async () => { calls++; };
  const cookie = challengeCookie(await send(f));
  for (let i = 0; i < 5; i++) assert.equal(location(await callback(f, cookie, 'invalid-authorization-code')), '/?login=invalid');
  assert.equal(location(await callback(f, cookie)), '/?login=expired');
  assert.equal(calls, 5);
});

test('Expired and cancelled challenges cannot create sessions', async (t) => {
  let now = Date.now();
  const f = await fixture(t, { login: false, loginClock: () => now });
  const expired = challengeCookie(await send(f));
  now += LOGIN_TTL;
  assert.equal(location(await callback(f, expired)), '/?login=expired');
  const cancelled = challengeCookie(await send(f));
  const result = await f.request('/v1/login', { method: 'DELETE', headers: { cookie: cancelled } });
  assert.equal(result.status, 200);
  assert.match(result.headers.get('set-cookie'), /fdn_login=;.*Max-Age=0/);
  assert.equal(location(await callback(f, cancelled)), '/?login=expired');
});

test('Cross-origin send/cancellation are denied while the provider callback is accepted', async (t) => {
  const f = await fixture(t, { login: false });
  const denied = await f.request('/v1/login', { method: 'POST', data: { email: 'new@example.test' }, headers: { origin: 'https://evil.example' } });
  assert.equal(denied.status, 403);
  assert.equal(f.auth.links.size, 0);
  const cookie = challengeCookie(await send(f));
  assert.equal((await f.request('/v1/login', { method: 'DELETE', headers: { cookie, origin: 'https://evil.example' } })).status, 403);
  assert.equal(location(await callback(f, cookie)), '/');
});

test('Failed delivery is not claimed as sent and leaves an existing challenge intact', async (t) => {
  const f = await fixture(t, { login: false });
  const cookie = challengeCookie(await send(f));
  f.auth.sendHandler = async () => { throw new Error('secret-provider-credential'); };
  const failed = await send(f, 'second@example.test', cookie);
  assert.equal(failed.status, 500);
  assert.equal(failed.headers.get('set-cookie'), null);
  assert.doesNotMatch(failed.text, /secret-provider-credential|second@example/);
  assert.equal(location(await callback(f, cookie)), '/');
});

for (const action of ['cancel', 'resend', 'logout', 'expire']) test(`In-flight verification cannot restore a login after ${action}`, async (t) => {
  let now = Date.now(), began, finish, revoked = 0;
  const f = await fixture(t, { login: false, loginClock: () => now });
  const cookie = challengeCookie(await send(f)), code = f.auth.links.get('new@example.test').code;
  const started = new Promise(resolve => { began = resolve; });
  f.auth.verifyHandler = async () => { began(); await new Promise(resolve => { finish = resolve; }); };
  f.auth.logout = async () => { revoked++; };
  const pending = callback(f, cookie, code);
  await started;
  assert.equal(location(await callback(f, cookie, code)), '/?login=busy');
  if (action === 'cancel') await f.request('/v1/login', { method: 'DELETE', headers: { cookie } });
  if (action === 'logout') await f.request('/v1/session', { method: 'DELETE', headers: { cookie } });
  if (action === 'resend') { now += 60_001; assert.equal((await send(f, 'new@example.test', cookie)).status, 202); }
  if (action === 'expire') now += LOGIN_TTL;
  finish();
  const result = await pending;
  assert.equal(location(result), '/?login=expired');
  assert.equal(result.headers.get('set-cookie'), null);
  assert.equal(revoked, 1);
  assert.equal((await f.request('/v1/state')).status, 401);
});

test('A provider response for a different email cannot authenticate the browser', async (t) => {
  const f = await fixture(t, { login: false });
  const cookie = challengeCookie(await send(f));
  f.auth.exchangeLink = async () => f.auth.value('someone-else@example.test');
  let revoked = 0;
  f.auth.logout = async () => { revoked++; };
  assert.equal(location(await callback(f, cookie)), '/?login=expired');
  assert.equal(revoked, 1);
});
