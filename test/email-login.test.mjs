import test from 'node:test';
import assert from 'node:assert/strict';
import { EmailLogins, LOGIN_TTL } from '../src/email-login.mjs';
import { fail } from '../src/errors.mjs';
import { fixture, FakeAuth, USER_A, USER_B } from './helpers.mjs';

const deliveryCookie = response => response.headers.getSetCookie().find(value => value.startsWith('fdn_login=')).split(';')[0];
const sessionCookie = response => response.headers.getSetCookie().find(value => value.startsWith('fdn_session=')).split(';')[0];
const send = (f, email = 'new@example.test', cookie, return_to) => f.request('/v1/login', { method: 'POST', data: { email, return_to }, headers: cookie ? { cookie } : {} });
const verify = (f, link = f.auth.links.get('new@example.test'), options = {}) => f.request('/v1/login/verify', {
  method: 'POST', data: { email: link.email, token_hash: link.code }, ...options,
});

test('送信したメールと再送可能時刻を返し、期限後に送信状況を破棄する', () => {
  let now = 1000;
  const logins = new EmailLogins({ now: () => now });
  const { token, row } = logins.reserve('new@example.test');
  assert.equal(logins.summary(token), null);
  logins.sent(token);
  assert.deepEqual(logins.summary(token), { email: row.email, expires_at: now + LOGIN_TTL, resend_at: now + 60_000 });
  assert.throws(() => logins.reserve(row.email), { status: 429, code: 'link_cooldown' });
  now += LOGIN_TTL;
  assert.equal(logins.summary(token), null);
  assert.ok(logins.reserve(row.email).token);
});

test('大量の送信要求を制限し、期限後に受け付けを再開する', () => {
  let now = 0;
  const logins = new EmailLogins({ now: () => now });
  for (let i = 0; i < 1000; i++) logins.reserve('user-' + i + '@example.test');
  assert.throws(() => logins.reserve('overflow@example.test'), { status: 429 });
  now = LOGIN_TTL;
  assert.ok(logins.reserve('later@example.test').token);
});

test('送信元のCookieを持たない利用環境でメールの鍵を検証しログインする', async t => {
  const f = await fixture(t, { login: false, publicOrigin: 'https://foundation.example.test' });
  const sent = await send(f, ' New@Example.Test ');
  assert.equal(sent.status, 202, sent.text);
  assert.equal(sent.json.pending.email, 'new@example.test');
  const cookie = deliveryCookie(sent), link = f.auth.links.get('new@example.test');
  const url = new URL(link.url);
  assert.equal(url.origin, 'https://foundation.example.test');
  assert.equal(url.pathname, '/login/confirm');
  assert.equal(new URLSearchParams(url.hash.slice(1)).get('token_hash'), link.code);
  assert.deepEqual((await f.request('/v1/login', { headers: { cookie } })).json.pending, sent.json.pending);
  const result = await verify(f);
  assert.equal(result.status, 200, result.text);
  assert.deepEqual(result.json, { ok: true, return_to: '/' });
  assert.match(result.headers.getSetCookie().find(value => value.startsWith('fdn_session=')), /HttpOnly; SameSite=Lax; Path=\/; Max-Age=1209600; Secure/);
  assert.equal(result.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(result.headers.get('cache-control'), 'no-store');
  const state = await f.request('/v1/overview', { headers: { cookie: sessionCookie(result) } });
  assert.equal(state.status, 200);
  assert.equal(state.json.user.id, USER_B);
  assert.equal(state.json.user.email, 'new@example.test');
  assert.equal((await f.request('/v1/overview', { headers: { cookie } })).status, 401);
});

test('メールの先読みには確認画面だけを返し、ボタンからの検証を待つ', async t => {
  const f = await fixture(t, { login: false });
  await send(f);
  for (let i = 0; i < 3; i++) {
    const page = await f.request('/login/confirm', { headers: { 'sec-fetch-site': 'cross-site' } });
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type'), /^text\/html/);
    assert.equal(page.headers.get('cache-control'), 'no-store');
    assert.equal((await f.request('/v1/overview')).status, 401);
  }
  assert.equal((await verify(f)).status, 200);
});

test('サーバーを再起動してもメールで受け取った有効な鍵を検証する', async t => {
  const auth = new FakeAuth();
  const first = await fixture(t, { login: false, auth });
  await send(first);
  await first.close();
  const next = await fixture(t, { login: false, auth });
  assert.equal((await verify(next)).status, 200);
});

test('別のアドレスへの送信状況よりも、確認したリンクの本人情報を採用する', async t => {
  const f = await fixture(t, { login: false });
  await send(f);
  const cookie = deliveryCookie(await send(f, 'second@example.test'));
  const result = await verify(f, undefined, { headers: { cookie } });
  const state = await f.request('/v1/overview', { headers: { cookie: sessionCookie(result) } });
  assert.equal(state.json.user.email, 'new@example.test');
});

test('同じ鍵の再利用と期限を過ぎた鍵を拒否する', async t => {
  const f = await fixture(t, { login: false });
  await send(f);
  const link = f.auth.links.get('new@example.test');
  assert.equal((await verify(f, link)).status, 200);
  assert.equal((await verify(f, link)).status, 401);
  await send(f, 'expired@example.test');
  const expired = f.auth.links.get('expired@example.test');
  f.auth.now = () => expired.expires_at;
  assert.equal((await verify(f, expired)).status, 401);
});

test('確認画面のメールアドレスと認証結果が異なる場合は既存アカウントを維持する', async t => {
  const f = await fixture(t);
  await send(f, 'attacker@example.test');
  let revoked = 0;
  f.auth.logout = async () => { revoked++; };
  const result = await verify(f, { ...f.auth.links.get('attacker@example.test'), email: 'owner@example.test' });
  assert.equal(result.status, 401);
  assert.equal(result.json.error.code, 'invalid_link');
  assert.equal(revoked, 1);
  assert.equal((await f.request('/v1/overview')).json.user.id, USER_A);
});

test('利用が許可されたメールアドレスだけでログインする', async t => {
  const f = await fixture(t, { login: false, owners: ['new@example.test'] });
  assert.equal((await send(f, 'other@example.test')).status, 403);
  await f.auth.sendLink('other@example.test', f.base + '/login/confirm');
  assert.equal((await verify(f, f.auth.links.get('other@example.test'))).status, 403);
  const spoofed = await verify(f, { ...f.auth.links.get('other@example.test'), email: 'new@example.test' });
  assert.equal(spoofed.status, 401);
  await send(f);
  assert.equal((await verify(f)).status, 200);
});

test('外部サイトからの送信・検証・送信画面の変更を拒否する', async t => {
  const f = await fixture(t, { login: false });
  const data = { email: 'new@example.test' };
  assert.equal((await f.request('/v1/login', { method: 'POST', data, headers: { origin: 'https://evil.example' } })).status, 403);
  const cookie = deliveryCookie(await send(f));
  const link = f.auth.links.get('new@example.test');
  for (const origin of ['https://evil.example', 'null', '']) {
    assert.equal((await verify(f, link, { headers: { cookie, origin } })).status, 403);
  }
  assert.equal((await verify(f, link, { headers: { authorization: 'Bearer ignored', origin: 'https://evil.example' } })).status, 403);
  assert.equal((await f.request('/v1/login', { method: 'DELETE', headers: { cookie, origin: 'https://evil.example' } })).status, 403);
  assert.equal((await verify(f, link)).status, 200);
});

test('不正な入力と外部への戻り先を拒否し、許可されたページへ戻す', async t => {
  const f = await fixture(t, { login: false });
  await send(f, 'new@example.test', undefined, '/grants');
  const link = f.auth.links.get('new@example.test');
  assert.equal(new URL(link.url).searchParams.get('return_to'), '/grants');
  for (const changes of [{ email: '' }, { email: 'not-an-email' }, { token_hash: 'short' }, { token_hash: ['ambiguous'] }, { return_to: 'https://evil.example' }, { return_to: '//evil.example' }, { return_to: '/login/confirm' }]) {
    const result = await f.request('/v1/login/verify', { method: 'POST', data: { email: link.email, token_hash: link.code, ...changes } });
    assert.equal(result.status, 400, result.text);
  }
  assert.equal((await f.request('/v1/login/verify', { method: 'POST', raw: 'token_hash=' + link.code, type: 'application/x-www-form-urlencoded' })).status, 415);
  const result = await f.request('/v1/login/verify', { method: 'POST', data: { email: link.email, token_hash: link.code, return_to: '/grants' } });
  assert.equal(result.status, 200);
  assert.equal(result.json.return_to, '/grants');
});

test('再送を1分待ち、再送後は最新のメールの鍵でログインする', async t => {
  let now = Date.now();
  const f = await fixture(t, { login: false, loginClock: () => now });
  const cookie = deliveryCookie(await send(f)), old = f.auth.links.get('new@example.test');
  assert.equal((await send(f, old.email, cookie)).status, 429);
  now += 60_001;
  assert.equal((await send(f, old.email, cookie)).status, 202);
  assert.equal((await verify(f, old)).status, 401);
  assert.equal((await verify(f)).status, 200);
});

test('送信障害時は送信済みとせず、前のメールからログインを続行する', async t => {
  const f = await fixture(t, { login: false });
  const cookie = deliveryCookie(await send(f));
  f.auth.sendHandler = async () => fail(503, 'email_unavailable', 'メールを送信できませんでした。');
  const failed = await send(f, 'second@example.test', cookie);
  assert.equal(failed.status, 503);
  assert.equal((await f.request('/v1/login', { headers: { cookie } })).json.pending.email, 'new@example.test');
  assert.equal((await verify(f)).status, 200);
});

test('認証サービスの予期しないエラーを秘密情報を含めず返す', async t => {
  const f = await fixture(t, { login: false });
  await send(f);
  f.auth.verifyLink = async () => { throw new Error('provider-secret-must-stay-private'); };
  const result = await verify(f);
  assert.equal(result.status, 503);
  assert.deepEqual(result.json, { error: { code: 'auth_unavailable', message: 'ログインサービスに接続できません。しばらく待ってからお試しください。' } });
});

test('検証の連続試行を制限する', async t => {
  const f = await fixture(t, { login: false });
  let calls = 0;
  f.auth.verifyLink = async () => { calls++; fail(401, 'invalid_link', '無効なリンクです。'); };
  const link = { email: 'new@example.test', code: 'invalid-key-with-enough-length' };
  for (let i = 0; i < 30; i++) assert.equal((await verify(f, link)).status, 401);
  assert.equal((await verify(f, link)).status, 429);
  assert.equal(calls, 30);
});

test('同じリンクを同時に確認しても一度だけログインする', async t => {
  const f = await fixture(t, { login: false });
  await send(f);
  const link = f.auth.links.get('new@example.test');
  let begin, finish;
  const started = new Promise(resolve => { begin = resolve; });
  f.auth.verifyHandler = async () => { begin(); await new Promise(resolve => { finish = resolve; }); };
  const first = verify(f, link);
  await started;
  assert.equal((await verify(f, link)).status, 401);
  finish();
  assert.equal((await first).status, 200);
});
