import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fail } from '../src/errors.mjs';
import { fixture, USER_A } from './helpers.mjs';

const deliveryCookie = response => response.headers.getSetCookie().find(value => value.startsWith('fdn_signin=')).split(';')[0];
const sessionCookie = response => response.headers.getSetCookie().find(value => value.startsWith('fdn_session=')).split(';')[0];
const send = (f, email = 'new@example.test', cookie, return_to) => f.request('/v1/session/challenges', { method: 'POST', data: { kind: 'email', address: email, return_to }, headers: cookie ? { cookie } : {} });
const verify = (f, link = f.mailer.link('new@example.test'), options = {}) => f.request('/v1/session', { method: 'POST', data: { kind: 'email', email: link.email, token: link.token }, ...options,
});
// Moves what Foundation remembers of the sign-ins under way back in time.
const age = (f, ms) => f.app.store.db.prepare('UPDATE challenges SET created_at=created_at-?, expires_at=expires_at-?').run(ms, ms);

test('メールで送ったリンクを、送信元のCookieを持たないブラウザでも検証し、サインインする', async t => {
  const f = await fixture(t, { signin: false, publicOrigin: 'https://foundation.example.test' });
  const sent = await send(f, ' New@Example.Test ');
  assert.equal(sent.status, 202, sent.text);
  assert.equal(sent.json.pending.email, 'new@example.test');
  const cookie = deliveryCookie(sent), link = f.mailer.link('new@example.test');
  const url = new URL(link.url);
  assert.equal(url.origin, 'https://foundation.example.test');
  assert.equal(url.pathname, '/signin/confirm');
  assert.match(link.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(f.mailer.sent.at(-1).subject, 'Foundationへのサインイン');
  assert.deepEqual((await f.request('/v1/session', { headers: { cookie } })).json.pending, sent.json.pending);
  const result = await verify(f);
  assert.equal(result.status, 200, result.text);
  assert.deepEqual(result.json, { ok: true, return_to: '/' });
  assert.match(result.headers.getSetCookie().find(value => value.startsWith('fdn_session=')), /HttpOnly; SameSite=Lax; Path=\/; Max-Age=1209600; Secure/);
  assert.equal(result.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(result.headers.get('cache-control'), 'no-store');
  const state = await f.request('/v1/principals/me/credentials', { headers: { cookie: sessionCookie(result) } });
  assert.equal(state.status, 200);
  assert.deepEqual(state.json.credentials.map(item => [item.kind, item.name]), [['email', 'new@example.test']]);
  assert.equal((await f.request('/v1/principals/me', { headers: { cookie } })).status, 401);
});

test('初めて確かめたアドレスは新しいプリンシパルになり、同じアドレスでまたサインインすると同じプリンシパルに戻る', async t => {
  const f = await fixture(t, { signin: false });
  await send(f);
  const first = await f.request('/v1/principals/me', { headers: { cookie: sessionCookie(await verify(f)) } });
  await age(f, 60_001);
  await send(f);
  const again = await f.request('/v1/principals/me', { headers: { cookie: sessionCookie(await verify(f)) } });
  assert.match(first.json.principal.id, /^[0-9a-f-]{36}$/);
  assert.match(first.json.principal.name, /^[A-Z][A-Za-z' ]+ [A-Z][A-Za-z' ]+$/, 'it is given a name, drawn as for any other');
  assert.equal(again.json.principal.id, first.json.principal.id);
  assert.equal(again.json.principal.name, first.json.principal.name, 'and keeps it');
  // One made before names were given gets one the next time it signs in.
  f.app.principals.rename(first.json.principal.id, '');
  await age(f, 60_001);
  await send(f);
  assert.match((await f.request('/v1/principals/me', { headers: { cookie: sessionCookie(await verify(f)) } })).json.principal.name, /^[A-Z][A-Za-z' ]+ [A-Z][A-Za-z' ]+$/);
  await send(f, 'someone@example.test');
  const other = await f.request('/v1/principals/me', { headers: { cookie: sessionCookie(await verify(f, f.mailer.link('someone@example.test'))) } });
  assert.notEqual(other.json.principal.id, first.json.principal.id);
});

test('メールの先読みには確認画面だけを返し、ボタンからの検証を待つ', async t => {
  const f = await fixture(t, { signin: false });
  await send(f);
  for (let i = 0; i < 3; i++) {
    const page = await f.request('/signin/confirm', { headers: { 'sec-fetch-site': 'cross-site' } });
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type'), /^text\/html/);
    assert.equal(page.headers.get('cache-control'), 'no-store');
    assert.equal((await f.request('/v1/principals/me')).status, 401);
  }
  assert.equal((await verify(f)).status, 200);
});

test('サーバーを再起動しても、メールで受け取った有効なリンクを検証する', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-signin-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const database = join(directory, 'state.sqlite');
  const first = await fixture(t, { signin: false, database });
  await send(first);
  const link = first.mailer.link('new@example.test');
  await first.close();
  const next = await fixture(t, { signin: false, database });
  assert.equal((await verify(next, link)).status, 200);
});

test('別のアドレスへの送信状況よりも、確認したリンクの持ち主を採用する', async t => {
  const f = await fixture(t, { signin: false });
  await send(f);
  const cookie = deliveryCookie(await send(f, 'second@example.test'));
  const result = await verify(f, undefined, { headers: { cookie } });
  const state = await f.request('/v1/principals/me/credentials', { headers: { cookie: sessionCookie(result) } });
  assert.deepEqual(state.json.credentials.map(item => item.name), ['new@example.test']);
});

test('同じリンクの再利用と期限を過ぎたリンクを拒否する', async t => {
  const f = await fixture(t, { signin: false });
  await send(f);
  const link = f.mailer.link('new@example.test');
  assert.equal((await verify(f, link)).status, 200);
  assert.equal((await verify(f, link)).status, 401);
  await send(f, 'expired@example.test');
  await age(f, 15 * 60_000);
  assert.equal((await verify(f, f.mailer.link('expired@example.test'))).status, 401);
});

test('リンクを送ったアドレスと違うアドレスでは検証せず、今のサインインを保つ', async t => {
  const f = await fixture(t);
  await send(f, 'attacker@example.test');
  const result = await verify(f, { ...f.mailer.link('attacker@example.test'), email: 'owner@example.test' });
  assert.equal(result.status, 401);
  assert.equal(result.json.error.code, 'invalid_link');
  assert.equal((await f.request('/v1/principals/me')).json.principal.id, USER_A);
});

test('外部サイトからの送信・検証・送信状況の取り消しを拒否する', async t => {
  const f = await fixture(t, { signin: false });
  const data = { kind: 'email', address: 'new@example.test' };
  assert.equal((await f.request('/v1/session/challenges', { method: 'POST', data, headers: { origin: 'https://evil.example' } })).status, 403);
  const cookie = deliveryCookie(await send(f));
  const link = f.mailer.link('new@example.test');
  for (const origin of ['https://evil.example', 'null', '']) {
    assert.equal((await verify(f, link, { headers: { cookie, origin } })).status, 403);
  }
  assert.equal((await verify(f, link, { headers: { authorization: 'Bearer ignored', origin: 'https://evil.example' } })).status, 403);
  assert.equal((await f.request('/v1/session', { method: 'DELETE', headers: { cookie, origin: 'https://evil.example' } })).status, 403);
  assert.equal((await verify(f, link)).status, 200);
});

test('不正な入力と外部への戻り先を拒否し、許可されたページへ戻す', async t => {
  const f = await fixture(t, { signin: false });
  await send(f, 'new@example.test', undefined, '/secrets');
  const link = f.mailer.link('new@example.test');
  assert.equal(new URL(link.url).searchParams.get('return_to'), '/secrets');
  for (const changes of [{ email: '' }, { email: 'not-an-email' }, { token: 'short' }, { token: ['ambiguous'] }, { return_to: 'https://evil.example' }, { return_to: '//evil.example' }, { return_to: '/\\evil.example' }, { return_to: '/objects?redirect=https://evil.example' }, { return_to: '/services?prefix=private' }, { return_to: '/signin/confirm' }]) {
    const result = await f.request('/v1/session', { method: 'POST', data: { kind: 'email', email: link.email, token: link.token, ...changes } });
    assert.equal(result.status, 400, result.text);
  }
  assert.equal((await f.request('/v1/session', { method: 'POST', raw: 'token=' + link.token, type: 'application/x-www-form-urlencoded' })).status, 415);
  const result = await f.request('/v1/session', { method: 'POST', data: { kind: 'email', email: link.email, token: link.token, return_to: '/secrets' } });
  assert.equal(result.status, 200);
  assert.equal(result.json.return_to, '/secrets');
});

test('再送を1分待ち、再送後は最新のメールのリンクでだけサインインする', async t => {
  const f = await fixture(t, { signin: false });
  const cookie = deliveryCookie(await send(f)), old = f.mailer.link('new@example.test');
  assert.equal((await send(f, old.email, cookie)).status, 429);
  await age(f, 60_001);
  assert.equal((await send(f, old.email, cookie)).status, 202);
  assert.equal((await verify(f, old)).status, 401);
  assert.equal((await verify(f)).status, 200);
});

test('送信に失敗したリンクは使えず、前のメールのリンクからサインインを続ける', async t => {
  const f = await fixture(t, { signin: false });
  const cookie = deliveryCookie(await send(f));
  let attempted;
  f.mailer.sendHandler = async message => { attempted = message; fail(503, 'email_unavailable', 'メールを送信できませんでした。'); };
  const failed = await send(f, 'second@example.test', cookie);
  assert.equal(failed.status, 503);
  const unsent = new URLSearchParams(new URL(attempted.text.match(/https?:\/\/\S+/)[0]).hash.slice(1));
  assert.equal((await verify(f, { email: 'second@example.test', token: unsent.get('token') })).status, 401);
  assert.equal((await f.request('/v1/session', { headers: { cookie } })).json.pending.email, 'new@example.test');
  assert.equal((await verify(f)).status, 200);
});

test('検証の連続試行を制限する', async t => {
  const f = await fixture(t, { signin: false });
  const link = { email: 'new@example.test', token: 'x'.repeat(43) };
  for (let i = 0; i < 30; i++) assert.equal((await verify(f, link)).status, 401);
  assert.equal((await verify(f, link)).status, 429);
});

test('同じリンクを同時に確認しても一度だけサインインする', async t => {
  const f = await fixture(t, { signin: false });
  await send(f);
  const link = f.mailer.link('new@example.test');
  const results = await Promise.all([verify(f, link), verify(f, link)]);
  assert.deepEqual(results.map(result => result.status).sort(), [200, 401]);
});

test('サインアウトするとそのセッションだけを終え、ほかのブラウザのサインインは続く', async t => {
  const f = await fixture(t, { signin: false });
  await send(f);
  const one = sessionCookie(await verify(f));
  await age(f, 60_001);
  await send(f);
  const two = sessionCookie(await verify(f));
  assert.equal((await f.request('/v1/session', { method: 'DELETE', headers: { cookie: one } })).status, 200);
  assert.equal((await f.request('/v1/principals/me', { headers: { cookie: one } })).status, 401);
  assert.equal((await f.request('/v1/principals/me', { headers: { cookie: two } })).status, 200);
});

test('プリンシパルが頼んだリンクは、開いて確かめるとそのアドレスをそのプリンシパルの入口にし、誰もサインインさせない', async t => {
  const f = await fixture(t);
  // One that came by a key alone asks for an address, as any client may.
  const machine = await f.become('machine'), as = { token: machine.token, anonymous: true };
  const asked = await f.request('/v1/principals/me/credentials/challenges', { ...as, method: 'POST', data: { kind: 'email', address: ' Machine@Example.Test ' } });
  assert.equal(asked.status, 202, asked.text);
  assert.equal(asked.json.pending.email, 'machine@example.test');
  assert.equal(f.mailer.sent.at(-1).subject, 'Foundationにメールアドレスを追加');
  const link = f.mailer.link('machine@example.test');
  assert.equal(new URLSearchParams(new URL(link.url).hash.slice(1)).get('attach'), 'machine', 'the page says whose it becomes');
  // Whoever opens the link confirms it, in any browser: the address is attached, and that browser is signed in as nobody.
  const opened = await f.request('/v1/session', { method: 'POST', anonymous: true, data: { kind: 'email', email: link.email, token: link.token } });
  assert.equal(opened.status, 200, opened.text);
  assert.equal(opened.json.attached, true);
  assert.equal(opened.headers.getSetCookie().some(value => value.startsWith('fdn_session=')), false);
  const entries = (await f.request('/v1/principals/me/credentials', as)).json.credentials;
  assert.deepEqual(entries.map(item => [item.kind, item.name]), [['email', 'machine@example.test'], ['key', null]]);
  assert.equal(f.app.emails.principalOf('machine@example.test'), machine.id, 'and it signs that principal in from then on');
  assert.equal((await f.request('/v1/session', { method: 'POST', anonymous: true, data: { kind: 'email', email: link.email, token: link.token } })).status, 401, 'the link is spent');
  // An address another principal has is not taken from it.
  const taken = await f.request('/v1/principals/me/credentials/challenges', { ...as, method: 'POST', data: { kind: 'email', address: 'owner@example.test' } });
  assert.equal(taken.status, 409); assert.equal(taken.json.error.code, 'email_taken');
  // Whoever manages a principal adds its entries: an owner for what it owns, and nobody for a stranger.
  const agent = await f.issueKey();
  assert.equal((await f.request('/v1/principals/' + agent.id + '/credentials/challenges', { method: 'POST', data: { kind: 'email', address: 'agent@example.test' } })).status, 202);
  assert.equal((await f.request('/v1/principals/' + USER_A + '/credentials/challenges', { ...as, method: 'POST', data: { kind: 'email', address: 'mine@example.test' } })).status, 401);
  // An address is removed like any other entry.
  const address = entries.find(item => item.kind === 'email');
  assert.equal((await f.request('/v1/principals/me/credentials/' + address.id, { ...as, method: 'DELETE', data: {} })).status, 200);
  assert.equal(f.app.emails.principalOf('machine@example.test'), undefined);
});
