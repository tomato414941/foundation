import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';
import { createPasskey, answer } from '../cli/passkey.mjs';

const sessionCookie = response => response.headers.getSetCookie().find(value => value.startsWith('fdn_session=')).split(';')[0];
// Registers a passkey for whoever the options are asked as, made where the server is.
async function register(f, name = 'この端末', options = {}) {
  const asked = await f.request('/v1/passkeys/options', { method: 'POST', data: {}, ...options });
  assert.equal(asked.status, 200, asked.text);
  const made = createPasskey(asked.json.options, f.base);
  const saved = await f.request('/v1/passkeys', { method: 'POST', data: { name, credential: made.response }, ...options });
  assert.equal(saved.status, 201, saved.text);
  return { ...made.passkey, row: saved.json.passkey };
}
async function signin(f, passkey, { session, origin = f.base } = {}) {
  const asked = await f.request('/v1/signin/passkey/options', { method: 'POST', data: {}, anonymous: true });
  assert.equal(asked.status, 200, asked.text);
  return f.request('/v1/signin/passkey', { method: 'POST', anonymous: true, data: { credential: answer(asked.json.options, passkey, origin), ...(session ? { session } : {}) } });
}

test('登録したパスキーで、ブラウザはCookieのセッションを、プログラムは1時間のトークンを受け取ってサインインする', async t => {
  const f = await fixture(t);
  const passkey = await register(f);
  assert.equal(passkey.row.name, 'この端末');
  const browser = await signin(f, passkey);
  assert.equal(browser.status, 200, browser.text);
  assert.deepEqual(browser.json, { ok: true, return_to: '/' });
  assert.equal((await f.request('/v1/overview', { anonymous: true, headers: { cookie: sessionCookie(browser) } })).json.user.id, USER_A);
  const program = await signin(f, passkey, { session: 'token' });
  assert.equal(program.status, 200, program.text);
  assert.ok(Math.abs(program.json.expires_at - (Date.now() + 3600_000)) < 60_000);
  assert.equal((await f.request('/v1/overview', { anonymous: true, token: program.json.token })).json.user.id, USER_A);
  assert.equal(program.headers.getSetCookie().length, 0);
  const listed = (await f.request('/v1/passkeys')).json.passkeys;
  assert.deepEqual(listed.map(item => item.id), [passkey.id]);
  assert.ok(listed[0].last_used_at);
});

test('ほかのサイトから中継されたチャレンジへの答えと、一度使ったチャレンジへの答えを拒否する', async t => {
  const f = await fixture(t);
  const passkey = await register(f);
  assert.equal((await signin(f, passkey, { origin: 'https://evil.example' })).status, 401);
  const asked = await f.request('/v1/signin/passkey/options', { method: 'POST', data: {}, anonymous: true });
  const credential = answer(asked.json.options, passkey, f.base);
  assert.equal((await f.request('/v1/signin/passkey', { method: 'POST', anonymous: true, data: { credential, session: 'token' } })).status, 200);
  assert.equal((await f.request('/v1/signin/passkey', { method: 'POST', anonymous: true, data: { credential, session: 'token' } })).status, 401);
});

test('パスキーの持ち主と違うプリンシパルを名乗る答えを拒否する', async t => {
  const f = await fixture(t);
  const passkey = await register(f);
  const other = await f.become('someone');
  const forged = { ...passkey, user: Buffer.from(other.id).toString('base64url') };
  assert.equal((await signin(f, forged, { session: 'token' })).status, 401);
});

test('ブラウザとしてのサインインは、Foundationの画面からでなければ受け付けない', async t => {
  const f = await fixture(t);
  const passkey = await register(f);
  const asked = await f.request('/v1/signin/passkey/options', { method: 'POST', data: {}, anonymous: true });
  const refused = await f.request('/v1/signin/passkey', { method: 'POST', anonymous: true, headers: { origin: 'https://evil.example' }, data: { credential: answer(asked.json.options, passkey, f.base) } });
  assert.equal(refused.status, 403);
});

test('パスキーを削除すると、それで証明したセッションは終わり、ほかのサインインは続く', async t => {
  const f = await fixture(t);
  const passkey = await register(f);
  const program = await signin(f, passkey, { session: 'token' });
  assert.equal((await f.request('/v1/passkeys/' + passkey.id, { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/overview', { anonymous: true, token: program.json.token })).status, 401);
  assert.equal((await f.request('/v1/overview')).status, 200, 'the email sign-in goes on');
  assert.equal((await signin(f, passkey, { session: 'token' })).status, 401);
});

test('鍵で動くAIが自分のパスキーを登録し、その後はパスキーで証明して働く', async t => {
  const f = await fixture(t);
  const agent = await f.issueKey();
  const passkey = await register(f, 'laptop', { token: agent.token, anonymous: true, as: agent.id });
  const program = await signin(f, passkey, { session: 'token' });
  const me = await f.request('/v1/principals/me', { anonymous: true, token: program.json.token });
  assert.equal(me.json.principal.id, agent.id);
  assert.deepEqual(me.json.acts_for, [USER_A]);
  const held = await f.request('/v1/resources?' + new URLSearchParams({ kind: 'secret', name: 'x' }) + '&as=' + USER_A, { anonymous: true, token: program.json.token });
  assert.equal(held.status, 404, held.text);
});

test('パスキーを足せるのはそのプリンシパル自身だけで、持ち主も外せるが足せない', async t => {
  const f = await fixture(t);
  const agent = await f.issueKey();
  assert.equal((await f.request('/v1/passkeys/options?as=' + agent.id, { method: 'POST', data: {} })).status, 403);
  const passkey = await register(f, 'laptop', { token: agent.token, anonymous: true, as: agent.id });
  assert.equal((await f.request('/v1/passkeys?as=' + agent.id)).json.passkeys.length, 1);
  assert.equal((await f.request('/v1/passkeys/' + passkey.id, { method: 'DELETE', data: {} })).status, 200);
});

test('名前のないパスキーや、ほかのプリンシパル向けのチャレンジで作ったパスキーは登録しない', async t => {
  const f = await fixture(t);
  const asked = await f.request('/v1/passkeys/options', { method: 'POST', data: {} });
  const made = createPasskey(asked.json.options, f.base);
  assert.equal((await f.request('/v1/passkeys', { method: 'POST', data: { name: '', credential: made.response } })).status, 400);
  const agent = await f.issueKey();
  const stolen = await f.request('/v1/passkeys', { method: 'POST', anonymous: true, token: agent.token, as: agent.id, data: { name: 'x', credential: made.response } });
  assert.equal(stolen.status, 400);
  assert.equal((await f.request('/v1/passkeys')).json.passkeys.length, 0);
});
