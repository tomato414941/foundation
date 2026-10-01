import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';
import { createCredential, answer } from '../cli/webauthn.mjs';

const sessionCookie = response => response.headers.getSetCookie().find(value => value.startsWith('fdn_session=')).split(';')[0];
// Registers a WebAuthn credential for whoever the options are asked as, made where the server is.
async function register(f, name = 'この端末', options = {}) {
  const asked = await f.request('/v1/webauthn-credentials/options', { method: 'POST', data: {}, ...options });
  assert.equal(asked.status, 200, asked.text);
  const made = createCredential(asked.json.options, f.base);
  const saved = await f.request('/v1/webauthn-credentials', { method: 'POST', data: { name, credential: made.response }, ...options });
  assert.equal(saved.status, 201, saved.text);
  return { ...made.credential, row: saved.json.webauthn_credential };
}
async function signin(f, credential, { session, origin = f.base } = {}) {
  const asked = await f.request('/v1/signin/webauthn/options', { method: 'POST', data: {}, anonymous: true });
  assert.equal(asked.status, 200, asked.text);
  return f.request('/v1/signin/webauthn', { method: 'POST', anonymous: true, data: { credential: answer(asked.json.options, credential, origin), ...(session ? { session } : {}) } });
}

test('登録したWebAuthnの資格情報で、ブラウザはCookieのセッションを、プログラムは1時間のトークンを受け取ってサインインする', async t => {
  const f = await fixture(t);
  const credential = await register(f);
  assert.equal(credential.row.name, 'この端末');
  const browser = await signin(f, credential);
  assert.equal(browser.status, 200, browser.text);
  assert.deepEqual(browser.json, { ok: true, return_to: '/' });
  assert.equal((await f.request('/v1/overview', { anonymous: true, headers: { cookie: sessionCookie(browser) } })).json.user.id, USER_A);
  const program = await signin(f, credential, { session: 'token' });
  assert.equal(program.status, 200, program.text);
  assert.ok(Math.abs(program.json.expires_at - (Date.now() + 3600_000)) < 60_000);
  assert.equal((await f.request('/v1/overview', { anonymous: true, token: program.json.token })).json.user.id, USER_A);
  assert.equal(program.headers.getSetCookie().length, 0);
  const listed = (await f.request('/v1/webauthn-credentials')).json.webauthn_credentials;
  assert.deepEqual(listed.map(item => item.id), [credential.id]);
  assert.ok(listed[0].last_used_at);
});

test('ほかのサイトから中継されたチャレンジへの答えと、一度使ったチャレンジへの答えを拒否する', async t => {
  const f = await fixture(t);
  const credential = await register(f);
  assert.equal((await signin(f, credential, { origin: 'https://evil.example' })).status, 401);
  const asked = await f.request('/v1/signin/webauthn/options', { method: 'POST', data: {}, anonymous: true });
  const answered = answer(asked.json.options, credential, f.base);
  assert.equal((await f.request('/v1/signin/webauthn', { method: 'POST', anonymous: true, data: { credential: answered, session: 'token' } })).status, 200);
  assert.equal((await f.request('/v1/signin/webauthn', { method: 'POST', anonymous: true, data: { credential: answered, session: 'token' } })).status, 401);
});

test('WebAuthnの資格情報の持ち主と違うプリンシパルを名乗る答えを拒否する', async t => {
  const f = await fixture(t);
  const credential = await register(f);
  const other = await f.become('someone');
  const forged = { ...credential, user: Buffer.from(other.id).toString('base64url') };
  assert.equal((await signin(f, forged, { session: 'token' })).status, 401);
});

test('ブラウザとしてのサインインは、Foundationの画面からでなければ受け付けない', async t => {
  const f = await fixture(t);
  const credential = await register(f);
  const asked = await f.request('/v1/signin/webauthn/options', { method: 'POST', data: {}, anonymous: true });
  const refused = await f.request('/v1/signin/webauthn', { method: 'POST', anonymous: true, headers: { origin: 'https://evil.example' }, data: { credential: answer(asked.json.options, credential, f.base) } });
  assert.equal(refused.status, 403);
});

test('WebAuthnの資格情報を削除すると、それで証明したセッションは終わり、ほかのサインインは続く', async t => {
  const f = await fixture(t);
  const credential = await register(f);
  const program = await signin(f, credential, { session: 'token' });
  assert.equal((await f.request('/v1/webauthn-credentials/' + credential.id, { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/overview', { anonymous: true, token: program.json.token })).status, 401);
  assert.equal((await f.request('/v1/overview')).status, 200, 'the email sign-in goes on');
  assert.equal((await signin(f, credential, { session: 'token' })).status, 401);
});

test('鍵で動くAIが自分のWebAuthnの資格情報を登録し、その後はWebAuthnの資格情報で証明して働く', async t => {
  const f = await fixture(t);
  const agent = await f.issueKey();
  const credential = await register(f, 'laptop', { token: agent.token, anonymous: true, as: agent.id });
  const program = await signin(f, credential, { session: 'token' });
  const me = await f.request('/v1/principals/me', { anonymous: true, token: program.json.token });
  assert.equal(me.json.principal.id, agent.id);
  assert.deepEqual(me.json.acts_for, [USER_A]);
  const held = await f.request('/v1/resources?' + new URLSearchParams({ kind: 'secret', name: 'x' }) + '&as=' + USER_A, { anonymous: true, token: program.json.token });
  assert.equal(held.status, 404, held.text);
});

test('WebAuthnの資格情報を足せるのはそのプリンシパル自身だけで、持ち主も外せるが足せない', async t => {
  const f = await fixture(t);
  const agent = await f.issueKey();
  assert.equal((await f.request('/v1/webauthn-credentials/options?as=' + agent.id, { method: 'POST', data: {} })).status, 403);
  const credential = await register(f, 'laptop', { token: agent.token, anonymous: true, as: agent.id });
  assert.equal((await f.request('/v1/webauthn-credentials?as=' + agent.id)).json.webauthn_credentials.length, 1);
  assert.equal((await f.request('/v1/webauthn-credentials/' + credential.id, { method: 'DELETE', data: {} })).status, 200);
});

test('名前のないWebAuthnの資格情報や、ほかのプリンシパル向けのチャレンジで作ったWebAuthnの資格情報は登録しない', async t => {
  const f = await fixture(t);
  const asked = await f.request('/v1/webauthn-credentials/options', { method: 'POST', data: {} });
  const made = createCredential(asked.json.options, f.base);
  assert.equal((await f.request('/v1/webauthn-credentials', { method: 'POST', data: { name: '', credential: made.response } })).status, 400);
  const agent = await f.issueKey();
  const stolen = await f.request('/v1/webauthn-credentials', { method: 'POST', anonymous: true, token: agent.token, as: agent.id, data: { name: 'x', credential: made.response } });
  assert.equal(stolen.status, 400);
  assert.equal((await f.request('/v1/webauthn-credentials')).json.webauthn_credentials.length, 0);
});
