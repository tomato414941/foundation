import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';
import { createCredential, answer } from '../cli/webauthn.mjs';

const sessionCookie = response => response.headers.getSetCookie().find(value => value.startsWith('fdn_session=')).split(';')[0];
// Registers a WebAuthn credential for whoever the options are asked as, made where the server is.
async function register(f, name = 'この端末', options = {}) {
  const asked = await f.request('/v1/principals/me/credentials', { method: 'POST', data: { kind: 'webauthn' }, ...options });
  assert.equal(asked.status, 200, asked.text);
  const made = createCredential(asked.json.options, f.base);
  const saved = await f.request('/v1/principals/me/credentials', { method: 'PUT', data: { kind: 'webauthn', name, credential: made.response }, ...options });
  assert.equal(saved.status, 201, saved.text);
  return { ...made.credential, row: saved.json.credential };
}
async function signin(f, credential, { session, origin = f.base } = {}) {
  const asked = await f.request('/v1/session', { method: 'POST', data: { kind: 'webauthn' }, anonymous: true });
  assert.equal(asked.status, 200, asked.text);
  return f.request('/v1/session', { method: 'PUT', anonymous: true, data: { kind: 'webauthn', credential: answer(asked.json.options, credential, origin), ...(session ? { session } : {}) } });
}

test('登録したWebAuthnの資格情報で、ブラウザはCookieのセッションを、プログラムは1時間のトークンを受け取ってサインインする', async t => {
  const f = await fixture(t);
  const credential = await register(f);
  assert.equal(credential.row.name, 'この端末');
  const browser = await signin(f, credential);
  assert.equal(browser.status, 200, browser.text);
  assert.deepEqual(browser.json, { ok: true, return_to: '/' });
  assert.equal((await f.request('/v1/principals/me', { anonymous: true, headers: { cookie: sessionCookie(browser) } })).json.principal.id, USER_A);
  const program = await signin(f, credential, { session: 'token' });
  assert.equal(program.status, 200, program.text);
  assert.ok(Math.abs(program.json.expires_at - (Date.now() + 3600_000)) < 60_000);
  assert.equal((await f.request('/v1/principals/me', { anonymous: true, token: program.json.token })).json.principal.id, USER_A);
  assert.equal(program.headers.getSetCookie().length, 0);
  const listed = (await f.request('/v1/principals/me/credentials')).json.credentials.filter(item => item.kind === 'webauthn');
  assert.deepEqual(listed.map(item => item.id), [credential.id]);
  assert.ok(listed[0].last_used_at);
});

test('ほかのサイトから中継されたチャレンジへの答えと、一度使ったチャレンジへの答えを拒否する', async t => {
  const f = await fixture(t);
  const credential = await register(f);
  assert.equal((await signin(f, credential, { origin: 'https://evil.example' })).status, 401);
  const asked = await f.request('/v1/session', { method: 'POST', data: { kind: 'webauthn' }, anonymous: true });
  const answered = answer(asked.json.options, credential, f.base);
  assert.equal((await f.request('/v1/session', { method: 'PUT', anonymous: true, data: { kind: 'webauthn', credential: answered, session: 'token' } })).status, 200);
  assert.equal((await f.request('/v1/session', { method: 'PUT', anonymous: true, data: { kind: 'webauthn', credential: answered, session: 'token' } })).status, 401);
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
  const asked = await f.request('/v1/session', { method: 'POST', data: { kind: 'webauthn' }, anonymous: true });
  const refused = await f.request('/v1/session', { method: 'PUT', anonymous: true, headers: { origin: 'https://evil.example' }, data: { kind: 'webauthn', credential: answer(asked.json.options, credential, f.base) } });
  assert.equal(refused.status, 403);
});

test('WebAuthnの資格情報を削除すると、それで証明したセッションは終わり、ほかのサインインは続く', async t => {
  const f = await fixture(t);
  const credential = await register(f);
  const program = await signin(f, credential, { session: 'token' });
  assert.equal((await f.request('/v1/principals/me/credentials/' + credential.id, { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/principals/me', { anonymous: true, token: program.json.token })).status, 401);
  assert.equal((await f.request('/v1/principals/me')).status, 200, 'the email sign-in goes on');
  assert.equal((await signin(f, credential, { session: 'token' })).status, 401);
});

test('鍵で動くAIが自分のWebAuthnの資格情報を登録し、その後はWebAuthnの資格情報で証明して働く', async t => {
  const f = await fixture(t);
  const agent = await f.issueKey();
  const credential = await register(f, 'laptop', { token: agent.token, anonymous: true });
  const program = await signin(f, credential, { session: 'token' });
  const me = await f.request('/v1/principals/me', { anonymous: true, token: program.json.token });
  assert.equal(me.json.principal.id, agent.id);
  assert.deepEqual(me.json.acts_for, [USER_A]);
  const held = await f.request('/v1/principals/' + USER_A + '/resources?' + new URLSearchParams({ kind: 'secret', name: 'x' }), { anonymous: true, token: program.json.token });
  assert.equal(held.status, 404, held.text);
});

test('パスキーはそのプリンシパル自身と持ち主が足し、他人は足せず、持ち主は外せる', async t => {
  const f = await fixture(t);
  const agent = await f.issueKey(), stranger = await f.become('stranger');
  assert.equal((await f.request('/v1/principals/' + agent.id + '/credentials', { method: 'POST', data: { kind: 'webauthn' } })).status, 200, 'the owner manages its entries');
  assert.equal((await f.request('/v1/principals/' + agent.id + '/credentials', { method: 'POST', token: stranger.token, anonymous: true, data: { kind: 'webauthn' } })).status, 401, 'a key acting for nobody is told so');
  const credential = await register(f, 'laptop', { token: agent.token, anonymous: true });
  assert.equal((await f.request('/v1/principals/' + agent.id + '/credentials')).json.credentials.filter(item => item.kind === 'webauthn').length, 1);
  assert.equal((await f.request('/v1/principals/' + agent.id + '/credentials/' + credential.id, { method: 'DELETE', data: {} })).status, 200);
});

test('名前のないWebAuthnの資格情報や、ほかのプリンシパル向けのチャレンジで作ったWebAuthnの資格情報は登録しない', async t => {
  const f = await fixture(t);
  const asked = await f.request('/v1/principals/me/credentials', { method: 'POST', data: { kind: 'webauthn' } });
  const made = createCredential(asked.json.options, f.base);
  assert.equal((await f.request('/v1/principals/me/credentials', { method: 'PUT', data: { kind: 'webauthn', name: '', credential: made.response } })).status, 400);
  const agent = await f.issueKey();
  const stolen = await f.request('/v1/principals/me/credentials', { method: 'PUT', anonymous: true, token: agent.token, data: { kind: 'webauthn', name: 'x', credential: made.response } });
  assert.equal(stolen.status, 400);
  assert.equal((await f.request('/v1/principals/me/credentials')).json.credentials.filter(item => item.kind === 'webauthn').length, 0);
});

test('WebAuthnの資格情報だけで新しいプリンシパルになり、ブラウザはCookieを、プログラムはトークンをその場で受け取る', async t => {
  const f = await fixture(t, { signin: false });
  const asked = await f.request('/v1/principals', { method: 'POST', data: { kind: 'webauthn' }, anonymous: true });
  assert.equal(asked.status, 200, asked.text);
  const made = createCredential(asked.json.options, f.base);
  const browser = await f.request('/v1/principals', { method: 'PUT', anonymous: true, data: { kind: 'webauthn', name: 'この端末', credential: made.response, return_to: '/secrets' } });
  assert.equal(browser.status, 201, browser.text);
  assert.equal(browser.json.principal.name, '', 'the name is the client\'s to give, from the options');
  assert.match(asked.json.options.user.name, /^[A-Z][A-Za-z' ]+ [A-Z][A-Za-z' ]+$/, 'a role at a star, drawn for the passkey\'s label');
  assert.equal(asked.json.options.user.displayName, asked.json.options.user.name);
  assert.equal((await f.request('/v1/principals/me', { method: 'PATCH', data: { name: 'はじめての人' }, headers: { cookie: browser.headers.getSetCookie().find(v => v.startsWith('fdn_session='))?.split(';')[0] ?? '' }, anonymous: true })).json.principal.name, 'はじめての人');
  assert.equal(browser.json.return_to, '/secrets');
  const cookie = sessionCookie(browser);
  assert.equal((await f.request('/v1/principals/me', { anonymous: true, headers: { cookie } })).json.principal.id, browser.json.principal.id);
  assert.equal((await signin(f, made.credential, { session: 'token' })).status, 200, 'and it signs in with that credential afterwards');

  const program = createCredential((await f.request('/v1/principals', { method: 'POST', data: { kind: 'webauthn', name: 'laptop' }, anonymous: true })).json.options, f.base);
  const made2 = await f.request('/v1/principals', { method: 'PUT', anonymous: true, data: { kind: 'webauthn', principal_name: 'laptop', name: 'laptop', credential: program.response, session: 'token' } });
  assert.equal(made2.status, 201, made2.text);
  assert.equal((await f.request('/v1/principals/me', { anonymous: true, token: made2.json.token })).json.principal.name, 'laptop');
});

test('既にいるプリンシパル向けのチャレンジで新しいプリンシパルは作れず、名前のない作成も受け付けない', async t => {
  const f = await fixture(t);
  const forExisting = createCredential((await f.request('/v1/principals/me/credentials', { method: 'POST', data: { kind: 'webauthn' } })).json.options, f.base);
  const refused = await f.request('/v1/principals', { method: 'PUT', anonymous: true, data: { kind: 'webauthn', principal_name: 'x', name: 'x', credential: forExisting.response, session: 'token' } });
  assert.equal(refused.status, 400);
  const forNew = createCredential((await f.request('/v1/principals', { method: 'POST', data: { kind: 'webauthn', name: 'x' }, anonymous: true })).json.options, f.base);
  assert.equal((await f.request('/v1/principals/me/credentials', { method: 'PUT', data: { kind: 'webauthn', name: 'x', credential: forNew.response } })).status, 400, 'nor is it added to an existing one');
  assert.equal((await f.request('/v1/principals', { method: 'PUT', anonymous: true, data: { kind: 'webauthn', principal_name: 'x', name: '', credential: forNew.response, session: 'token' } })).status, 400);
});
