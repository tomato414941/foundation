import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';
import { createCredential, answer } from '../cli/webauthn.mjs';
import { seal, open } from '../cli/envelope.mjs';

const b64 = buffer => Buffer.from(buffer).toString('base64url');

// Another account, begun with a passkey (the CLI's software authenticator stands in for the device), with things of
// its own: a secret, a connection, an owned principal, an address.
async function other(f, name = 'Navigator Vega') {
  const options = (await f.request('/v1/credentials', { method: 'POST', data: { kind: 'webauthn' }, anonymous: true })).json.options;
  const made = createCredential(options, f.base);
  const became = await f.request('/v1/credentials', { method: 'PUT', anonymous: true, data: { kind: 'webauthn', principal_name: name, name: 'phone', credential: made.response, session: 'token' } });
  assert.equal(became.status, 201, became.text);
  const as = { token: became.json.token, anonymous: true };
  await f.allowFoundation({ ...as, as: became.json.principal.id });
  const kept = await f.request('/v1/resources?kind=secret&name=theirs', { ...as, method: 'PUT', raw: 'their-value' });
  assert.equal(kept.status, 200, kept.text);
  const owned = await f.request('/v1/principals', { ...as, method: 'POST', data: { name: 'their agent', key: true } });
  f.app.emails.add(became.json.principal.id, 'other@example.test');
  return { id: became.json.principal.id, token: became.json.token, credential: made.credential, secret: kept.json.resource, owned: owned.json.principal, as };
}
async function begin(f, credential, otherId) {
  const asked = await f.request('/v1/merge/options', { method: 'POST', data: { principal_id: otherId } });
  assert.equal(asked.status, 200, asked.text);
  assert.deepEqual(asked.json.options.allowCredentials.map(one => one.id), [credential.id], 'only the other\'s passkeys may answer');
  return f.request('/v1/merge', { method: 'POST', data: { credential: answer(asked.json.options, credential, f.base), principal_id: otherId } });
}

test('別のアカウントをそのパスキーでまとめると、持ち物・相手・パスキー・アドレスがこちらのものになり、相手は終わる', async t => {
  const f = await fixture(t), them = await other(f);
  const begun = await begin(f, them.credential, them.id);
  assert.equal(begun.status, 200, begun.text);
  assert.equal(begun.json.other.id, them.id);
  assert.deepEqual(begun.json.secrets.map(one => one.name), ['theirs']);
  assert.ok(begun.json.secrets[0].envelope, 'their envelope, for their key');
  // The browser opens their envelopes with their key and seals the keys for this principal.
  const theirKey = await f.keyOf(them.as), mine = await f.keyOf({});
  const envelopes = Object.fromEntries(begun.json.secrets.map(one => [one.id, b64(seal(open(Buffer.from(one.envelope, 'base64url'), theirKey.privateKey), mine.publicKey))]));
  const done = await f.request('/v1/merge/complete', { method: 'POST', data: { ticket: begun.json.ticket, envelopes } });
  assert.equal(done.status, 200, done.text);
  assert.deepEqual(done.json.moved, { secrets: 1, connections: 0, objects: 0, apps: 0, services: 0, principals: 1, webauthn_credentials: 1, emails: 1 });
  assert.equal((await f.read('secret', 'theirs')).text, 'their-value', 'opened with this principal\'s key');
  assert.ok((await f.request('/v1/principals')).json.principals.some(row => row.id === them.owned.id), 'their principal is owned here now');
  assert.deepEqual((await f.request('/v1/credentials')).json.credentials.filter(item => item.kind === 'webauthn').map(row => row.name), ['phone']);
  assert.equal(f.app.emails.principalOf('other@example.test'), USER_A);
  assert.equal(f.app.principals.get(them.id), undefined, 'the other ended');
  assert.equal((await f.request('/v1/principals/me', them.as)).status, 401, 'and so did its sessions');
  const log = (await f.request('/v1/audit-log')).json.entries.find(row => row.action === 'principal.merged');
  assert.equal(log.detail.from, them.id);
  // The passkey now signs this principal in.
  const signin = (await f.request('/v1/session', { method: 'POST', data: { kind: 'webauthn' }, anonymous: true })).json.options;
  const proven = await f.request('/v1/session', { method: 'PUT', anonymous: true, data: { kind: 'webauthn', credential: answer(signin, them.credential, f.base), session: 'token' } });
  assert.equal(proven.status, 200, proven.text);
  assert.equal((await f.request('/v1/principals/me', { token: proven.json.token, anonymous: true })).json.principal.id, USER_A);
});

test('名前がぶつかれば何も動かず、券は一度きりで、封筒がなければ Foundation が作る', async t => {
  const f = await fixture(t), them = await other(f);
  assert.equal((await f.request('/v1/merge/options', { method: 'POST', data: { principal_id: USER_A } })).json.error.code, 'invalid_merge', 'not with itself');
  assert.equal((await f.request('/v1/merge/options', { method: 'POST', data: { principal_id: them.owned.id } })).json.error.code, 'no_passkey', 'an account with no passkey cannot answer');
  await f.keep('secret', 'theirs', 'mine-already');
  const begun = await begin(f, them.credential, them.id);
  assert.equal(begun.status, 200, begun.text);
  const clash = await f.request('/v1/merge/complete', { method: 'POST', data: { ticket: begun.json.ticket } });
  assert.equal(clash.status, 409); assert.equal(clash.json.error.code, 'name_taken');
  assert.ok(f.app.principals.get(them.id), 'nothing moved');
  assert.equal(f.app.resources.get(them.secret.id).owner_id, them.id);
  assert.equal((await f.request('/v1/merge/complete', { method: 'POST', data: { ticket: begun.json.ticket } })).json.error.code, 'invalid_merge', 'spent');
  await f.drop('secret', 'theirs');
  const again = await begin(f, them.credential, them.id);
  const done = await f.request('/v1/merge/complete', { method: 'POST', data: { ticket: again.json.ticket } });
  assert.equal(done.status, 200, done.text);
  assert.equal((await f.read('secret', 'theirs')).text, 'their-value', 'without an envelope from the browser, Foundation sealed it for this principal from its own');
});

test('残すほうを相手にすれば、こちらの持ち物・パスキー・アドレスが相手のものになり、こちらは終わってセッションも切れる', async t => {
  const f = await fixture(t), them = await other(f);
  await f.keep('secret', 'mine', 'my-value');
  const begun = await begin(f, them.credential, them.id);
  assert.equal(begun.status, 200, begun.text);
  // The browser seals this account's secrets for the other's key.
  const mine = await f.keyOf({}), kept = await f.request('/v1/resources/' + (await f.lookup('secret', 'mine')).json.resource.id + '/content');
  const envelopes = { [kept.json.recipients.length && (await f.lookup('secret', 'mine')).json.resource.id]: b64(seal(open(Buffer.from(kept.json.envelope, 'base64url'), mine.privateKey), Buffer.from(begun.json.key.public_key, 'base64url'))) };
  const done = await f.request('/v1/merge/complete', { method: 'POST', data: { ticket: begun.json.ticket, into: 'other', envelopes } });
  assert.equal(done.status, 200, done.text);
  assert.equal(done.json.into, them.id); assert.equal(done.json.from, USER_A);
  assert.equal(done.json.moved.secrets, 1); assert.equal(done.json.moved.emails, 1);
  assert.equal((await f.request('/v1/principals/me')).status, 401, 'this account ended, and its session with it');
  assert.equal(f.app.emails.principalOf('owner@example.test'), them.id);
  assert.equal((await f.read('secret', 'mine', them.as)).text, 'my-value', 'opened with the other\'s key');
  assert.equal((await f.read('secret', 'theirs', them.as)).text, 'their-value');
});
