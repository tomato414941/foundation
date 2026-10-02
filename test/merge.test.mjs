import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';
import { createCredential, answer } from '../cli/webauthn.mjs';
import { seal, open } from '../cli/envelope.mjs';

const b64 = buffer => Buffer.from(buffer).toString('base64url');

// Another account, begun with a passkey (the CLI's software authenticator stands in for the device), with things of
// its own: a secret, a connection, an owned principal, an address.
async function other(f, name = 'Navigator Vega') {
  const options = (await f.request('/v1/principals/options', { method: 'POST', data: {}, anonymous: true })).json.options;
  const made = createCredential(options, f.base);
  const became = await f.request('/v1/principals', { method: 'POST', anonymous: true, data: { name, webauthn_credential: { name: 'phone', credential: made.response }, session: 'token' } });
  assert.equal(became.status, 201, became.text);
  const as = { token: became.json.token, anonymous: true };
  await f.allowFoundation({ ...as, as: became.json.principal.id });
  const kept = await f.request('/v1/resources?kind=secret&name=theirs', { ...as, method: 'PUT', raw: 'their-value' });
  assert.equal(kept.status, 200, kept.text);
  const owned = await f.request('/v1/principals', { ...as, method: 'POST', data: { name: 'their agent', key: true } });
  f.app.emails.add(became.json.principal.id, 'other@example.test');
  return { id: became.json.principal.id, token: became.json.token, credential: made.credential, secret: kept.json.resource, owned: owned.json.principal, as };
}
async function begin(f, credential) {
  const { options } = (await f.request('/v1/merge/options', { method: 'POST', data: {} })).json;
  return f.request('/v1/merge', { method: 'POST', data: { credential: answer(options, credential, f.base) } });
}

test('別のアカウントをそのパスキーでまとめると、持ち物・相手・パスキー・アドレスがこちらのものになり、相手は終わる', async t => {
  const f = await fixture(t), them = await other(f);
  const begun = await begin(f, them.credential);
  assert.equal(begun.status, 200, begun.text);
  assert.equal(begun.json.from.id, them.id);
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
  assert.deepEqual((await f.request('/v1/webauthn-credentials')).json.webauthn_credentials.map(row => row.name), ['phone']);
  assert.equal(f.app.emails.principalOf('other@example.test'), USER_A);
  assert.equal(f.app.principals.get(them.id), undefined, 'the other ended');
  assert.equal((await f.request('/v1/principals/me', them.as)).status, 401, 'and so did its sessions');
  const log = (await f.request('/v1/audit-log')).json.entries.find(row => row.action === 'principal.merged');
  assert.equal(log.detail.from, them.id);
  // The passkey now signs this principal in.
  const signin = (await f.request('/v1/signin/webauthn/options', { method: 'POST', data: {}, anonymous: true })).json.options;
  const proven = await f.request('/v1/signin/webauthn', { method: 'POST', anonymous: true, data: { credential: answer(signin, them.credential, f.base), session: 'token' } });
  assert.equal(proven.status, 200, proven.text);
  assert.equal((await f.request('/v1/principals/me', { token: proven.json.token, anonymous: true })).json.principal.id, USER_A);
});

test('名前がぶつかれば何も動かず、券は一度きりで、封筒がなければ Foundation が作る', async t => {
  const f = await fixture(t), them = await other(f);
  await f.keep('secret', 'theirs', 'mine-already');
  const begun = await begin(f, them.credential);
  assert.equal(begun.status, 200, begun.text);
  const clash = await f.request('/v1/merge/complete', { method: 'POST', data: { ticket: begun.json.ticket } });
  assert.equal(clash.status, 409); assert.equal(clash.json.error.code, 'name_taken');
  assert.ok(f.app.principals.get(them.id), 'nothing moved');
  assert.equal(f.app.resources.get(them.secret.id).owner_id, them.id);
  assert.equal((await f.request('/v1/merge/complete', { method: 'POST', data: { ticket: begun.json.ticket } })).json.error.code, 'invalid_merge', 'spent');
  await f.drop('secret', 'theirs');
  const again = await begin(f, them.credential);
  const done = await f.request('/v1/merge/complete', { method: 'POST', data: { ticket: again.json.ticket } });
  assert.equal(done.status, 200, done.text);
  assert.equal((await f.read('secret', 'theirs')).text, 'their-value', 'without an envelope from the browser, Foundation sealed it for this principal from its own');
});
