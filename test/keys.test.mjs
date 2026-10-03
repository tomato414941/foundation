import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, USER_A } from './helpers.mjs';
import { generateKey, publicKeyOf, open, seal, wrap, unwrap } from '../cli/envelope.mjs';

const b64 = buffer => Buffer.from(buffer).toString('base64url');

test('主体は公開鍵を一度だけ公開し、相手の公開鍵は誰でも読める', async t => {
  const f = await fixture(t, { signin: false }), machine = await f.request('/v1/principals', { method: 'POST', anonymous: true, data: { kind: 'key', name: 'machine' } });
  const options = { token: machine.json.token, anonymous: true }, made = generateKey();
  assert.deepEqual((await f.request('/v1/principals/me/key', options)).json.key, { principal_id: machine.json.principal.id, public_key: null, wraps: {} });
  const published = await f.request('/v1/principals/me/key', { ...options, method: 'PUT', data: { public_key: b64(made.publicKey) } });
  assert.equal(published.status, 200, published.text);
  assert.equal(published.json.key.public_key, b64(made.publicKey));
  const again = await f.request('/v1/principals/me/key', { ...options, method: 'PUT', data: { public_key: b64(generateKey().publicKey) } });
  assert.equal(again.status, 409); assert.equal(again.json.error.code, 'key_exists');
  assert.equal((await f.request('/v1/principals/me/key', { ...options, method: 'PUT', data: { public_key: 'short' } })).json.error.code, 'invalid_key');
  await f.signin();
  assert.equal((await f.request('/v1/principals/' + machine.json.principal.id + '/key')).json.key.public_key, b64(made.publicKey));
});

test('秘密鍵はパスキーごとに包んで預け、そのパスキーで証明したセッションに返す', async t => {
  const f = await fixture(t), yielded = Buffer.alloc(32, 9), made = generateKey();
  // A credential registered by a browser, standing in for one here.
  f.app.store.db.prepare('INSERT INTO webauthn_credentials (id,principal_id,public_key,sign_count,name,user_handle,created_at) VALUES (?,?,?,?,?,?,?)').run('credential-0000000001', USER_A, Buffer.alloc(8), 0, 'phone', USER_A, Date.now());
  const published = await f.request('/v1/principals/me/key', { method: 'PUT', data: { public_key: b64(made.publicKey), wraps: { 'credential-0000000001': b64(wrap(made.privateKey, yielded)) } } });
  assert.equal(published.status, 409, 'the signin already published one');
  const kept = await f.request('/v1/principals/me/credentials/credential-0000000001/wrap', { method: 'PUT', data: { wrapped: b64(wrap(made.privateKey, yielded)) } });
  assert.equal(kept.status, 200, kept.text);
  const { wraps } = (await f.request('/v1/principals/me/key')).json.key;
  assert.deepEqual(Object.keys(wraps), ['credential-0000000001']);
  assert.deepEqual(unwrap(Buffer.from(wraps['credential-0000000001'], 'base64url'), yielded), made.privateKey);
  const someone = await f.become('someone');
  const shown = await f.request('/v1/principals/' + USER_A + '/key', { token: someone.token, anonymous: true });
  assert.equal(shown.json.key.public_key, b64((await f.keyOf({})).publicKey), 'anyone may read the public half, to seal for it');
  assert.equal(shown.json.key.wraps, undefined, 'wraps are the principal\'s own');
  assert.equal((await f.request('/v1/principals/me/credentials/credential-0000000009/wrap', { method: 'PUT', data: { wrapped: 'x' } })).status, 404);
});

test('宛先は持ち主と、持ち主の代わりに動くFoundationで、Foundationが代わりに動かなければ注入も預けもできない', async t => {
  const f = await fixture(t, { signin: false });
  f.known('owner@example.test');
  const token = f.app.challenges.issue('email', 'owner@example.test', { ttl: 900_000 });
  const session = await fetch(f.base + '/v1/session', { method: 'PUT', headers: { 'content-type': 'application/json', origin: f.base }, body: JSON.stringify({ kind: 'email', email: 'owner@example.test', token }) });
  const cookie = session.headers.getSetCookie()[0].split(';')[0], as = { headers: { cookie }, anonymous: true };
  const made = generateKey();
  assert.equal((await f.request('/v1/principals/me/key', { ...as, method: 'PUT', data: { public_key: b64(made.publicKey) } })).status, 200);
  assert.deepEqual((await f.request('/v1/principals/me/recipients', as)).json.recipients, [{ principal_id: USER_A, public_key: b64(made.publicKey) }], 'nobody but the owner');
  const sealed = await f.sealed('mine', as, [{ principal_id: USER_A, public_key: b64(made.publicKey) }]);
  const kept = await f.request('/v1/principals/me/resources?kind=secret&name=mine', { ...as, method: 'PUT', data: sealed });
  assert.equal(kept.status, 200, kept.text);
  assert.deepEqual(kept.json.resource.recipients, [USER_A]);
  const injected = await f.request('/v1/injections', { ...as, method: 'POST', data: { names: [{ name: 'mine', as: 'MINE' }] } });
  assert.equal(injected.status, 403); assert.equal(injected.json.error.code, 'foundation_not_agent');
  const plain = await f.request('/v1/principals/me/resources?kind=secret&name=plain', { ...as, method: 'PUT', data: { plain: b64(Buffer.from('x')) } });
  assert.equal(plain.status, 403); assert.equal(plain.json.error.code, 'foundation_not_agent');
  // Made its agent, Foundation is a recipient of what is kept from then on, and opens what was sealed for it.
  await f.allowFoundation({ ...as, as: USER_A });
  const recipients = (await f.request('/v1/principals/me/recipients', as)).json.recipients.map(one => one.principal_id);
  assert.deepEqual(recipients, [USER_A, f.app.keys.agentId]);
  assert.equal((await f.request('/v1/injections', { ...as, method: 'POST', data: { names: [{ name: 'mine', as: 'MINE' }] } })).json.error.code, 'not_sealed_for_foundation', 'sealed before Foundation was a recipient');
  const handed = await f.request('/v1/resources/' + kept.json.resource.id + '/envelopes/' + f.app.keys.agentId, { ...as, method: 'PUT', data: { wrapped: b64(resealed(sealed, made, f.app.keys.publicKeyOf(f.app.keys.agentId))) } });
  assert.equal(handed.status, 200, handed.text);
  assert.deepEqual((await f.request('/v1/injections', { ...as, method: 'POST', data: { names: [{ name: 'mine', as: 'MINE' }] } })).json.injection.environment, { MINE: 'mine' });
});
// The owner opens its own envelope and seals the key for one more recipient, as a client does.
function resealed(sealed, own, recipientPublicKey) {
  const contentKey = open(Buffer.from(sealed.envelopes[USER_A], 'base64url'), own.privateKey);
  return seal(contentKey, recipientPublicKey);
}

test('封筒は共有できる者が渡し、Foundationに封をさせることもでき、鍵のない相手には渡せない', async t => {
  const f = await fixture(t), reader = await f.request('/v1/principals', { method: 'POST', data: { name: 'reader', key: true } });
  const kept = await f.keep('secret', 'shared', 'shared-value');
  const path = '/v1/resources/' + kept.json.resource.id + '/envelopes/' + reader.json.principal.id;
  const noKey = await f.request(path, { method: 'POST', data: {} });
  assert.equal(noKey.status, 409); assert.equal(noKey.json.error.code, 'no_key');
  const own = await f.keyOf({ token: reader.json.token, anonymous: true });
  assert.equal((await f.request(path, { method: 'POST', data: {} })).status, 200, 'Foundation seals it from its own envelope');
  const shown = await f.request('/v1/resources/' + kept.json.resource.id + '/content', { token: reader.json.token, anonymous: true });
  assert.equal(shown.status, 403, 'an envelope alone reaches nothing: the line decides');
  f.app.principals.relate(reader.json.principal.id, 'viewer', 'resource', kept.json.resource.id);
  const read = await f.request('/v1/resources/' + kept.json.resource.id + '/content', { token: reader.json.token, anonymous: true });
  assert.equal(read.status, 200); assert.equal(read.text, 'shared-value');
  assert.deepEqual(read.json.recipients.map(one => one.principal_id).sort(), [USER_A, f.app.keys.agentId, own.id].sort());
  assert.equal((await f.request(path, { method: 'DELETE', data: {} })).status, 200);
  const gone = await f.request('/v1/resources/' + kept.json.resource.id + '/content', { token: reader.json.token, anonymous: true });
  assert.equal(gone.json.envelope, null);
  assert.equal((await f.request(path, { method: 'DELETE', data: {} })).status, 404);
  assert.equal((await f.request(path, { method: 'PUT', token: reader.json.token, anonymous: true, data: { wrapped: 'AAAA' } })).status, 403, 'only one who may share hands envelopes');
  assert.equal((await f.request(path, { method: 'PUT', data: { wrapped: '' } })).json.error.code, 'invalid_envelope');
  const audit = (await f.request('/v1/principals/me/audit-log')).json.entries.map(row => row.action).filter(action => action.startsWith('envelope.'));
  assert.deepEqual(audit, ['envelope.dropped', 'envelope.kept']);
});

test('保管の依頼は宛先を示し、読み返す依頼では頼んだ側も宛先に入って、CLIがその封筒を開く', async t => {
  const f = await fixture(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-read-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const machine = await f.request('/v1/principals', { method: 'POST', anonymous: true, data: { kind: 'key', name: 'machine' } });
  const keyPath = join(dir, 'key'), env = { ...process.env, FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  await writeFile(keyPath, machine.json.token, { mode: 0o600 });
  const cli = args => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['cli/runtime.mjs', ...args], { env });
    let out = '', err = '';
    child.stdout.on('data', part => { out += part; }); child.stderr.on('data', part => { err += part; });
    child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
  });
  // The first run makes the machine's credential and publishes its key.
  const first = await cli(['api', 'GET', '/v1/principals/me/key']);
  assert.equal(first.code, 0, first.err);
  const file = JSON.parse(await readFile(keyPath, 'utf8'));
  assert.match(file.key.private_key, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(JSON.parse(first.out).key.public_key, b64(publicKeyOf(Buffer.from(file.key.private_key, 'base64url'))));
  // Approved to act for the owner first, as a machine is; then it asks them to keep two values, one to read back.
  const approval = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: machine.json.token, data: { authorization_details: [{ type: 'relation', relation: 'agent' }] } });
  assert.equal((await f.request('/v1/requests/' + approval.json.request.id + '/grant', { method: 'POST', data: { user_code: approval.json.request.user_code } })).status, 200);
  const asked = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: machine.json.token, data: { authorization_details: [{ type: 'secret', fields: [{ name: 'app/id', label: 'ID', readable: true }, { name: 'app/secret', label: 'Secret' }] }], binding_message: '設定に使います。', to: USER_A } });
  assert.equal(asked.status, 201, asked.text);
  const shown = (await f.request('/v1/requests/' + asked.json.request.id)).json.request;
  assert.deepEqual(shown.recipients.map(one => one.principal_id), [USER_A, f.app.keys.agentId, machine.json.principal.id]);
  const granted = await f.request('/v1/requests/' + asked.json.request.id + '/grant', { method: 'POST', data: { entries: [{ name: 'app/id', content: 'id-123' }, { name: 'app/secret', content: 'very-secret' }] } });
  assert.equal(granted.status, 200, granted.text);
  const read = await cli(['read', 'app/id']);
  assert.equal(read.code, 0, read.err);
  assert.equal(read.out, 'id-123');
  const refused = await cli(['read', 'app/secret']);
  assert.equal(refused.code, 1);
  assert.doesNotMatch(refused.out + refused.err, /very-secret/);
});

test('サーバー自身のプリンシパルは Foundation Agent と名乗り、前の名前で作られていたものもそう名乗り直す', async t => {
  const { Keys } = await import('../src/keys.mjs');
  const f = await fixture(t), db = f.app.store.db, id = f.app.keys.agentId;
  const name = () => db.prepare('SELECT name FROM principals WHERE id=?').get(id).name;
  assert.equal(name(), 'Foundation Agent');
  db.prepare("UPDATE principals SET name='Foundation' WHERE id=?").run(id);
  assert.equal(new Keys(f.app.store).agentId, id, 'the same principal');
  assert.equal(name(), 'Foundation Agent');
});
