import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fixture } from './support.js';
import { KeyMigration } from '../server/key-migration.js';
import { encode, decode, newEncryptionKey, open, seal, unwrap, wrap } from '../shared/encryption.js';
import { JweSealed, PublicKey, Sealed } from '../shared/contracts.js';
import type { KeyMigrationInput } from '../shared/key-migration.js';

async function setup(t: test.TestContext) {
  const f = await fixture();
  t.after(() => f.close());
  const sample = JSON.parse(await readFile(new URL('./fixtures/legacy-encryption.json', import.meta.url), 'utf8'));
  const owner = await f.person(), reader = await f.person('Reader');
  const id = owner.actor.id, publicKey = PublicKey.parse(sample.publicKey);
  await f.db.pool.query('UPDATE principals SET public_key=$2 WHERE id=$1', [id, JSON.stringify(publicKey)]);
  const passkeys = [];
  for (let i = 0; i < 2; i++) {
    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const cose = Buffer.concat([Buffer.from('a5010203262001215820', 'hex'), Buffer.from(jwk.x!, 'base64url'),
      Buffer.from('225820', 'hex'), Buffer.from(jwk.y!, 'base64url')]);
    const credentialId = randomUUID(), identifier = randomBytes(32).toString('base64url'), prf = randomBytes(32);
    await f.db.pool.query(
      "INSERT INTO credentials(id,principal_id,kind,name,identifier,data,private_wrap) VALUES($1,$2,'passkey',$3,$4,$5,$6)",
      [credentialId, id, 'Passkey ' + (i + 1), identifier,
        JSON.stringify({ publicKey: cose.toString('base64url'), counter: 0, transports: ['internal'] }),
        await wrap(sample.privateKey, prf, id)],
    );
    passkeys.push({ id: credentialId, identifier, privateKey: pair.privateKey, prf });
  }
  const session = await f.authentication.session(id, passkeys[0]!.id);
  const migration = new KeyMigration(f.resources, f.authentication);
  const legacyId = randomUUID(), sharedId = randomUUID();
  await f.resources.insert(id, 'secret', 'Legacy secret', { bytes: encode(sample.plaintext).length, recipients: [id] },
    { id: legacyId, sealed: Sealed.parse({ ...sample.sealed, aad: Buffer.from('resource:' + legacyId).toString('base64url'),
      recipients: sample.sealed.recipients.map((recipient: { header: object }) => ({ ...recipient, header: { ...recipient.header, kid: id } })) }) });
  const recipients = [{ id, publicKey }, { id: reader.actor.id, publicKey: reader.keys.publicKey }, { id: f.identity.id, publicKey: f.identity.publicKey }];
  await f.resources.insert(id, 'secret', 'Shared secret', { bytes: 12, recipients: recipients.map(item => item.id) },
    { id: sharedId, sealed: await seal(encode('shared-value'), recipients, 'resource:' + sharedId) });
  await f.resources.grant(owner.actor, await f.resources.get(sharedId), f.identity.id, ['use']);
  const newKey = await newEncryptionKey();
  async function prepare() {
    const plan = await migration.start(session.actor, id, 'browser', newKey.publicKey);
    const input: KeyMigrationInput = { challengeId: plan.challengeId, credentials: [], items: [] };
    for (const item of plan.credentials) {
      const credential = passkeys.find(passkey => passkey.id === item.id)!;
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: item.options.challenge, origin: f.config.origin, crossOrigin: false }));
      const authenticatorData = Buffer.concat([createHash('sha256').update('foundation.test').digest(), Buffer.from([5, 0, 0, 0, 1])]);
      const signature = sign('sha256', Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]), credential.privateKey);
      input.credentials.push({ id: item.id, wrappedKey: await wrap(newKey.privateKey, credential.prf, id), credential: {
        id: credential.identifier, rawId: credential.identifier, type: 'public-key', clientExtensionResults: {},
        response: { clientDataJSON: clientDataJSON.toString('base64url'), authenticatorData: authenticatorData.toString('base64url'), signature: signature.toString('base64url') },
      } });
    }
    for (const item of plan.items) {
      const content = await open(item.sealed, sample.privateKey, id, 'resource:' + item.id);
      input.items.push({ id: item.id, version: item.version, sealed: JweSealed.parse(await seal(content,
        item.recipients.map(recipient => recipient.id === id ? { ...recipient, publicKey: newKey.publicKey } : recipient), 'resource:' + item.id)) });
    }
    return input;
  }
  async function checkOriginal() {
    assert.deepEqual((await f.principals.get(id)).public_key, publicKey);
    for (const credential of passkeys) {
      const row = await f.db.one<{ private_wrap: string }>('SELECT private_wrap FROM credentials WHERE id=$1', [credential.id]);
      const key = await unwrap(row!.private_wrap, credential.prf, id);
      assert.equal(decode(await open((await f.resources.get(legacyId)).sealed!, key, id, 'resource:' + legacyId)), sample.plaintext);
    }
  }
  return { f, id, owner, reader, publicKey, sample, passkeys, session, migration, legacyId, sharedId, newKey, prepare, checkOriginal };
}

test('本人の全パスキーで認証して暗号鍵を更新し、各パスキーと共有相手で同じシークレットを復号する', async t => {
  const s = await setup(t), input = await s.prepare();
  await s.migration.commit(s.session.actor, s.id, 'browser', input);
  assert.deepEqual((await s.f.principals.get(s.id)).public_key, s.newKey.publicKey);
  for (const credential of s.passkeys) {
    const row = await s.f.db.one<{ private_wrap: string }>('SELECT private_wrap FROM credentials WHERE id=$1', [credential.id]);
    const key = await unwrap(row!.private_wrap, credential.prf, s.id);
    assert.equal(decode(await open((await s.f.resources.get(s.legacyId)).sealed!, key, s.id, 'resource:' + s.legacyId)), s.sample.plaintext);
    assert.equal(decode(await open((await s.f.resources.get(s.sharedId)).sealed!, key, s.id, 'resource:' + s.sharedId)), 'shared-value');
  }
  const shared = await s.f.resources.get(s.sharedId);
  assert.equal(decode(await open(shared.sealed!, s.reader.keys.privateKey, s.reader.actor.id, 'resource:' + shared.id)), 'shared-value');
  assert.equal(decode(await s.f.identity.open(shared.sealed!, 'resource:' + shared.id)), 'shared-value');
  assert.equal(await s.f.authorization.resource({ id: s.f.identity.id }, shared, 'use'), true);
  await assert.rejects(s.migration.commit(s.session.actor, s.id, 'browser', input), { code: 'invalid_challenge' });
  const freshId = randomUUID();
  const fresh = await seal(encode('new-value'), [{ id: s.id, publicKey: s.newKey.publicKey }], 'resource:' + freshId);
  await s.f.resources.createSecret(s.session.actor, s.id, { kind: 'secret', id: freshId, name: 'New secret', sealed: fresh, bytes: 9, allowUse: false });
  const staleId = randomUUID();
  await assert.rejects(s.f.resources.createSecret(s.session.actor, s.id, { kind: 'secret', id: staleId, name: 'Concurrent secret',
    sealed: await seal(encode('stale-value'), [{ id: s.id, publicKey: s.publicKey }], 'resource:' + staleId), bytes: 11, allowUse: false }), { code: 'encryption_key_changed' });
  await assert.rejects(s.f.authentication.setWrap(s.session.actor, s.id, s.passkeys[0]!.id,
    await wrap(s.sample.privateKey, s.passkeys[0]!.prf, s.id), s.publicKey), { code: 'encryption_key_changed' });
});

test('切り替え時に共有相手が不足していた場合も移行前の全パスキーでシークレットを復号する', async t => {
  const s = await setup(t), input = await s.prepare();
  input.items.find(item => item.id === s.sharedId)!.sealed.recipients.pop();
  await assert.rejects(s.migration.commit(s.session.actor, s.id, 'browser', input), { code: 'missing_recipient' });
  await s.checkOriginal();
});

test('移行中に編集したシークレットを保持して新しい移行を要求する', async t => {
  const s = await setup(t), input = await s.prepare();
  await s.f.resources.rename(s.session.actor, await s.f.resources.get(s.legacyId), 'Edited during migration');
  await assert.rejects(s.migration.commit(s.session.actor, s.id, 'browser', input), { code: 'migration_changed' });
  assert.equal((await s.f.resources.get(s.legacyId)).name, 'Edited during migration');
  await s.checkOriginal();
});

test('ブラウザーと今回のパスキー認証を確認して本人による移行を受け付ける', async t => {
  const s = await setup(t), input = await s.prepare();
  await assert.rejects(s.migration.start(s.reader.actor, s.id, 'browser', s.newKey.publicKey), { code: 'forbidden' });
  await assert.rejects(s.migration.commit(s.session.actor, s.id, 'other-browser', input), { code: 'invalid_challenge' });
  const latest = await s.prepare();
  latest.credentials = input.credentials;
  await assert.rejects(s.migration.commit(s.session.actor, s.id, 'browser', latest), { code: 'invalid_passkey' });
  await s.checkOriginal();
});
