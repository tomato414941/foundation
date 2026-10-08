import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import * as authority from '../shared/authority.js';
import { encode, decode, seal, open } from '../shared/encryption.js';
import { migrateServerIdentity } from '../scripts/migrate-server-identity.mjs';

async function setup() {
  const f = await fixture(), server = await f.person('Foundation'), owner = await f.person();
  await f.db.pool.query('DELETE FROM principal_key_bindings WHERE principal_id=$1', [server.actor.id]);
  await f.db.pool.query("INSERT INTO system_settings(name,value) VALUES('server-identity',$1)", [JSON.stringify({
    id: server.actor.id, publicKey: server.keys.publicKey, key: await f.vault.encrypt(server.keys.privateKey, 'server-identity'),
  })]);
  await f.db.pool.query("INSERT INTO relations(id,subject_id,principal_id,relation) VALUES($1,$2,$3,'agent')",
    [crypto.randomUUID(), server.actor.id, owner.actor.id]);
  const ciphertext = await seal(encode('existing connection'), [{ id: server.actor.id, publicKey: server.keys.publicKey }], 'connection-check');
  const migrate = (apply = false) => migrateServerIdentity({ db: f.db, vault: f.vault, authority }, { principalId: server.actor.id, apply });
  return { ...f, server, ciphertext, migrate };
}

test('Foundationが同じ暗号鍵とAgent関係を維持して署名鍵を登録し、繰り返し確認できる', async () => {
  const f = await setup();
  try {
    const relationships = await f.db.all('SELECT * FROM relations');
    const before = await f.db.one("SELECT value FROM system_settings WHERE name='server-identity'");
    assert.equal((await f.migrate()).migrated, false);
    assert.deepEqual(await f.db.one("SELECT value FROM system_settings WHERE name='server-identity'"), before);
    const migrated = await f.migrate(true);
    assert.equal(migrated.changed, true);
    const current = await f.bindings.current(f.server.actor.id);
    await authority.verifyBinding(current);
    const stored = await f.db.one("SELECT value FROM system_settings WHERE name='server-identity'");
    const keys = await f.vault.decrypt<authority.IdentityKeys>(stored!.value.keys, 'server-identity:keys');
    assert.equal(await authority.fingerprint(keys.encryption), await authority.fingerprint(f.server.keys.privateKey));
    assert.equal(decode(await open(f.ciphertext, keys.encryption, f.server.actor.id, 'connection-check')), 'existing connection');
    assert.deepEqual(await f.db.all('SELECT * FROM relations'), relationships);
    assert.equal(stored!.value.key, before!.value.key);
    assert.equal((await f.migrate(true)).bindingId, migrated.bindingId);
    assert.equal((await f.migrate()).changed, false);
  } finally { await f.close(); }
});

test('移行保存が失敗した場合も既存鍵で開き、再試行して移行する', async () => {
  const f = await setup();
  try {
    await f.db.pool.query("CREATE FUNCTION reject_identity() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Simulated failure'; END $$");
    await f.db.pool.query('CREATE TRIGGER reject_identity BEFORE UPDATE ON system_settings FOR EACH ROW EXECUTE FUNCTION reject_identity()');
    await assert.rejects(f.migrate(true), /Simulated failure/);
    assert.equal(decode(await open(f.ciphertext, f.server.keys.privateKey, f.server.actor.id, 'connection-check')), 'existing connection');
    await f.db.pool.query('DROP TRIGGER reject_identity ON system_settings');
    assert.equal((await f.migrate(true)).changed, true);
  } finally { await f.close(); }
});

test('本人の既存暗号鍵と一致する鍵だけを新形式に登録する', async () => {
  const f = await setup();
  try {
    const other = await authority.newIdentityKeys();
    await f.db.pool.query('UPDATE principals SET public_key=$2 WHERE id=$1', [f.server.actor.id, JSON.stringify(authority.publicPart(other.encryption))]);
    await assert.rejects(f.migrate(true), /encryption_key_mismatch/);
    await f.db.pool.query('UPDATE principals SET public_key=$2 WHERE id=$1', [f.server.actor.id, JSON.stringify(f.server.keys.publicKey)]);
    assert.equal((await f.migrate(true)).changed, true);
  } finally { await f.close(); }
});
