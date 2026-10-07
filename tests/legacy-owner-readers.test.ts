import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { restoreLegacyOwnerReaders } from '../scripts/restore-legacy-owner-readers.mjs';
import { decode, encode, newEncryptionKey, open, seal } from '../shared/encryption.js';

async function setup() {
  const f = await fixture(), owner = await f.person(), server = await f.person('Foundation');
  await f.db.pool.query("INSERT INTO system_settings(name,value) VALUES('server-identity',$1)", [JSON.stringify({
    id: server.actor.id, publicKey: server.keys.publicKey,
    key: await f.vault.encrypt(server.keys.privateKey, 'server-identity'),
  })]);
  async function secret(name: string, otherRecipient = false) {
    const id = crypto.randomUUID(), recipients = otherRecipient
      ? [{ id: owner.actor.id, publicKey: owner.keys.publicKey }] : [{ id: server.actor.id, publicKey: server.keys.publicKey }];
    const sealed = await seal(encode(name + '-value'), recipients, 'resource:' + id);
    await f.resources.insert(owner.actor.id, 'secret', name,
      { bytes: encode(name + '-value').length, recipients: recipients.map(item => item.id) }, { id, sealed });
    await f.db.pool.query("INSERT INTO grants(resource_id,principal_id,actions) VALUES($1,$2,ARRAY['use'])", [id, server.actor.id]);
    return id;
  }
  const first = await secret('first'), second = await secret('second');
  const repair = (applyPlan?: string) => restoreLegacyOwnerReaders({ db: f.db, vault: f.vault, open, seal }, {
    ownerId: owner.actor.id, expectedCount: 2, applyPlan,
  });
  return { ...f, owner, server, first, second, repair, secret };
}

test('鍵を後から登録した所有者が既存の秘密を開き、実行先も同じ値を使い続ける', async () => {
  const f = await setup();
  try {
    const original = await f.resources.get(f.first);
    const grants = await f.db.all('SELECT * FROM grants ORDER BY resource_id');
    const preview = await f.repair();
    assert.equal(preview.verified, 2);
    assert.equal(preview.changed, 0);
    assert.deepEqual((await f.resources.get(f.first)).sealed, original.sealed);
    assert.equal((await f.repair(preview.planHash)).changed, 2);
    for (const [id, name] of [[f.first, 'first'], [f.second, 'second']]) {
      const resource = await f.resources.get(id!);
      assert.equal(resource.owner_id, f.owner.actor.id);
      assert.equal(resource.version, 2);
      assert.equal(decode(await open(resource.sealed!, f.owner.keys.privateKey, f.owner.actor.id, 'resource:' + id)), name + '-value');
      assert.equal(decode(await open(resource.sealed!, f.server.keys.privateKey, f.server.actor.id, 'resource:' + id)), name + '-value');
    }
    assert.deepEqual(await f.db.all('SELECT * FROM grants ORDER BY resource_id'), grants);
    const again = await f.repair();
    assert.equal(again.verified, 0);
    assert.equal((await f.repair(again.planHash)).changed, 0);
    const log = await f.db.all("SELECT details FROM audit_log WHERE action='secret.restoreOwnerRecipient'");
    assert.equal(log.length, 2);
    assert.equal(log[0]!.details.ownerKeyFingerprint, preview.ownerKeyFingerprint);
  } finally { await f.close(); }
});

test('確認後に所有者の鍵や秘密が変わった場合は、最新の計画での確認を求める', async () => {
  const f = await setup();
  try {
    const preview = await f.repair(), original = await f.resources.get(f.first);
    const replacement = await newEncryptionKey();
    await f.db.pool.query('UPDATE principals SET public_key=$2 WHERE id=$1', [f.owner.actor.id, JSON.stringify(replacement.publicKey)]);
    await assert.rejects(f.repair(preview.planHash), { code: 'plan_changed' });
    assert.deepEqual((await f.resources.get(f.first)).sealed, original.sealed);
    const current = await f.repair();
    await f.db.pool.query('UPDATE resources SET version=version+1 WHERE id=$1', [f.second]);
    await assert.rejects(f.repair(current.planHash), { code: 'plan_changed' });
    assert.deepEqual((await f.resources.get(f.first)).sealed, original.sealed);
  } finally { await f.close(); }
});

test('途中の保存が失敗した場合は全件を元の状態に保ち、次の実行でまとめて完了する', async () => {
  const f = await setup();
  try {
    const preview = await f.repair(), rows = await f.db.all('SELECT * FROM resources ORDER BY id');
    const failedId = rows.at(-1)!.id;
    await f.db.pool.query(`CREATE FUNCTION reject_repair() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
      IF NEW.id='${failedId}' THEN RAISE EXCEPTION 'Simulated storage failure'; END IF;
      RETURN NEW; END $$`);
    await f.db.pool.query('CREATE TRIGGER repair_failure BEFORE UPDATE ON resources FOR EACH ROW EXECUTE FUNCTION reject_repair()');
    await assert.rejects(f.repair(preview.planHash), /Simulated storage failure/);
    assert.deepEqual(await f.db.all('SELECT * FROM resources ORDER BY id'), rows);
    await f.db.pool.query('DROP TRIGGER repair_failure ON resources');
    assert.equal((await f.repair(preview.planHash)).changed, 2);
  } finally { await f.close(); }
});

test('既に本人の鍵で開ける秘密を保持し、確認した件数の秘密だけを対象にする', async () => {
  const f = await setup();
  try {
    const readable = await f.secret('already-readable', true);
    await assert.rejects(f.repair(), { code: 'resource_count_changed' });
    const before = await f.resources.get(readable);
    const options = { ownerId: f.owner.actor.id, expectedCount: 3 };
    const deps = { db: f.db, vault: f.vault, open, seal };
    const plan = await restoreLegacyOwnerReaders(deps, options);
    assert.equal((await restoreLegacyOwnerReaders(deps, { ...options, applyPlan: plan.planHash })).changed, 2);
    assert.deepEqual(await f.resources.get(readable), before);
  } finally { await f.close(); }
});

test('他の読み手を含む秘密はそのまま保持し、全員の鍵を確認する計画を求める', async () => {
  const f = await setup();
  try {
    const reader = await f.person('Reader');
    const sealed = await seal(encode('shared-value'), [
      { id: f.server.actor.id, publicKey: f.server.keys.publicKey },
      { id: reader.actor.id, publicKey: reader.keys.publicKey },
    ], 'resource:' + f.first);
    await f.db.pool.query('UPDATE resources SET sealed=$2 WHERE id=$1', [f.first, JSON.stringify(sealed)]);
    const before = await f.db.all('SELECT * FROM resources ORDER BY id');
    await assert.rejects(f.repair(), { code: 'different_recipients' });
    assert.deepEqual(await f.db.all('SELECT * FROM resources ORDER BY id'), before);
    assert.equal(decode(await open((await f.resources.get(f.first)).sealed!, reader.keys.privateKey,
      reader.actor.id, 'resource:' + f.first)), 'shared-value');
  } finally { await f.close(); }
});
