import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { CustodyClient } from '../shared/client.js';
import { fingerprint } from '../shared/authority.js';
import { ContentTypes, reveal } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';
import { signKeyring } from '../shared/keyring.js';
import { JournalTrust } from '../runtime/trust.js';

test('一台で検証した公開鍵を、同じプリンシパルのほかの端末も検証済みとして使い、その相手に封じ直す', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const ai = await f.person('Agent');
  const device = () => new CustodyClient(f.api(f.owner.token), f.config.origin, f.owner.binding, f.owner.keys,
    new JournalTrust(new MemoryJournal()));
  const saved = await f.client.save('Token', encode('owner value'), await f.client.policy(f.owner.actor.id, ContentTypes.value));
  await f.db.pool.query("INSERT INTO relations(subject_id,relation,principal_id) VALUES($1,'delegate',$2)", [ai.actor.id, f.owner.actor.id]);
  assert.equal(await device().verifiedIdentity(ai.actor.id), false);

  await device().trustIdentity(ai.actor.id, await fingerprint(ai.binding));
  const other = device();
  assert.equal(await other.verifiedIdentity(ai.actor.id), true);
  assert.deepEqual((await other.reprotectPending()).failed, []);
  const shared = await f.custody.read(ai.actor, saved.id);
  assert.equal(decode(await reveal(shared.content, ai.binding, ai.keys.encryption)), 'owner value');
});

test('端末に残っている検証の記録を、次に使ったときに検証済みの公開鍵の一覧へ移す', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const ai = await f.person('Agent'), trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(ai.binding);
  await new CustodyClient(f.api(f.owner.token), f.config.origin, f.owner.binding, f.owner.keys, trust).keyring();

  const other = new CustodyClient(f.api(f.owner.token), f.config.origin, f.owner.binding, f.owner.keys,
    new JournalTrust(new MemoryJournal()));
  assert.equal(await other.verifiedIdentity(ai.actor.id), true);
});

test('サーバーが前に見たものより古い一覧を返すと、端末はその一覧を使わない', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const first = await f.person('First'), second = await f.person('Second'), trust = new JournalTrust(new MemoryJournal());
  const device = () => new CustodyClient(f.api(f.owner.token), f.config.origin, f.owner.binding, f.owner.keys, trust);
  await device().trustIdentity(first.actor.id, await fingerprint(first.binding));
  const { rows: [older] } = await f.db.pool.query("SELECT data FROM resources WHERE owner_id=$1 AND kind='keyring'", [f.owner.actor.id]);
  await device().trustIdentity(second.actor.id, await fingerprint(second.binding));

  await f.db.pool.query("UPDATE resources SET data=$2 WHERE owner_id=$1 AND kind='keyring'", [f.owner.actor.id, older.data]);
  await assert.rejects(device().verifiedIdentity(first.actor.id), { code: 'keyring_conflict' });
});

test('委任先は持ち主の検証済みの公開鍵の一覧を読めても書き換えられず、続きの版番号でない一覧は保存しない', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const ai = await f.person('Agent'), stranger = await f.person('Stranger');
  await f.db.pool.query("INSERT INTO relations(subject_id,relation,principal_id) VALUES($1,'delegate',$2)", [ai.actor.id, f.owner.actor.id]);
  await f.client.trustIdentity(stranger.actor.id, await fingerprint(stranger.binding));
  const path = '/api/principals/' + f.owner.actor.id + '/keyring';
  const { keyring } = await f.api(ai.token).json<{ keyring: { version: number } }>(path);

  const forged = await signKeyring({ origin: f.config.origin, ownerId: f.owner.actor.id, signerId: ai.binding.id, revision: 2,
    keys: [{ binding: ai.binding, verifiedAt: new Date().toISOString() }] }, ai.keys.signing);
  await assert.rejects(f.api(ai.token).json(path, { method: 'PUT', body: { version: keyring.version, signature: forged } }),
    { code: 'forbidden' });
  const replayed = await signKeyring({ origin: f.config.origin, ownerId: f.owner.actor.id, signerId: f.owner.binding.id,
    revision: 1, keys: [] }, f.owner.keys.signing);
  await assert.rejects(f.api(f.owner.token).json(path, { method: 'PUT', body: { version: keyring.version, signature: replayed } }),
    { code: 'changed' });
  const owner = new CustodyClient(f.api(f.owner.token), f.config.origin, f.owner.binding, f.owner.keys, f.client.trust);
  assert.equal(await owner.verifiedIdentity(stranger.actor.id), true);
  assert.equal(await owner.verifiedIdentity(ai.actor.id), false);
});
