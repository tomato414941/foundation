import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { LegacySecrets } from '../server/legacy-secrets.js';
import { CustodyClient, type JsonApi } from '../shared/client.js';
import { MemoryJournal } from './delegation-support.js';
import { JournalTrust } from '../runtime/trust.js';
import { encode, decode, open, seal } from '../shared/encryption.js';
import { canonical, hash } from '../shared/authority.js';
import { protect, reveal, useContent, type ExecutionIntent } from '../shared/custody.js';
import { ApiError } from '../cli/src/client.js';
import { DomainError } from '../server/errors.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';

async function setup(t: TestContext) {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person(), agent = await f.person('Agent'), stranger = await f.person('Stranger');
  await f.principals.relate(owner.actor, agent.actor.id, 'agent', owner.actor.id);
  const legacy = new LegacySecrets(f.custody), id = crypto.randomUUID(), bytes = encode('legacy-sensitive-token');
  const sealed = await seal(bytes, [{ id: owner.actor.id, publicKey: owner.keys.publicKey }], 'resource:' + id);
  const resource = await f.resources.insert(owner.actor.id, 'secret', 'Legacy secret',
    { bytes: bytes.length, allowUse: true, recipients: [owner.actor.id] }, { id, sealed });
  const api: JsonApi = { async json(path, options = {}, schema) {
    try {
      const value = path === '/api/migrations/secrets' ? await legacy.pending(owner.actor)
        : path.endsWith('/legacy-secret') ? options.method === 'POST'
          ? await f.resources.view(owner.actor, await legacy.complete(owner.actor, options.body as Parameters<typeof legacy.complete>[1]))
          : await legacy.plan(owner.actor, id)
        : await f.custody.read(owner.actor, id);
      return schema ? schema.parse(value) : value as never;
    } catch (error) {
      if (error instanceof DomainError) throw new ApiError(error.code, error.status, error.message);
      throw error;
    }
  } };
  const trust = new JournalTrust(new MemoryJournal()),
    client = new CustodyClient(api, f.config.origin, owner.binding, owner.keys, trust);
  return { ...f, owner, agent, stranger, legacy, id, bytes, resource, client, trust };
}

test('既存の秘密を読むと端末側で移行し、所有者の値とエージェントの使用権限を保つ', async t => {
  const f = await setup(t);
  const item = await f.client.read(f.id);
  assert.equal(decode(await f.client.reveal(f.id)), decode(f.bytes));
  assert.equal(item.version, f.resource.version + 1);
  assert.deepEqual(item.content.policy.readers.map(reader => reader.principalId), [f.owner.actor.id]);
  assert.deepEqual(item.content.policy.grants.map(grant => grant.actor.principalId), [f.agent.actor.id]);
  await assert.rejects(reveal(item.content, f.agent.binding, f.agent.keys.encryption));
  const intent: ExecutionIntent = {
    format: 1, id: crypto.randomUUID(), origin: f.config.origin, ownerId: f.owner.actor.id,
    actor: f.agent.binding, executor: f.agent.binding, environmentId: f.agent.binding.id,
    environmentDigest: await hash(f.agent.binding), operation: 'command', operationDigest: await hash({}),
    functionDigest: null, sources: [{ id: f.id, kind: 'secret', policyDigest: await hash(item.content.policy), materialRevision: 1 }],
    resultRecipients: [f.agent.binding], createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString(),
  };
  assert.equal(decode(await useContent(item.content, intent, f.agent.keys)), decode(f.bytes));
  await assert.rejects(useContent(item.content, { ...intent, actor: f.stranger.binding, executor: f.stranger.binding }, f.stranger.keys));
  await f.client.migrateSecrets();
  assert.equal((await f.resources.get(f.id)).version, item.version);
  assert.equal((await f.db.all("SELECT * FROM audit_log WHERE action='secret.migrate'")).length, 1);
});

test('使用だけを許可されたプリンシパルからの移行を拒否し、旧データを保持する', async t => {
  const f = await setup(t);
  await assert.rejects(f.legacy.plan(f.agent.actor, f.id), { code: 'forbidden' });
  await assert.rejects(f.legacy.plan(f.stranger.actor, f.id), { code: 'forbidden' });
  assert.deepEqual((await f.resources.get(f.id)).sealed, f.resource.sealed);
  assert.equal(decode(await open(f.resource.sealed!, f.owner.keys.encryption, f.owner.actor.id, 'resource:' + f.id)), decode(f.bytes));
});

test('移行の確認後にデータや権限が変わると旧データを保持し、最新状態で再試行する', async t => {
  const f = await setup(t);
  const plan = await f.legacy.plan(f.owner.actor, f.id);
  const content = await protect(f.bytes, plan.policy, 1, f.owner.binding, f.owner.keys);
  await f.db.pool.query("DELETE FROM relations WHERE subject_id=$1 AND principal_id=$2 AND relation='agent'", [f.agent.actor.id, f.owner.actor.id]);
  await assert.rejects(f.legacy.complete(f.owner.actor, { name: plan.name, version: plan.version, content }), { code: 'changed' });
  assert.deepEqual((await f.resources.get(f.id)).sealed, f.resource.sealed);
  const migrated = await f.client.read(f.id);
  assert.deepEqual(migrated.content.policy.grants, []);
});

test('保存中の障害では旧データを復号できる状態に保ち、再実行で移行を完了する', async t => {
  const f = await setup(t);
  await f.db.pool.query(`CREATE FUNCTION fail_migration() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'simulated migration failure'; END $$`);
  await f.db.pool.query('CREATE TRIGGER fail_migration BEFORE INSERT ON resource_custody FOR EACH ROW EXECUTE FUNCTION fail_migration()');
  await assert.rejects(f.client.read(f.id), /simulated migration failure/);
  assert.deepEqual((await f.resources.get(f.id)).sealed, f.resource.sealed);
  assert.equal((await f.resources.get(f.id)).version, f.resource.version);
  await f.db.pool.query('DROP TRIGGER fail_migration ON resource_custody');
  assert.equal(decode(await f.client.reveal(f.id)), decode(f.bytes));
});

test('同時に移行する端末は先に保存した内容を検証し、同じ秘密を重複更新しない', async t => {
  const f = await setup(t);
  await Promise.all([f.client.migrateSecret(f.id), f.client.migrateSecret(f.id)]);
  assert.equal((await f.resources.get(f.id)).version, f.resource.version + 1);
  assert.equal(decode(await f.client.reveal(f.id)), decode(f.bytes));
});

test('以前確認した鍵や署名付きデータと食い違う移行を拒否する', async t => {
  const f = await setup(t);
  const altered = { ...f.agent.binding, generation: 2, previous: await hash(f.agent.binding) };
  await f.trust.rememberBinding(altered);
  await assert.rejects(f.client.migrateSecret(f.id), /recipient changed keys/);
  assert.deepEqual((await f.resources.get(f.id)).sealed, f.resource.sealed);
  await f.trust.rememberBinding(f.agent.binding);
  const plan = await f.legacy.plan(f.owner.actor, f.id);
  await f.trust.rememberContent(await protect(f.bytes, plan.policy, 1, f.owner.binding, f.owner.keys));
  await assert.rejects(f.client.migrateSecret(f.id), /already observed signed content/);
  assert.equal(canonical((await f.resources.get(f.id)).sealed), canonical(f.resource.sealed));
});

test('HTTP APIで所有者が移行し、同じ保存要求を再送しても版と値を保つ', async t => {
  const f = await setup(t);
  const context = await createContext(f.config, { db: f.db, mailer: f.mailer }), app = await buildApp(context);
  t.after(() => app.close());
  const url = '/api/resources/' + f.id + '/legacy-secret';
  const agent = await app.inject({ url, headers: { authorization: 'Bearer ' + f.agent.token } });
  assert.equal(agent.statusCode, 403, agent.body);
  const headers = { authorization: 'Bearer ' + f.owner.token };
  const response = await app.inject({ url, headers });
  assert.equal(response.statusCode, 200, response.body);
  const plan = response.json(), content = await protect(f.bytes, plan.policy, 1, f.owner.binding, f.owner.keys);
  const payload = { name: plan.name, version: plan.version, content };
  const changedPolicy = { ...plan.policy, readers: [...plan.policy.readers, f.stranger.binding] };
  const rejected = await app.inject({ url, method: 'POST', headers,
    payload: { ...payload, content: await protect(f.bytes, changedPolicy, 1, f.owner.binding, f.owner.keys) } });
  assert.equal(rejected.statusCode, 409, rejected.body);
  for (let attempt = 0; attempt < 2; attempt++) {
    const saved = await app.inject({ url, method: 'POST', headers, payload });
    assert.equal(saved.statusCode, 200, saved.body);
    assert.equal(saved.json().version, f.resource.version + 1);
  }
  assert.equal(decode(await reveal((await f.custody.get(f.id)), f.owner.binding, f.owner.keys.encryption)), decode(f.bytes));
});
