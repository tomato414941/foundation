import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { LegacyConnections } from '../server/legacy-connections.js';
import { LegacySecrets } from '../server/legacy-secrets.js';
import { CustodyClient, type JsonApi } from '../shared/client.js';
import { MemoryJournal } from './delegation-support.js';
import { JournalTrust } from '../runtime/trust.js';
import { Connections } from '../runtime/connections.js';
import type { ConnectionBroker } from '../runtime/connections.js';
import { ConnectionOperations } from '../server/connection-operations.js';
import { canonical, hash } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import { MethodDefinition } from '../shared/contracts.js';
import { AppMaterial, ConnectionMaterial, connectionMetadata } from '../shared/connections.js';
import { protect, reveal, useContent, type CustodyContent, type ExecutionIntent } from '../shared/custody.js';
import { decode, encode, open } from '../shared/encryption.js';
import { ApiError } from '../cli/src/client.js';
import { DomainError } from '../server/errors.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';

async function setup(t: TestContext) {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person(), agent = await f.person('Agent'), stranger = await f.person('Stranger');
  await f.principals.relate(owner.actor, agent.actor.id, 'agent', owner.actor.id);
  const legacy = new LegacyConnections(f.custody, f.vault), secrets = new LegacySecrets(f.custody);
  const token = MethodDefinition.parse({ name: 'Legacy token', kind: 'token', config: {
    fields: [{ name: 'token', label: 'Token', secret: true }], outputs: { TOKEN: '/token' },
  } });
  const oauth = MethodDefinition.parse({ name: 'Legacy OAuth', kind: 'oauth', config: {
    authorizeUrl: 'https://provider.example/authorize', tokenUrl: 'https://provider.example/token',
    identity: { url: 'https://provider.example/account', id: '/id', name: '/name' }, scopes: { default: ['read'] },
    outputs: { SECOND_TOKEN: '/accessToken', FIRST_TOKEN: '/accessToken' },
  } });
  const role = MethodDefinition.parse({ name: 'Legacy role', kind: 'role', config: { kind: 'aws' } });
  async function insert(kind: 'token' | 'oauth' | 'role' = 'token', reconnect = false) {
    const id = crypto.randomUUID(), method = { token, oauth, role }[kind];
    const material = { formatVersion: 2, methodId: kind === 'role' ? 'aws:role' : kind === 'token' ? 'render:token' : 'google:oauth', method,
      app: { clientId: kind === 'oauth' ? 'existing-client' : '', fields: {}, ...(kind === 'oauth' ? { clientSecret: 'existing-client-secret' } : {}) },
      ...(kind === 'token' ? { fields: { token: 'existing-token' } } : {}),
      ...(kind === 'oauth' ? { oauth: { accessToken: 'existing-access', refreshToken: 'existing-refresh', expiresAt: Date.now() + 3_600_000,
        scopes: ['read'], account: 'existing-account', accountName: 'Existing account', accountVerified: true,
        scopesStatus: 'reported', extra: {}, facts: { plan: 'existing' } } } : {}),
      ...(kind === 'role' ? { role: { arn: 'arn:aws:iam::123456789012:role/Existing', externalId: 'existing-external-id', region: 'ap-northeast-1' } } : {}),
    };
    const row = await f.resources.insert(owner.actor.id, 'connection', kind + ' ' + id, {
      methodId: material.methodId, methodName: method.name, methodKind: kind, state: reconnect ? 'reconnect' : 'ready',
      appId: null, outputs: kind === 'token' ? ['TOKEN'] : ['ACCESS_TOKEN'],
    }, { id, privateData: await f.vault.encrypt(material, 'resource:' + id) });
    return { id, row, material };
  }
  const first = await insert();
  const api: JsonApi = { async json(path, options = {}, schema) {
    try {
      const id = path.split('/')[3]!;
      const value = path === '/api/migrations/connections' ? await legacy.pending(owner.actor)
        : path.endsWith('/legacy-connection') ? options.method === 'POST'
          ? await f.resources.view(owner.actor, await legacy.complete(owner.actor, options.body as Parameters<typeof legacy.complete>[1]))
          : await legacy.plan(owner.actor, id)
        : path.endsWith('/legacy-secret') ? await secrets.plan(owner.actor, id)
        : await f.custody.read(owner.actor, id);
      return schema ? schema.parse(value) : value as never;
    } catch (error) {
      if (error instanceof DomainError) throw new ApiError(error.code, error.status, error.message);
      throw error;
    }
  } };
  const trust = new JournalTrust(new MemoryJournal()), client = new CustodyClient(api, f.config.origin, owner.binding, owner.keys, trust);
  const state = async (id: string) => ConnectionMaterial.parse(JSON.parse(decode(await client.reveal(id))));
  return { ...f, owner, agent, stranger, legacy, insert, first, client, trust, state };
}
async function intent(content: CustodyContent, actor: { binding: BoundKeys },
  operation: ExecutionIntent['operation'] = 'command'): Promise<ExecutionIntent> {
  return { format: 1, id: crypto.randomUUID(), origin: content.policy.origin, ownerId: content.policy.ownerId,
    actor: actor.binding, executor: actor.binding, environmentId: actor.binding.id, environmentDigest: await hash(actor.binding),
    operation, operationDigest: await hash({}), functionDigest: null,
    sources: [{ id: content.policy.id, kind: content.policy.kind, policyDigest: await hash(content.policy), materialRevision: content.materialRevision }],
    resultRecipients: [actor.binding], createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() };
}

test('接続を読むと端末側で署名して移行し、同じトークンと使用だけの権限を維持する', async t => {
  const f = await setup(t), current = await f.client.read(f.first.id), state = await f.state(f.first.id);
  assert.deepEqual(state.fields, f.first.material.fields);
  assert.equal(current.version, f.first.row.version + 1);
  assert.deepEqual(current.content.policy.readers.map(reader => reader.principalId), [f.owner.actor.id]);
  const agentIntent = await intent(current.content, f.agent);
  const agentState = ConnectionMaterial.parse(JSON.parse(decode(await useContent(current.content, agentIntent, f.agent.keys))));
  assert.equal(agentState.fields!.token, 'existing-token');
  await assert.rejects(reveal(current.content, f.agent.binding, f.agent.keys.encryption));
  await assert.rejects(useContent(current.content, await intent(current.content, f.stranger), f.stranger.keys));
  const runtime = new Connections(f.agent.binding, f.agent.keys, {} as ConnectionBroker, new MemoryJournal(), { send: async () => { throw Error('No network call expected'); } });
  assert.equal((await runtime.outputs(current.content, agentIntent, [current.content], new AbortController().signal)).TOKEN, 'existing-token');
  await f.client.migrateConnections();
  await f.client.migrateConnection(f.first.id);
  assert.equal((await f.resources.get(f.first.id)).version, current.version);
});

test('OAuthのトークン、期限、スコープとアプリ認証情報を一緒に移行する', async t => {
  const f = await setup(t), old = await f.insert('oauth');
  await f.client.migrateConnection(old.id);
  const state = await f.state(old.id), content = await f.custody.get(old.id);
  assert.deepEqual(state.oauth, old.material.oauth);
  assert.deepEqual(content.metadata, await connectionMetadata(state));
  const app = AppMaterial.parse(JSON.parse(decode(await f.client.reveal(state.appId!))));
  assert.equal(app.clientSecret, old.material.app.clientSecret);
  assert.equal(app.clientId, old.material.app.clientId);
  assert.deepEqual(app.fields, old.material.app.fields);
  assert.equal(app.generation, state.appGeneration);
  const appContent = await f.custody.get(state.appId!);
  assert.deepEqual(appContent.policy.grants[0]!.operations, ['refresh', 'revoke']);
  await assert.rejects(useContent(appContent, await intent(appContent, f.agent, 'connect'), f.agent.keys));
  const refreshed = AppMaterial.parse(JSON.parse(decode(await useContent(appContent, await intent(appContent, f.agent, 'refresh'), f.agent.keys))));
  assert.equal(refreshed.clientSecret, 'existing-client-secret');
});

test('IAMロールのARN、外部IDとリージョンを維持して実行先に渡す', async t => {
  const f = await setup(t), old = await f.insert('role');
  await f.client.migrateConnection(old.id);
  const state = await f.state(old.id), content = await f.custody.get(old.id);
  assert.deepEqual(state.role, old.material.role);
  const calls: unknown[] = [], runtime = new Connections(f.agent.binding, f.agent.keys, {} as ConnectionBroker,
    new MemoryJournal(), { send: async () => { throw Error('Unexpected HTTP'); } }, {
      async obtain(arn, externalId, region) { calls.push([arn, externalId, region]); return {
        AWS_ACCESS_KEY_ID: 'assumed-key', AWS_SECRET_ACCESS_KEY: 'assumed-secret', AWS_SESSION_TOKEN: 'session', AWS_DEFAULT_REGION: region,
      }; },
    });
  await runtime.outputs(content, await intent(content, f.agent), [content], new AbortController().signal);
  assert.deepEqual(calls, [[old.material.role!.arn, old.material.role!.externalId, old.material.role!.region]]);
});

test('再接続が必要な接続を移行後もその状態で表示し、再認証まで使用を止める', async t => {
  const f = await setup(t), old = await f.insert('oauth', true);
  await f.client.migrateConnection(old.id);
  const content = await f.custody.get(old.id);
  assert.equal(content.metadata.state, 'reconnect');
  assert.deepEqual((await f.state(old.id)).oauth, old.material.oauth);
  const runtime = new Connections(f.agent.binding, f.agent.keys, {} as ConnectionBroker, new MemoryJournal(), { send: async () => { throw Error('Unexpected network'); } });
  await assert.rejects(runtime.outputs(content, await intent(content, f.agent), [content], new AbortController().signal), { code: 'reconnect_required' });
});

test('使用だけの主体や無関係な主体には移行用の認証情報を渡さない', async t => {
  const f = await setup(t);
  await assert.rejects(f.legacy.plan(f.agent.actor, f.first.id), { code: 'forbidden' });
  await assert.rejects(f.legacy.plan(f.stranger.actor, f.first.id), { code: 'forbidden' });
  const plan = await f.legacy.plan(f.owner.actor, f.first.id);
  await assert.rejects(open(plan.connection.sealed, f.agent.keys.encryption, f.agent.actor.id, 'resource:' + f.first.id));
});

test('途中の障害では接続とアプリをまとめて元に戻し、再試行で移行を完了する', async t => {
  const f = await setup(t), old = await f.insert('oauth');
  await f.db.pool.query(`CREATE FUNCTION fail_connection_migration() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.resource_id='${old.id}' THEN RAISE EXCEPTION 'simulated migration failure'; END IF; RETURN NEW; END $$`);
  await f.db.pool.query('CREATE TRIGGER fail_connection_migration BEFORE INSERT ON resource_custody FOR EACH ROW EXECUTE FUNCTION fail_connection_migration()');
  await assert.rejects(f.client.migrateConnection(old.id), /simulated migration failure/);
  const oldRow = await f.resources.get(old.id);
  assert.deepEqual(await f.vault.decrypt(oldRow.private_data!, 'resource:' + old.id), old.material);
  const plan = await f.legacy.plan(f.owner.actor, old.id);
  assert.ok(plan.app);
  await f.db.pool.query('DROP TRIGGER fail_connection_migration ON resource_custody');
  await f.client.migrateConnection(old.id);
  assert.deepEqual((await f.state(old.id)).oauth, old.material.oauth);
  assert.equal((await f.resources.get(plan.app.id)).kind, 'app');
});

test('同時に移行する端末は同じ接続とアプリを保存し、版を重複更新しない', async t => {
  const f = await setup(t), old = await f.insert('oauth');
  await Promise.all([f.client.migrateConnection(old.id), f.client.migrateConnection(old.id)]);
  assert.deepEqual((await f.state(old.id)).oauth, old.material.oauth);
  assert.equal((await f.resources.get(old.id)).version, old.row.version + 1);
});

test('確認後に権限が変わった場合は最新の移行計画を求める', async t => {
  const f = await setup(t), plan = await f.legacy.plan(f.owner.actor, f.first.id);
  const bytes = await open(plan.connection.sealed, f.owner.keys.encryption, f.owner.actor.id, 'resource:' + f.first.id);
  const content = await protect(bytes, plan.connection.policy, 1, f.owner.binding, f.owner.keys, plan.connection.metadata);
  await f.db.pool.query("DELETE FROM relations WHERE subject_id=$1 AND principal_id=$2 AND relation='agent'", [f.agent.actor.id, f.owner.actor.id]);
  await assert.rejects(f.legacy.complete(f.owner.actor, { digest: plan.digest, connection: { name: plan.connection.name, version: plan.version, content }, app: null }), { code: 'changed' });
  await f.client.migrateConnection(f.first.id);
  assert.deepEqual((await f.custody.get(f.first.id)).policy.grants, []);
});

test('署名付きの履歴と確認済みの鍵を優先して移行計画を検証する', async t => {
  const f = await setup(t);
  await f.trust.rememberBinding({ ...f.agent.binding, generation: 2, previous: await hash(f.agent.binding) });
  await assert.rejects(f.client.migrateConnection(f.first.id), /recipient changed keys/);
  await f.trust.rememberBinding(f.agent.binding);
  const plan = await f.legacy.plan(f.owner.actor, f.first.id);
  await f.trust.rememberContent(await protect(encode('observed content'), plan.connection.policy, 1, f.owner.binding, f.owner.keys, plan.connection.metadata));
  await assert.rejects(f.client.migrateConnection(f.first.id), /already observed signed content/);
});

test('HTTP APIで所有者が接続を移行し、再送時も値と版を保つ', async t => {
  const f = await setup(t), context = await createContext(f.config, { db: f.db, mailer: f.mailer }), app = await buildApp(context);
  t.after(() => app.close());
  const url = '/api/resources/' + f.first.id + '/legacy-connection', headers = { authorization: 'Bearer ' + f.owner.token };
  assert.equal((await app.inject({ url, headers: { authorization: 'Bearer ' + f.agent.token } })).statusCode, 403);
  const response = await app.inject({ url, headers });
  assert.equal(response.statusCode, 200, response.body);
  const plan = response.json(), bytes = await open(plan.connection.sealed, f.owner.keys.encryption, f.owner.actor.id, 'resource:' + f.first.id);
  const content = await protect(bytes, plan.connection.policy, 1, f.owner.binding, f.owner.keys, plan.connection.metadata);
  const payload = { digest: plan.digest, connection: { name: plan.connection.name, version: plan.version, content }, app: null };
  const policy = { ...plan.connection.policy, readers: [...plan.connection.policy.readers, f.stranger.binding] };
  const changed = await app.inject({ url, method: 'POST', headers, payload: { ...payload, connection: { ...payload.connection,
    content: await protect(bytes, policy, 1, f.owner.binding, f.owner.keys, plan.connection.metadata) } } });
  assert.equal(changed.statusCode, 409, changed.body);
  for (let attempt = 0; attempt < 2; attempt++) {
    const saved = await app.inject({ url, method: 'POST', headers, payload });
    assert.equal(saved.statusCode, 200, saved.body);
    assert.equal(saved.json().version, f.first.row.version + 1);
  }
  assert.equal((await f.state(f.first.id)).fields!.token, 'existing-token');
});
