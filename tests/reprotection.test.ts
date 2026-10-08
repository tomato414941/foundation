import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { hash } from '../shared/authority.js';
import { firstFormat } from './legacy-support.js';
import { ContentTypes, Operations, reveal } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';
import type { JsonValue } from '../shared/contracts.js';

async function stored(f: Awaited<ReturnType<typeof flowFixture>>, id: string, kind: 'variable' | 'connection',
  content: unknown, data: Record<string, JsonValue>) {
  await f.resources.insert(f.owner.actor.id, kind, kind === 'variable' ? 'API token' : 'Provider account', data, { id });
  await f.db.pool.query('INSERT INTO resource_custody(resource_id,content) VALUES($1,$2)', [id, JSON.stringify(content)]);
}

test('旧い形式の項目を待ち行列に示し、所有者の端末が同じ内容と宛先のまま現在の形式へ封じ直す', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const variable = crypto.randomUUID(), connection = crypto.randomUUID();
  await stored(f, variable, 'variable', await firstFormat({ origin: f.config.origin, id: variable, ownerId: f.owner.actor.id,
    kind: 'secret', authority: f.owner.binding, keys: f.owner.keys, readers: [f.owner.binding], executor: f.executor.binding,
    operations: ['http', 'command', 'function', 'refresh', 'revoke'], bytes: encode('first-format-value'),
    metadata: { bytes: 18 } }), { bytes: 18 });
  const connectionMetadata = { methodId: 'provider:oauth', methodName: 'Provider', methodKind: 'oauth',
    generation: crypto.randomUUID(), authorizationDigest: await hash({ account: 'account-1' }), appId: null,
    account: 'Account One', accountId: 'account-1', accountVerified: true, scopes: ['read'], scopesStatus: 'reported',
    outputs: ['ACCESS_TOKEN'], state: 'ready' };
  await stored(f, connection, 'connection', await firstFormat({ origin: f.config.origin, id: connection,
    ownerId: f.owner.actor.id, kind: 'connection', authority: f.owner.binding, keys: f.owner.keys,
    readers: [f.owner.binding], executor: f.executor.binding, operations: ['http', 'refresh'],
    bytes: encode('{"token":"first"}'), metadata: connectionMetadata }), connectionMetadata);

  await assert.rejects(f.client.read(variable), { code: 'reprotection_required' });
  assert.deepEqual((await f.client.pendingProtection()).map(item => item.id).sort(), [variable, connection].sort());
  assert.deepEqual((await f.client.reprotectPending()).sort(), [variable, connection].sort());
  assert.deepEqual(await f.client.pendingProtection(), []);

  const value = (await f.client.read(variable)).content;
  assert.equal(value.policy.format, 2);
  assert.equal(value.policy.contentType, ContentTypes.value);
  assert.equal(value.policy.revision, 2);
  assert.equal(value.materialRevision, 2);
  assert.deepEqual(value.policy.grants[0]!.operations, [Operations.http, Operations.command, Operations.function]);
  assert.equal(decode(await reveal(value, f.owner.binding, f.owner.keys.encryption)), 'first-format-value');
  assert.equal((await f.resources.get(variable)).kind, 'variable');

  const renewed = (await f.client.read(connection)).content;
  assert.equal(renewed.policy.contentType, ContentTypes.tokenSet);
  assert.deepEqual(renewed.policy.grants[0]!.operations, [Operations.http, Operations.refresh]);
  assert.equal('methodName' in renewed.metadata || 'account' in renewed.metadata, false);
  const labels = (await f.resources.get(connection)).data;
  assert.equal(labels.methodName, 'Provider');
  assert.equal(labels.account, 'Account One');
  assert.equal(decode(await reveal(renewed, f.owner.binding, f.owner.keys.encryption)), '{"token":"first"}');
});

test('旧い形式の項目を、内容や宛先を変えた形で置き換える依頼を拒否する', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const id = crypto.randomUUID();
  const legacy = await firstFormat({ origin: f.config.origin, id, ownerId: f.owner.actor.id, kind: 'secret',
    authority: f.owner.binding, keys: f.owner.keys, readers: [f.owner.binding], executor: f.executor.binding,
    operations: ['command'], bytes: encode('kept'), metadata: { bytes: 4 } });
  await stored(f, id, 'variable', legacy, { bytes: 4 });
  const resource = await f.resources.get(id);
  const policy = { format: 2 as const, origin: f.config.origin, id, ownerId: f.owner.actor.id, contentType: ContentTypes.value,
    revision: 2, authorities: [f.owner.binding], readers: [f.owner.binding], grants: [], producers: [] };
  const { protect } = await import('../shared/custody.js');
  const content = await protect(encode('replaced'), policy, 2, f.owner.binding, f.owner.keys);
  const response = await f.app.inject({ method: 'PUT', url: '/api/resources/' + id + '/custody',
    headers: { authorization: 'Bearer ' + f.owner.token },
    payload: { name: resource.name, content, version: resource.version } });
  assert.equal(response.statusCode, 409);
  assert.equal(response.json().error.code, 'changed');
  assert.deepEqual((await f.client.pendingProtection()).map(item => item.id), [id]);
});

test('起動時に、旧い種類名の項目と操作履歴の名前を変数の名前へ移す', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  await f.db.pool.query("DELETE FROM schema_migrations WHERE name='variables'");
  await f.db.pool.query('ALTER TABLE resources DROP CONSTRAINT resources_kind_check');
  const id = crypto.randomUUID();
  await f.db.pool.query(
    "INSERT INTO resources(id,owner_id,kind,name,data) VALUES($1,$2,'secret','Old token','{}')", [id, f.owner.actor.id]);
  await f.audit.record(f.owner.actor.id, f.owner.actor.id, 'secret.create', id);
  await f.db.initialize();
  assert.equal((await f.resources.get(id)).kind, 'variable');
  const actions = await f.db.all<{ action: string }>('SELECT action FROM audit_log WHERE target_id=$1', [id]);
  assert.deepEqual(actions.map(row => row.action), ['variable.create']);
});
