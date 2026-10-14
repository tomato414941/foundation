import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { Resource, ServiceInputDefinition } from '../shared/contracts.js';
import { Task } from '../shared/runtime-protocol.js';

test('同じ所有者が同名のOpenAI接続を複数保存し、選んだキーだけを更新して使用する', async t => {
  for (const [method, field, output, path] of [
    ['api_key', 'token', 'OPENAI_API_KEY', '/models'],
    ['admin_key', 'adminKey', 'OPENAI_ADMIN_KEY', '/organization/projects'],
  ] as const) await t.test(method, async t => {
    const f = await flowFixture();
    t.after(f.close);
    const connections = [];
    for (const key of ['first-key', 'second-key']) {
      connections.push(await f.saveConnection({ methodId: 'openai:' + method, name: 'OpenAI', fields: { [field]: key } }));
    }
    assert.notEqual(connections[0]!.id, connections[1]!.id);
    const updated = await f.saveConnection({ methodId: 'openai:' + method, connectionId: connections[0]!.id,
      name: 'OpenAI', fields: { [field]: 'updated-first-key' } });
    assert.equal(updated.id, connections[0]!.id);
    for (const connection of connections) {
      assert.equal((await f.http(connection.id, output, 'https://api.openai.com/v1' + path))?.ok, true);
    }
    assert.deepEqual(f.requests.map(request => request.headers.authorization), ['Bearer updated-first-key', 'Bearer second-key']);
  });
});

test('OpenAIのキーと任意のプロジェクト・組織を実行環境へ渡す', async t => {
  for (const specified of [true, false]) await t.test(specified ? '接続先を指定する' : '接続先を省略する', async t => {
    const f = await flowFixture();
    t.after(f.close);
    const connection = await f.saveConnection({ methodId: 'openai:api_key', fields: {
      token: 'model-test-key', ...(specified ? { projectId: 'proj_test', organizationId: 'org-test' } : {}),
    } });
    const expected = { OPENAI_API_KEY: 'model-test-key', OPENAI_PROJECT_ID: specified ? 'proj_test' : '',
      OPENAI_ORG_ID: specified ? 'org-test' : '' };
    const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
      kind: 'command', command: [process.execPath, '-e',
        'const assert=require("node:assert/strict");for(const [name,value] of Object.entries(' + JSON.stringify(expected) +
        '))assert.equal(process.env[name],value);console.log("OpenAI credentials delivered");'],
      inputs: Object.keys(expected).map(name => ({ name, source: { id: connection.id, output: name } })), timeoutSeconds: 10,
    });
    await f.executor.tick();
    const result = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
    assert.equal(result?.ok, true);
    assert.match(JSON.stringify(result), /OpenAI credentials delivered/);
  });
});

test('OpenAIの保存済みキーを組込み方式に移し、同じ接続と共有先で使用する', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const builtin = await f.method('openai:api_key');
  const service = await f.context.catalog.createService(f.owner.actor, f.owner.actor.id, 'OpenAI API',
    ServiceInputDefinition.parse({ name: 'OpenAI API', methods: { api_key: builtin } }));
  const custom = (await f.context.catalog.list(f.owner.actor)).find(item => item.id === service.id)!.methods.api_key!;
  const original = await f.saveConnection({ methodId: custom.id, name: 'OpenAI / project',
    fields: { token: 'saved-openai-key', projectId: 'proj_saved', organizationId: '' } });
  assert.equal((await f.http(original.id, 'OPENAI_API_KEY'))?.ok, true);
  const previous = await f.client.read(original.id);
  await f.client.api.json('/api/resources/' + service.id, { method: 'PATCH', body: { version: service.version, definition: {
    name: 'OpenAI API', methods: { api_key: custom.id, builtin: 'openai:api_key' },
  } } }, Resource);
  const migrated = await f.saveConnection({ methodId: 'openai:api_key', connectionId: original.id,
    name: original.name, fields: { token: '', projectId: 'proj_saved', organizationId: '' } });
  assert.equal(migrated.id, original.id);
  const current = await f.client.read(migrated.id);
  assert.deepEqual(current.content.policy.grants, previous.content.policy.grants);
  assert.deepEqual(current.content.policy.readers, previous.content.policy.readers);
  await f.context.resources.delete(f.owner.actor, await f.context.resources.get(service.id));
  await f.context.resources.delete(f.owner.actor, await f.context.resources.get(custom.id));
  const saved = await f.client.api.json('/api/resources/' + original.id, {}, Resource);
  assert.equal(saved.kind, 'connection');
  if (saved.kind !== 'connection') return;
  assert.equal(saved.data.methodId, 'openai:api_key');
  assert.deepEqual(saved.data.services, [{ id: 'openai', name: 'OpenAI' }]);
  assert.equal((await f.http(saved.id, 'OPENAI_API_KEY', 'https://api.openai.com/v1/models'))?.ok, true);
  assert.equal(f.requests.at(-1)!.headers.authorization, 'Bearer saved-openai-key');
});
