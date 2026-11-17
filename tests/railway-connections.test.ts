import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';

const endpoint = 'https://backboard.railway.com/graphql/v2';
const methods = [
  { id: 'railway:token', field: 'token', output: 'RAILWAY_API_TOKEN' },
  { id: 'railway:project-token', field: 'projectToken', output: 'RAILWAY_TOKEN' },
] as const;

test('Railwayのトークンだけを暗号化して登録し、CLI用のトークンとAPIのURLを手元のコマンドへ渡す', async t => {
  for (const method of methods) await t.test(method.id, async t => {
    const f = await flowFixture();
    t.after(f.close);
    const token = 'private-railway-test-token';
    const connection = await f.saveConnection({ methodId: method.id, fields: { [method.field]: token } });
    assert.equal(connection.kind, 'connection');
    if (connection.kind !== 'connection') return;
    assert.deepEqual(connection.data.services, [{ id: 'railway', name: 'Railway' }]);
    const stored = await f.client.read(connection.id);
    assert.equal(JSON.stringify({ connection, content: stored.content }).includes(token), false);
    const used = await f.inputs([method.output, 'RAILWAY_API_URL'].map(name => ({ name, source: { id: connection.id, output: name } })));
    assert.deepEqual(used.environment, { [method.output]: token, RAILWAY_API_URL: endpoint });
  });
});

test('Railwayの同じ接続を再接続し、更新したトークンを手元のコマンドへ渡す', async t => {
  for (const method of methods) await t.test(method.id, async t => {
    const f = await flowFixture();
    t.after(f.close);
    const first = await f.saveConnection({ methodId: method.id, fields: { [method.field]: 'first-token' } });
    const updated = await f.saveConnection({ methodId: method.id, connectionId: first.id,
      fields: { [method.field]: 'updated-token' } });
    assert.equal(updated.id, first.id);
    const used = await f.inputs([{ name: method.output, source: { id: updated.id, output: method.output } }]);
    assert.equal(used.environment[method.output], 'updated-token');
  });
});
