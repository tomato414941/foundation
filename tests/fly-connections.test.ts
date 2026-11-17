import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';

test('Flyのトークンを暗号化して保存し、選んだ接続だけを更新して手元のコマンドへ渡す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const tokens = ['FlyV1 fm2_first_token,fm2_discharge', 'FlyV1 fm2_second_token'];
  const connections = [];
  for (const token of tokens) {
    const saved = await f.saveConnection({ methodId: 'fly:token', name: 'Fly.io', fields: { token } });
    if (saved.kind !== 'connection') throw new Error('Expected a saved connection.');
    assert.deepEqual(saved.data.services, [{ id: 'fly', name: 'Fly.io' }]);
    const encrypted = await f.client.read(saved.id);
    assert.equal(JSON.stringify({ saved, content: encrypted.content }).includes(token), false);
    connections.push(saved);
  }
  assert.notEqual(connections[0]!.id, connections[1]!.id);
  const updated = await f.saveConnection({ methodId: 'fly:token', connectionId: connections[0]!.id,
    name: connections[0]!.name, fields: { token: 'FlyV1 fm2_updated_token' } });
  assert.equal(updated.id, connections[0]!.id);
  const used = await f.inputs(connections.map((connection, index) =>
    ({ name: 'FLY_API_TOKEN_' + index, source: { id: connection.id, output: 'FLY_API_TOKEN' } })));
  assert.deepEqual(used.environment, { FLY_API_TOKEN_0: 'FlyV1 fm2_updated_token', FLY_API_TOKEN_1: 'FlyV1 fm2_second_token' });
});
