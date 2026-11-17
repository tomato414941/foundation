import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';

test('CloudRiftのAPIキーを暗号化して保存し、同じ接続を更新して手元のコマンドへ渡す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const key = 'cloudrift_initial_test_key';
  const used = async (id: string) =>
    (await f.inputs([{ name: 'CLOUDRIFT_API_KEY', source: { id, output: 'CLOUDRIFT_API_KEY' } }])).environment.CLOUDRIFT_API_KEY;
  const original = await f.saveConnection({ methodId: 'cloudrift:api_key', name: 'CloudRift compute', fields: { token: key } });
  if (original.kind !== 'connection') throw new Error('Expected a saved connection.');
  assert.deepEqual(original.data.services, [{ id: 'cloudrift', name: 'CloudRift' }]);
  const encrypted = await f.client.read(original.id);
  assert.equal(JSON.stringify({ original, content: encrypted.content }).includes(key), false);
  assert.equal(await used(original.id), key);
  const updated = await f.saveConnection({ methodId: 'cloudrift:api_key', connectionId: original.id,
    name: original.name, fields: { token: 'cloudrift_updated_test_key' } });
  assert.equal(updated.id, original.id);
  assert.equal(updated.name, original.name);
  assert.equal(await used(updated.id), 'cloudrift_updated_test_key');
  const reconnected = await f.saveConnection({ methodId: 'cloudrift:api_key', connectionId: updated.id,
    name: updated.name, fields: {} });
  assert.equal(reconnected.id, original.id);
  assert.equal(await used(reconnected.id), 'cloudrift_updated_test_key');
});
