import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';

test('Anthropicの通常キーとAdminキーを暗号化して保存し、更新した接続のキーを手元のコマンドへ環境変数で渡す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const inputs = [];
  for (const [method, field, output] of [
    ['api_key', 'token', 'ANTHROPIC_API_KEY'], ['admin_key', 'adminKey', 'ANTHROPIC_ADMIN_KEY'],
  ] as const) {
    const original = await f.saveConnection({ methodId: 'anthropic:' + method, fields: { [field]: 'old-key' } });
    if (original.kind !== 'connection') throw new Error('Expected a saved connection.');
    assert.deepEqual(original.data.services, [{ id: 'anthropic', name: 'Anthropic' }]);
    const updated = await f.saveConnection({ methodId: 'anthropic:' + method, connectionId: original.id,
      fields: { [field]: 'updated-' + method } });
    assert.equal(updated.id, original.id);
    const encrypted = await f.client.read(updated.id);
    assert.equal(JSON.stringify({ updated, content: encrypted.content }).includes('updated-' + method), false);
    inputs.push({ name: output, source: { id: updated.id, output } });
  }
  assert.deepEqual((await f.inputs(inputs)).environment,
    { ANTHROPIC_API_KEY: 'updated-api_key', ANTHROPIC_ADMIN_KEY: 'updated-admin_key' });
});
