import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';

test('Resendの送信専用キーを暗号化して保存し、同じ接続のキーを更新して手元のコマンドへ渡す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const key = 're_sending_test_key';
  const used = async (id: string) =>
    (await f.inputs([{ name: 'RESEND_API_KEY', source: { id, output: 'RESEND_API_KEY' } }])).environment.RESEND_API_KEY;
  const original = await f.saveConnection({ methodId: 'resend:api_key', name: 'Resend delivery', fields: { token: key } });
  if (original.kind !== 'connection') throw new Error('Expected a saved connection.');
  assert.deepEqual(original.data.services, [{ id: 'resend', name: 'Resend' }]);
  const encrypted = await f.client.read(original.id);
  assert.equal(JSON.stringify({ original, content: encrypted.content }).includes(key), false);
  assert.equal(await used(original.id), key);
  const updated = await f.saveConnection({ methodId: 'resend:api_key', connectionId: original.id,
    name: original.name, fields: { token: 're_updated_sending_test_key' } });
  assert.equal(updated.id, original.id);
  assert.equal(await used(updated.id), 're_updated_sending_test_key');
});
