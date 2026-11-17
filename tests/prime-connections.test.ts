import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';

test('Prime IntellectのAPIキーを暗号化して保存し、APIキーとAPIの場所を手元のコマンドへ環境変数で渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const token = 'private-prime-test-key';
  const connection = await f.saveConnection({ methodId: 'prime:token', fields: { token } });
  assert.equal(connection.kind, 'connection');
  if (connection.kind !== 'connection') return;
  assert.deepEqual(connection.data.services, [{ id: 'prime', name: 'Prime Intellect' }]);
  const stored = await f.client.read(connection.id);
  assert.equal(JSON.stringify({ connection, content: stored.content }).includes(token), false);
  const used = await f.inputs(['PRIME_API_KEY', 'PRIME_API_BASE_URL'].map(name => ({ name, source: { id: connection.id, output: name } })));
  assert.deepEqual(used.environment, { PRIME_API_KEY: token, PRIME_API_BASE_URL: 'https://api.primeintellect.ai' });
});
