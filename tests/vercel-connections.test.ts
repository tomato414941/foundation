import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';

test('Vercelのトークンを暗号化して保存し、再接続で更新したトークンとAPIのURLを手元のコマンドへ渡す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const service = (await f.context.catalog.list(f.owner.actor)).find(item => item.id === 'vercel')!;
  assert.equal(service.name, 'Vercel');
  assert.equal(service.methods.token!.availability, 'ready');
  const first = await f.saveConnection({ methodId: service.methods.token!.id, fields: { token: 'first-vercel-token' } });
  if (first.kind !== 'connection') throw new Error('Expected a saved connection.');
  assert.deepEqual(first.data.services, [{ id: 'vercel', name: 'Vercel' }]);
  const updated = await f.saveConnection({ methodId: 'vercel:token', connectionId: first.id,
    fields: { token: 'updated-vercel-token' } });
  assert.equal(updated.id, first.id);
  const stored = await f.client.read(updated.id);
  assert.equal(JSON.stringify({ updated, content: stored.content }).includes('updated-vercel-token'), false);
  const used = await f.inputs(['VERCEL_TOKEN', 'VERCEL_API_URL'].map(name => ({ name, source: { id: updated.id, output: name } })));
  assert.deepEqual(used.environment, { VERCEL_TOKEN: 'updated-vercel-token', VERCEL_API_URL: 'https://api.vercel.com' });
});
