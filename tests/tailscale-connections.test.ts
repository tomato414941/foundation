import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';

test('TailscaleのAPIアクセストークンを暗号化して保存し、再接続で更新したトークンとAPIの場所を手元のコマンドへ渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const service = (await f.context.catalog.list(f.owner.actor)).find(item => item.id === 'tailscale')!;
  assert.equal(service.name, 'Tailscale');
  assert.equal(service.methods['api-access-token']!.availability, 'ready');
  const first = await f.saveConnection({ methodId: service.methods['api-access-token']!.id,
    fields: { token: 'tskey-api-first-test-token' } });
  if (first.kind !== 'connection') throw new Error('Expected a saved connection.');
  assert.deepEqual(first.data.services, [{ id: 'tailscale', name: 'Tailscale' }]);
  const updated = await f.saveConnection({ methodId: 'tailscale:api-access-token', connectionId: first.id,
    fields: { token: 'tskey-api-updated-test-token' } });
  assert.equal(updated.id, first.id);
  const stored = await f.client.read(updated.id);
  assert.equal(JSON.stringify({ updated, content: stored.content }).includes('tskey-api-updated-test-token'), false);
  const used = await f.inputs(['TAILSCALE_API_KEY', 'TAILSCALE_BASE_URL'].map(name => ({ name, source: { id: updated.id, output: name } })));
  assert.deepEqual(used.environment, { TAILSCALE_API_KEY: 'tskey-api-updated-test-token', TAILSCALE_BASE_URL: 'https://api.tailscale.com' });
});

test('TailscaleのAPIアクセストークン以外の鍵を受け付けない', async t => {
  const f = await flowFixture();
  t.after(f.close);
  for (const token of ['tskey-auth-private-test-key', 'tskey-client-private-test-secret']) {
    await assert.rejects(f.saveConnection({ methodId: 'tailscale:api-access-token', fields: { token } }));
  }
});
