import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';

test('Hugging Face接続を暗号化して保存し、HF_TOKENでHub APIを呼び出す', async t => {
  const token = 'hf_test_connection_token';
  const f = await flowFixture(request => {
    assert.equal(request.url, 'https://huggingface.co/api/whoami-v2');
    assert.equal(request.headers?.authorization, 'Bearer ' + token);
    return jsonResponse({ name: 'test-model-owner', type: 'user' });
  });
  t.after(f.close);

  const service = (await f.context.catalog.list(f.owner.actor)).find(item => item.id === 'huggingface');
  assert.ok(service);
  const method = service.methods.token;
  assert.ok(method);
  assert.equal(method.availability, 'ready');

  const started = await f.start({ methodId: method.id, fields: { token }, name: 'Model storage' });
  const review = await f.tick(started.flow.id);
  assert.equal(review.kind, 'review');
  if (review.kind !== 'review') return;
  assert.deepEqual(review.metadata.outputs, ['HF_TOKEN']);

  const saved = await f.accept(started.flow.id);
  assert.equal(saved.kind, 'connection');
  if (saved.kind !== 'connection') return;
  assert.deepEqual(saved.data.services, [{ id: 'huggingface', name: 'Hugging Face' }]);
  assert.equal(JSON.stringify(saved).includes(token), false);
  assert.equal((await f.http(saved.id, 'HF_TOKEN', 'https://huggingface.co/api/whoami-v2'))?.ok, true);
  assert.equal(f.requests.length, 1);
});
