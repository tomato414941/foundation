import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { HttpRequest } from '../shared/contracts.js';
import { Task } from '../shared/runtime-protocol.js';

type Fixture = Awaited<ReturnType<typeof flowFixture>>;
const email = { from: 'Sender <sender@example.com>', to: ['recipient@example.com'], subject: 'Test', text: 'Test message' };
async function send(f: Fixture, connectionId: string, url: string) {
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'http', request: HttpRequest.parse({ connectionId, url, method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify(email) }), save: {},
  });
  await f.executor.tick();
  const completed = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  return { task: completed, result: await f.client.result(completed) };
}

test('Resendの送信専用キーを暗号化して保存し、同じ接続のキーを更新して送信APIを使用する', async t => {
  const f = await flowFixture(request => {
    assert.equal(request.url, 'https://api.resend.com/emails');
    assert.equal(request.method, 'POST');
    assert.deepEqual(JSON.parse(String(request.body)), email);
    return jsonResponse({ id: 'test-email-id' });
  }); t.after(f.close);
  const key = 're_sending_test_key';
  const original = await f.saveConnection({ methodId: 'resend:api_key', name: 'Resend delivery', fields: { token: key } });
  if (original.kind !== 'connection') throw new Error('Expected a saved connection.');
  assert.deepEqual(original.data.services, [{ id: 'resend', name: 'Resend' }]);
  const encrypted = await f.client.read(original.id);
  assert.equal(JSON.stringify({ original, content: encrypted.content }).includes(key), false);
  const sent = await send(f, original.id, 'https://api.resend.com/emails');
  assert.equal(sent.task.state, 'succeeded', JSON.stringify(sent.result));
  const updated = await f.saveConnection({ methodId: 'resend:api_key', connectionId: original.id,
    name: original.name, fields: { token: 're_updated_sending_test_key' } });
  assert.equal(updated.id, original.id);
  const resent = await send(f, updated.id, 'https://api.resend.com/emails');
  assert.equal(resent.task.state, 'succeeded', JSON.stringify(resent.result));
  assert.deepEqual(f.requests.map(request => request.headers?.Authorization),
    ['Bearer re_sending_test_key', 'Bearer re_updated_sending_test_key']);
});

test('ResendのHTTP接続でAPIキーの送信先をResendのAPIホストに限定する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'resend:api_key', fields: { token: 're_private_test_key' } });
  for (const url of ['https://other.example/emails', 'https://api.resend.com.other.example/emails']) {
    const { task, result } = await send(f, connection.id, url);
    assert.equal(task.state, 'failed');
    assert.equal(result?.error?.code, 'invalid_destination');
  }
  assert.equal(f.requests.length, 0);
});
