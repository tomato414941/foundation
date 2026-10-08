import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { Webhook, WebhookVerificationError } from 'standardwebhooks';
import { Integrations } from '../server/integrations.js';
import type { Transport } from '../server/transport.js';
import { fixture } from './support.js';

async function integrationFixture(t: TestContext, send?: Transport['send']) {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person();
  const deliveries: Array<{ url: string; body: string; headers: Record<string, string> }> = [];
  const transport: Transport = {
    async send(input) {
      assert.equal(input.method, 'POST');
      assert.equal(input.headers?.['content-type'], 'application/json');
      assert.ok(typeof input.body === 'string');
      assert.ok(input.headers);
      deliveries.push({ url: input.url, body: input.body, headers: input.headers });
      return send ? send(input) : { status: 204, headers: {}, body: new Uint8Array() };
    },
  };
  const integrations = new Integrations(f.db, f.authorization, f.vault, transport, f.config.origin);
  return { ...f, owner, deliveries, integrations };
}

test('標準形式のキーでWebhookを検証し、イベントID・時刻・本文の改ざんを拒否する', async (t) => {
  const f = await integrationFixture(t);
  const { webhookSecret } = await f.integrations.set(f.owner.actor, f.owner.actor.id, {
    webhookUrl: 'https://receiver.example/events',
  });
  assert.ok(webhookSecret);
  assert.match(webhookSecret, /^whsec_[A-Za-z0-9+/]{43}=$/);
  const receiver = new Webhook(webhookSecret);
  const payload = {
    type: 'request.created',
    requestId: randomUUID(),
    message: '承認 "許可"\n完了 🔐',
  };
  await f.integrations.enqueue(f.owner.actor.id, payload);
  const before = Math.floor(Date.now() / 1000);
  await f.integrations.deliver();
  const after = Math.floor(Date.now() / 1000);
  assert.equal(f.deliveries.length, 1);
  const { url, body, headers } = f.deliveries[0]!;
  assert.equal(url, 'https://receiver.example/events');
  assert.match(headers['webhook-id']!, /^[0-9a-f-]{36}$/);
  assert.match(headers['webhook-timestamp']!, /^\d+$/);
  assert.ok(Number(headers['webhook-timestamp']) >= before && Number(headers['webhook-timestamp']) <= after);
  assert.deepEqual(receiver.verify(body, headers), { ...payload, id: headers['webhook-id'] });
  assert.throws(() => receiver.verify(body + ' ', headers), WebhookVerificationError);
  assert.throws(() => receiver.verify(body, { ...headers, 'webhook-id': randomUUID() }), WebhookVerificationError);
  assert.throws(
    () => receiver.verify(body, { ...headers, 'webhook-timestamp': String(Number(headers['webhook-timestamp']) + 1) }),
    WebhookVerificationError,
  );
  const delivered = await f.db.one<{ attempts: number; delivered_at: Date }>(
    'SELECT attempts,delivered_at FROM webhooks WHERE id=$1', [headers['webhook-id']],
  );
  assert.equal(delivered?.attempts, 1);
  assert.ok(delivered?.delivered_at);
});

test('配信失敗後は同じイベントIDと本文を新しい時刻の署名で再送する', async (t) => {
  let attempts = 0;
  const f = await integrationFixture(t, async () => {
    attempts++;
    if (attempts === 2) throw new Error('Connection lost');
    return { status: attempts === 1 ? 503 : 204, headers: {}, body: new Uint8Array() };
  });
  const { webhookSecret } = await f.integrations.set(f.owner.actor, f.owner.actor.id, {
    webhookUrl: 'https://receiver.example/events',
  });
  const receiver = new Webhook(webhookSecret!);
  await f.integrations.enqueue(f.owner.actor.id, { type: 'request.created', requestId: randomUUID() });
  const start = Date.now();
  t.mock.timers.enable({ apis: ['Date'], now: start });
  for (let attempt = 0; attempt < 3; attempt++) {
    t.mock.timers.setTime(start + attempt * 60_000);
    await f.integrations.deliver();
    assert.equal(f.deliveries.length, attempt + 1);
    const delivery = f.deliveries[attempt]!;
    const first = f.deliveries[0]!;
    assert.equal(delivery.headers['webhook-id'], first.headers['webhook-id']);
    assert.equal(delivery.body, first.body);
    assert.equal(delivery.headers['webhook-timestamp'], String(Math.floor((start + attempt * 60_000) / 1000)));
    assert.deepEqual(receiver.verify(delivery.body, delivery.headers), JSON.parse(first.body));
    const event = await f.db.one<{ attempts: number; delivered_at: Date | null; delay: number }>(
      'SELECT attempts,delivered_at,extract(epoch FROM next_attempt-now())::float AS delay FROM webhooks WHERE id=$1',
      [delivery.headers['webhook-id']],
    );
    assert.equal(event?.attempts, attempt + 1);
    if (attempt < 2) {
      assert.equal(event?.delivered_at, null);
      assert.ok(event!.delay > 0 && event!.delay <= 30 * 2 ** attempt);
      await f.db.pool.query("UPDATE webhooks SET next_attempt=now() WHERE id=$1", [delivery.headers['webhook-id']]);
    } else assert.ok(event?.delivered_at);
  }
  await f.integrations.deliver();
  assert.equal(f.deliveries.length, 3);
});

test('送信先の変更後も発行済みの署名キーで検証し、キーの更新後は新しいキーで検証する', async (t) => {
  const f = await integrationFixture(t);
  const first = await f.integrations.set(f.owner.actor, f.owner.actor.id, {
    webhookUrl: 'https://receiver.example/events',
  });
  const receiver = new Webhook(first.webhookSecret!);
  await f.integrations.set(f.owner.actor, f.owner.actor.id, {
    webhookUrl: 'https://receiver.example/updated-events',
  });
  await f.integrations.enqueue(f.owner.actor.id, { type: 'request.created', requestId: randomUUID() });
  await f.integrations.deliver();
  const initial = f.deliveries[0]!;
  assert.equal(initial.url, 'https://receiver.example/updated-events');
  assert.deepEqual(receiver.verify(initial.body, initial.headers), JSON.parse(initial.body));

  await f.integrations.enqueue(f.owner.actor.id, { type: 'request.completed', requestId: randomUUID() });
  const rotated = await f.integrations.rotate(f.owner.actor, f.owner.actor.id);
  assert.match(rotated.webhookSecret, /^whsec_[A-Za-z0-9+/]{43}=$/);
  await f.integrations.deliver();
  assert.equal(f.deliveries.length, 2);
  const updated = f.deliveries[1]!;
  assert.equal(updated.url, initial.url);
  assert.notEqual(updated.headers['webhook-id'], initial.headers['webhook-id']);
  assert.deepEqual(new Webhook(rotated.webhookSecret).verify(updated.body, updated.headers), JSON.parse(updated.body));
  assert.throws(() => receiver.verify(updated.body, updated.headers), WebhookVerificationError);
});

test('送信先の設定前に発行した署名キーでWebhookを検証する', async (t) => {
  const f = await integrationFixture(t);
  const { webhookSecret } = await f.integrations.rotate(f.owner.actor, f.owner.actor.id);
  assert.match(webhookSecret, /^whsec_[A-Za-z0-9+/]{43}=$/);
  await f.integrations.set(f.owner.actor, f.owner.actor.id, { webhookUrl: 'https://receiver.example/events' });
  await f.integrations.enqueue(f.owner.actor.id, { type: 'request.created', requestId: randomUUID() });
  await f.integrations.deliver();
  assert.equal(f.deliveries.length, 1);
  const { body, headers } = f.deliveries[0]!;
  assert.deepEqual(new Webhook(webhookSecret).verify(body, headers), JSON.parse(body));
});

test('HTTP受信先の失敗と応答切断を再送し、処理済みイベントを受信側で一度だけ処理する', async (t) => {
  let receiver: Webhook;
  let attempts = 0;
  const receipts: Array<{ id: string; body: string }> = [];
  const errors: unknown[] = [];
  const server = createServer(async (request, response) => {
    try {
      assert.equal(request.method, 'POST');
      assert.equal(request.url, '/events');
      let body = '';
      for await (const chunk of request) body += chunk;
      const payload = receiver.verify(body, request.headers) as { id: string; type: string };
      assert.equal(payload.type, 'request.created');
      assert.equal(payload.id, request.headers['webhook-id']);
      receipts.push({ id: payload.id, body });
      attempts++;
      if (attempts === 1) {
        response.writeHead(503).end();
        return;
      }
      await f.db.pool.query(
        'INSERT INTO received_webhooks(id,payload) VALUES($1,$2) ON CONFLICT(id) DO NOTHING',
        [payload.id, body],
      );
      if (attempts === 2) request.socket.destroy();
      else response.writeHead(204).end();
    } catch (error) {
      errors.push(error);
      response.writeHead(400).end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const f = await integrationFixture(t, async (input) => {
    const response = await fetch(`http://127.0.0.1:${address.port}${new URL(input.url).pathname}`, {
      method: input.method,
      headers: input.headers,
      body: input.body,
      signal: AbortSignal.timeout(5000),
    });
    return { status: response.status, headers: {}, body: new Uint8Array(await response.arrayBuffer()) };
  });
  await f.db.pool.query('CREATE TABLE received_webhooks(id uuid PRIMARY KEY,payload jsonb NOT NULL)');
  const { webhookSecret } = await f.integrations.set(f.owner.actor, f.owner.actor.id, {
    webhookUrl: 'https://receiver.example/events',
  });
  receiver = new Webhook(webhookSecret!);
  const payload = { type: 'request.created', requestId: randomUUID(), message: '承認をお願いします 🔐' };
  await f.integrations.enqueue(f.owner.actor.id, payload);
  for (let attempt = 1; attempt <= 3; attempt++) {
    await f.integrations.deliver();
    assert.deepEqual(errors, []);
    assert.equal(receipts.length, attempt);
    assert.deepEqual(receipts[attempt - 1], receipts[0]);
    const event = await f.db.one<{ attempts: number; delivered_at: Date | null }>(
      'SELECT attempts,delivered_at FROM webhooks WHERE id=$1', [receipts[0]!.id],
    );
    assert.equal(event?.attempts, attempt);
    const processed = await f.db.all<{ payload: unknown }>('SELECT payload FROM received_webhooks');
    assert.equal(processed.length, attempt === 1 ? 0 : 1);
    if (attempt > 1) assert.deepEqual(processed[0]!.payload, { ...payload, id: receipts[0]!.id });
    if (attempt < 3) {
      assert.equal(event?.delivered_at, null);
      await f.db.pool.query('UPDATE webhooks SET next_attempt=now() WHERE id=$1', [receipts[0]!.id]);
    } else assert.ok(event?.delivered_at);
  }
  await f.integrations.deliver();
  assert.equal(receipts.length, 3);
});
