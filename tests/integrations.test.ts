import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';

const settings = { returnUrl: 'https://client.example/complete', refreshUrl: 'https://client.example/retry' };

test('外部連携のURLを保存し、承認依頼の状態を含めた完了URLを返す', async (t) => {
  const f = await fixture();
  const context = await createContext(f.config, { db: f.db, mailer: f.mailer });
  const app = await buildApp(context);
  t.after(async () => { await app.close(); await f.close(); });
  const sender = await f.person(), recipient = await f.person();
  const headers = { authorization: 'Bearer ' + sender.token };
  const saved = await app.inject({ method: 'PUT', url: `/api/principals/${sender.actor.id}/settings`, headers, payload: settings });
  assert.equal(saved.statusCode, 200, saved.body);
  assert.deepEqual(saved.json().settings, settings);
  const read = await app.inject({ url: `/api/principals/${sender.actor.id}/settings`, headers });
  assert.equal(read.statusCode, 200, read.body);
  assert.deepEqual(read.json(), settings);
  const created = await app.inject({ method: 'POST', url: '/api/requests', headers, payload: {
    to: recipient.actor.id,
    operations: [{ method: 'POST', path: '/api/relations', body: {
      relation: 'agent', objectId: '$approver', subjectId: sender.actor.id,
    } }],
  } });
  assert.equal(created.statusCode, 201, created.body);
  const pending = created.json();
  const expected = new URL(settings.returnUrl);
  expected.searchParams.set('requestId', pending.id);
  expected.searchParams.set('state', 'pending');
  assert.equal(pending.returnUrl, expected.href);
  assert.equal(pending.refreshUrl, settings.refreshUrl);
  const cancelled = await app.inject({ method: 'POST', url: `/api/requests/${pending.id}/cancel`, headers, payload: {} });
  assert.equal(cancelled.statusCode, 200, cancelled.body);
  expected.searchParams.set('state', 'cancelled');
  assert.equal(cancelled.json().returnUrl, expected.href);
});
