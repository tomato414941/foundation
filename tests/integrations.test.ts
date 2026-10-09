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

test('既存データを更新しても完了URLとやり直し用URL、利用者の情報を保持する', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person('Existing owner');
  await f.db.pool.query('ALTER TABLE integration_settings ADD COLUMN webhook_secret text NOT NULL DEFAULT \'fixture\'');
  await f.db.pool.query('INSERT INTO integration_settings(principal_id,settings) VALUES($1,$2)', [
    owner.actor.id, JSON.stringify({ ...settings, webhookUrl: 'https://client.example/events' }),
  ]);
  await f.db.pool.query("DELETE FROM schema_migrations WHERE name='remove-outbound-webhooks'");
  await f.db.initialize();
  await f.db.initialize();
  const context = await createContext(f.config, { db: f.db, mailer: f.mailer });
  const current = await context.integrations.get(owner.actor, owner.actor.id);
  assert.equal(current.returnUrl, settings.returnUrl);
  assert.equal(current.refreshUrl, settings.refreshUrl);
  assert.equal((await f.principals.get(owner.actor.id)).name, 'Existing owner');
  const updated = { returnUrl: 'https://client.example/done', refreshUrl: settings.refreshUrl };
  await context.integrations.set(owner.actor, owner.actor.id, updated);
  assert.deepEqual(await context.integrations.get(owner.actor, owner.actor.id), updated);
});
