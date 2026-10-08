import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { MethodDefinition, Resource, ServiceInputDefinition } from '../shared/contracts.js';

const keyMethod = (name: string, field = 'token', output = 'API_KEY') =>
  MethodDefinition.parse({ name, kind: 'token',
    config: { fields: [{ name: field, label: field, secret: true }], outputs: { [output]: '/' + field } } });

test('ShopifyのOAuth・Client credentials・APIキーの接続方法を共通サービスから選択する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const shopify = (await f.context.catalog.list(f.owner.actor)).find(item => item.id === 'shopify')!;
  assert.equal(shopify.builtin, true);
  assert.deepEqual(Object.values(shopify.methods).map(method => method.id),
    ['shopify:oauth', 'shopify:client_credentials', 'shopify:token']);
  const method = shopify.methods.client_credentials!;
  assert.equal(method.availability, 'ready');
});

test('一つのサービスから同方式の複数の接続方法を選び、それぞれの値を利用する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const service = await f.context.catalog.createService(f.owner.actor, f.owner.actor.id, 'Example',
    ServiceInputDefinition.parse({ name: 'Example', methods: {
      personal: keyMethod('Personal key', 'personal', 'PERSONAL_KEY'),
      project: keyMethod('Project key', 'project', 'PROJECT_KEY'),
    } }));
  const catalog = (await f.context.catalog.list(f.owner.actor)).find(item => item.id === service.id)!;
  const ids = [];
  for (const [key, output] of [['personal', 'PERSONAL_KEY'], ['project', 'PROJECT_KEY']] as const) {
    const started = await f.start({ methodId: catalog.methods[key]!.id, fields: { [key]: key + '-value' } });
    assert.equal((await f.tick(started.flow.id)).kind, 'review');
    const saved = await f.accept(started.flow.id);
    ids.push(saved.id);
    assert.equal((await f.http(saved.id, output))?.ok, true);
    assert.equal(f.requests.at(-1)!.headers.authorization, 'Bearer ' + key + '-value');
  }
  assert.notEqual(ids[0], ids[1]);
});

test('複数のサービスに同じ接続を分類し、分類変更後も接続IDと値を維持する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const method = await f.client.api.json('/api/principals/' + f.owner.actor.id + '/resources',
    { method: 'POST', body: { kind: 'method', name: 'Shared method', definition: keyMethod('Shared method') } }, Resource);
  const groups = await Promise.all(['First', 'Second'].map(name => f.context.catalog.createService(f.owner.actor,
    f.owner.actor.id, name, ServiceInputDefinition.parse({ name, methods: { key: method.id } }))));
  const started = await f.start({ methodId: method.id, fields: { token: 'kept-value' } });
  await f.tick(started.flow.id);
  const saved = await f.accept(started.flow.id);
  assert.equal(saved.kind, 'connection');
  if (saved.kind !== 'connection') return;
  assert.equal(saved.data.services.length, 2);
  await f.context.resources.rename(f.owner.actor, groups[0]!, 'Renamed group');
  await f.context.resources.delete(f.owner.actor, groups[1]!);
  const view = await f.client.api.json('/api/resources/' + saved.id, {}, Resource);
  assert.equal(view.kind, 'connection');
  if (view.kind !== 'connection') return;
  assert.deepEqual(view.data.services, [{ id: groups[0]!.id, name: 'Renamed group' }]);
  assert.equal((await f.http(saved.id, 'API_KEY'))?.ok, true);
  assert.equal(f.requests.at(-1)!.headers.authorization, 'Bearer kept-value');
  await assert.rejects(f.context.resources.delete(f.owner.actor, await f.context.resources.get(method.id)));
});

test('接続先で使うOAuthアプリを接続方法に結び付けて確認する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const application = await f.saveApp('google:oauth');
  const started = await f.start({ methodId: 'render:oauth', appId: application.id });
  const result = await f.tick(started.flow.id);
  assert.equal(result.kind, 'failed');
  if (result.kind !== 'failed') return;
  assert.equal((result.error as { code: string }).code, 'wrong_app');
});
