import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { MethodDefinition, Resource, ServiceInputDefinition } from '../shared/contracts.js';

const keyMethod = (name: string, field = 'token', output = 'API_KEY') =>
  MethodDefinition.parse({ name, kind: 'token',
    config: { fields: [{ name: field, label: field, secret: true }], outputs: { [output]: '/' + field } } });

test('OVHcloudのアプリ認証を保存し選んだAPI接続先へのHTTP実行でトークンを再取得する', async t => {
  for (const [methodId, tokenUrl, apiBaseUrl] of [
    ['ovh:client_credentials', 'https://www.ovh.com/auth/oauth2/token', 'https://eu.api.ovh.com/1.0'],
    ['ovh:client_credentials_ca', 'https://ca.ovh.com/auth/oauth2/token', 'https://ca.api.ovh.com/1.0'],
    ['ovh:client_credentials_us', 'https://us.ovhcloud.com/auth/oauth2/token', 'https://api.us.ovhcloud.com/1.0'],
  ] as const) await t.test(methodId, async t => {
    let grants = 0;
    const f = await flowFixture(request => {
      if (request.url === tokenUrl) {
        const form = new URLSearchParams(String(request.body));
        assert.equal(form.get('grant_type'), 'client_credentials');
        assert.equal(form.get('client_id'), 'application-id');
        assert.equal(form.get('client_secret'), 'application-secret');
        assert.equal(form.get('scope'), 'all');
        return jsonResponse({ access_token: 'ovh-access-' + ++grants, token_type: 'Bearer', expires_in: 10, scope: 'all' });
      }
      assert.equal(request.url, apiBaseUrl + '/vps');
      assert.equal(request.headers?.authorization, 'Bearer ovh-access-2');
      return jsonResponse(['vps-test']);
    }); t.after(f.close);
    const application = await f.saveApp(methodId);
    const started = await f.start({ methodId, appId: application.id });
    const reviewed = await f.tick(started.flow.id);
    assert.equal(reviewed.kind, 'review', JSON.stringify(reviewed));
    if (reviewed.kind !== 'review') return;
    assert.equal(reviewed.metadata.account, 'application-id');
    assert.equal(reviewed.metadata.accountVerified, false);
    assert.deepEqual(reviewed.metadata.scopes, ['all']);
    const saved = await f.accept(started.flow.id);
    assert.equal((await f.http(saved.id, 'OVH_ACCESS_TOKEN', apiBaseUrl + '/vps'))?.ok, true);
    const renewed = await f.client.read(saved.id);
    assert.equal(renewed.content.materialRevision, 2);
    assert.equal(grants, 2);
  });
});

test('Shopifyのアプリ認証で接続先と権限を確認して保存し、利用時にトークンを更新する', async t => {
  let grants = 0;
  const f = await flowFixture(request => {
    if (request.url.endsWith('/admin/oauth/access_token')) {
      const form = new URLSearchParams(String(request.body));
      assert.equal(form.get('grant_type'), 'client_credentials');
      assert.equal(form.get('client_id'), 'application-id');
      return jsonResponse({ access_token: 'shopify-access-' + ++grants, expires_in: 10, scope: 'read_products' });
    }
    if (request.url.endsWith('/graphql.json')) return jsonResponse({ data: { shop: {
      id: 'gid://shopify/Shop/1', name: 'My shop', myshopifyDomain: 'example.myshopify.com',
    } } });
    return jsonResponse({ ok: true });
  }); t.after(f.close);
  const shopify = (await f.context.catalog.list(f.owner.actor)).find(item => item.id === 'shopify')!;
  assert.equal(shopify.builtin, true);
  assert.deepEqual(Object.values(shopify.methods).map(method => method.id),
    ['shopify:oauth', 'shopify:client_credentials', 'shopify:token']);
  const method = shopify.methods.client_credentials!;
  assert.equal(method.availability, 'app-required');
  const application = await f.saveApp(method.id, 'Shopify app', { shop: 'example' });
  const started = await f.start({ methodId: method.id, appId: application.id });
  const reviewed = await f.tick(started.flow.id);
  assert.equal(reviewed.kind, 'review', JSON.stringify(reviewed));
  if (reviewed.kind !== 'review') return;
  assert.equal(reviewed.metadata.account, 'My shop');
  assert.equal(reviewed.metadata.accountVerified, true);
  assert.deepEqual(reviewed.metadata.scopes, ['read_products']);
  const saved = await f.accept(started.flow.id);
  assert.equal((await f.http(saved.id, 'SHOPIFY_ACCESS_TOKEN'))?.ok, true);
  assert.equal(f.requests.at(-1)!.headers.authorization, 'Bearer shopify-access-2');
  const renewed = await f.client.read(saved.id);
  assert.equal(renewed.content.materialRevision, 2);
  assert.equal(grants, 2);
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

test('初期スコープを選び直し、必須スコープと選択内容を保存と自動更新で維持する', async t => {
  for (const [selection, expected] of [
    [undefined, ['identity', 'read']], [[], ['identity']], [['write', 'identity'], ['identity', 'write']],
  ] as const) await t.test(selection?.join(',') ?? 'default selection', async t => {
    const f = await flowFixture(request => request.url.endsWith('/token')
      ? jsonResponse({ access_token: 'selected-scopes-token', token_type: 'Bearer', expires_in: 10,
        scope: new URLSearchParams(String(request.body)).get('scope') }) : jsonResponse({ ok: true }));
    t.after(f.close);
    const method = await f.client.api.json('/api/principals/' + f.owner.actor.id + '/resources',
      { method: 'POST', body: { kind: 'method', name: 'Scoped application', definition: {
        name: 'Scoped application', kind: 'oauth', config: { grantType: 'client_credentials',
          tokenUrl: 'https://provider.example/token', scopes: { default: ['read'], required: ['identity'] },
          identity: { from: 'app', id: '/clientId', name: '/clientId' } },
      } } }, Resource);
    const app = await f.saveApp(method.id);
    const started = await f.start({ methodId: method.id, appId: app.id,
      ...(selection === undefined ? {} : { scopes: [...selection] }) });
    const reviewed = await f.tick(started.flow.id);
    assert.equal(reviewed.kind, 'review', JSON.stringify(reviewed));
    if (reviewed.kind !== 'review') return;
    assert.deepEqual(reviewed.metadata.scopes, expected);
    const saved = await f.accept(started.flow.id);
    assert.equal((await f.http(saved.id, 'ACCESS_TOKEN'))?.ok, true);
    const tokenRequests = f.requests.filter(request => request.url.endsWith('/token'));
    assert.equal(tokenRequests.length, 2);
    assert.deepEqual(tokenRequests.map(request => new URLSearchParams(String(request.body)).get('scope')), [expected.join(' '), expected.join(' ')]);
    const renewed = await f.client.read(saved.id);
    assert.equal(renewed.content.materialRevision, 2);
    assert.equal(renewed.content.metadata.authorizationDigest, reviewed.metadata.authorizationDigest);
  });
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
