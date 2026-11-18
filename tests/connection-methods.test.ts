import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { MethodDefinition, Resource, ServiceInputDefinition } from '../shared/contracts.js';
import { AppMaterial } from '../shared/connections.js';
import { canonical } from '../shared/authority.js';
import { decode, encode } from '../shared/encryption.js';

const keyMethod = (name: string, field = 'token', output = 'API_KEY') =>
  MethodDefinition.parse({ name, kind: 'token',
    config: { fields: [{ name: field, label: field, secret: true }], outputs: { [output]: '/' + field } } });

test('作成権限を持つプリンシパルだけが所有者のサービス定義を作成する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const body = { kind: 'service', name: 'Authorized service', definition: {
    name: 'Authorized service', methods: { bearer: 'http:bearer' },
  } };
  const path = '/api/principals/' + f.owner.actor.id + '/resources';
  await assert.rejects(f.api(f.stranger.token).json(path, { method: 'POST', body }), { code: 'forbidden' });
  await f.relations.draw(f.owner.actor, {
    subjectId: f.stranger.actor.id, relation: 'creator', objectId: f.owner.actor.id,
  });
  const saved = await f.api(f.stranger.token).json(path, { method: 'POST', body }, Resource);
  assert.equal(saved.ownerId, f.owner.actor.id);
  assert.equal(saved.kind, 'service');
  assert.equal((await f.context.catalog.list(f.owner.actor)).find(item => item.id === saved.id)?.name, body.name);
});

test('OVHcloudのアプリ認証を保存し選んだAPI接続先へのHTTP実行でトークンを再取得する', async t => {
  for (const [apiRegion, tokenUrl, apiBaseUrl] of [
    ['eu', 'https://www.ovh.com/auth/oauth2/token', 'https://eu.api.ovh.com/1.0'],
    ['ca', 'https://ca.ovh.com/auth/oauth2/token', 'https://ca.api.ovh.com/1.0'],
    ['us', 'https://us.ovhcloud.com/auth/oauth2/token', 'https://api.us.ovhcloud.com/1.0'],
  ] as const) await t.test(apiRegion, async t => {
    const methodId = 'ovh:client_credentials';
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
      assert.equal(request.headers?.authorization, 'Bearer ovh-access-1');
      return jsonResponse(['vps-test']);
    }); t.after(f.close);
    const application = await f.saveApp(methodId, 'Application', { apiRegion });
    const saved = await f.saveConnection({ methodId, appId: application.id });
    assert.equal((await f.http(saved.id, 'OVH_ACCESS_TOKEN', apiBaseUrl + '/vps'))?.ok, true);
    const renewed = await f.client.read(saved.id);
    assert.ok(renewed.content.materialRevision > 1);
    const current = await f.client.api.json('/api/resources/' + saved.id, {}, Resource);
    if (current.kind === 'connection') {
      assert.deepEqual(current.data.fields, { apiRegion });
      assert.equal(current.data.settings.find(setting => setting.name === 'apiRegion')?.value, apiRegion.toUpperCase());
    }
    assert.equal(grants, 1);
  });
});

test('接続のAPI区分を維持し、アプリの設定が変わった場合は再接続を要求する', async t => {
  let grants = 0;
  const f = await flowFixture(() => {
    grants++;
    return jsonResponse({ access_token: 'fixed-region-token', token_type: 'Bearer', expires_in: 10, scope: 'all' });
  }); t.after(f.close);
  const application = await f.saveApp('ovh:client_credentials', 'OVH application', { apiRegion: 'ca' });
  const connection = await f.saveConnection({ methodId: 'ovh:client_credentials', appId: application.id }), previous = await f.client.read(application.id);
  const material = AppMaterial.parse(JSON.parse(decode(await f.client.reveal(application.id))));
  const changed = { ...material, fields: { apiRegion: 'eu' } };
  await f.client.save(application.name, encode(canonical(changed)), { ...previous.content.policy, revision: previous.content.policy.revision + 1 },
    { previous, metadata: { ...previous.content.metadata, fields: { apiRegion: 'eu' } } });
  const result = await f.http(connection.id, 'OVH_ACCESS_TOKEN');
  assert.equal(result?.ok, false);
  assert.equal(result?.error?.code, 'app_changed');
});

test('Shopifyのアプリ認証を保存し、利用時にトークンを取得する', async t => {
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
  const saved = await f.saveConnection({ methodId: method.id, appId: application.id });
  assert.equal((await f.http(saved.id, 'SHOPIFY_ACCESS_TOKEN'))?.ok, true);
  assert.equal(f.requests.at(-1)!.headers.authorization, 'Bearer shopify-access-1');
  const renewed = await f.client.read(saved.id);
  assert.ok(renewed.content.materialRevision > 1);
  assert.equal(grants, 1);
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
    const saved = await f.saveConnection({ methodId: catalog.methods[key]!.id, fields: { [key]: key + '-value' } });
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
  const saved = await f.saveConnection({ methodId: method.id, fields: { token: 'kept-value' } });
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
          tokenUrl: 'https://provider.example/token', scopes: { default: ['read'], required: ['identity'] } },
      } } }, Resource);
    const app = await f.saveApp(method.id);
    const saved = await f.saveConnection({ methodId: method.id, appId: app.id,
      ...(selection === undefined ? {} : { scopes: [...selection] }) });
    const registered = await f.client.read(saved.id);
    assert.deepEqual(registered.content.metadata.scopes, expected);
    assert.equal((await f.http(saved.id, 'ACCESS_TOKEN'))?.ok, true);
    const tokenRequests = f.requests.filter(request => request.url.endsWith('/token'));
    assert.equal(tokenRequests.length, 1);
    assert.deepEqual(tokenRequests.map(request => new URLSearchParams(String(request.body)).get('scope')), [expected.join(' ')]);
    const renewed = await f.client.read(saved.id);
    assert.ok(renewed.content.materialRevision > 1);
    assert.equal(renewed.content.metadata.authorizationDigest, registered.content.metadata.authorizationDigest);
  });
});

test('接続先で使うOAuthアプリを接続方法に結び付けて確認する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const application = await f.saveApp('google:oauth');
  await assert.rejects(f.authorize({ methodId: 'render:oauth', appId: application.id }), /application for this connection method/);
});
