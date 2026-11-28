import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { CustodyClient } from '../shared/client.js';
import { KeySharingItem } from '../shared/protocol.js';
import { HttpBroker } from '../runtime/broker.js';
import { Connections } from '../runtime/connections.js';
import { openInputs } from '../runtime/inputs.js';

async function sharedShopify(onGrant: (number: number) => Promise<void> | void) {
  let grants = 0;
  const f = await flowFixture(async request => {
    assert.ok(request.url.endsWith('/admin/oauth/access_token'));
    const number = ++grants;
    await onGrant(number);
    return jsonResponse({ access_token: 'token-' + number, expires_in: 3600, scope: 'read_products' });
  });
  const methodId = 'shopify:client_credentials';
  const app = await f.saveApp(methodId, 'Shopify app', { shop: 'example' });
  const connection = await f.saveConnection({ methodId, appId: app.id });
  const reader = new CustodyClient(f.api(f.stranger.token), f.config.origin, f.stranger.actor.id, f.stranger.keys);
  await f.relations.draw(f.owner.actor, { objectId: app.id, subjectId: reader.principalId, relation: 'revealer' });
  await f.client.reprotect(app.id);
  const path = '/api/connections/' + connection.id + '/shares/' + reader.principalId;
  const plan = await f.client.api.json(path + '/recipients?permission=reveal', {}, KeySharingItem);
  const protection = (await f.client.sharing([plan]))[connection.id];
  await f.client.api.json(path, { method: 'PUT', body: { permission: 'reveal', protection } });
  const readerRuntime = new Connections(reader, new HttpBroker(reader.api).connections(), new MemoryJournal(), f.transport);
  const inputs = [{ name: 'TOKEN', source: { id: connection.id, output: 'SHOPIFY_ACCESS_TOKEN' } }];
  return { f, id: connection.id, grants: () => grants,
    useOwner: async () => (await f.inputs(inputs)).environment.TOKEN,
    useReader: async () => (await openInputs(reader, readerRuntime, inputs)).environment.TOKEN };
}

test('アプリ認証の応答が端末に届かなくても、接続を共有された読み手がトークンを取得して使う', async t => {
  const s = await sharedShopify(number => { if (number === 1) throw new Error('Token response lost'); });
  t.after(s.f.close);
  await assert.rejects(s.useOwner());
  assert.equal(await s.useReader(), 'token-2');
  assert.equal(await s.useOwner(), 'token-2');
  assert.equal(s.grants(), 2);
});

test('同じアプリで並行して取得したトークンのうち、先に保存した方を両方の端末で使う', async t => {
  const started = Promise.withResolvers<void>(), release = Promise.withResolvers<void>();
  const s = await sharedShopify(async number => {
    if (number === 1) { started.resolve(); await release.promise; }
  });
  t.after(s.f.close);
  const owner = s.useOwner();
  try {
    await Promise.race([started.promise, owner]);
    assert.equal(await s.useReader(), 'token-2');
  } finally {
    release.resolve();
    await owner;
  }
  assert.equal(await owner, 'token-2');
  assert.equal(await s.useOwner(), 'token-2');
  assert.equal(s.grants(), 2);
});
