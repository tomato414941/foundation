import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';

test('接続一覧で所有するプリンシパルの接続を検索し、持ち主とページ送りを示す', async t => {
  const f = await fixture(), context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('Owner'), other = await f.person('Other owner'),
    child = await f.principals.create('AI', null, owner.actor.id),
    nested = await f.principals.create('Nested AI', null, child.id);
  const data = { methodId: 'shopify:client_credentials', methodName: 'Shopify · Sign in with app credentials',
    methodKind: 'oauth', account: 'Nipponika', accountVerified: true,
    scopes: [], outputs: ['SHOPIFY_ACCESS_TOKEN'], state: 'ready', appId: null };
  const ids = [1, 2, 3, 4].map(n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`);
  await f.resources.insert(owner.actor.id, 'connection', 'Main account', data, { id: ids[0] });
  await f.resources.insert(child.id, 'connection', 'Nipponika Shopify', data, { id: ids[1] });
  await f.resources.insert(nested.id, 'connection', 'Nipponika reports', data, { id: ids[2] });
  await f.resources.insert(other.actor.id, 'connection', 'Other account', data, { id: ids[3] });
  await f.resources.insert(child.id, 'variable', 'Nipponika variable', { bytes: 0 });
  const headers = { authorization: 'Bearer ' + owner.token },
    url = `/api/principals/${owner.actor.id}/resources?kind=connection`;
  const list = async (query: string) => {
    const response = await app.inject({ url: url + query, headers });
    assert.equal(response.statusCode, 200, response.body);
    return response.json();
  };
  assert.deepEqual((await list('')).items.map((item: { id: string }) => item.id), [ids[0]]);
  assert.deepEqual((await list('&includeOwned=false')).items.map((item: { id: string }) => item.id), [ids[0]]);
  const first = await list('&includeOwned=true&limit=1');
  assert.deepEqual(first.items.map((item: { id: string }) => item.id), [ids[0]]);
  assert.equal(first.next, ids[0]);
  const second = await list('&includeOwned=true&limit=1&after=' + first.next);
  assert.equal(second.items[0].id, ids[1]);
  assert.equal(second.items[0].ownerId, child.id);
  assert.ok(second.items[0].permissions.includes('update'));
  const third = await list('&includeOwned=true&limit=1&after=' + second.next);
  assert.equal(third.items[0].id, ids[2]);
  assert.equal(third.items[0].ownerId, nested.id);
  assert.equal(third.next, null);
  const found = await list('&includeOwned=true&query=Nipponika');
  assert.deepEqual(found.items.map((item: { id: string }) => item.id), ids.slice(1, 3));
});

test('所有範囲の一覧でも接続ごとの読み取り権限を確認する', async t => {
  const f = await fixture(), context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('Owner'), reader = await f.person('Principal reader'), stranger = await f.person('Stranger'),
    child = await f.principals.create('Owned AI', null, owner.actor.id);
  await f.resources.insert(child.id, 'connection', 'AI connection', { methodId: 'shopify:client_credentials',
    methodName: 'Shopify · Sign in with app credentials', methodKind: 'oauth', account: 'Nipponika',
    scopes: [], outputs: ['SHOPIFY_ACCESS_TOKEN'], state: 'ready', appId: null });
  await f.relations.draw(owner.actor, { subjectId: reader.actor.id, relation: 'reader', objectId: owner.actor.id });
  const url = `/api/principals/${owner.actor.id}/resources?kind=connection&includeOwned=true`;
  const readable = await app.inject({ url, headers: { authorization: 'Bearer ' + reader.token } });
  assert.equal(readable.statusCode, 200, readable.body);
  assert.deepEqual(readable.json().items, []);
  const forbidden = await app.inject({ url, headers: { authorization: 'Bearer ' + stranger.token } });
  assert.equal(forbidden.statusCode, 403, forbidden.body);
});
