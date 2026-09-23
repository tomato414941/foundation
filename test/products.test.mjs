import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';

// A product embeds Foundation: it makes a room for each of its own users, and is billed for them.
async function product(t, name = 'ai-simplicity') {
  const f = await fixture(t);
  const created = await f.request('/api/products', { method: 'POST', data: { name } });
  assert.equal(created.status, 201, created.text);
  return { ...f, product: created.json.product };
}

test('registers a product and hands its key over once', async (t) => {
  const f = await product(t);
  assert.match(f.product.token, /^fdnp_[A-Za-z0-9_-]{43}$/);
  const listed = await f.request('/api/products');
  assert.deepEqual(listed.json.products.map(item => ({ name: item.name, rooms: item.rooms })), [{ name: 'ai-simplicity', rooms: 0 }]);
  assert.ok(!('token' in listed.json.products[0]), 'the key is never returned again');
});

test('makes one room per user of the product, and keeps them apart', async (t) => {
  const f = await product(t);
  const taro = await f.request('/v1/rooms', { method: 'POST', token: f.product.token, anonymous: true, data: { external_id: 'u_taro' } });
  assert.equal(taro.status, 201, taro.text);
  const hanako = await f.request('/v1/rooms', { method: 'POST', token: f.product.token, anonymous: true, data: { external_id: 'u_hanako' } });
  assert.notEqual(taro.json.room.id, hanako.json.room.id);

  await f.request('/v1/entries/notes/plan', { method: 'PUT', token: taro.json.key, anonymous: true, raw: 'taro のメモ', type: 'text/plain' });
  const mine = await f.request('/v1/entries', { token: taro.json.key, anonymous: true });
  assert.deepEqual(mine.json.entries.map(entry => entry.path), ['notes/plan']);
  const theirs = await f.request('/v1/entries', { token: hanako.json.key, anonymous: true });
  assert.deepEqual(theirs.json.entries, []);
});

test('returns the same room when the same user comes back', async (t) => {
  const f = await product(t);
  const first = await f.request('/v1/rooms', { method: 'POST', token: f.product.token, anonymous: true, data: { external_id: 'u_taro' } });
  const again = await f.request('/v1/rooms', { method: 'POST', token: f.product.token, anonymous: true, data: { external_id: 'u_taro' } });
  assert.equal(again.json.room.id, first.json.room.id);
  assert.notEqual(again.json.key, first.json.key, 'a fresh key each time, so an old one can be revoked');
});

test('tells the product what its rooms are using, and nothing of what is in them', async (t) => {
  const f = await product(t);
  const taro = await f.request('/v1/rooms', { method: 'POST', token: f.product.token, anonymous: true, data: { external_id: 'u_taro' } });
  await f.request('/v1/entries/keys/token?secret=true', { method: 'PUT', token: taro.json.key, anonymous: true, raw: 'sh-a-secret', type: 'text/plain' });
  const rooms = await f.request('/v1/rooms', { token: f.product.token, anonymous: true });
  assert.equal(rooms.status, 200, rooms.text);
  assert.equal(rooms.json.rooms.length, 1);
  assert.equal(rooms.json.rooms[0].usage.entries.count, 1);
  assert.ok(!rooms.text.includes('sh-a-secret'));
  assert.ok(!rooms.text.includes('keys/token'));
});

test('keeps a product key out of the rooms themselves', async (t) => {
  const f = await product(t);
  const taro = await f.request('/v1/rooms', { method: 'POST', token: f.product.token, anonymous: true, data: { external_id: 'u_taro' } });
  await f.request('/v1/entries/notes/plan', { method: 'PUT', token: taro.json.key, anonymous: true, raw: 'taro のメモ', type: 'text/plain' });
  const refused = await f.request('/v1/entries', { token: f.product.token, anonymous: true });
  assert.equal(refused.status, 401);
  assert.equal(refused.json.error.code, 'not_approved');
});

test('stops making rooms once the product is removed', async (t) => {
  const f = await product(t);
  const removed = await f.request('/api/products/' + f.product.id, { method: 'DELETE', data: {} });
  assert.equal(removed.status, 200, removed.text);
  const refused = await f.request('/v1/rooms', { method: 'POST', token: f.product.token, anonymous: true, data: { external_id: 'u_taro' } });
  assert.equal(refused.status, 401);
  assert.equal(refused.json.error.code, 'not_a_product');
});
