import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A, USER_B } from './helpers.mjs';

async function deliver(f, key, holder, name) {
  const response = await f.request('/v1/deliveries', {
    method: 'POST', token: key.token, anonymous: true, as: holder,
    data: { names: [{ name, as: 'VALUE' }] },
  });
  assert.equal(response.status, 200, response.text);
}

async function deliveries(f, options) {
  const response = await f.request('/v1/records', options);
  assert.equal(response.status, 200, response.text);
  return response.json.records.filter(row => row.action === 'delivery');
}

test('複数の利用者の代理を務めるキーの操作履歴を、対象の利用者ごとに取得する', async t => {
  const f = await fixture(t), key = await f.issueKey('shared agent');
  await f.keep('grant', 'first-value', 'fixture-a');
  await deliver(f, key, USER_A, 'first-value');

  await f.login('other@example.test');
  await f.keep('grant', 'second-value', 'fixture-b');
  const asked = await f.request('/v1/requests', {
    method: 'POST', token: key.token, anonymous: true,
    data: { kind: 'actor', to: USER_B, input: { name: 'shared agent' } },
  });
  assert.equal(asked.status, 201, asked.text);
  const accepted = await f.request('/v1/requests/' + asked.json.request.id + '/done', {
    method: 'POST', data: { confirmation_code: asked.json.request.confirmation_code },
  });
  assert.equal(accepted.status, 200, accepted.text);
  await deliver(f, key, USER_B, 'second-value');

  const forSecond = await deliveries(f);
  assert.deepEqual(forSecond.map(row => [row.object_id, row.detail.names]), [[USER_B, ['second-value']]]);
  await f.login();
  const forFirst = await deliveries(f);
  assert.deepEqual(forFirst.map(row => [row.object_id, row.detail.names]), [[USER_A, ['first-value']]]);

  const byAgent = await deliveries(f, { token: key.token, anonymous: true });
  assert.deepEqual(new Set(byAgent.map(row => row.id)), new Set([...forFirst, ...forSecond].map(row => row.id)));
});

test('代理の許可を取り消した後も、本人を対象とした操作履歴を取得する', async t => {
  const f = await fixture(t), key = await f.issueKey();
  await f.keep('grant', 'kept-value', 'fixture-value');
  await deliver(f, key, USER_A, 'kept-value');
  const before = await deliveries(f);
  assert.equal(before.length, 1);

  const removed = await f.request('/v1/relations', {
    method: 'DELETE',
    data: { subject: key.id, relation: 'actor', object_type: 'principal', object_id: USER_A },
  });
  assert.equal(removed.status, 200, removed.text);
  assert.deepEqual(await deliveries(f), before);
});
