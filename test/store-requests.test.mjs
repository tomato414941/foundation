import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';

async function ask(f, token, names = ['suggested'], options = {}) {
  const response = await f.request('/v1/requests', { method: 'POST', token, data: {
    kind: 'store', input: { fields: names.map(name => ({ name, label: 'APIキー', ...options })) },
  } });
  assert.equal(response.status, 201, response.text);
  return response.json.request;
}
const save = (f, row, entries) => f.request(`/v1/requests/${row.id}/done`, { method: 'POST', data: { entries } });
const entry = (name, content = 'fixture-private-value') => ({ name, content });

test('利用者が選んだ名前で保存し、依頼元に実際の保存名を返す', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const row = await ask(f, token);
  const response = await save(f, row, [entry('stripe-test-api-key')]);
  assert.equal(response.status, 200, response.text);
  assert.deepEqual(response.json.names, ['stripe-test-api-key']);
  const done = (await f.request(`/v1/requests/${row.id}`, { token })).json.request;
  assert.equal(done.status, 'done');
  assert.deepEqual(done.result.names, ['stripe-test-api-key']);
  const kept = f.app.secrets.list(USER_A);
  assert.deepEqual(kept.map(value => value.name), ['stripe-test-api-key']);
  const delivered = await f.request('/v1/deliveries', { method: 'POST', token,
    data: { names: [{ name: done.result.names[0], as: 'STRIPE_KEY' }] } });
  assert.equal(delivered.json.delivery.environment.STRIPE_KEY, 'fixture-private-value');
});

test('同じ名前を使う登録を全件保留し、既存の値を保ったまま別名で再試行する', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  await f.request('/v1/holdings?kind=secret&name=existing', { method: 'PUT', raw: 'keep-this-value', type: 'text/plain' });
  const before = f.app.secrets.list(USER_A);
  const row = await ask(f, token, ['first', 'second'], { readable: true });
  const refused = await save(f, row, [entry('new-name'), entry('existing', 'replacement')]);
  assert.equal(refused.status, 409, refused.text);
  assert.equal(refused.json.error.code, 'name_taken');
  assert.deepEqual(f.app.secrets.list(USER_A), before);
  assert.equal(f.app.secrets.content(f.app.secrets.find(USER_A, 'existing')).toString(), 'keep-this-value');
  assert.equal((await f.request(`/v1/requests/${row.id}`, { token })).json.request.status, 'pending');
  const saved = await save(f, row, [entry('new-name'), entry('other-name', 'replacement')]);
  assert.equal(saved.status, 200, saved.text);
  assert.equal((await f.read('secret', 'other-name', { token })).text, 'replacement');
  assert.deepEqual(saved.json.names, ['new-name', 'other-name']);
});

test('依頼された名前をそのまま使う場合も同名の値を保護する', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const row = await ask(f, token, ['existing']);
  await f.request('/v1/holdings?kind=secret&name=existing', { method: 'PUT', raw: 'original', type: 'text/plain' });
  const refused = await save(f, row, [entry('existing')]);
  assert.equal(refused.status, 409, refused.text);
  assert.equal(f.app.secrets.content(f.app.secrets.find(USER_A, 'existing')).toString(), 'original');
});

test('保存名と値を検証して全件をまとめて登録する', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const row = await ask(f, token, ['first', 'second']);
  for (const entries of [
    [entry('same'), entry('same')],
    [entry('one'), entry('')],
    [entry('one'), entry('bad\nname')],
    [entry('one'), entry('x'.repeat(201))],
    [entry('one'), entry('\ud800')],
    [entry('one'), entry('two', '')],
    [entry('one'), entry('two', 42)],
    [entry('one')],
  ]) {
    assert.equal((await save(f, row, entries)).status, 400);
    assert.deepEqual(f.app.secrets.list(USER_A), []);
    assert.equal((await f.request(`/v1/requests/${row.id}`, { token })).json.request.status, 'pending');
  }
  const names = ['__proto__', ' 日本語, {{name}} '];
  const saved = await save(f, row, names.map(name => entry(name)));
  assert.equal(saved.status, 200, saved.text);
  assert.deepEqual(saved.json.names, names);
});

test('同じ保存名への同時登録は一方だけを保存し、もう一方を保留する', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const first = await ask(f, token, ['first']);
  const second = await ask(f, token, ['second']);
  const results = await Promise.all([
    save(f, first, [entry('shared', 'first-value')]),
    save(f, second, [entry('shared', 'second-value')]),
  ]);
  assert.deepEqual(results.map(response => response.status).sort(), [200, 409]);
  const winner = results.findIndex(response => response.status === 200);
  assert.equal(f.app.secrets.content(f.app.secrets.find(USER_A, 'shared')).toString(), ['first-value', 'second-value'][winner]);
  const statuses = await Promise.all([first, second].map(async row => (await f.request(`/v1/requests/${row.id}`, { token })).json.request.status));
  assert.equal(statuses[winner], 'done');
  assert.equal(statuses[1 - winner], 'pending');
});

test('依頼を作る時点で保存先を確かめ、食い違いは依頼元にだけ返す', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  await f.request('/v1/holdings?kind=secret&name=existing', { method: 'PUT', raw: 'keep-this-value', type: 'text/plain' });
  const taken = await f.request('/v1/requests', { method: 'POST', token, data: { kind: 'store', input: { fields: { name: 'existing', label: 'APIキー' }  }} });
  assert.equal(taken.status, 409); assert.equal(taken.json.error.code, 'name_taken');
  const missing = await f.request('/v1/requests', { method: 'POST', token, data: { kind: 'store', input: { fields: { name: 'nothing-here', label: 'APIキー', replace: true }  }} });
  assert.equal(missing.status, 409); assert.equal(missing.json.error.code, 'name_missing');
  assert.deepEqual((await f.request('/v1/requests', { token })).json.requests, [], 'nothing reached the owner');
  assert.equal((await f.request('/v1/requests', { method: 'POST', token, data: { kind: 'store', input: { fields: { name: 'existing', label: 'APIキー', replace: 'yes' }  }} })).status, 400);
});

test('置き換えの依頼は、持ち主がそのままの名前で完了すると既存の値だけを入れ替え、線はそのまま保つ', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  await f.request('/v1/holdings?kind=secret&name=npm-token', { method: 'PUT', raw: 'old-value', type: 'text/plain' });
  const before = f.app.secrets.find(USER_A, 'npm-token');
  const row = await ask(f, token, ['npm-token'], { replace: true, readable: true });
  assert.equal(row.store[0].replace, true);
  const saved = await save(f, row, [entry('npm-token', 'new-value')]);
  assert.equal(saved.status, 200, saved.text);
  assert.deepEqual(saved.json, { stored: true, names: ['npm-token'], replaced: ['npm-token'] });
  const after = f.app.secrets.find(USER_A, 'npm-token');
  assert.equal(f.app.secrets.content(after).toString(), 'new-value');
  assert.equal((await f.read('secret', 'npm-token', { token })).status, 403, 'the request cannot loosen what the owner kept to themselves');
  assert.equal(after.id, before.id, 'the same value, updated');
  assert.equal(f.app.secrets.list(USER_A).length, 1);
});

test('置き換えの依頼でも持ち主が別の名前を付ければ、既存の値は残り新しく保管される', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  await f.request('/v1/holdings?kind=secret&name=npm-token', { method: 'PUT', raw: 'old-value', type: 'text/plain' });
  const row = await ask(f, token, ['npm-token'], { replace: true });
  const saved = await save(f, row, [entry('npm-token-2', 'new-value')]);
  assert.equal(saved.status, 200, saved.text);
  assert.deepEqual(saved.json, { stored: true, names: ['npm-token-2'], replaced: [] });
  assert.equal(f.app.secrets.content(f.app.secrets.find(USER_A, 'npm-token')).toString(), 'old-value');
  assert.equal(f.app.secrets.content(f.app.secrets.find(USER_A, 'npm-token-2')).toString(), 'new-value');
  const done = (await f.request(`/v1/requests/${row.id}`, { token })).json.request;
  assert.deepEqual(done.result, { names: ['npm-token-2'], replaced: [] });
});

test('完了までに置き換える相手が消えていれば止め、依頼は保留のまま理由を記録する', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  await f.request('/v1/holdings?kind=secret&name=npm-token', { method: 'PUT', raw: 'old-value', type: 'text/plain' });
  const row = await ask(f, token, ['npm-token'], { replace: true });
  await f.drop('secret', 'npm-token');
  const refused = await save(f, row, [entry('npm-token', 'new-value')]);
  assert.equal(refused.status, 409); assert.equal(refused.json.error.code, 'name_missing');
  const seen = (await f.request(`/v1/requests/${row.id}`, { token })).json.request;
  assert.equal(seen.status, 'pending');
  assert.equal(seen.events.at(-1).code, 'name_missing');
  assert.deepEqual(f.app.secrets.list(USER_A), []);
});
