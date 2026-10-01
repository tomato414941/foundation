import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';

test('シークレットの名前を完全一致で扱い、名前とIDで別の保存値を指定する', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  const plain = (await f.keep('secret', 'api-token', 'plain-value')).json.resource;
  await f.keep('secret', 'api-token#work', 'work-value');
  await f.keep('secret', plain.id, 'uuid-name-value');
  await f.keep('secret', 'a/aa/aaa', 'slash-value');
  const used = await f.request('/v1/injections', { method: 'POST', token: agent.token, data: { names: [
    { name: 'api-token', as: 'PLAIN' }, { name: 'api-token#work', as: 'WORK' },
    { name: plain.id, as: 'BY_NAME' }, { id: plain.id, as: 'BY_ID' }, { name: 'a/aa/aaa', as: 'SLASH' },
  ] } });
  assert.equal(used.status, 200, used.text);
  assert.deepEqual(used.json.injection.environment, { PLAIN: 'plain-value', WORK: 'work-value', BY_NAME: 'uuid-name-value', BY_ID: 'plain-value', SLASH: 'slash-value' });
  const namedOnly = '12345678-1234-4234-8234-123456789012';
  await f.keep('secret', namedOnly, 'named-only');
  const missing = await f.request('/v1/injections', { method: 'POST', data: { names: [{ id: namedOnly, as: 'VALUE' }] } });
  assert.equal(missing.status, 404);
});

test('接続の出力を明示して一つ選び、名前を変えたりファイルにしたりして渡す', async t => {
  const f = await fixture(t), connection = await f.connection();
  const selected = await f.request('/v1/injections', { method: 'POST', data: { names: [
    { id: connection.id, output: 'GOOGLE_OAUTH_ACCESS_TOKEN', as: 'TOKEN' },
    { id: connection.id, output: 'GOOGLE_ACCOUNT_EMAIL', as: 'ACCOUNT_FILE', filename: 'account.txt' },
  ] } });
  assert.equal(selected.status, 200, selected.text);
  assert.deepEqual(selected.json.injection.environment, { TOKEN: 'google-access-personal' });
  assert.equal(Buffer.from(selected.json.injection.files[0].content, 'base64').toString(), 'personal@example.test');
  const all = await f.inject(connection);
  assert.equal(all.status, 200, all.text);
  assert.equal(all.json.injection.environment.GOOGLE_OAUTH_ACCESS_TOKEN, 'google-access-personal');
  assert.equal(all.json.injection.environment.GOOGLE_ACCOUNT_EMAIL, 'personal@example.test');
});

test('参照の対象と出力を検証し、不正な指定では接続先に認証情報を要求しない', async t => {
  const f = await fixture(t), connection = await f.connection();
  const secret = (await f.keep('secret', 'value', 'private')).json.resource;
  f.expire(connection.id);
  const calls = f.google.calls.length;
  for (const input of [{ name: 'value', id: secret.id, as: 'VALUE' }, { name: 'value', output: 'VALUE', as: 'VALUE' },
    { id: secret.id, output: 'VALUE', as: 'VALUE' }, { id: connection.id, output: 'UNKNOWN' }, { id: connection.id, output: '' },
    { name: '', as: 'VALUE' }, { id: null }, { name: 'value', as: 'VALUE', extra: true }]) {
    const refused = await f.request('/v1/injections', { method: 'POST', data: { names: [input] } });
    assert.equal(refused.status, 400, JSON.stringify(input));
  }
  assert.equal(f.google.calls.length, calls);
  await f.signin('other@example.test');
  const refused = await f.request('/v1/injections', { method: 'POST', data: { names: [{ id: connection.id, output: 'GOOGLE_OAUTH_ACCESS_TOKEN' }] } });
  assert.equal(refused.status, 404);
  assert.equal(f.google.calls.length, calls);
});
