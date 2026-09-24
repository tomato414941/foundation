import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';

test('同じURLでCookieとBearerを受け付け、Bearerがある場合はその所有者として扱う', async t => {
  const f = await fixture(t), first = await f.credential(), key = await f.issueKey();
  await f.login('second@example.test');
  await f.credential('work');
  const browser = await f.request('/v1/connections');
  assert.equal(browser.json.connections[0].subject, 'work@example.test');
  const agent = await f.request('/v1/connections', { token: key.token });
  assert.deepEqual(agent.json.connections.map(item => item.id), [first.id]);
  const anonymous = await f.request('/v1/connectors', { anonymous: true });
  assert.deepEqual(anonymous.json.connectors.map(item => item.id), ['gmail.readonly', 'gmail.metadata']);
});

test('解釈できないAuthorizationが付いた要求をCookieで代用せず拒否する', async t => {
  const f = await fixture(t);
  await f.credential();
  for (const authorization of ['Basic invalid', 'Bearer', '', 'Bearer invalid token', 'Bearer not-an-approved-key']) {
    const read = await f.request('/v1/connections', { headers: { authorization } });
    assert.equal(read.status, 401, authorization || '(empty header)');
    const write = await f.request('/v1/secrets?name=must-not-write', { method: 'PUT', raw: 'untrusted', headers: { authorization } });
    assert.equal(write.status, 401, authorization || '(empty header)');
  }
  assert.deepEqual((await f.request('/v1/secrets')).json.secrets, []);
});

test('Cookieによる更新は同一Originに限定し、CLIのBearerではOriginなしで更新する', async t => {
  const f = await fixture(t), key = await f.issueKey(), path = '/v1/secrets?name=url-review';
  const request = async headers => {
    const response = await fetch(f.base + path, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', ...headers }, body: 'fixture-value' });
    await response.arrayBuffer();
    return response.status;
  };
  assert.equal(await request({ cookie: f.cookie() }), 403);
  assert.equal(await request({ cookie: f.cookie(), origin: 'https://elsewhere.example' }), 403);
  assert.equal(await request({ authorization: 'Bearer ' + key.token, origin: 'https://elsewhere.example' }), 403);
  assert.equal(await request({ authorization: 'Bearer ' + key.token }), 200);
  assert.equal((await f.request(path)).text, 'fixture-value');
});
