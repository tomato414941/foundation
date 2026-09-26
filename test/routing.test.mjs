import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';

test('認証情報と接続の画面をそれぞれのURLから開く', async t => {
  const f = await fixture(t);
  for (const path of ['/credentials', '/connections']) {
    const page = await f.request(path, { anonymous: true });
    assert.equal(page.status, 200, path);
    assert.match(page.headers.get('content-type'), /^text\/html/);
    assert.match(page.text, /src="\/app\.js"/);
    assert.equal(page.headers.get('cache-control'), 'no-cache');
  }
});

test('以前のブックマークから認証情報の画面へ案内する', async t => {
  const f = await fixture(t), page = await f.request('/grants', { anonymous: true });
  assert.equal(page.status, 303);
  assert.equal(page.headers.get('location'), '/credentials');
});

test('ログインを終えると開こうとしていた認証情報または接続の画面へ戻る', async t => {
  const f = await fixture(t);
  for (const [path, destination] of [['/credentials', '/credentials'], ['/connections', '/connections'], ['/grants', '/credentials']]) {
    const email = 'return-' + destination.slice(1) + '@example.test';
    await f.auth.sendLink(email, f.base + '/login/confirm');
    const result = await f.request('/v1/login/verify', { method: 'POST', data: { email, token_hash: f.auth.links.get(email).code, return_to: path } });
    assert.equal(result.status, 200, result.text);
    assert.equal(result.json.return_to, destination);
  }
});

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
    const write = await f.request('/v1/holdings?kind=grant&name=must-not-write', { method: 'PUT', raw: 'untrusted', headers: { authorization } });
    assert.equal(write.status, 401, authorization || '(empty header)');
  }
  assert.deepEqual((await f.request('/v1/holdings?kind=grant&method=given')).json.holdings, []);
});

test('Cookieによる更新は同一Originに限定し、CLIのBearerではOriginなしで更新する', async t => {
  const f = await fixture(t), key = await f.issueKey(), path = '/v1/holdings?kind=grant&name=url-review&as=' + USER_A;
  const request = async headers => {
    const response = await fetch(f.base + path, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', ...headers }, body: 'fixture-value' });
    await response.arrayBuffer();
    return response.status;
  };
  assert.equal(await request({ cookie: f.cookie() }), 403);
  assert.equal(await request({ cookie: f.cookie(), origin: 'https://elsewhere.example' }), 403);
  assert.equal(await request({ authorization: 'Bearer ' + key.token, origin: 'https://elsewhere.example' }), 403);
  assert.equal(await request({ authorization: 'Bearer ' + key.token }), 200);
  assert.equal((await f.read('grant', 'url-review')).text, 'fixture-value');
});
