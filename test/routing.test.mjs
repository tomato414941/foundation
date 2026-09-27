import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';

test('公開入口のHTMLからFoundationの説明とAPIガイドを読めるようにする', async t => {
  const f = await fixture(t, { login: false });
  const page = await f.request('/', { anonymous: true });
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-type'), /^text\/html/);
  assert.match(page.text, /人・AI・アプリが使う認証情報やファイルを保管し、権限を決めて共有できます。/);
  const link = page.text.match(/<a href="([^"]+)">APIガイド<\/a>/);
  assert.ok(link, 'HTMLのリンクからガイドへ進める');
  const guide = await f.request(link[1], { anonymous: true });
  assert.equal(guide.status, 200);
  assert.match(guide.text, /POST \/v1\/principals/);
});

test('未ログインのAIに接続先・接続手順・利用可能なAPIを案内する', async t => {
  const f = await fixture(t, { login: false });
  const page = await f.request('/start', { anonymous: true, headers: { 'sec-fetch-site': 'cross-site' } });
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-type'), /^text\/plain; charset=utf-8$/);
  assert.ok(page.text.includes('Server: ' + f.base));
  assert.ok(page.text.includes('foundation connect ' + f.base));
  assert.match(page.text, /npm install -g @tomato414941\/foundation/);
  assert.match(page.text, /request\.verification_uri and request\.confirmation_code/);
  assert.match(page.text, /foundation api GET \/v1\/principals\/me/);
  assert.match(page.text, /GET \/v1\/holdings/);
  assert.match(page.text, /gmail\.readonly/);
});

test('公開用の接続先を案内し、HEADでも案内の形式を確認できる', async t => {
  const origin = 'https://foundation.example.test';
  const f = await fixture(t, { login: false, publicOrigin: origin });
  const page = await f.request('/start', { anonymous: true });
  assert.equal(page.status, 200);
  assert.ok(page.text.includes('foundation connect ' + origin));
  const head = await f.request('/start', { method: 'HEAD', anonymous: true });
  assert.equal(head.status, 200);
  assert.equal(head.headers.get('content-type'), page.headers.get('content-type'));
  assert.equal(head.text, '');
});

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

test('ログインを終えると開こうとしていた認証情報または接続の画面へ戻る', async t => {
  const f = await fixture(t);
  for (const [path, destination] of [['/credentials', '/credentials'], ['/connections', '/connections']]) {
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
  const browser = await f.request('/v1/holdings?kind=grant&method=authorized');
  assert.equal(browser.json.holdings[0].subject, 'work@example.test');
  const agent = await f.request('/v1/holdings?kind=grant&method=authorized', { token: key.token });
  assert.deepEqual(agent.json.holdings.map(item => item.id), [first.id]);
  const anonymous = await f.request('/v1/connectors', { anonymous: true });
  assert.deepEqual(anonymous.json.connectors.map(item => item.id), ['google.oauth']);
});

test('解釈できないAuthorizationが付いた要求をCookieで代用せず拒否する', async t => {
  const f = await fixture(t);
  await f.credential();
  for (const authorization of ['Basic invalid', 'Bearer', '', 'Bearer invalid token', 'Bearer not-an-approved-key']) {
    const read = await f.request('/v1/holdings?kind=grant&method=authorized', { headers: { authorization } });
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
