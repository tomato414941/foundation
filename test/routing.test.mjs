import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';

test('未定義のURLには認証状態によらず404を返し、認証が必要なAPIにはログインを要求する', async t => {
  const f = await fixture(t);
  for (const anonymous of [true, false]) {
    for (const path of ['/unknown-page', '/v1/unknown-operation']) {
      const response = await f.request(path, { anonymous });
      assert.equal(response.status, 404);
      assert.equal(response.json.error.code, 'not_found');
      const head = await f.request(path, { method: 'HEAD', anonymous });
      assert.equal(head.status, 404);
      assert.equal(head.text, '');
    }
  }
  const protectedResource = await f.request('/v1/resources?kind=secret', { anonymous: true });
  assert.equal(protectedResource.status, 401);
  assert.equal(protectedResource.json.error.code, 'login_required');
});

test('公開入口のHTMLからAPI仕様へ進める', async t => {
  const f = await fixture(t, { login: false });
  const page = await f.request('/', { anonymous: true });
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-type'), /^text\/html/);
  const link = page.text.match(/<a href="([^"]+)">API仕様<\/a>/);
  assert.ok(link, 'HTMLのリンクからAPI仕様へ進める');
  const docs = await f.request(link[1], { anonymous: true });
  assert.equal(docs.status, 200);
  assert.match(docs.text, /href="\/openapi.json"/);
});

test('未ログインのAIへOpenAPIで接続先・認証要件・入力形式を公開する', async t => {
  const f = await fixture(t, { login: false });
  const page = await f.request('/openapi.json', { anonymous: true, headers: { 'sec-fetch-site': 'cross-site' } });
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-type'), /^application\/json/);
  assert.deepEqual(page.json.servers, [{ url: f.base }]);
  assert.match(page.json.paths['/v1/principals'].post.description, /verification_uri and user_code/);
  assert.deepEqual(page.json.paths['/v1/connections/complete'].post.security, [{ session: [] }]);
  assert.equal(page.json.paths['/v1/injections'].post.requestBody.content['application/json'].schema.$ref, '#/components/schemas/Inject');
});

test('OpenAPIに公開用の接続先を示し、HEADでも仕様の形式を確認する', async t => {
  const origin = 'https://foundation.example.test';
  const f = await fixture(t, { login: false, publicOrigin: origin });
  const page = await f.request('/openapi.json', { anonymous: true });
  assert.equal(page.status, 200);
  assert.deepEqual(page.json.servers, [{ url: origin }]);
  const head = await f.request('/openapi.json', { method: 'HEAD', anonymous: true });
  assert.equal(head.status, 200);
  assert.equal(head.headers.get('content-type'), page.headers.get('content-type'));
  assert.equal(head.text, '');
});

test('認証情報と接続の画面をそれぞれのURLから開く', async t => {
  const f = await fixture(t);
  for (const path of ['/secrets', '/services']) {
    const page = await f.request(path, { anonymous: true });
    assert.equal(page.status, 200, path);
    assert.match(page.headers.get('content-type'), /^text\/html/);
    assert.match(page.text, /src="\/app\.js"/);
    assert.equal(page.headers.get('cache-control'), 'private, no-store');
  }
});

test('ログイン済みの初回HTMLで行き先の見出しとメニューを表示し、データは認証済みAPIから取得する', async t => {
  const f = await fixture(t);
  await f.request('/v1/resources?kind=secret&name=private-test-name', { method: 'PUT', raw: 'private-test-value' });
  const page = await f.request('/secrets');
  assert.match(page.text, /<h1>シークレット<\/h1>/);
  assert.match(page.text, /href="\/secrets" aria-current="page"/);
  assert.match(page.text, /role="status" aria-label="読み込み中"/);
  assert.equal(page.headers.get('cache-control'), 'private, no-store');
  for (const privateValue of ['private-test-name', 'private-test-value', 'owner@example.test']) assert.ok(!page.text.includes(privateValue));
  const records = await f.request('/v1/resources?kind=secret');
  assert.equal(records.json.resources[0].name, 'private-test-name');
  const denied = await f.request('/v1/resources?kind=connection', { headers: { cookie: 'fdn_session=unverified' } });
  assert.equal(denied.status, 401);
});

test('公開アセットの更新確認と再利用を行う', async t => {
  const f = await fixture(t);
  for (const path of ['/app.js', '/workspace-view.js', '/styles.css']) {
    const asset = await f.request(path, { anonymous: true });
    assert.equal(asset.status, 200);
    assert.equal(asset.headers.get('cache-control'), 'no-cache');
    const again = await f.request(path, { anonymous: true, headers: { 'if-none-match': asset.headers.get('etag') } });
    assert.equal(again.status, 304);
  }
});

test('ログインを終えると開こうとしていた認証情報または接続の画面へ戻る', async t => {
  const f = await fixture(t);
  for (const [at, path] of ['/secrets', '/services', '/objects?prefix=reports%2F', '/objects?prefix=%E8%B3%87%E6%96%99+%23%3F%2F', '/principals#apps'].entries()) {
    const email = 'return-' + at + '@example.test';
    await f.auth.sendLink(email, f.base + '/login/confirm');
    const result = await f.request('/v1/login/verify', { method: 'POST', data: { email, token_hash: f.auth.links.get(email).code, return_to: path } });
    assert.equal(result.status, 200, result.text);
    assert.equal(result.json.return_to, path);
  }
});

test('同じURLでCookieとBearerを受け付け、Bearerがある場合はその所有者として扱う', async t => {
  const f = await fixture(t), first = await f.connection(), key = await f.issueKey();
  await f.login('second@example.test');
  await f.connection('work');
  const browser = await f.request('/v1/resources?kind=connection');
  assert.equal(browser.json.resources[0].subject, 'work@example.test');
  const agent = await f.request('/v1/resources?kind=connection', { token: key.token });
  assert.deepEqual(agent.json.resources.map(item => item.id), [first.id]);
  const anonymous = await f.request('/v1/services', { anonymous: true });
  assert.deepEqual(anonymous.json.services.map(item => item.id), ['google']);
});

test('解釈できないAuthorizationが付いた要求をCookieで代用せず拒否する', async t => {
  const f = await fixture(t);
  await f.connection();
  for (const authorization of ['Basic invalid', 'Bearer', '', 'Bearer invalid token', 'Bearer not-an-approved-key']) {
    const read = await f.request('/v1/resources?kind=connection', { headers: { authorization } });
    assert.equal(read.status, 401, authorization || '(empty header)');
    const write = await f.request('/v1/resources?kind=secret&name=must-not-write', { method: 'PUT', raw: 'untrusted', headers: { authorization } });
    assert.equal(write.status, 401, authorization || '(empty header)');
  }
  assert.deepEqual((await f.request('/v1/resources?kind=secret')).json.resources, []);
});

test('Cookieによる更新は同一Originに限定し、CLIのBearerではOriginなしで更新する', async t => {
  const f = await fixture(t), key = await f.issueKey(), path = '/v1/resources?kind=secret&name=url-review&as=' + USER_A;
  const request = async headers => {
    const response = await fetch(f.base + path, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', ...headers }, body: 'fixture-value' });
    await response.arrayBuffer();
    return response.status;
  };
  assert.equal(await request({ cookie: f.cookie() }), 403);
  assert.equal(await request({ cookie: f.cookie(), origin: 'https://elsewhere.example' }), 403);
  assert.equal(await request({ authorization: 'Bearer ' + key.token, origin: 'https://elsewhere.example' }), 403);
  assert.equal(await request({ authorization: 'Bearer ' + key.token }), 200);
  assert.equal((await f.read('secret', 'url-review')).text, 'fixture-value');
});

test('ファビコンとホーム画面のアイコンを、名前で探すブラウザにもPNGで返す', async t => {
  const f = await fixture(t);
  for (const path of ['/favicon.ico', '/favicon.png', '/apple-touch-icon.png']) {
    const response = await fetch(f.base + path);
    assert.equal(response.status, 200, path);
    assert.equal(response.headers.get('content-type'), 'image/png', path);
    assert.deepEqual([...new Uint8Array(await response.arrayBuffer()).slice(0, 4)], [0x89, 0x50, 0x4e, 0x47], path);
  }
  const page = await (await fetch(f.base + '/')).text();
  assert.match(page, /<link rel="apple-touch-icon" href="\/apple-touch-icon.png">/);
});
