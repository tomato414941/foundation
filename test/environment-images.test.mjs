import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, json } from './helpers.mjs';
import { EnvironmentImages } from '../src/environment-images.mjs';

test('サインインした利用者がDocker Hubを検索し、説明と公式表示と続きのページを取得する', async t => {
  const sent = [];
  const f = await fixture(t, { imageFetcher: async (url, options) => {
    sent.push({ url: new URL(url), headers: options.headers });
    return json({ num_pages: 2, results: [{ name: 'python', description: 'Python language', is_official: true }, { name: 'example/python', description: 'Tools' }] });
  } });
  await f.signin();
  const first = await f.request('/v1/environment-images?query=python');
  assert.equal(first.status, 200, first.text);
  assert.deepEqual(first.json, { images: [{ name: 'python', description: 'Python language', official: true }, { name: 'example/python', description: 'Tools', official: false }], next: 2 });
  assert.equal(sent[0].url.origin, 'https://index.docker.io');
  assert.equal(sent[0].url.searchParams.get('q'), 'python');
  assert.deepEqual(sent[0].headers, { accept: 'application/json' });
  assert.deepEqual((await f.request('/v1/environment-images?query=python')).json, first.json);
  assert.equal(sent.length, 1, '同じ検索は保存した結果を返す');
  assert.equal((await f.request('/v1/environment-images?query=python&page=2')).json.next, null);
  assert.equal(sent[1].url.searchParams.get('page'), '2');
});

test('Docker Hubのタグを名前で絞り込み、Linux amd64で使えるタグをページごとに取得する', async t => {
  const sent = [];
  const f = await fixture(t, { imageFetcher: async url => {
    sent.push(new URL(url));
    if (new URL(url).pathname.endsWith('/latest')) return json({ name: 'latest', images: [{ os: 'linux', architecture: 'amd64' }] });
    return json({ next: 'https://hub.docker.com/next', results: [
      { name: '3.12-slim', images: [{ os: 'unknown', architecture: 'unknown' }, { os: 'linux', architecture: 'amd64' }] },
      { name: '3.12-windows', images: [{ os: 'windows', architecture: 'amd64' }] },
      { name: '3.12-arm', images: [{ os: 'linux', architecture: 'arm64' }] },
    ] });
  } });
  await f.signin();
  const answer = await f.request('/v1/environment-images/tags?repository=python&query=3.12&page=2');
  assert.equal(answer.status, 200, answer.text);
  assert.deepEqual(answer.json, { tags: [{ name: '3.12-slim' }], next: 3 });
  assert.equal(sent[0].pathname, '/v2/namespaces/library/repositories/python/tags');
  assert.equal(sent[0].searchParams.get('name'), '3.12');
  assert.equal(sent[0].searchParams.get('page'), '2');
  const initial = await f.request('/v1/environment-images/tags?repository=example/tools');
  assert.equal(initial.json.default_tag, 'latest');
  assert.ok(sent.some(url => url.pathname === '/v2/namespaces/example/repositories/tools/tags'));
});

test('既定のバージョンがあると自動選択に使い、既定を持たないイメージでは選べるバージョンを返す', async () => {
  for (const [response, expected] of [[json({ name: 'latest', images: [{ os: 'linux', architecture: 'amd64' }] }), 'latest'], [json({}, 404), null], [json({ name: 'latest', images: [{ os: 'windows', architecture: 'amd64' }] }), null]]) {
    const catalog = new EnvironmentImages(async url => url.endsWith('/latest') ? response : json({ results: [{ name: '1.0', images: [{ os: 'linux', architecture: 'amd64' }] }], next: null }));
    assert.deepEqual(await catalog.tags('example/tool'), { tags: [{ name: '1.0' }], next: null, default_tag: expected });
  }
});

test('検索には認証を求め、画像名やページの不正な指定を入力エラーとして返す', async t => {
  const f = await fixture(t, { imageFetcher: async () => json({ results: [] }) });
  assert.equal((await f.request('/v1/environment-images?query=python', { anonymous: true })).status, 401);
  await f.signin();
  for (const suffix of ['?page=0', '?page=1.5', '?query=' + 'a'.repeat(201), '/tags?repository=../secrets', '/tags?repository=https://example.com/image', '/tags']) {
    const result = await f.request('/v1/environment-images' + suffix);
    assert.equal(result.status, 400, suffix + ': ' + result.text);
    assert.equal(result.json.error.code, 'invalid_image_search');
  }
});

test('Docker Hubの一時エラーを表示し、同じ検索を再試行すると結果を取得する', async t => {
  let attempt = 0;
  const f = await fixture(t, { imageFetcher: async () => ++attempt === 1 ? json({}, 429) : json({ results: [], num_pages: 0 }) });
  await f.signin();
  const failed = await f.request('/v1/environment-images?query=python', { headers: { 'x-foundation-locale': 'en' } });
  assert.equal(failed.status, 503);
  assert.equal(failed.json.error.message, 'Cannot reach Docker Hub. Please try again shortly.');
  assert.deepEqual((await f.request('/v1/environment-images?query=python')).json, { images: [], next: null });
});

test('応答の破損や通信エラーを検索の一時エラーとして扱い、見つからないリポジトリを区別する', async () => {
  for (const fetcher of [async () => { throw new Error('network'); }, async () => new Response('bad json'), async () => json({ wrong: [] }), async () => new Response('x'.repeat(2_000_001))]) {
    await assert.rejects(new EnvironmentImages(fetcher).search('python'), error => error.status === 503 && error.code === 'image_catalog_unavailable');
  }
  await assert.rejects(new EnvironmentImages(async () => json({}, 404)).tags('unknown/image'), error => error.status === 404 && error.code === 'image_repository_missing');
});
