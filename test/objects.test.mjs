import test from 'node:test';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';
import { Objects, S3Space } from '../src/objects.mjs';
import { fail } from '../src/errors.mjs';

const KEY = 'fdn_' + 'o'.repeat(43);

// A bucket that answers like S3 does: whole objects under a key, listed by prefix as XML.
class FakeBucket {
  constructor() { this.objects = new Map(); this.calls = []; }
  get enabled() { return true; }
  async put(prefix, key, body, contentType) { this.calls.push(['put', prefix + key]); this.objects.set(prefix + key, { body, contentType, updated_at: Date.now() }); }
  async get(prefix, key) {
    const found = this.objects.get(prefix + key);
    if (!found) fail(404, 'not_found', 'その名前のものは置かれていません。');
    return { content: found.body, contentType: found.contentType };
  }
  async remove(prefix, key) { this.objects.delete(prefix + key); }
  async list(prefix, under) {
    const objects = [...this.objects].filter(([name]) => name.startsWith(prefix + under))
      .map(([name, value]) => ({ key: name.slice(prefix.length), size: value.body.length, updated_at: value.updated_at }));
    return { objects, cursor: null };
  }
  async link(prefix, key, seconds) { return 'https://bucket.example/' + prefix + key + '?expires=' + seconds; }
}

async function space(t) {
  const bucket = new FakeBucket();
  const f = await fixture(t, { space: bucket });
  await f.approveKey(KEY);
  return { ...f, bucket };
}

test('keeps an object for an owner who has no bucket of their own', async (t) => {
  const f = await space(t);
  const put = await f.request('/v1/holdings?kind=object&name=report.pdf', { method: 'PUT', token: KEY, raw: Buffer.from('%PDF-1.4 hello'), type: 'application/pdf' });
  assert.equal(put.status, 200, put.text);
  assert.match(put.json.holding.id, /^[0-9a-f-]{36}$/);
  assert.deepEqual({ ...put.json.holding, id: undefined, created_at: 0, updated_at: 0 }, { id: undefined, kind: 'object', name: 'report.pdf', size: 14, type: 'application/pdf', holder_id: put.json.holding.holder_id, created_at: 0, updated_at: 0 });

  const got = await f.read('object', 'report.pdf', { token: KEY });
  assert.equal(got.status, 200);
  assert.equal(got.text, '%PDF-1.4 hello');
  assert.equal(got.headers.get('content-type'), 'application/pdf');
});

test('keeps the bytes under the holding\'s own id, so where they live is nobody else\'s business', async (t) => {
  const f = await space(t);
  const put = await f.request('/v1/holdings?kind=object&name=notes/today.txt', { method: 'PUT', token: KEY, raw: Buffer.from('mine'), type: 'text/plain' });
  assert.deepEqual(f.bucket.calls, [['put', 'holdings/' + put.json.holding.id]]);
  const listed = await f.request('/v1/holdings?kind=object', { token: KEY });
  assert.equal(listed.json.holdings[0].id, put.json.holding.id);
});

test('オブジェクトの取得中に失効したキーへの返却を拒否する', async t => {
  const f = await space(t);
  await f.request('/v1/holdings?kind=object&name=private.txt', { method: 'PUT', token: KEY, raw: 'private-content' });
  const key = (await f.request('/v1/principals/me', { token: KEY })).json.principal;
  const get = f.bucket.get.bind(f.bucket);
  let began, release;
  const started = new Promise(resolve => began = resolve);
  f.bucket.get = async (...args) => { began(); await new Promise(resolve => release = resolve); return get(...args); };
  const pending = f.read('object', 'private.txt', { token: KEY });
  await started;
  await f.request('/v1/principals/' + key.id, { method: 'DELETE', data: {} });
  release();
  const refused = await pending;
  assert.equal(refused.status, 401);
  assert.equal(refused.json.error.code, 'not_approved');
  f.bucket.get = get;
  assert.equal((await f.read('object', 'private.txt')).text, 'private-content');
});

test('lists what is there, and narrows by prefix', async (t) => {
  const f = await space(t);
  for (const key of ['a/one.txt', 'a/two.txt', 'b/three.txt']) {
    await f.request('/v1/holdings?' + new URLSearchParams({ kind: 'object', name: key }), { method: 'PUT', token: KEY, raw: Buffer.from(key), type: 'text/plain' });
  }
  const all = await f.request('/v1/holdings?kind=object', { token: KEY });
  assert.deepEqual(all.json.holdings.map(item => item.name).sort(), ['a/one.txt', 'a/two.txt', 'b/three.txt']);
  const some = await f.request('/v1/holdings?kind=object&prefix=a/', { token: KEY });
  assert.deepEqual(some.json.holdings.map(item => item.name).sort(), ['a/one.txt', 'a/two.txt']);
});

test('removes an object', async (t) => {
  const f = await space(t);
  await f.request('/v1/holdings?kind=object&name=gone.txt', { method: 'PUT', token: KEY, raw: Buffer.from('x'), type: 'text/plain' });
  const removed = await f.drop('object', 'gone.txt', { token: KEY });
  assert.equal(removed.status, 200);
  assert.equal((await f.request('/v1/holdings?kind=object', { token: KEY })).json.holdings.length, 0);
});

test('hands out a time-limited URL for something that only takes a URL', async (t) => {
  const f = await space(t);
  await f.request('/v1/holdings?kind=object&name=template.yaml', { method: 'PUT', token: KEY, raw: Buffer.from('Resources: {}'), type: 'text/plain' });
  const link = await f.request('/v1/holdings/' + (await f.lookup('object', 'template.yaml', { token: KEY })).json.holding.id + '/link', { method: 'POST', token: KEY, data: { minutes: 30 } });
  assert.equal(link.status, 200, link.text);
  assert.match(link.json.url, /expires=1800$/);
  assert.ok(link.json.url_expires_at > Date.now());
});

test('refuses a name that is not a name', async (t) => {
  const f = await space(t);
  for (const key of ['/leading', 'trailing/', 'double//slash', '../escape', 'with\\backslash']) {
    const result = await f.request('/v1/holdings?' + new URLSearchParams({ kind: 'object', name: key }), { method: 'PUT', token: KEY, raw: Buffer.from('x'), type: 'text/plain' });
    assert.equal(result.json.error.code, 'invalid_key', key);
  }
});

test('takes a name in the owner\'s own language', async (t) => {
  const f = await space(t);
  const put = await f.request('/v1/holdings?' + new URLSearchParams({ kind: 'object', name: '見積書/2026年 9月.pdf' }), { method: 'PUT', token: KEY, raw: Buffer.from('%PDF'), type: 'application/pdf' });
  assert.equal(put.status, 200, put.text);
  assert.equal(put.json.holding.name, '見積書/2026年 9月.pdf');
  const listed = await f.request('/v1/holdings?kind=object', { token: KEY });
  assert.deepEqual(listed.json.holdings.map(item => item.name), ['見積書/2026年 9月.pdf']);
  const back = await f.read('object', '見積書/2026年 9月.pdf', { token: KEY });
  assert.equal(back.text, '%PDF');
});

test('says so when no bucket is configured', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  const result = await f.request('/v1/holdings?kind=object', { token: KEY });
  assert.equal(result.status, 503);
  assert.equal(result.json.error.code, 'space_unavailable');
});

test('keeps one owner out of another owner\'s room', async (t) => {
  const f = await space(t);
  await f.request('/v1/holdings?kind=object&name=private.txt', { method: 'PUT', token: KEY, raw: Buffer.from('secret'), type: 'text/plain' });
  const other = 'fdn_' + 'p'.repeat(43);
  await f.login('other@example.test');
  await f.approveKey(other, 'their-ai');
  const listed = await f.request('/v1/holdings?kind=object', { token: other });
  assert.deepEqual(listed.json.holdings, []);
  const read = await f.read('object', 'private.txt', { token: other });
  assert.equal(read.status, 404);
});

test('signs a listing the way S3 asks for it', async (t) => {
  const seen = [];
  const bucket = new S3Space({
    bucket: 'example-bucket', region: 'ap-northeast-1',
    credentials: async () => ({ accessKeyId: 'AKIAEXAMPLE', secretAccessKey: 'secret' }),
    fetcher: async (url, options) => {
      seen.push({ url, authorization: options.headers.authorization, payload: options.headers['x-amz-content-sha256'] });
      return new Response('<ListBucketResult><Contents><Key>owners/1/a.txt</Key><Size>3</Size><LastModified>2026-09-23T00:00:00.000Z</LastModified></Contents><IsTruncated>false</IsTruncated></ListBucketResult>', { status: 200 });
    },
  });
  const listed = await bucket.list('owners/1/', '');
  assert.deepEqual(listed.objects, [{ key: 'a.txt', size: 3, updated_at: Date.parse('2026-09-23T00:00:00.000Z') }]);
  assert.equal(listed.cursor, null);
  assert.match(seen[0].url, /^https:\/\/example-bucket\.s3\.ap-northeast-1\.amazonaws\.com\/\?/);
  assert.match(seen[0].url, /list-type=2/);
  assert.match(seen[0].url, /prefix=owners%2F1%2F/);
  assert.match(seen[0].authorization, /^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\/\d{8}\/ap-northeast-1\/s3\/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/);
  // S3 checks the hash in the header against the one the signature covers; an empty body hashes to this.
  assert.equal(seen[0].payload, createHash('sha256').update('').digest('hex'));
});

test('says what an owner is using and what they may use', async (t) => {
  const f = await space(t);
  await f.request('/v1/holdings?kind=object&name=a.txt', { method: 'PUT', token: KEY, raw: Buffer.from('12345'), type: 'text/plain' });
  await f.request('/v1/holdings?kind=secret&name=notes/plan', { method: 'PUT', token: KEY, raw: 'abc', type: 'text/plain' });
  const usage = await f.request('/v1/usage', { token: KEY });
  assert.equal(usage.status, 200, usage.text);
  assert.equal(usage.json.objects.count, 1);
  assert.equal(usage.json.objects.bytes, 5);
  assert.equal(usage.json.objects.bytes_max, 1024 * 1024 * 1024);
  assert.equal(usage.json.secrets.count, 1);
  assert.equal(usage.json.secrets.bytes, 3);
  assert.equal(usage.json.secrets.count_max, 200);
});

test('refuses to keep more than the space lends', async (t) => {
  const f = await space(t);
  const owner = (await f.request('/v1/overview')).json.user.id;
  f.app.store.db.prepare("INSERT INTO holdings (id,holder_id,kind,name,size,type,created_at,updated_at) VALUES ('big-1',?,'object','big',?,'text/plain','2026-01-01','2026-01-01')").run(owner, 1024 * 1024 * 1024);
  const refused = await f.request('/v1/holdings?kind=object&name=more.txt', { method: 'PUT', token: KEY, raw: Buffer.from('x'), type: 'text/plain' });
  assert.equal(refused.status, 409, refused.text);
  assert.equal(refused.json.error.code, 'space_full');
});

test('置いたものは ID で共有でき、見せられた相手は同じものを読み、編集を許された相手は同じものを書き換える', async (t) => {
  const f = await space(t);
  const put = await f.request('/v1/holdings?kind=object&name=plan.md', { method: 'PUT', raw: Buffer.from('# plan'), type: 'text/markdown' });
  const made = await f.request('/v1/principals', { method: 'POST', data: { name: 'colleague', credential: 'key' } });
  const token = made.json.token, id = made.json.principal.id;
  assert.equal((await f.request('/v1/holdings/' + put.json.holding.id + '/content', { token, anonymous: true })).status, 403, 'nothing before a line is drawn');
  assert.equal((await f.request('/v1/relations', { method: 'POST', data: { subject: id, relation: 'viewer', object_type: 'holding', object_id: put.json.holding.id } })).status, 201);
  const shown = await f.request('/v1/holdings?shown=me', { token, anonymous: true });
  assert.deepEqual(shown.json.holdings.map(row => [row.id, row.kind, row.name, row.relation]), [[put.json.holding.id, 'object', 'plan.md', 'viewer']]);
  const read = await f.request('/v1/holdings/' + put.json.holding.id + '/content', { token, anonymous: true });
  assert.equal(read.status, 200); assert.equal(read.text, '# plan'); assert.equal(read.headers.get('content-type'), 'text/markdown');
  assert.equal((await f.request('/v1/holdings/' + put.json.holding.id + '/content', { method: 'PUT', raw: Buffer.from('# changed'), type: 'text/markdown', token, anonymous: true })).status, 403, 'a viewer does not write');
  assert.equal((await f.request('/v1/relations', { method: 'POST', data: { subject: id, relation: 'editor', object_type: 'holding', object_id: put.json.holding.id } })).status, 201);
  assert.equal((await f.request('/v1/holdings/' + put.json.holding.id + '/content', { method: 'PUT', raw: Buffer.from('# changed'), type: 'text/markdown', token, anonymous: true })).status, 200);
  assert.equal((await f.read('object', 'plan.md')).text, '# changed', 'the holder sees the change under their own name for it');
  const lines = await f.request('/v1/holdings/' + put.json.holding.id);
  assert.deepEqual(lines.json.holding.lines.map(row => [row.subject_id, row.relation]).sort(), [[id, 'editor'], [id, 'viewer']], 'the holder sees who is on the thing');
  assert.equal((await f.request('/v1/relations', { method: 'POST', data: { subject: id, relation: 'viewer', object_type: 'holding', object_id: put.json.holding.id }, token, anonymous: true })).status, 403, 'only the holder draws lines');
});
