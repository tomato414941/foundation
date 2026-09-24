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
  const put = await f.request('/v1/objects/report.pdf', { method: 'PUT', token: KEY, raw: Buffer.from('%PDF-1.4 hello'), type: 'application/pdf' });
  assert.equal(put.status, 200, put.text);
  assert.deepEqual(put.json, { key: 'report.pdf', size: 14, content_type: 'application/pdf' });

  const got = await f.request('/v1/objects/report.pdf', { token: KEY });
  assert.equal(got.status, 200);
  assert.equal(got.text, '%PDF-1.4 hello');
  assert.equal(got.headers.get('content-type'), 'application/pdf');
});

test('gives each owner their own room in the bucket', async (t) => {
  const f = await space(t);
  await f.request('/v1/objects/notes/today.txt', { method: 'PUT', token: KEY, raw: Buffer.from('mine'), type: 'text/plain' });
  const owner = (await f.request('/v1/state')).json.user.id;
  assert.deepEqual(f.bucket.calls, [['put', 'owners/' + owner + '/notes/today.txt']]);
});

test('lists what is there, and narrows by prefix', async (t) => {
  const f = await space(t);
  for (const key of ['a/one.txt', 'a/two.txt', 'b/three.txt']) {
    await f.request('/v1/objects/' + key, { method: 'PUT', token: KEY, raw: Buffer.from(key), type: 'text/plain' });
  }
  const all = await f.request('/v1/objects', { token: KEY });
  assert.deepEqual(all.json.objects.map(item => item.key).sort(), ['a/one.txt', 'a/two.txt', 'b/three.txt']);
  const some = await f.request('/v1/objects?prefix=a/', { token: KEY });
  assert.deepEqual(some.json.objects.map(item => item.key).sort(), ['a/one.txt', 'a/two.txt']);
});

test('removes an object', async (t) => {
  const f = await space(t);
  await f.request('/v1/objects/gone.txt', { method: 'PUT', token: KEY, raw: Buffer.from('x'), type: 'text/plain' });
  const removed = await f.request('/v1/objects/gone.txt', { method: 'DELETE', token: KEY, data: {} });
  assert.equal(removed.status, 200);
  assert.equal((await f.request('/v1/objects', { token: KEY })).json.objects.length, 0);
});

test('hands out a time-limited URL for something that only takes a URL', async (t) => {
  const f = await space(t);
  await f.request('/v1/objects/template.yaml', { method: 'PUT', token: KEY, raw: Buffer.from('Resources: {}'), type: 'text/plain' });
  const link = await f.request('/v1/objects/template.yaml/link', { method: 'POST', token: KEY, data: { minutes: 30 } });
  assert.equal(link.status, 200, link.text);
  assert.match(link.json.url, /expires=1800$/);
  assert.ok(link.json.url_expires_at > Date.now());
});

test('refuses a name that is not a name', async (t) => {
  const f = await space(t);
  for (const key of ['/leading', 'trailing/', 'double//slash', '../escape', 'with\\backslash']) {
    const result = await f.request('/v1/objects/' + encodeURIComponent(key), { method: 'PUT', token: KEY, raw: Buffer.from('x'), type: 'text/plain' });
    assert.equal(result.json.error.code, 'invalid_key', key);
  }
});

test('takes a name in the owner\'s own language', async (t) => {
  const f = await space(t);
  const put = await f.request('/v1/objects/' + encodeURIComponent('見積書/2026年 9月.pdf'), { method: 'PUT', token: KEY, raw: Buffer.from('%PDF'), type: 'application/pdf' });
  assert.equal(put.status, 200, put.text);
  assert.equal(put.json.key, '見積書/2026年 9月.pdf');
  const listed = await f.request('/v1/objects', { token: KEY });
  assert.deepEqual(listed.json.objects.map(item => item.key), ['見積書/2026年 9月.pdf']);
  const back = await f.request('/v1/objects/' + encodeURIComponent('見積書/2026年 9月.pdf'), { token: KEY });
  assert.equal(back.text, '%PDF');
});

test('says so when no bucket is configured', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  const result = await f.request('/v1/objects', { token: KEY });
  assert.equal(result.status, 503);
  assert.equal(result.json.error.code, 'space_unavailable');
});

test('keeps one owner out of another owner\'s room', async (t) => {
  const f = await space(t);
  await f.request('/v1/objects/private.txt', { method: 'PUT', token: KEY, raw: Buffer.from('secret'), type: 'text/plain' });
  const other = 'fdn_' + 'p'.repeat(43);
  await f.login('other@example.test');
  await f.approveKey(other, 'their-ai');
  const listed = await f.request('/v1/objects', { token: other });
  assert.deepEqual(listed.json.objects, []);
  const read = await f.request('/v1/objects/private.txt', { token: other });
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
  const listed = await new Objects(bucket).list('1', '');
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
  await f.request('/v1/objects/a.txt', { method: 'PUT', token: KEY, raw: Buffer.from('12345'), type: 'text/plain' });
  await f.request('/v1/secrets?name=notes/plan', { method: 'PUT', token: KEY, raw: 'abc', type: 'text/plain' });
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
  f.bucket.objects.set('owners/x/big', { body: Buffer.alloc(0), contentType: 'text/plain', updated_at: Date.now() });
  const owner = (await f.request('/v1/state')).json.user.id;
  f.bucket.objects.delete('owners/x/big');
  f.bucket.objects.set(`owners/${owner}/big`, { body: { length: 1024 * 1024 * 1024 }, contentType: 'text/plain', updated_at: Date.now() });
  const refused = await f.request('/v1/objects/more.txt', { method: 'PUT', token: KEY, raw: Buffer.from('x'), type: 'text/plain' });
  assert.equal(refused.status, 409, refused.text);
  assert.equal(refused.json.error.code, 'space_full');
});
