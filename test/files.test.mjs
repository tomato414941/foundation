import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture } from './helpers.mjs';
import { S3Files } from '../src/files.mjs';
import { presignAws } from '../src/aws-sigv4.mjs';

// Keeps objects in memory and answers links as S3 would name them; never contacts AWS.
class FakeFiles {
  constructor() { this.enabled = true; this.objects = new Map(); }
  async put(id, body, meta) { if (this.objects.has(id)) throw new Error('overwrite'); this.objects.set(id, { body, ...meta }); }
  async url(id, seconds) { return 'https://files.s3.ap-northeast-1.amazonaws.com/files/' + id + '?X-Amz-Expires=' + seconds; }
}

async function withKey(t, options = {}) {
  const f = await fixture(t, { files: new FakeFiles(), ...options }), agent = await f.agent();
  const put = (content, { name = 'stack.yaml', type = 'text/plain; charset=utf-8', minutes, token = agent.token } = {}) => fetch(f.base + '/v1/files?' + new URLSearchParams({ name, ...(minutes === undefined ? {} : { minutes }) }), { method: 'POST', headers: { authorization: 'Bearer ' + token, 'content-type': type }, body: content })
    .then(async response => ({ status: response.status, json: await response.json() }));
  return { f, agent, put };
}

test('An approved key puts a file and receives a time-limited link that reads it', async t => {
  const { f, agent, put } = await withKey(t), content = 'Resources: {}\n';
  const placed = await put(content, { minutes: '30' });
  assert.equal(placed.status, 201, JSON.stringify(placed.json));
  assert.equal(placed.json.file.name, 'stack.yaml');
  assert.equal(placed.json.file.size, content.length);
  assert.equal(placed.json.file.sha256, createHash('sha256').update(content).digest('hex'));
  assert.match(placed.json.url, new RegExp('/files/' + placed.json.file.id + '\\?X-Amz-Expires=1800$'));
  const listed = await f.request('/v1/files', { token: agent.token, anonymous: true });
  assert.deepEqual(listed.json.files.map(file => file.id), [placed.json.file.id]);
  const again = await f.request('/v1/files/' + placed.json.file.id + '/link', { method: 'POST', token: agent.token, anonymous: true, data: {} });
  assert.equal(again.status, 200, again.text);
  assert.match(again.json.url, /X-Amz-Expires=3600$/);
});

test('Any approved key of the same owner may link a file; another owner and unapproved keys may not', async t => {
  const { f, put } = await withKey(t), placed = await put('a');
  const second = await f.agent('laptop');
  assert.equal((await f.request('/v1/files/' + placed.json.file.id + '/link', { method: 'POST', token: second.token, anonymous: true, data: {} })).status, 200);
  await f.login('other@example.test');
  const stranger = await f.agent('stranger');
  assert.equal((await f.request('/v1/files/' + placed.json.file.id + '/link', { method: 'POST', token: stranger.token, anonymous: true, data: {} })).status, 404);
  assert.deepEqual((await f.request('/v1/files', { token: stranger.token, anonymous: true })).json.files, []);
  assert.equal((await put('b', { token: 'fdn_' + 'A'.repeat(43) })).status, 401);
});

test('A file is refused when its name, type, size or link period is out of range', async t => {
  const { put } = await withKey(t);
  assert.equal((await put('a', { name: '../x' })).json.error.code, 'invalid_name');
  assert.equal((await put('a', { type: 'not a type' })).json.error.code, 'invalid_type');
  assert.equal((await put('a', { minutes: '0' })).json.error.code, 'invalid_minutes');
  assert.equal((await put('a', { minutes: '10081' })).json.error.code, 'invalid_minutes');
  assert.equal((await put(Buffer.alloc(5 * 1024 * 1024 + 1))).status, 413);
});

test('Without a configured backend the file space answers that it is unavailable', async t => {
  const { put } = await withKey(t, { files: null });
  const result = await put('a');
  assert.equal(result.status, 503);
  assert.equal(result.json.error.code, 'files_unavailable');
});

test('The S3 backend creates objects only if absent and links with presigned GET URLs', async t => {
  const calls = [], credentials = { accessKeyId: 'ASIAEXAMPLE', secretAccessKey: 'secret', sessionToken: 'session' };
  const s3 = new S3Files({ bucket: 'foundation-files', region: 'ap-northeast-1', credentials: async () => credentials, fetcher: async (url, options) => { calls.push({ url, options }); return new Response('', { status: 200 }); } });
  await s3.put('abc', Buffer.from('Resources: {}'), { contentType: 'text/plain; charset=utf-8', name: 'スタック.yaml' });
  assert.equal(calls[0].url, 'https://foundation-files.s3.ap-northeast-1.amazonaws.com/files/abc');
  assert.equal(calls[0].options.method, 'PUT');
  assert.equal(calls[0].options.headers['if-none-match'], '*');
  assert.equal(calls[0].options.headers['content-disposition'], "inline; filename*=UTF-8''" + encodeURIComponent('スタック.yaml'));
  assert.match(calls[0].options.headers.authorization, /SignedHeaders=content-disposition;content-type;host;if-none-match;x-amz-content-sha256;x-amz-date;x-amz-security-token,/);
  const link = new URL(await s3.url('abc', 600));
  assert.equal(link.origin + link.pathname, 'https://foundation-files.s3.ap-northeast-1.amazonaws.com/files/abc');
  assert.equal(link.searchParams.get('X-Amz-Expires'), '600');
  assert.equal(link.searchParams.get('X-Amz-Security-Token'), 'session');
});

test('Presigned URLs match the signature AWS documents for its example request', () => {
  const url = presignAws({ service: 's3', region: 'us-east-1', host: 'examplebucket.s3.amazonaws.com', path: '/test.txt', expires: 86400,
    credentials: { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' }, now: new Date('2013-05-24T00:00:00Z') });
  assert.equal(new URL(url).searchParams.get('X-Amz-Signature'), 'aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404');
});

test('A key publishes a file behind a time-limited URL, lists what it published, and asks for the URL again', async t => {
  const { f, agent } = await withKey(t);
  const placed = await f.request('/v1/files?' + new URLSearchParams({ name: 'stack.yaml', minutes: '120' }), { method: 'POST', token: agent.token, anonymous: true, raw: 'Resources: {}\n', type: 'text/plain; charset=utf-8' });
  assert.equal(placed.status, 201, placed.text);
  assert.equal(placed.json.file.content_type, 'text/plain; charset=utf-8');
  assert.match(placed.json.url, /X-Amz-Expires=7200$/);
  const listed = await f.request('/v1/files', { token: agent.token, anonymous: true });
  assert.equal(listed.json.files[0].id, placed.json.file.id);
  const again = await f.request('/v1/files/' + placed.json.file.id + '/link', { method: 'POST', token: agent.token, anonymous: true, data: { minutes: 5 } });
  assert.equal(again.status, 200, again.text);
  assert.match(again.json.url, /X-Amz-Expires=300$/);
});
