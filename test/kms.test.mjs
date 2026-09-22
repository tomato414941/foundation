import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Kms, resolveEncryptionKey } from '../src/kms.mjs';
import { signAws } from '../src/aws-sigv4.mjs';
import { Store } from '../src/store.mjs';
import { json, KEY } from './helpers.mjs';

// A KMS that wraps by prefixing and checks the signature's shape and target; it never sees a real key.
function fakeKms({ refuse = false } = {}) {
  const calls = [];
  const fetcher = async (url, options) => {
    calls.push({ url, options });
    if (url.startsWith('http://169.254.169.254/')) {
      if (url.endsWith('/api/token')) return new Response('imds-token');
      if (url.endsWith('/security-credentials/')) return new Response('foundation-host\n');
      return json({ Code: 'Success', AccessKeyId: 'ASIAROLE', SecretAccessKey: 'role-secret', Token: 'role-session' });
    }
    assert.equal(url, 'https://kms.ap-northeast-1.amazonaws.com/');
    assert.match(options.headers.authorization, /Credential=ASIAROLE\/\d{8}\/ap-northeast-1\/kms\/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target,/);
    assert.equal(options.headers['x-amz-security-token'], 'role-session');
    const payload = JSON.parse(options.body);
    assert.deepEqual(payload.EncryptionContext, { app: 'foundation', purpose: 'data-key' });
    if (refuse) return json({ __type: 'AccessDeniedException' }, 400);
    if (options.headers['x-amz-target'] === 'TrentService.Encrypt') return json({ CiphertextBlob: Buffer.from('wrapped:' + payload.Plaintext).toString('base64') });
    if (options.headers['x-amz-target'] === 'TrentService.Decrypt') {
      const inner = Buffer.from(payload.CiphertextBlob, 'base64').toString();
      return inner.startsWith('wrapped:') ? json({ Plaintext: inner.slice(8) }) : json({ __type: 'InvalidCiphertextException' }, 400);
    }
    return json({ __type: 'UnknownOperationException' }, 400);
  };
  return { calls, kms: new Kms({ keyId: 'arn:aws:kms:ap-northeast-1:052438773980:key/test', region: 'ap-northeast-1', fetcher }) };
}

test('signAws includes the session token and target header for JSON services', () => {
  const request = signAws({ service: 'kms', region: 'ap-northeast-1', host: 'kms.ap-northeast-1.amazonaws.com', body: '{}', credentials: { accessKeyId: 'AKIA', secretAccessKey: 's', sessionToken: 't' }, headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': 'TrentService.Decrypt' }, now: new Date('2026-09-22T00:00:00Z') });
  assert.equal(request.headers['x-amz-security-token'], 't');
  assert.match(request.headers.authorization, /SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=[0-9a-f]{64}$/);
});

test('An existing key is wrapped once through the instance role, then unwrapped on later starts without any key file', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'foundation-kms-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const database = join(dir, 'state.sqlite');
  // A database sealed with the file key, as today.
  const store = new Store(database, KEY); store.close();
  const { kms, calls } = fakeKms();
  const first = await resolveEncryptionKey({ database, encryptionKey: KEY, kms, log: () => {} });
  assert.ok(first.equals(KEY), 'the same key keeps existing rows readable');
  assert.deepEqual(calls.filter(call => call.url.includes('kms.')).map(call => call.options.headers['x-amz-target']), ['TrentService.Encrypt']);
  const stored = new DatabaseSync(database, { readOnly: true }).prepare("SELECT value FROM metadata WHERE name='wrapped_key'").get().value;
  assert.ok(!stored.includes(KEY.toString('base64')), 'the plaintext key is not stored');
  // Next start: no plaintext key anywhere; KMS unwraps.
  const second = await resolveEncryptionKey({ database, encryptionKey: null, kms, log: () => {} });
  assert.ok(second.equals(KEY));
  const reopened = new Store(database, second); reopened.close();
  // Refusal from KMS fails closed.
  await assert.rejects(resolveEncryptionKey({ database, encryptionKey: null, kms: fakeKms({ refuse: true }).kms, log: () => {} }), /KMS refused Decrypt/);
  // A wrong wrapped blob cannot be opened.
  const db = new DatabaseSync(database); db.prepare("UPDATE metadata SET value=? WHERE name='wrapped_key'").run(Buffer.from('nonsense').toString('base64')); db.close();
  await assert.rejects(resolveEncryptionKey({ database, encryptionKey: null, kms, log: () => {} }), /KMS refused Decrypt/);
});

test('A fresh deployment with KMS gets a random key that never touches disk in plaintext', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'foundation-kms-fresh-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const database = join(dir, 'state.sqlite');
  const { kms } = fakeKms();
  const key = await resolveEncryptionKey({ database, encryptionKey: null, kms, log: () => {} });
  assert.equal(key.length, 32);
  assert.ok(!(await readFile(database)).includes(key), 'the plaintext key is not in the database file');
  const again = await resolveEncryptionKey({ database, encryptionKey: null, kms, log: () => {} });
  assert.ok(again.equals(key));
  const store = new Store(database, key); store.close();
});

test('Without KMS the configured key is used unchanged', async () => {
  assert.equal(await resolveEncryptionKey({ database: ':memory:', encryptionKey: KEY, kms: null }), KEY);
});
