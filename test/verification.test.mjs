import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { cloudflareFixture, CLOUDFLARE_TOKEN, CLOUDFLARE_ACCOUNT } from './cloudflare-helper.mjs';
import { fixture, FakeGmail, USER_A, json } from './helpers.mjs';
import { GenericClient } from '../src/generic.mjs';
import { generic, gmailReadonly, gmailMetadata } from '../src/adapters.mjs';
import { verification, verificationResult } from '../src/verification.mjs';
import { HttpError } from '../src/errors.mjs';

const key = () => 'fdn_' + randomBytes(32).toString('base64url');
async function create(f, token = key(), extra = {}) {
  const result = await f.request('/v1/access-requests', { method: 'POST', anonymous: true, token, data: { name: 'dev-us', adapter: 'cloudflare.api-token', purpose: 'R2の一覧を確認', ...extra } });
  assert.equal(result.status, 201, result.text);
  return { token, row: result.json.request };
}
// The owner sees verification on the connection; the runtime sees only whether it may use it.
const usable = (f, token) => f.request('/v1/credentials', { anonymous: true, token });
const shown = async (f, id) => (await f.request('/api/state')).json.credentials.find(account => account.id === id)?.verification;
const check = (report, name) => report.checks.find(item => item.check === name);
const approve = (f, row) => f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { confirmationCode: row.confirmation_code } });
const credentials = (f, id, token) => f.request('/v1/credentials/' + id + '/deliver', { method: 'POST', anonymous: true, token, data: {} });

test('A failed import stores no secret, tells the owner in the response, and tells the runtime nothing', async t => {
  const f = await cloudflareFixture(t), { row, token } = await create(f);
  const failed = await f.importCloudflare({ accessRequestId: row.id, token: 'invalid-token-with-valid-syntax' });
  assert.equal(failed.status, 409); assert.equal(failed.json.error.code, 'reconnect_required');
  assert.equal(f.app.store.credentials(USER_A).length, 0);
  assert.equal(f.app.store.agents(USER_A).length, 0);
  const stored = JSON.stringify(f.app.store.db.prepare('SELECT * FROM access_requests').all());
  assert.doesNotMatch(stored, /invalid-token-with-valid-syntax|fixturetoken|test-bucket-do-not-store|verification/);
  assert.equal((await usable(f, token)).status, 401);
  assert.equal((await f.request('/v1/access-requests/current', { anonymous: true, token })).json.request.events.at(-1).code, 'reconnect_required', 'the runtime may read what happened, not the token');
  const originalCookie = 'fdn_session=' + f.app.store.createSession(f.auth.value());
  await f.login('other@example.test');
  assert.equal((await f.request('/api/access-requests/' + row.id)).status, 404);
  assert.equal((await f.importCloudflare({ accessRequestId: row.id })).status, 404);
  const valid = await f.request('/api/adapters/cloudflare.api-token/connect', { method: 'POST', headers: { cookie: originalCookie }, data: { name: 'Cloudflare', values: { token: CLOUDFLARE_TOKEN, account_id: CLOUDFLARE_ACCOUNT }, accessRequestId: row.id } });
  assert.equal(valid.status, 200, valid.text);
  assert.equal(check(valid.json.verification, 'credential').status, 'passed');
  assert.equal(check(valid.json.verification, 'permissions').status, 'unknown');
  assert.equal((await credentials(f, valid.json.credential_id, token)).status, 401);
});

test('R2 failure permits explicit approval and delivery; the failed observation stays on the connection for the owner', async t => {
  const f = await cloudflareFixture(t), { row, token } = await create(f);
  f.cloudflare.handler = url => url.includes('/r2/') ? json({ success: false, errors: [{ message: CLOUDFLARE_TOKEN }] }, 403) : null;
  const imported = await f.importCloudflare({ accessRequestId: row.id });
  assert.equal(imported.status, 200);
  assert.equal(check(imported.json.verification, 'credential').status, 'passed');
  assert.equal(check(imported.json.verification, 'r2_bucket_list').http_status, 403);
  assert.equal(check(await shown(f, imported.json.credential_id), 'r2_bucket_list').status, 'failed');
  assert.equal((await credentials(f, imported.json.credential_id, token)).status, 401);
  const result = await approve(f, row);
  assert.equal(result.status, 200, result.text);
  const issued = await credentials(f, imported.json.credential_id, token);
  assert.equal(issued.status, 200);
  assert.equal(issued.json.delivery.environment.CLOUDFLARE_API_TOKEN, CLOUDFLARE_TOKEN);
  assert.equal(check(issued.json.verification, 'r2_bucket_list').code, 'r2_unavailable');
  assert.ok(!JSON.stringify(issued.json.verification).includes(CLOUDFLARE_TOKEN));
});

test('Correcting an account ID while the request is open updates this request\'s candidate; approval closes it', async t => {
  const f = await cloudflareFixture(t), { row, token } = await create(f);
  const first = await f.importCloudflare({ accessRequestId: row.id, fields: { account_id: 'f'.repeat(32) } });
  assert.equal(first.status, 200);
  assert.equal(check(first.json.verification, 'r2_bucket_list').status, 'failed');
  const second = await f.importCloudflare({ accessRequestId: row.id });
  assert.equal(second.status, 200, second.text); assert.equal(second.json.credential_id, first.json.credential_id);
  assert.equal(f.app.store.credentials(USER_A).length, 1);
  assert.equal(check(await shown(f, second.json.credential_id), 'r2_bucket_list').status, 'passed');
  assert.equal((await approve(f, row)).status, 200);
  const retry = await f.importCloudflare({ accessRequestId: row.id, fields: { account_id: 'e'.repeat(32) } });
  assert.equal(retry.status, 409);
  assert.equal((await credentials(f, second.json.credential_id, token)).status, 200);
  assert.equal(f.app.store.secret(f.app.store.credential(USER_A, second.json.credential_id)).details.account_id, CLOUDFLARE_ACCOUNT);
});

test('Verification output is a bounded allowlist, not upstream messages or input fields', () => {
  const secret = 'sensitive-credential-and-upstream-prompt';
  const error = new HttpError(502, 'service_response', secret);
  assert.ok(!JSON.stringify(verificationResult(null, error)).includes(secret));
  const result = verification([{ check: secret, status: secret, code: secret, message: secret, token: secret, http_status: secret }]);
  assert.ok(!JSON.stringify(result).includes(secret));
  assert.equal(result.checks[0].status, 'unknown');
  assert.equal(verification(Array(100).fill({})).checks.length, 8);
  assert.equal(verification([null]).checks[0].status, 'unknown');
  assert.equal(verificationResult({ secret: { verification: { checks: 'invalid' } } }).checks[0].status, 'unknown');
});

test('A provider outage is an error to the owner, never proof of bad credentials, and stores nothing', async t => {
  const f = await cloudflareFixture(t), { row, token } = await create(f);
  f.cloudflare.handler = () => { throw new Error(CLOUDFLARE_TOKEN); };
  const outage = await f.importCloudflare({ accessRequestId: row.id });
  assert.equal(outage.status, 502); assert.equal(outage.json.error.code, 'service_unavailable');
  assert.ok(!outage.text.includes(CLOUDFLARE_TOKEN));
  assert.equal(f.app.store.credentials(USER_A).length, 0);
  assert.equal((await usable(f, token)).status, 401);
});

test('Generic API keys report unverified to the owner, without pretending to verify the provider or permissions', async t => {
  const gmail = new FakeGmail(), f = await fixture(t, { gmail, adapters: [gmailReadonly(gmail), gmailMetadata(gmail), generic(new GenericClient())] });
  const details = { service: 'Example', site: 'https://example.test/keys', fields: [{ id: 'EXAMPLE_API_KEY' }] };
  const { row } = await create(f, key(), { adapter: 'generic', details });
  const result = await f.request('/api/adapters/generic/connect', { method: 'POST', data: { name: 'Example', values: { EXAMPLE_API_KEY: 'example-private-key' }, accessRequestId: row.id } });
  assert.equal(result.status, 200, result.text);
  const report = await shown(f, result.json.credential_id);
  assert.deepEqual(report.checks.map(item => item.status), ['unknown', 'unknown']);
  assert.doesNotMatch(JSON.stringify(report), /example-private-key/);
});

test('OAuth failures return to the approval page and the connection records what passed', async t => {
  const f = await fixture(t), { row, token } = await create(f, key(), { adapter: 'gmail.metadata' });
  const begin = async () => new URL((await f.request('/api/adapters/gmail.metadata/connect', { method: 'POST', data: { name: 'Gmail', accessRequestId: row.id } })).json.url);
  const failed = await f.callback(await begin(), 'personal-readonly');
  assert.match(failed.headers.get('location'), /connection=scope/);
  assert.equal(f.app.store.credentials(USER_A).length, 0);
  const succeeded = await f.callback(await begin(), 'personal-metadata');
  assert.match(succeeded.headers.get('location'), /connection=connected/);
  const account = f.app.store.credentials(USER_A)[0];
  assert.equal(check(await shown(f, account.id), 'connection').status, 'passed');
  assert.equal((await usable(f, token)).status, 401);
});

for (const end of ['cancel', 'logout', 'newer']) test('A stale import cannot create a connection after ' + end, { timeout: 8000 }, async t => {
  const f = await cloudflareFixture(t), { row, token } = await create(f);
  let release, entered;
  const ready = new Promise(resolve => entered = resolve);
  f.cloudflare.handler = async () => { entered(); await new Promise(resolve => release = resolve); return json({ success: false }, 401); };
  const first = f.importCloudflare({ accessRequestId: row.id });
  await Promise.race([ready, first.then(result => { throw new Error('Probe did not begin: ' + result.status); })]);
  try {
    if (end === 'cancel') await f.request('/v1/access-requests/current', { method: 'DELETE', token, anonymous: true, data: {} });
    if (end === 'logout') await f.request('/api/session', { method: 'DELETE' });
    if (end === 'newer') {
      f.cloudflare.handler = null;
      assert.equal((await f.importCloudflare({ accessRequestId: row.id })).status, 200);
    }
  } finally { release(); }
  assert.notEqual((await first).status, 200);
  assert.equal(f.app.store.credentials(USER_A).length, end === 'newer' ? 1 : 0);
  assert.equal((await usable(f, token)).status, 401);
});
