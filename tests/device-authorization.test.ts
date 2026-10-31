import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { CustodyClient } from '../shared/client.js';
import { ConnectionClient } from '../shared/connection-client.js';
import { ExecutionClient } from '../shared/execution-client.js';
import { RemoteFlowStore } from '../shared/operation-continuations.js';
import { JournalTrust } from '../runtime/trust.js';
import { MemoryJournal } from './delegation-support.js';
import { flowOutput } from '../cli/src/connections.js';
import { AppMaterial, ConnectionMaterial } from '../shared/connections.js';
import { Resource } from '../shared/contracts.js';
import { Execution } from '../shared/executions.js';
import { canonical } from '../shared/authority.js';
import { decode, encode } from '../shared/encryption.js';
import { DomainError } from '../shared/errors.js';

type Fixture = Awaited<ReturnType<typeof flowFixture>>;
const deviceUrl = 'https://github.com/login/device/code';
const tokenUrl = 'https://github.com/login/oauth/access_token';
const authorization = { device_code: 'private-cli-device-code', user_code: 'WXYZ-ABCD',
  verification_uri: 'https://github.com/login/device', expires_in: 900, interval: 5 };
const token = { access_token: 'private-device-access-token', token_type: 'bearer', scope: 'repo,gist' };

async function cli(f: Fixture, delegate = false) {
  const identity = delegate ? f.executorIdentity : f.owner, trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.owner.binding);
  await trust.rememberBinding(f.executorIdentity.binding);
  const custody = new CustodyClient(f.api(identity.token), f.config.origin, identity.binding, identity.keys, trust);
  const store = new RemoteFlowStore(custody), connections = new ConnectionClient(custody, store, f.transport, 'cli');
  return { custody, store, connections, operations: new ExecutionClient(custody, connections) };
}
async function start(f: Fixture, client: Awaited<ReturnType<typeof cli>>) {
  const app = await f.saveApp('github:device');
  const progress = await client.operations.execute({ name: 'connection.connect', input: {
    ownerId: f.owner.actor.id, methodId: 'github:device', appId: app.id, scopes: ['repo', 'gist'],
  } });
  if (!('kind' in progress) || progress.kind !== 'authorize' || !progress.device) throw new Error('Expected a device code.');
  return { app, progress };
}

test('代理のCLIで確認コードを表示し、確認間隔を守って続行し、所有者のGitHub接続を保存して使用する', async t => {
  let polls = 0;
  const f = await flowFixture(request => {
    if (request.url === deviceUrl) return jsonResponse(authorization);
    if (request.url === tokenUrl) {
      assert.equal(JSON.parse(String(request.body)).device_code, authorization.device_code);
      return jsonResponse(++polls === 1 ? { error: 'authorization_pending' } : polls === 2 ? { error: 'slow_down' } : token);
    }
    assert.equal(request.url, 'https://api.github.com/user');
    assert.equal(request.headers?.authorization, 'Bearer ' + token.access_token);
    return jsonResponse({ ok: true });
  }); t.after(f.close);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const first = await cli(f, true), { progress } = await start(f, first);
  const shown = flowOutput(progress);
  assert.equal(shown.userCode, authorization.user_code);
  assert.equal(shown.authorizationUrl, authorization.verification_uri);
  assert.equal(shown.verificationUri, authorization.verification_uri);
  assert.match(shown.next!, new RegExp('foundation connect wait ' + progress.flow.execution.id));
  assert.equal(JSON.stringify(shown).includes(authorization.device_code), false);
  const sealed = await first.custody.api.json('/api/operation-continuations/' + progress.flow.id);
  assert.equal(JSON.stringify(sealed).includes(authorization.device_code), false);
  await first.connections.progress(progress.flow.id);
  assert.equal(polls, 0);
  t.mock.timers.tick(5_000);
  assert.equal((await first.connections.progress(progress.flow.id)).kind, 'authorize');
  t.mock.timers.tick(5_000);
  assert.equal((await first.connections.progress(progress.flow.id)).kind, 'authorize');
  assert.equal(polls, 2);
  const resumed = await cli(f, true);
  t.mock.timers.tick(9_999);
  const waiting = await resumed.connections.progress(progress.flow.id);
  assert.equal(waiting.kind, 'authorize');
  assert.equal(polls, 2);
  t.mock.timers.tick(1);
  const connected = await resumed.connections.progress(progress.flow.id);
  if (connected.kind !== 'connected') throw new Error('Expected a saved connection.');
  assert.equal(polls, 3);
  const resource = await f.client.api.json('/api/resources/' + connected.id, {}, Resource);
  assert.equal(resource.ownerId, f.owner.actor.id);
  const material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(connected.id))));
  assert.equal(material.oauth?.accessToken, token.access_token);
  assert.deepEqual(material.oauth?.scopes, ['gist', 'repo']);
  assert.equal((await f.http(resource.id, 'GH_TOKEN', 'https://api.github.com/user'))?.ok, true);
});

test('デバイス認証の拒否と期限切れを知らせ、終了した認証への確認を止める', async t => {
  for (const [error, expected] of [
    ['access_denied', 'device_access_denied'], ['expired_token', 'device_code_expired'], ['local_expiry', 'device_code_expired'],
  ]) await t.test(error!, async t => {
    let polls = 0;
    const f = await flowFixture(request => {
      if (request.url === deviceUrl) return jsonResponse(authorization);
      polls++; return { ...jsonResponse({ error }), status: 400 };
    }); t.after(f.close);
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
    const client = await cli(f), { progress } = await start(f, client);
    t.mock.timers.tick(error === 'local_expiry' ? 900_000 : 5_000);
    const failed = await client.connections.progress(progress.flow.id);
    assert.equal(failed.kind, 'failed');
    if (failed.kind !== 'failed') throw new Error('Expected a failed authorization.');
    assert.equal(failed.error, expected);
    assert.equal((await client.connections.progress(progress.flow.id)).kind, 'failed');
    assert.equal(polls, error === 'local_expiry' ? 0 : 1);
  });
});

test('デバイス認証の通信に失敗したら確認間隔を延ばし、保存した間隔を守って再開する', async t => {
  const times: number[] = [];
  const f = await flowFixture(request => {
    if (request.url === deviceUrl) return jsonResponse(authorization);
    times.push(Date.now());
    if (times.length === 1) throw new DomainError(502, 'service_unavailable', 'The service could not be reached.');
    return jsonResponse(times.length === 2 ? { error: 'authorization_pending' } : token);
  }); t.after(f.close);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const now = Date.now(), client = await cli(f), { progress } = await start(f, client);
  t.mock.timers.tick(5_000);
  assert.equal((await client.connections.progress(progress.flow.id)).kind, 'authorize');
  const resumed = await cli(f);
  t.mock.timers.tick(9_999);
  await resumed.connections.progress(progress.flow.id);
  assert.equal(times.length, 1);
  t.mock.timers.tick(1);
  assert.equal((await resumed.connections.progress(progress.flow.id)).kind, 'authorize');
  t.mock.timers.tick(10_000);
  assert.equal((await resumed.connections.progress(progress.flow.id)).kind, 'connected');
  assert.deepEqual(times, [now + 5_000, now + 15_000, now + 25_000]);
});

test('デバイス認証中にアプリが変更されたら、現在のアプリでのやり直しを求める', async t => {
  const f = await flowFixture(() => jsonResponse(authorization)); t.after(f.close);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const client = await cli(f), { app, progress } = await start(f, client);
  const previous = await f.client.read(app.id);
  const material = AppMaterial.parse(JSON.parse(decode(await f.client.reveal(app.id))));
  const changed = { ...material, generation: crypto.randomUUID(), clientId: 'another-client' };
  await f.client.save(app.name, encode(canonical(changed)), { ...previous.content.policy, revision: previous.content.policy.revision + 1 },
    { previous, metadata: { ...previous.content.metadata, generation: changed.generation, clientId: changed.clientId } });
  t.mock.timers.tick(5_000);
  await assert.rejects(client.connections.progress(progress.flow.id), /current application/);
  assert.equal(f.requests.length, 1);
});

test('同時に確認しても一度だけ問い合わせ、キャンセル済みのデバイス認証を保存しない', async t => {
  let received!: () => void, release!: () => void;
  const requested = new Promise<void>(resolve => { received = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  const f = await flowFixture(async request => {
    if (request.url === deviceUrl) return jsonResponse(authorization);
    received(); await gate; return jsonResponse(token);
  }); t.after(f.close);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const client = await cli(f), { progress } = await start(f, client);
  t.mock.timers.tick(5_000);
  const first = client.connections.progress(progress.flow.id);
  await requested;
  const finished = Promise.allSettled([first, client.connections.progress(progress.flow.id)]);
  try { assert.equal((await client.connections.cancel(progress.flow.id)).kind, 'cancelled'); }
  finally { release(); }
  assert.ok((await finished).every(result => result.status === 'rejected'));
  const execution = await f.client.api.json('/api/executions/' + progress.flow.execution.id, {}, Execution);
  assert.equal(execution.state, 'cancelled');
  assert.equal(f.requests.filter(request => request.url === tokenUrl).length, 1);
});
