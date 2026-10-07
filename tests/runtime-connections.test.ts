import test from 'node:test';
import assert from 'node:assert/strict';
import { delegatedFixture, MemoryJournal } from './delegation-support.js';
import { ConnectionOperations } from '../server/connection-operations.js';
import { Connections } from '../runtime/connections.js';
import type { ConnectionBroker } from '../runtime/connections.js';
import { Executor } from '../runtime/executor.js';
import { CommandProcess } from '../runtime/command.js';
import { MethodDefinition } from '../shared/contracts.js';
import type { JsonValue } from '../shared/contracts.js';
import { AppMaterial, ConnectionMaterial, connectionMetadata } from '../shared/connections.js';
import { hash, canonical } from '../shared/authority.js';
import { approvePolicy, prepareRun, protect, reveal } from '../shared/custody.js';
import type { CustodyContent, CustodyPolicy, ExecutionIntent } from '../shared/custody.js';
import { readReceipt } from '../shared/execution.js';
import { decode, encode } from '../shared/encryption.js';
import type { OutboundRequest, OutboundResponse, Transport } from '../server/transport.js';

const response = (body: unknown): OutboundResponse => ({ status: 200, headers: { 'content-type': 'application/json' },
  body: encode(JSON.stringify(body)) });
async function setup(respond: (request: OutboundRequest) => Promise<OutboundResponse> | OutboundResponse) {
  const f = await delegatedFixture();
  const method = MethodDefinition.parse({ name: 'Provider', kind: 'oauth', config: {
    authorizeUrl: 'https://provider.example/authorize', tokenUrl: 'https://provider.example/token',
    identity: { url: 'https://provider.example/account', id: '/id', name: '/name' },
    scopes: { default: ['read'] },
  } });
  const policy = (kind: CustodyPolicy['kind'], operations: CustodyPolicy['grants'][number]['operations']): CustodyPolicy => ({
    ...f.policy, id: crypto.randomUUID(), kind, grants: [{ ...f.policy.grants[0]!, operations }],
  });
  const appMaterial = AppMaterial.parse({ format: 1, methodId: 'provider:oauth', generation: crypto.randomUUID(),
    clientId: 'runtime-client', clientSecret: 'runtime-client-secret', fields: {} });
  const appPolicy = policy('app', ['connect', 'refresh', 'revoke']);
  const appContent = await protect(encode(canonical(appMaterial)), appPolicy, 1, f.owner.binding, f.owner.keys,
    { methodId: 'provider:oauth', clientId: appMaterial.clientId, generation: appMaterial.generation });
  await f.custody.put(f.owner.actor, { name: 'Application', content: appContent });
  const operations = new ConnectionOperations(f.custody), journal = new MemoryJournal();
  const broker: ConnectionBroker = {
    capture: (name, content) => f.custody.putProduced(f.executor.actor, { name, content }),
    prepare: (id, resourceId, revision) => operations.prepare(f.executor.actor, id, resourceId, revision),
    dispatch: (id, fence) => operations.dispatch(f.executor.actor, id, fence),
    commit: (id, fence, content) => operations.commit(f.executor.actor, id, fence, content),
    uncertain: (id, fence) => operations.uncertain(f.executor.actor, id, fence),
    abort: (id, fence) => operations.abort(f.executor.actor, id, fence),
    state: resourceId => operations.state(f.executor.actor, resourceId),
  };
  const requests: OutboundRequest[] = [];
  const transport: Transport = { async send(request) { requests.push(request); return respond(request); } };
  const connections = new Connections(f.executor.binding, f.executor.keys, broker, journal, transport);
  const executor = new Executor(f.environment, f.executor.keys, f.broker, journal, transport,
    new CommandProcess({ isolation: 'process' }), connections);
  async function intent(operation: JsonValue, sources: CustodyContent[], kind: ExecutionIntent['operation'], id = crypto.randomUUID()) {
    return { ...f.intent, id, operation: kind, operationDigest: await hash(operation),
      sources: await Promise.all(sources.map(async content => ({ id: content.policy.id, kind: content.policy.kind,
        materialRevision: content.materialRevision, policyDigest: await hash(content.policy),
        ...(content.policy.kind === 'connection' ? { authorizationDigest: String(content.metadata.authorizationDigest) } : {}),
      }))) };
  }
  async function run(input: JsonValue, sources: CustodyContent[] = [appContent], id = crypto.randomUUID()) {
    const operation = { kind: 'connect', input }, authorization = await intent(operation, sources, 'connect', id);
    await f.delegation.submit(f.owner.actor, await prepareRun(authorization, operation, f.owner.keys));
    await executor.tick();
    const task = await f.delegation.get(f.owner.actor, id);
    const result = await readReceipt(task.receipt!, authorization, f.owner.binding.id, f.owner.keys);
    assert.equal(task.state, 'succeeded', JSON.stringify(result.error));
    return result.result as Record<string, JsonValue>;
  }
  async function storedConnection() {
    const material = ConnectionMaterial.parse({ format: 1, methodId: 'provider:oauth', method,
      generation: crypto.randomUUID(), appId: appPolicy.id, appGeneration: appMaterial.generation,
      oauth: { accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 0,
        scopes: ['read'], scopesStatus: 'reported', account: 'account-1', accountName: 'Account',
        accountVerified: true, extra: {}, facts: {} } });
    const content = await protect(encode(canonical(material)), policy('connection', ['http', 'refresh', 'revoke']),
      1, f.owner.binding, f.owner.keys, await connectionMetadata(material));
    await f.custody.put(f.owner.actor, { name: 'Connection', content });
    const authorization = await intent({ kind: 'http' }, [content, appContent], 'http');
    return { material, content, authorization, sources: [content, appContent] };
  }
  return { ...f, method, policy, appMaterial, appContent, appPolicy, operations, journal, broker, connections,
    requests, transport, run, storedConnection };
}

test('選んだ実行先でOAuthコードを交換し、接続先と権限を確認してから承認した宛先へ保存する', async () => {
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'runtime-access', refresh_token: 'runtime-refresh', token_type: 'bearer', expires_in: 3600, scope: 'read' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const flowId = crypto.randomUUID();
    const started = await f.run({ action: 'start', flowId, name: 'My connection', methodId: 'provider:oauth',
      method: f.method, appId: f.appPolicy.id, redirectUri: f.config.origin + '/oauth/callback' });
    const url = new URL(String(started.url));
    assert.equal(url.searchParams.get('client_id'), 'runtime-client');
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    const reviewed = await f.run({ action: 'exchange', flowId,
      parameters: new URLSearchParams({ state: url.searchParams.get('state')!, code: 'approved-code' }).toString() });
    assert.equal(reviewed.kind, 'review');
    const metadata = reviewed.metadata as Record<string, JsonValue>;
    assert.equal(metadata.account, 'Account');
    assert.deepEqual(metadata.scopes, ['read']);
    const runId = crypto.randomUUID();
    const policy = { ...f.policy('connection', ['http', 'refresh']), producers: [{ executor: f.executor.binding,
      runId, expiresAt: f.intent.expiresAt, materialRevision: 1 }] };
    const connected = await f.run({ action: 'commit', flowId, authorizationDigest: metadata.authorizationDigest!,
      approval: await approvePolicy(policy, f.owner.binding, f.owner.keys) }, [f.appContent], runId);
    assert.equal(connected.id, policy.id);
    const saved = await f.custody.read(f.owner.actor, policy.id);
    const material = ConnectionMaterial.parse(JSON.parse(decode(await reveal(saved.content, f.owner.binding, f.owner.keys.encryption))));
    assert.equal(material.oauth!.refreshToken, 'runtime-refresh');
    assert.equal(new URLSearchParams(String(f.requests[0]!.body)).get('client_secret'), 'runtime-client-secret');
    assert.equal(f.requests.length, 2);
  } finally { await f.close(); }
});

test('更新したトークンを実行先に記録し、管理サーバーへの応答が途切れても同じ結果で復旧する', async () => {
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'new-access', refresh_token: 'new-refresh', token_type: 'bearer', expires_in: 3600, scope: 'read' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const c = await f.storedConnection();
    const disconnected = new Connections(f.executor.binding, f.executor.keys, { ...f.broker,
      async commit() { throw new Error('offline'); } }, f.journal, f.transport);
    await assert.rejects(disconnected.outputs(c.content, c.authorization, c.sources, new AbortController().signal),
      { code: 'connection_uncertain' });
    assert.equal((await f.operations.state(f.executor.actor, c.content.policy.id))!.state, 'uncertain');
    await f.connections.reconcile();
    await f.connections.reconcile();
    const updated = (await f.custody.read(f.owner.actor, c.content.policy.id)).content;
    assert.equal(updated.materialRevision, 2);
    assert.equal(ConnectionMaterial.parse(JSON.parse(decode(await reveal(updated, f.owner.binding,
      f.owner.keys.encryption)))).oauth!.refreshToken, 'new-refresh');
    assert.equal(f.requests.filter(request => request.url.endsWith('/token')).length, 1);
  } finally { await f.close(); }
});

test('トークン更新後のアカウント確認が途切れた場合、記録した新しいトークンで確認を再開する', async () => {
  let inspections = 0;
  const f = await setup(request => {
    if (request.url.endsWith('/token')) return response({ access_token: 'new-access', refresh_token: 'new-refresh',
      token_type: 'bearer', expires_in: 3600, scope: 'read' });
    assert.equal(request.headers?.authorization, 'Bearer new-access');
    if (++inspections === 1) throw new Error('account response lost');
    return response({ id: 'account-1', name: 'Account' });
  });
  try {
    const c = await f.storedConnection();
    await assert.rejects(f.connections.outputs(c.content, c.authorization, c.sources, new AbortController().signal),
      { code: 'connection_uncertain' });
    await f.connections.reconcile();
    const updated = (await f.custody.read(f.owner.actor, c.content.policy.id)).content;
    assert.equal(updated.materialRevision, 2);
    assert.equal(f.requests.filter(request => request.url.endsWith('/token')).length, 1);
    assert.equal(inspections, 2);
  } finally { await f.close(); }
});

test('更新で権限が変わった接続を確認待ちにして、利用者の再承認を要求する', async () => {
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'broad-access', refresh_token: 'new-refresh', token_type: 'bearer', expires_in: 3600, scope: 'read write' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const c = await f.storedConnection();
    await assert.rejects(f.connections.outputs(c.content, c.authorization, c.sources, new AbortController().signal),
      { code: 'connection_review' });
    assert.equal((await f.operations.state(f.executor.actor, c.content.policy.id))!.state, 'uncertain');
    assert.equal((await f.custody.read(f.owner.actor, c.content.policy.id)).content.materialRevision, 1);
    await assert.rejects(f.connections.outputs(c.content, c.authorization, c.sources, new AbortController().signal),
      { code: 'connection_busy' });
  } finally { await f.close(); }
});

test('更新要求の結果が不明な場合は接続を保留し、別の実行先からの更新にも確認を要求する', async () => {
  const f = await setup(() => { throw new Error('token response lost'); });
  try {
    const c = await f.storedConnection();
    await assert.rejects(f.connections.outputs(c.content, c.authorization, c.sources, new AbortController().signal),
      { code: 'connection_uncertain' });
    await f.connections.reconcile();
    await assert.rejects(f.operations.prepare(f.executor.actor, crypto.randomUUID(), c.content.policy.id, 1),
      { code: 'connection_uncertain' });
    assert.equal(f.requests.length, 1);
  } finally { await f.close(); }
});
