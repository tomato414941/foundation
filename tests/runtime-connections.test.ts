import test from 'node:test';
import assert from 'node:assert/strict';
import { STSClient } from '@aws-sdk/client-sts';
import { delegatedFixture, MemoryJournal } from './delegation-support.js';
import { ConnectionOperations } from '../server/connection-operations.js';
import { Connections } from '../runtime/connections.js';
import type { ConnectionBroker } from '../runtime/connections.js';
import type { AwsConnectionProvider } from '../runtime/aws.js';
import { DeliveryPending, Executor } from '../runtime/executor.js';
import { CommandProcess } from '../runtime/command.js';
import { MethodDefinition } from '../shared/contracts.js';
import type { JsonValue } from '../shared/contracts.js';
import { AppMaterial, ConnectionMaterial, connectionMetadata } from '../shared/connections.js';
import { hash, canonical } from '../shared/authority.js';
import { ContentTypes, Operations, approvePolicy, prepareRun, protect, renewContent, reveal } from '../shared/custody.js';
import type { CustodyContent, CustodyPolicy, ExecutionIntent } from '../shared/custody.js';
import { readReceipt } from '../shared/runtime-protocol.js';
import { decode, encode } from '../shared/encryption.js';
import type { OutboundRequest, OutboundResponse, Transport } from '../server/transport.js';

const response = (body: unknown): OutboundResponse => ({ status: 200, headers: { 'content-type': 'application/json' },
  body: encode(JSON.stringify(body)) });
async function setup(respond: (request: OutboundRequest) => Promise<OutboundResponse> | OutboundResponse, aws?: AwsConnectionProvider) {
  const f = await delegatedFixture();
  const method = MethodDefinition.parse({ name: 'Provider', kind: 'oauth', config: {
    authorizeUrl: 'https://provider.example/authorize', tokenUrl: 'https://provider.example/token',
    scopes: { default: ['read'] },
  } });
  const policy = (contentType: CustodyPolicy['contentType'], operations: CustodyPolicy['grants'][number]['operations']): CustodyPolicy => ({
    ...f.policy, id: crypto.randomUUID(), contentType, grants: [{ ...f.policy.grants[0]!, operations }],
  });
  const appMaterial = AppMaterial.parse({ format: 1, methodId: 'provider:oauth', generation: crypto.randomUUID(),
    clientId: 'runtime-client', clientSecret: 'runtime-client-secret', fields: {} });
  const appPolicy = policy(ContentTypes.clientCredential, [Operations.connect, Operations.refresh, Operations.revoke]);
  const appContent = await protect(encode(canonical(appMaterial)), appPolicy, 1, f.owner.binding, f.owner.keys,
    { methodId: 'provider:oauth', clientId: appMaterial.clientId, generation: appMaterial.generation });
  await f.custody.put(f.owner.actor, { name: 'Application', content: appContent });
  const operations = new ConnectionOperations(f.custody), journal = new MemoryJournal();
  const broker: ConnectionBroker = {
    capture: (name, content, labels) => f.custody.putProduced(f.executor.actor, { name, content, labels }),
    prepare: (id, resourceId, revision) => operations.prepare(f.executor.actor, id, resourceId, revision),
    dispatch: (id, fence) => operations.dispatch(f.executor.actor, id, fence),
    commit: (id, fence, content) => operations.commit(f.executor.actor, id, fence, content),
    uncertain: (id, fence) => operations.uncertain(f.executor.actor, id, fence),
    abort: (id, fence) => operations.abort(f.executor.actor, id, fence),
    state: resourceId => operations.state(f.executor.actor, resourceId),
  };
  const requests: OutboundRequest[] = [];
  const transport: Transport = { async send(request) { requests.push(request); return respond(request); } };
  const connections = new Connections(f.executor.binding, f.executor.keys, broker, journal, transport, aws);
  const executor = new Executor(f.environment, f.executor.keys, f.broker, journal, transport,
    new CommandProcess({ isolation: 'process' }), connections);
  async function intent(operation: JsonValue, sources: CustodyContent[], kind: ExecutionIntent['operation'], id = crypto.randomUUID()) {
    return { ...f.intent, id, operation: kind, operationDigest: await hash(operation),
      sources: await Promise.all(sources.map(async content => ({ id: content.policy.id,
        materialRevision: content.materialRevision, policyDigest: await hash(content.policy),
        ...(content.policy.contentType === ContentTypes.tokenSet ? { authorizationDigest: String(content.metadata.authorizationDigest) } : {}),
      }))) };
  }
  async function storedConnection(name = 'Connection', grants?: CustodyPolicy['grants'], state?: 'reconnect') {
    const material = ConnectionMaterial.parse({ format: 2, methodId: 'provider:oauth', method,
      generation: crypto.randomUUID(), appId: appPolicy.id, appGeneration: appMaterial.generation,
      ...(state ? { state } : {}),
      oauth: { accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 0,
        scopes: ['read'], scopesStatus: 'reported', account: 'account-1', accountName: 'Account',
        accountVerified: true, extra: {}, facts: {} } });
    const connectionPolicy = policy(ContentTypes.tokenSet, [Operations.http, Operations.refresh, Operations.revoke]);
    if (grants) connectionPolicy.grants = grants;
    const content = await protect(encode(canonical(material)), connectionPolicy,
      1, f.owner.binding, f.owner.keys, await connectionMetadata(material));
    await f.custody.put(f.owner.actor, { name, content });
    const authorization = await intent({ kind: 'http' }, [content, appContent], Operations.http);
    return { material, content, authorization, sources: [content, appContent] };
  }
  return { ...f, method, policy, appMaterial, appContent, appPolicy, operations, journal, broker, connections,
    requests, transport, storedConnection, worker: executor };
}

test('再認証が必要な接続は利用とトークン更新を再接続まで保留する', async () => {
  const f = await setup(() => response({ access_token: 'unexpected-access' }));
  try {
    const c = await f.storedConnection('Needs reconnection', undefined, 'reconnect');
    await assert.rejects(f.connections.outputs(c.content, c.authorization, c.sources,
      new AbortController().signal), { code: 'reconnect_required' });
    const operation = { action: 'refresh', id: c.content.policy.id };
    await assert.rejects(f.connections.execute(operation, { ...c.authorization,
      operation: Operations.refresh, operationDigest: await hash({ kind: 'refresh', input: operation }) },
      c.sources, new AbortController().signal), { code: 'reconnect_required' });
    assert.equal(f.requests.length, 0);
    assert.equal((await f.custody.read(f.owner.actor, c.content.policy.id)).content.metadata.state, 'reconnect');
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

test('自動更新の依頼者と利用先を照合し、同じ委任で許可された接続だけを更新する', async () => {
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'new-access', refresh_token: 'new-refresh', token_type: 'bearer', expires_in: 3600, scope: 'read' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const grant = f.appPolicy.grants[0]!;
    for (const refresh of [
      { ...grant, actor: f.stranger.binding, operations: [Operations.refresh] as const },
      { ...grant, origins: ['https://another.example'], operations: [Operations.refresh] as const },
    ]) {
      const c = await f.storedConnection('Needs approval', [
        { ...grant, operations: [Operations.http] }, { ...refresh, operations: [...refresh.operations] },
      ]);
      await assert.rejects(f.connections.outputs(c.content, c.authorization, c.sources,
        new AbortController().signal, 'https://service.example/items'), { code: 'refresh_required' });
      assert.equal(await f.operations.state(f.executor.actor, c.content.policy.id), null);
    }
    assert.equal(f.requests.length, 0);
    const c = await f.storedConnection('Approved refresh', [
      { ...grant, operations: [Operations.http, Operations.refresh], origins: ['https://service.example'] },
    ]);
    await f.connections.outputs(c.content, c.authorization, c.sources,
      new AbortController().signal, 'https://service.example/items');
    const updated = await f.custody.get(c.content.policy.id);
    assert.equal(updated.materialRevision, 2);
    assert.equal(f.requests.filter(request => request.url.endsWith('/token')).length, 1);
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

test('トークン更新の送信前に通信が途切れた場合、予約を解放して新しい更新を開始する', async () => {
  const f = await setup(() => response({}));
  try {
    const c = await f.storedConnection();
    const disconnected = new Connections(f.executor.binding, f.executor.keys,
      { ...f.broker, async dispatch() { throw new Error('offline before dispatch'); } }, f.journal, f.transport);
    await assert.rejects(disconnected.outputs(c.content, c.authorization, c.sources, new AbortController().signal),
      { code: 'connection_uncertain' });
    assert.deepEqual(await f.connections.reconcile(), []);
    const next = await f.operations.prepare(f.executor.actor, crypto.randomUUID(), c.content.policy.id, 1);
    assert.equal(next.state, 'prepared');
    assert.equal(f.requests.length, 0);
  } finally { await f.close(); }
});

test('再承認が必要な接続を保留したまま、別の接続の復旧を完了する', async () => {
  let refreshes = 0;
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'new-access', refresh_token: 'new-refresh', token_type: 'bearer', expires_in: 3600,
        scope: ++refreshes === 1 ? 'read write' : 'read' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const first = await f.storedConnection('Changed permissions'), second = await f.storedConnection('Unchanged permissions');
    const offline = new Connections(f.executor.binding, f.executor.keys,
      { ...f.broker, async commit() { throw new Error('offline'); } }, f.journal, f.transport);
    await assert.rejects(offline.outputs(first.content, first.authorization, first.sources, new AbortController().signal), { code: 'connection_review' });
    await assert.rejects(offline.outputs(second.content, second.authorization, second.sources, new AbortController().signal), { code: 'connection_uncertain' });
    assert.equal((await f.connections.reconcile()).length, 1);
    assert.equal((await f.custody.get(second.content.policy.id)).materialRevision, 2);
    assert.equal((await f.operations.state(f.executor.actor, first.content.policy.id))!.state, 'uncertain');
  } finally { await f.close(); }
});
