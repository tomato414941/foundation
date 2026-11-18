import test from 'node:test';
import assert from 'node:assert/strict';
import { delegatedFixture, MemoryJournal } from './delegation-support.js';
import { ConnectionOperations } from '../server/connection-operations.js';
import { Connections } from '../runtime/connections.js';
import type { ConnectionBroker } from '../runtime/connections.js';
import type { AwsConnectionProvider } from '../runtime/aws.js';
import { MethodDefinition } from '../shared/contracts.js';
import { AppMaterial, ConnectionMaterial, connectionMetadata, openConnection, sealedConnection } from '../shared/connections.js';
import { canonical } from '../shared/authority.js';
import { ContentTypes, protect, reveal } from '../shared/custody.js';
import type { CustodyPolicy } from '../shared/custody.js';
import { encode } from '../shared/encryption.js';
import type { OutboundRequest, OutboundResponse, Transport } from '../server/transport.js';

const response = (body: unknown): OutboundResponse => ({ status: 200, headers: { 'content-type': 'application/json' },
  body: encode(JSON.stringify(body)) });
async function setup(respond: (request: OutboundRequest) => Promise<OutboundResponse> | OutboundResponse, aws?: AwsConnectionProvider) {
  const f = await delegatedFixture();
  const method = MethodDefinition.parse({ name: 'Provider', kind: 'oauth', config: {
    authorizeUrl: 'https://provider.example/authorize', tokenUrl: 'https://provider.example/token',
    scopes: { default: ['read'] },
  } });
  // The owner's items are sealed for its delegate as well, which uses and renews them on its own machine.
  const policy = (contentType: CustodyPolicy['contentType'], readers = f.policy.readers): CustodyPolicy => ({
    ...f.policy, id: crypto.randomUUID(), contentType, readers,
  });
  const appMaterial = AppMaterial.parse({ format: 1, methodId: 'provider:oauth', generation: crypto.randomUUID(),
    clientId: 'runtime-client', clientSecret: 'runtime-client-secret', fields: {} });
  const appPolicy = policy(ContentTypes.clientCredential);
  const appContent = await protect(encode(canonical(appMaterial)), appPolicy, 1, f.owner.binding, f.owner.keys,
    { methodId: 'provider:oauth', clientId: appMaterial.clientId, generation: appMaterial.generation });
  await f.custody.put(f.owner.actor, { name: 'Application', content: appContent });
  const operations = new ConnectionOperations(f.custody), journal = new MemoryJournal();
  const broker: ConnectionBroker = {
    method: async () => method,
    prepare: (id, resourceId, revision) => operations.prepare(f.delegate.actor, id, resourceId, revision),
    dispatch: (id, fence) => operations.dispatch(f.delegate.actor, id, fence),
    commit: (id, fence, content) => operations.commit(f.delegate.actor, id, fence, content),
    uncertain: (id, fence) => operations.uncertain(f.delegate.actor, id, fence),
    abort: (id, fence) => operations.abort(f.delegate.actor, id, fence),
    state: resourceId => operations.state(f.delegate.actor, resourceId),
  };
  const requests: OutboundRequest[] = [];
  const transport: Transport = { async send(request) { requests.push(request); return respond(request); } };
  const connections = new Connections(f.delegate.binding, f.delegate.keys, broker, journal, transport, aws);
  async function storedConnection(name = 'Connection', state?: 'reconnect', app = { policy: appPolicy, content: appContent }) {
    const material = ConnectionMaterial.parse({ format: 3, methodId: 'provider:oauth', method,
      generation: crypto.randomUUID(), appId: app.policy.id, appGeneration: appMaterial.generation,
      ...(state ? { state } : {}),
      oauth: { accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 0,
        scopes: ['read'], scopesStatus: 'reported', account: 'account-1',
        accountVerified: true, extra: {}, facts: {} } });
    const content = await protect(sealedConnection(material), policy(ContentTypes.tokenSet),
      1, f.owner.binding, f.owner.keys, await connectionMetadata(material));
    await f.custody.put(f.owner.actor, { name, content });
    return { material, content, sources: [content, app.content] };
  }
  return { ...f, method, policy, appMaterial, appContent, appPolicy, operations, journal, broker, connections,
    requests, transport, storedConnection };
}

test('再認証が必要な接続は利用とトークン更新を再接続まで保留する', async () => {
  const f = await setup(() => response({ access_token: 'unexpected-access' }));
  try {
    const c = await f.storedConnection('Needs reconnection', 'reconnect');
    await assert.rejects(f.connections.outputs(c.content, c.sources,
      new AbortController().signal), { code: 'reconnect_required' });
    assert.equal(f.requests.length, 0);
    assert.equal((await f.custody.read(f.owner.actor, c.content.policy.id)).content.metadata.state, 'reconnect');
  } finally { await f.close(); }
});

test('更新したトークンを手元に記録し、管理サーバーへの応答が途切れても同じ結果で復旧する', async () => {
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'new-access', refresh_token: 'new-refresh', token_type: 'bearer', expires_in: 3600, scope: 'read' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const c = await f.storedConnection();
    const disconnected = new Connections(f.delegate.binding, f.delegate.keys, { ...f.broker,
      async commit() { throw new Error('offline'); } }, f.journal, f.transport);
    await assert.rejects(disconnected.outputs(c.content, c.sources, new AbortController().signal),
      { code: 'connection_uncertain' });
    assert.equal((await f.operations.state(f.delegate.actor, c.content.policy.id))!.state, 'uncertain');
    await f.connections.reconcile();
    await f.connections.reconcile();
    const updated = (await f.custody.read(f.owner.actor, c.content.policy.id)).content;
    assert.equal(updated.materialRevision, 2);
    assert.equal(openConnection(await reveal(updated, f.owner.binding, f.owner.keys.encryption), updated.metadata,
      f.method).oauth!.refreshToken, 'new-refresh');
    assert.equal(f.requests.filter(request => request.url.endsWith('/token')).length, 1);
  } finally { await f.close(); }
});

test('アプリを開けない読み手は接続を更新せず、アプリも開ける読み手が更新する', async () => {
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'new-access', refresh_token: 'new-refresh', token_type: 'bearer', expires_in: 3600, scope: 'read' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const ownersApp = { ...f.appPolicy, id: crypto.randomUUID(), readers: [f.owner.binding], authorities: [f.owner.binding] };
    const ownersContent = await protect(encode(canonical(f.appMaterial)), ownersApp, 1, f.owner.binding, f.owner.keys,
      { methodId: 'provider:oauth', clientId: f.appMaterial.clientId, generation: f.appMaterial.generation });
    await f.custody.put(f.owner.actor, { name: 'Owner application', content: ownersContent });
    const kept = await f.storedConnection('Owner renews', undefined, { policy: ownersApp, content: ownersContent });
    await assert.rejects(f.connections.outputs(kept.content, kept.sources, new AbortController().signal), { code: 'refresh_required' });
    assert.equal(await f.operations.state(f.delegate.actor, kept.content.policy.id), null);
    assert.equal(f.requests.length, 0);
    const c = await f.storedConnection('Delegate renews');
    await f.connections.outputs(c.content, c.sources, new AbortController().signal);
    const updated = await f.custody.get(c.content.policy.id);
    assert.equal(updated.materialRevision, 2);
    assert.equal(updated.signerId, f.delegate.binding.id);
    assert.equal(f.requests.filter(request => request.url.endsWith('/token')).length, 1);
  } finally { await f.close(); }
});

test('更新で権限が変わった接続も、そのまま更新して使う', async () => {
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'broad-access', refresh_token: 'new-refresh', token_type: 'bearer', expires_in: 3600, scope: 'read write' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const c = await f.storedConnection();
    const used = await f.connections.outputs(c.content, c.sources, new AbortController().signal);
    assert.ok(Object.values(used.values).includes('broad-access'));
    const updated = await f.custody.get(c.content.policy.id);
    assert.equal(updated.materialRevision, 2);
    assert.deepEqual(updated.metadata.scopes, ['read', 'write']);
  } finally { await f.close(); }
});

test('更新要求の結果が不明な場合は接続を保留し、別の端末からの更新にも確認を要求する', async () => {
  const f = await setup(() => { throw new Error('token response lost'); });
  try {
    const c = await f.storedConnection();
    await assert.rejects(f.connections.outputs(c.content, c.sources, new AbortController().signal),
      { code: 'connection_uncertain' });
    await f.connections.reconcile();
    await assert.rejects(f.operations.prepare(f.delegate.actor, crypto.randomUUID(), c.content.policy.id, 1),
      { code: 'connection_uncertain' });
    assert.equal(f.requests.length, 1);
  } finally { await f.close(); }
});

test('トークン更新の送信前に通信が途切れた場合、予約を解放して新しい更新を開始する', async () => {
  const f = await setup(() => response({}));
  try {
    const c = await f.storedConnection();
    const disconnected = new Connections(f.delegate.binding, f.delegate.keys,
      { ...f.broker, async dispatch() { throw new Error('offline before dispatch'); } }, f.journal, f.transport);
    await assert.rejects(disconnected.outputs(c.content, c.sources, new AbortController().signal),
      { code: 'connection_uncertain' });
    assert.deepEqual(await f.connections.reconcile(), []);
    const next = await f.operations.prepare(f.delegate.actor, crypto.randomUUID(), c.content.policy.id, 1);
    assert.equal(next.state, 'prepared');
    assert.equal(f.requests.length, 0);
  } finally { await f.close(); }
});

test('確定できなかった更新を、あとで端末がまとめて確定する', async () => {
  let refreshes = 0;
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'new-access', refresh_token: 'new-refresh', token_type: 'bearer', expires_in: 3600,
        scope: ++refreshes === 1 ? 'read write' : 'read' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const first = await f.storedConnection('Changed permissions'), second = await f.storedConnection('Unchanged permissions');
    const offline = new Connections(f.delegate.binding, f.delegate.keys,
      { ...f.broker, async commit() { throw new Error('offline'); } }, f.journal, f.transport);
    await assert.rejects(offline.outputs(first.content, first.sources, new AbortController().signal), { code: 'connection_uncertain' });
    await assert.rejects(offline.outputs(second.content, second.sources, new AbortController().signal), { code: 'connection_uncertain' });
    assert.deepEqual(await f.connections.reconcile(), []);
    assert.equal((await f.custody.get(first.content.policy.id)).materialRevision, 2);
    assert.equal((await f.custody.get(second.content.policy.id)).materialRevision, 2);
  } finally { await f.close(); }
});
