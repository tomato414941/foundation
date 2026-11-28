import test from 'node:test';
import assert from 'node:assert/strict';
import { delegatedFixture, MemoryJournal } from './delegation-support.js';
import { ConnectionOperations } from '../server/connection-operations.js';
import { Connections } from '../runtime/connections.js';
import type { ConnectionBroker, Sources } from '../runtime/connections.js';
import type { AwsConnectionProvider } from '../runtime/aws.js';
import { MethodDefinition } from '../shared/contracts.js';
import { AppMaterial, ConnectionMaterial, connectionMetadata, openConnection, sealedConnection } from '../shared/connections.js';
import { canonical } from '../shared/digest.js';
import { openItem, sealItem } from '../shared/custody.js';
import { CustodyClient } from '../shared/client.js';
import type { JsonApi } from '../shared/client.js';
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
  // The owner's items are sealed for its delegate as well, which uses and renews them on its own machine.
  const appMaterial = AppMaterial.parse({ format: 1, methodId: 'provider:oauth', generation: crypto.randomUUID(),
    clientId: 'runtime-client', clientSecret: 'runtime-client-secret', fields: {} });
  const appMetadata = { methodId: 'provider:oauth', clientId: appMaterial.clientId, generation: appMaterial.generation };
  const app = await f.keep(f.owner.actor, f.owner.actor.id, 'Application', canonical(appMaterial), 'app', appMetadata);
  const appContent = (await f.custody.read(f.owner.actor, app.id)).content;
  const operations = new ConnectionOperations(f.custody), journal = new MemoryJournal();
  const broker: ConnectionBroker = {
    method: async () => method,
    saveToken: (id, content, appRevision) => operations.saveToken(f.delegate.actor, id, content, appRevision),
    prepare: (id, resourceId, revision) => operations.prepare(f.delegate.actor, id, resourceId, revision),
    dispatch: (id, fence) => operations.dispatch(f.delegate.actor, id, fence),
    commit: (id, fence, content) => operations.commit(f.delegate.actor, id, fence, content),
    uncertain: (id, fence) => operations.uncertain(f.delegate.actor, id, fence),
    abort: (id, fence) => operations.abort(f.delegate.actor, id, fence),
    refused: (id, fence) => operations.refused(f.delegate.actor, id, fence),
    state: resourceId => operations.state(f.delegate.actor, resourceId),
  };
  // The delegate's device learns from Foundation whom a renewed token set is sealed for.
  const api: JsonApi = { async json(path, _options, schema) {
    const id = /^\/api\/resources\/([^/]+)\/recipients$/.exec(path)?.[1];
    if (!id) throw new Error('Unexpected request: ' + path);
    const value = { items: await f.custody.recipients(await f.resources.get(id)), next: null };
    return (schema ? schema.parse(value) : value) as never;
  } };
  const device = new CustodyClient(api, f.config.origin, f.delegate.actor.id, f.delegate.keys);
  const requests: OutboundRequest[] = [];
  const transport: Transport = { async send(request) { requests.push(request); return respond(request); } };
  const connections = new Connections(device, broker, journal, transport, aws);
  async function storedConnection(name = 'Connection', state?: 'reconnect', application = { id: app.id, content: appContent }) {
    const material = ConnectionMaterial.parse({ format: 3, methodId: 'provider:oauth', method,
      generation: crypto.randomUUID(), appId: application.id, appGeneration: appMaterial.generation,
      ...(state ? { state } : {}),
      oauth: { accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 0,
        scopes: ['read'], scopesStatus: 'reported', account: 'account-1',
        accountVerified: true, extra: {}, facts: {} } });
    const row = await f.keep(f.owner.actor, f.owner.actor.id, name, decode(sealedConnection(material)), 'connection',
      await connectionMetadata(material));
    const content = (await f.custody.read(f.owner.actor, row.id)).content;
    const sources: Sources = new Map([[row.id, { kind: 'connection', content }], [application.id, { kind: 'app', content: application.content }]]);
    return { id: row.id, material, content, sources };
  }
  return { ...f, method, app, appMaterial, appMetadata, appContent, operations, journal, broker, device, connections,
    requests, transport, storedConnection };
}

test('再認証が必要な接続は利用とトークン更新を再接続まで保留する', async () => {
  const f = await setup(() => response({ access_token: 'unexpected-access' }));
  try {
    const c = await f.storedConnection('Needs reconnection', 'reconnect');
    await assert.rejects(f.connections.outputs(c.id, c.sources, new AbortController().signal), { code: 'reconnect_required' });
    assert.equal(f.requests.length, 0);
    assert.equal((await f.custody.read(f.owner.actor, c.id)).content.metadata.state, 'reconnect');
  } finally { await f.close(); }
});

test('更新したトークンを手元に記録し、管理サーバーへの応答が途切れても同じ結果で復旧する', async () => {
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'new-access', refresh_token: 'new-refresh', token_type: 'bearer', expires_in: 3600, scope: 'read' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const c = await f.storedConnection();
    const disconnected = new Connections(f.device, { ...f.broker, async commit() { throw new Error('offline'); } }, f.journal, f.transport);
    await assert.rejects(disconnected.outputs(c.id, c.sources, new AbortController().signal), { code: 'connection_uncertain' });
    assert.equal((await f.operations.state(f.delegate.actor, c.id))!.state, 'uncertain');
    await f.connections.reconcile();
    await f.connections.reconcile();
    const updated = (await f.custody.read(f.owner.actor, c.id)).content;
    assert.equal(updated.revision, 2);
    assert.equal(openConnection(await openItem(updated, f.owner.keys.privateKey, f.owner.keys.publicKey), updated.metadata,
      f.method).oauth!.refreshToken, 'new-refresh');
    assert.equal(f.requests.filter(request => request.url.endsWith('/token')).length, 1);
  } finally { await f.close(); }
});

test('アプリがまだ包まれていない読み手は接続を更新せず、アプリも開ける読み手が更新する', async () => {
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'new-access', refresh_token: 'new-refresh', token_type: 'bearer', expires_in: 3600, scope: 'read' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    // An application sealed only for its owner, as before it is sealed again for a delegate let in since.
    const ownersOnly = await sealItem(encode(canonical(f.appMaterial)), [f.owner.keys], 1, f.appMetadata);
    const kept = await f.storedConnection('Owner renews');
    kept.sources.set(f.app.id, { kind: 'app', content: ownersOnly });
    await assert.rejects(f.connections.outputs(kept.id, kept.sources, new AbortController().signal), { code: 'refresh_required' });
    assert.equal(await f.operations.state(f.delegate.actor, kept.id), null);
    assert.equal(f.requests.length, 0);
    const c = await f.storedConnection('Delegate renews');
    await f.connections.outputs(c.id, c.sources, new AbortController().signal);
    assert.equal((await f.custody.get(c.id)).revision, 2);
    assert.equal(f.requests.filter(request => request.url.endsWith('/token')).length, 1);
  } finally { await f.close(); }
});

test('更新で権限が変わった接続も、そのまま更新して使う', async () => {
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'broad-access', refresh_token: 'new-refresh', token_type: 'bearer', expires_in: 3600, scope: 'read write' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const c = await f.storedConnection();
    const used = await f.connections.outputs(c.id, c.sources, new AbortController().signal);
    assert.ok(Object.values(used.values).includes('broad-access'));
    const updated = await f.custody.get(c.id);
    assert.equal(updated.revision, 2);
    assert.deepEqual(updated.metadata.scopes, ['read', 'write']);
  } finally { await f.close(); }
});

test('更新したトークンを包む間に開ける相手が変わると、今の相手に包み直して確定する', async () => {
  const f = await setup(request => request.url.endsWith('/token')
    ? response({ access_token: 'new-access', refresh_token: 'new-refresh', token_type: 'bearer', expires_in: 3600, scope: 'read' })
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const c = await f.storedConnection();
    let drawn = false;
    // Someone is let in after the device sealed the renewed tokens, before Foundation has them.
    const racing = new Connections(f.device, { ...f.broker, async commit(id, fence, content) {
      if (!drawn) {
        drawn = true;
        await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'revealer', objectId: c.id });
      }
      return f.broker.commit(id, fence, content);
    } }, f.journal, f.transport);
    await racing.outputs(c.id, c.sources, new AbortController().signal);
    const shared = (await f.custody.read(f.stranger.actor, c.id)).content;
    assert.equal(openConnection(await openItem(shared, f.stranger.keys.privateKey, f.stranger.keys.publicKey), shared.metadata,
      f.method).oauth!.refreshToken, 'new-refresh');
  } finally { await f.close(); }
});

test('サービスが更新を断ったら結果を待たずに更新を終え、接続をつなぎ直し待ちにする', async () => {
  const f = await setup(request => request.url.endsWith('/token')
    ? { status: 400, headers: { 'content-type': 'application/json' }, body: encode(JSON.stringify({ error: 'invalid_grant' })) }
    : response({ id: 'account-1', name: 'Account' }));
  try {
    const c = await f.storedConnection();
    await assert.rejects(f.connections.outputs(c.id, c.sources, new AbortController().signal), { code: 'reconnect_required' });
    assert.equal(await f.operations.state(f.delegate.actor, c.id), null);
    assert.equal((await f.resources.get(c.id)).data.state, 'reconnect');
    assert.deepEqual(await f.connections.reconcile(), []);
  } finally { await f.close(); }
});

test('更新要求の結果が不明な場合は接続を保留し、別の端末からの更新にも確認を要求する', async () => {
  const f = await setup(() => { throw new Error('token response lost'); });
  try {
    const c = await f.storedConnection();
    await assert.rejects(f.connections.outputs(c.id, c.sources, new AbortController().signal), { code: 'connection_uncertain' });
    await f.connections.reconcile();
    await assert.rejects(f.operations.prepare(f.delegate.actor, crypto.randomUUID(), c.id, 1), { code: 'connection_uncertain' });
    assert.equal(f.requests.length, 1);
  } finally { await f.close(); }
});

test('トークン更新の送信前に通信が途切れた場合、予約を解放して新しい更新を開始する', async () => {
  const f = await setup(() => response({}));
  try {
    const c = await f.storedConnection();
    const disconnected = new Connections(f.device,
      { ...f.broker, async dispatch() { throw new Error('offline before dispatch'); } }, f.journal, f.transport);
    await assert.rejects(disconnected.outputs(c.id, c.sources, new AbortController().signal), { code: 'connection_uncertain' });
    assert.deepEqual(await f.connections.reconcile(), []);
    const next = await f.operations.prepare(f.delegate.actor, crypto.randomUUID(), c.id, 1);
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
    const offline = new Connections(f.device, { ...f.broker, async commit() { throw new Error('offline'); } }, f.journal, f.transport);
    await assert.rejects(offline.outputs(first.id, first.sources, new AbortController().signal), { code: 'connection_uncertain' });
    await assert.rejects(offline.outputs(second.id, second.sources, new AbortController().signal), { code: 'connection_uncertain' });
    assert.deepEqual(await f.connections.reconcile(), []);
    assert.equal((await f.custody.get(first.id)).revision, 2);
    assert.equal((await f.custody.get(second.id)).revision, 2);
  } finally { await f.close(); }
});
