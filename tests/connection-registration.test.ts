import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { CatalogMethod, Resource, listOf } from '../shared/contracts.js';
import { AppMaterial } from '../shared/connections.js';
import { activeConnectionField } from '../shared/connection-fields.js';
import { CustodyClient } from '../shared/client.js';
import { OperationClient } from '../shared/operation-client.js';
import { ConnectionClient } from '../shared/connection-client.js';
import { RemoteFlowStore } from '../shared/operation-continuations.js';
import { decode, encode, thumbprint } from '../shared/encryption.js';
import { OperationView } from '../shared/operations.js';
import { canonical } from '../shared/digest.js';
import { DomainError } from '../server/errors.js';

function browser(f: Awaited<ReturnType<typeof flowFixture>>, custody = f.client) {
  return new OperationClient(custody, new ConnectionClient(custody, new RemoteFlowStore(custody), f.transport, 'browser'));
}
const valueFor = (name: string) => name === 'url' ? 'https://receiver.example/webhook' :
  name === 'domain' ? 'example.com' : name === 'tenant' ? 'common' :
  name === 'site' ? 'example.atlassian.net' : name === 'email' ? 'person@example.com' : name === 'shop' || name === 'subdomain' ? 'example' : 'private-value-' + name;

test('サービスへアクセスできない端末でも入力式の認証情報を暗号化して保存する', async t => {
  const f = await flowFixture(() => { throw new Error('The service is offline.'); }); t.after(f.close);
  const catalog = await f.api(f.stranger.token).json('/api/connection-methods', {}, listOf(CatalogMethod));
  let device = 0;
  for (const method of catalog.items.filter(method => method.registration.kind === 'input')) await t.test(method.id, async () => {
    const custody = new CustodyClient(f.api(f.stranger.token, '198.18.0.' + ++device), f.config.origin,
      f.stranger.actor.id, f.stranger.keys);
    const client = browser(f, custody);
    const definitions = method.kind === 'aws' ? [] : method.config.fields;
    const entered = Object.fromEntries(definitions.map(field => [field.name, field.choices?.[0]?.value ?? field.defaultValue ??
      (field.name === 'endpoint' ? 'https://storage.example.com' : field.name === 'region' ? 'us-east-1' :
        field.name === 'domain' && method.id.startsWith('atlassian:') ? 'example.atlassian.net' :
        field.name === 'domain' && method.id.startsWith('kintone:') ? 'example.cybozu.com' :
        field.name === 'token' && method.id.startsWith('tailscale:') ? 'tskey-api-private-value' :
        field.name === 'token' && method.id.startsWith('supabase:') ? 'sbp_private-value' :
        field.name === 'url' && method.id.startsWith('supabase:') ? 'https://example.supabase.co' :
        field.name === 'projectId' && method.id.startsWith('supabase:') ? 'example' :
        field.name === 'credentials' && method.id.startsWith('google:') ?
          JSON.stringify({ type: 'service_account', client_email: 'robot@example.iam.gserviceaccount.com' }) :
        method.id.startsWith('ssh:') ? ({ host: 'server.example.test', user: 'deploy',
          privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-value\n-----END OPENSSH PRIVATE KEY-----\n' })[field.name]! :
        valueFor(field.name))]));
    const fields = Object.fromEntries(definitions.filter(field => activeConnectionField(field, entered))
      .map(field => [field.name, entered[field.name]!]));
    const saved = await client.perform({ name: 'connection.connect', input: { ownerId: f.stranger.actor.id,
      methodId: method.id, name: method.id, ...(method.registration.kind === 'input' && method.kind === 'oauth' ? { clientId: 'application-id' } : {}) } },
      { fields, clientSecret: 'private-application-secret', ...(method.kind === 'aws' ? { aws: {
        authentication: { kind: 'access_key', accessKeyId: 'AKIATESTREGISTRATION', secretAccessKey: 'private-aws-secret' }, region: 'ap-northeast-1',
      } } : {}) });
    if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected encrypted credentials.');
    const material = await custody.connection(saved.resource.id);
    assert.equal(material.methodId, method.id);
    if (method.kind === 'aws') assert.equal(material.aws!.authentication.kind, 'access_key');
    else if (method.kind === 'oauth') {
      const application = AppMaterial.parse(JSON.parse(decode(await custody.reveal(material.appId!))));
      assert.equal(application.clientId, 'application-id'); assert.equal(application.clientSecret, 'private-application-secret');
    } else for (const field of definitions.filter(field => activeConnectionField(field, fields)))
      assert.equal(material.fields![field.name], fields[field.name]);
    const completed = await custody.api.json('/api/operations/' + saved.operationId, {}, OperationView);
    assert.equal(completed.state, 'succeeded');
    const encrypted = await custody.read(saved.resource.id);
    assert.ok(encrypted.content.sealed.ciphertext.length > 0);
  });
});

test('アプリ認証を登録し、利用時にトークンを取得して同じ権限で更新する', async t => {
  let grants = 0;
  const f = await flowFixture(request => {
    if (request.url === 'https://ca.ovh.com/auth/oauth2/token') {
      const form = new URLSearchParams(String(request.body));
      assert.equal(form.get('client_id'), 'application-id'); assert.equal(form.get('client_secret'), 'application-secret');
      return jsonResponse({ access_token: 'use-token-' + ++grants, token_type: 'Bearer', expires_in: 10, scope: 'all' });
    }
    assert.equal(request.url, 'https://ca.api.ovh.com/1.0/vps');
    assert.equal(request.headers?.authorization, 'Bearer use-token-' + grants);
    return jsonResponse(['vps-example']);
  }); t.after(f.close);
  const app = await f.saveApp('ovh:client_credentials', 'App', { apiRegion: 'ca' });
  const saved = await f.saveConnection({ methodId: 'ovh:client_credentials', appId: app.id });
  assert.equal((await f.http(saved.id, 'OVH_ACCESS_TOKEN', 'https://ca.api.ovh.com/1.0/vps'))?.ok, true);
  assert.equal((await f.http(saved.id, 'OVH_ACCESS_TOKEN', 'https://ca.api.ovh.com/1.0/vps'))?.ok, true);
  assert.equal(grants, 2);
  const material = await f.client.connection(saved.id);
  assert.equal(material.oauth?.accessToken, 'use-token-2');
});

test('ブラウザの認可応答を暗号化して中継し、別のブラウザから交換して保存する', async t => {
  const f = await flowFixture(request => {
    assert.equal(request.url, 'https://oauth2.googleapis.com/token');
    assert.equal(new URLSearchParams(String(request.body)).get('code'), 'browser-code');
    return jsonResponse({ access_token: 'browser-token', refresh_token: 'browser-refresh', token_type: 'Bearer', expires_in: 3600 });
  }); t.after(f.close);
  const app = await f.saveApp('google:oauth'), first = browser(f);
  const started = await first.perform({ name: 'connection.connect', input: { ownerId: f.owner.actor.id, methodId: 'google:oauth', appId: app.id } });
  if (!('kind' in started) || started.kind !== 'authorize') throw new Error('Expected authorization.');
  const state = new URL(started.url).searchParams.get('state')!;
  const callback = await f.app.inject('/oauth/callback?state=' + state + '&code=browser-code');
  assert.equal(callback.statusCode, 302);
  const row = await f.db.one<{ sealed: unknown }>('SELECT sealed FROM oauth_relays WHERE id=$1', [started.flow.id]);
  assert.ok(row?.sealed);
  assert.equal(JSON.stringify(row).includes('browser-code'), false);
  const second = browser(f), connected = await second.continue(started.flow.operationId);
  if (!('kind' in connected) || connected.kind !== 'connected') throw new Error('Expected a saved connection.');
  const material = await f.client.connection(connected.id);
  assert.equal(material.oauth?.accessToken, 'browser-token');
  assert.equal(material.oauth?.refreshToken, 'browser-refresh');
  assert.equal((await f.client.api.json('/api/operations/' + started.flow.operationId, {}, OperationView)).state, 'succeeded');
});

test('CLIが必要な認可を同じプリンシパルのCLIで開始し、戻ったブラウザからCLIの続行を案内する', async t => {
  const f = await flowFixture(request => {
    assert.equal(request.url, 'https://github.com/login/oauth/access_token');
    return jsonResponse({ access_token: 'cli-token', token_type: 'bearer', scope: 'read:user' });
  }); t.after(f.close);
  const app = await f.saveApp('github:oauth'), client = browser(f);
  const started = await client.perform({ name: 'connection.connect', input: { ownerId: f.owner.actor.id, methodId: 'github:oauth', appId: app.id } });
  if (!('kind' in started) || started.kind !== 'cli') throw new Error('Expected CLI continuation.');
  assert.equal(started.command, 'foundation connect continue ' + started.flow.operationId);
  const cli = new OperationClient(f.client, new ConnectionClient(f.client, new RemoteFlowStore(f.client), f.transport, 'cli'));
  const authorization = await cli.continue(started.flow.operationId);
  if (!('kind' in authorization) || authorization.kind !== 'authorize') throw new Error('Expected authorization.');
  const state = new URL(authorization.url).searchParams.get('state')!;
  const callback = await f.app.inject('/oauth/callback?state=' + state + '&code=cli-code&iss=' + encodeURIComponent('https://github.com/login/oauth'));
  assert.equal(callback.statusCode, 302);
  const returning = await client.connections.progress(started.flow.id);
  if (returning.kind !== 'cli') throw new Error('Expected CLI continuation.');
  assert.equal(returning.command, 'foundation connect continue ' + started.flow.operationId);
  const connected = await cli.connections.progress(started.flow.id);
  if (connected.kind !== 'connected') throw new Error('Expected a saved connection.');
  const saved = await f.client.api.json('/api/resources/' + connected.id, {}, Resource);
  assert.equal(saved.ownerId, f.owner.actor.id);
  const material = await f.client.connection(connected.id);
  assert.equal(material.oauth?.accessToken, 'cli-token');
});

test('代理のCLIでGitHubの認可応答を受け取り、指定した所有者の接続として保存する', async t => {
  const f = await flowFixture(request => {
    assert.equal(request.url, 'https://github.com/login/oauth/access_token');
    assert.equal(JSON.parse(String(request.body)).code, 'delegate-code');
    return jsonResponse({ access_token: 'delegate-token', token_type: 'bearer', scope: 'repo' });
  }); t.after(f.close);
  const app = await f.saveApp('github:oauth');
  const identity = f.delegate;
  const custody = new CustodyClient(f.api(identity.token), f.config.origin, identity.actor.id, identity.keys);
  const cli = new OperationClient(custody, new ConnectionClient(custody, new RemoteFlowStore(custody), f.transport, 'cli'));
  const started = await cli.perform({ name: 'connection.connect', input: {
    ownerId: f.owner.actor.id, methodId: 'github:oauth', appId: app.id,
  } });
  if (!('kind' in started) || started.kind !== 'authorize') throw new Error('Expected authorization.');
  const parameters = new URLSearchParams({ state: new URL(started.url).searchParams.get('state')!,
    code: 'delegate-code', iss: 'https://github.com/login/oauth' });
  assert.equal((await f.app.inject('/oauth/callback?' + parameters)).statusCode, 302);
  const connected = await cli.connections.progress(started.flow.id);
  if (connected.kind !== 'connected') throw new Error('Expected a saved connection.');
  const saved = await custody.api.json('/api/resources/' + connected.id, {}, Resource);
  assert.equal(saved.ownerId, f.owner.actor.id);
  const material = await f.client.connection(connected.id);
  assert.equal(material.oauth?.accessToken, 'delegate-token');
});

test('認可コードをstateと結び付け、並行して画面を開いても一度の交換で保存する', async t => {
  let release!: () => void, received!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const dispatched = new Promise<void>(resolve => { received = resolve; });
  const f = await flowFixture(async () => { received(); await gate; return jsonResponse({ access_token: 'once-token', token_type: 'Bearer' }); });
  t.after(f.close);
  const app = await f.saveApp('google:oauth'), client = browser(f);
  const started = await client.perform({ name: 'connection.connect', input: { ownerId: f.owner.actor.id, methodId: 'google:oauth', appId: app.id } });
  if (!('kind' in started) || started.kind !== 'authorize') throw new Error('Expected authorization.');
  await assert.rejects(client.connections.complete(started.flow.id, 'state=another-flow&code=foreign'), /does not match/);
  const completing = client.connections.complete(started.flow.id, 'state=' + new URL(started.url).searchParams.get('state')! + '&code=valid');
  await dispatched;
  const polling = await browser(f).connections.progress(started.flow.id);
  assert.equal(polling.kind, 'pending');
  release(); assert.equal((await completing).kind, 'connected');
  assert.equal((await browser(f).connections.progress(started.flow.id)).kind, 'connected');
  assert.equal(f.requests.length, 1);
});

test('ブラウザで交換できなかったコードを捨て、CLIで新しい認可を開始する', async t => {
  const f = await flowFixture(() => { throw new DomainError(409, 'browser_exchange_unavailable', 'Browser exchange failed.'); }); t.after(f.close);
  const app = await f.saveApp('google:oauth'), client = browser(f);
  const started = await client.perform({ name: 'connection.connect', input: { ownerId: f.owner.actor.id, methodId: 'google:oauth', appId: app.id } });
  if (!('kind' in started) || started.kind !== 'authorize') throw new Error('Expected authorization.');
  const original = new URL(started.url).searchParams.get('state')!;
  await f.app.inject('/oauth/callback?state=' + original + '&code=used-code');
  const failed = await client.connections.progress(started.flow.id); assert.equal(failed.kind, 'cli');
  const cli = new ConnectionClient(f.client, new RemoteFlowStore(f.client), { async send() { return jsonResponse({ access_token: 'restarted-token', token_type: 'Bearer' }); } }, 'cli');
  const resumed = await cli.progress(started.flow.id);
  if (resumed.kind !== 'authorize') throw new Error('Expected fresh authorization.');
  assert.notEqual(new URL(resumed.url).searchParams.get('state')!, original);
  const previous = await f.app.inject('/oauth/callback?state=' + original + '&code=used-code');
  assert.match(previous.headers.location!, /error=connection_expired/);
  await f.app.inject('/oauth/callback?state=' + new URL(resumed.url).searchParams.get('state')! + '&code=new-code');
  assert.equal((await cli.progress(started.flow.id)).kind, 'connected');
});

test('間違ったアプリ認証は利用時に失敗し、修正して保存し直すと利用できる', async t => {
  const f = await flowFixture(request => {
    if (request.url.endsWith('/oauth2/token')) {
      if (new URLSearchParams(String(request.body)).get('client_secret') !== 'correct-secret')
        return { ...jsonResponse({ error: 'invalid_client' }), status: 401 };
      return jsonResponse({ access_token: 'correct-token', token_type: 'Bearer', expires_in: 3600, scope: 'all' });
    }
    assert.equal(request.headers?.authorization, 'Bearer correct-token'); return jsonResponse(['vps-example']);
  }); t.after(f.close);
  const app = await f.saveApp('ovh:client_credentials', 'App', { apiRegion: 'ca' });
  const saved = await f.saveConnection({ methodId: 'ovh:client_credentials', appId: app.id });
  const rejected = await f.http(saved.id, 'OVH_ACCESS_TOKEN', 'https://ca.api.ovh.com/1.0/vps');
  assert.equal(rejected?.error?.code, 'authorization_failed');
  const previous = await f.client.read(app.id), material = AppMaterial.parse(JSON.parse(decode(await f.client.reveal(app.id))));
  await f.client.save({ id: app.id, ownerId: app.ownerId, kind: 'app' }, app.name,
    encode(canonical({ ...material, clientSecret: 'correct-secret' })), { previous, metadata: previous.content.metadata });
  await f.saveConnection({ methodId: 'ovh:client_credentials', appId: app.id, connectionId: saved.id });
  assert.equal((await f.http(saved.id, 'OVH_ACCESS_TOKEN', 'https://ca.api.ovh.com/1.0/vps'))?.ok, true);
});

test('保存済みのキーを標準のOVH方式へ保存し直し、同じ接続と共有先を維持する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const native = await f.method('ovh:api_key');
  if (native.kind !== 'ovh') throw new Error('Expected OVH API keys.');
  const custom = await f.client.api.json('/api/principals/' + f.owner.actor.id + '/resources', { method: 'POST', body: {
    kind: 'method', name: 'Saved keys', definition: { name: 'Saved keys', kind: 'token', config: { fields: native.config.fields, outputs: native.config.outputs } },
  } }, Resource);
  const original = await f.saveConnection({ methodId: custom.id, name: 'OVHcloud', fields: {
    apiRegion: 'ca', applicationKey: 'saved-key', applicationSecret: 'saved-secret', consumerKey: 'saved-consumer',
  } });
  const saved = await f.saveConnection({ methodId: 'ovh:api_key', connectionId: original.id, name: 'OVHcloud', fields: {
    apiRegion: 'ca', applicationKey: '', applicationSecret: '', consumerKey: '',
  } });
  assert.equal(saved.id, original.id);
  const material = await f.client.connection(saved.id);
  assert.equal(material.method.kind, 'ovh'); assert.equal(material.fields!.applicationSecret, 'saved-secret');
  const current = await f.client.read(saved.id);
  assert.deepEqual(current.content.sealed.recipients.map(recipient => recipient.header.kid).sort(),
    (await Promise.all([f.owner, f.delegate].map(person => thumbprint(person.keys.publicKey)))).sort());
  await f.context.resources.delete(f.owner.actor, await f.context.resources.get(custom.id));
});

test('既存の接続を同じサービスの別の方式で保存し直し、別のサービスの方式では保存しない', async t => {
  const f = await flowFixture(); t.after(f.close);
  const saved = await f.saveConnection({ methodId: 'ovh:pat', name: 'OVHcloud', fields: { apiRegion: 'ca', token: 'private-token' } });
  await assert.rejects(f.saveConnection({ methodId: 'gitlab:token', connectionId: saved.id, name: 'OVHcloud', fields: { token: '' } }),
    { code: 'service_changed' });
  const moved = await f.saveConnection({ methodId: 'ovh:api_key', connectionId: saved.id, name: 'OVHcloud', fields: {
    apiRegion: 'ca', applicationKey: 'application-key', applicationSecret: 'application-secret', consumerKey: 'consumer-key' } });
  assert.equal(moved.id, saved.id);
  const material = await f.client.connection(saved.id);
  assert.equal(material.methodId, 'ovh:api_key');
});
