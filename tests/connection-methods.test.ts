import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { Catalog } from '../server/catalog.js';
import { Services } from '../server/services.js';
import { OAuth } from '../server/oauth.js';
import { digest } from '../server/vault.js';
import {
  ConnectionInput,
  LegacyServiceDefinition,
  MethodDefinition,
  ServiceInputDefinition,
} from '../shared/contracts.js';
import { encode } from '../shared/encryption.js';
import type { OutboundRequest, OutboundResponse, Transport } from '../server/transport.js';

class Provider implements Transport {
  respond: (request: OutboundRequest) => OutboundResponse = () => {
    throw new Error('Unexpected provider request');
  };
  async send(request: OutboundRequest) {
    return this.respond(request);
  }
}
const json = (value: unknown): OutboundResponse => ({
  status: 200,
  headers: {},
  body: encode(JSON.stringify(value)),
});
const keyMethod = (name: string, field = 'token', output = 'API_KEY') =>
  MethodDefinition.parse({
    name,
    kind: 'token',
    config: { fields: [{ name: field, label: field, secret: true }], outputs: { [output]: '/' + field } },
  });
async function setup() {
  const base = await fixture(),
    provider = new Provider(),
    context = await createContext(base.config, { db: base.db, mailer: base.mailer, transport: provider });
  return { ...base, ...context, provider };
}

test('一つのサービスから同じ方式の複数の接続方法を選び、それぞれの値を利用する', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person();
  const service = await f.services.createDefinition(owner.actor, owner.actor.id, {
    kind: 'service',
    name: 'Example',
    definition: ServiceInputDefinition.parse({
      name: 'Example',
      methods: {
        personal: keyMethod('Personal key', 'personal', 'PERSONAL_KEY'),
        project: keyMethod('Project key', 'project', 'PROJECT_KEY'),
      },
    }),
  });
  const catalog = (await f.catalog.list(owner.actor)).find((item) => item.id === service.id)!;
  const connections = [];
  for (const [key, output] of [
    ['personal', 'PERSONAL_KEY'],
    ['project', 'PROJECT_KEY'],
  ] as const) {
    const connected = await f.services.begin(
      owner.actor,
      owner.actor.id,
      ConnectionInput.parse({
        serviceId: service.id,
        methodId: catalog.methods[key]!.id,
        fields: { [key]: key + '-value' },
        name: 'Account',
      }),
      'browser',
    );
    assert.equal(connected.kind, 'connected');
    if (connected.kind !== 'connected') return;
    connections.push(connected.resource.id);
    assert.deepEqual(await f.services.outputs(owner.actor, await f.resources.get(connected.resource.id)), {
      [output]: key + '-value',
    });
  }
  assert.notEqual(connections[0], connections[1]);
  await assert.rejects(
    () =>
      f.services.begin(
        owner.actor,
        owner.actor.id,
        ConnectionInput.parse({
          serviceId: service.id,
          scheme: 'token',
          fields: { personal: 'value' },
        }),
        'browser',
      ),
    { code: 'method_required' },
  );
});

test('複数のサービスに同じ接続を分類し、分類変更後も接続IDと共有権限を保持する', async (t) => {
  const f = await setup(),
    app = await buildApp(f);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const owner = await f.person(),
    reader = await f.person('Reader'),
    stranger = await f.person('Stranger');
  const headers = { authorization: 'Bearer ' + owner.token };
  const created = await app.inject({
    method: 'POST',
    url: `/api/principals/${owner.actor.id}/resources`,
    headers,
    payload: { kind: 'method', name: 'Shared method', definition: keyMethod('Shared method') },
  });
  assert.equal(created.statusCode, 201, created.body);
  const methodId = created.json().id;
  const groups = [];
  for (const name of ['First group', 'Second group'])
    groups.push(
      await f.catalog.createService(
        owner.actor,
        owner.actor.id,
        name,
        ServiceInputDefinition.parse({ name, methods: { shared: methodId } }),
      ),
    );
  const connected = await f.services.begin(
    owner.actor,
    owner.actor.id,
    ConnectionInput.parse({ methodId, fields: { token: 'kept-value' } }),
    'browser',
  );
  assert.equal(connected.kind, 'connected');
  if (connected.kind !== 'connected') return;
  const row = await f.resources.get(connected.resource.id);
  await f.resources.grant(owner.actor, row, reader.actor.id, ['read', 'use', 'update']);
  const grants = await f.resources.grants(owner.actor, row);
  const changed = await app.inject({
    method: 'PATCH',
    url: '/api/resources/' + groups[0]!.id,
    headers,
    payload: {
      version: groups[0]!.version,
      name: 'Renamed group',
    },
  });
  assert.equal(changed.statusCode, 200, changed.body);
  const regrouped = await app.inject({
    method: 'PATCH',
    url: '/api/resources/' + groups[1]!.id,
    headers,
    payload: {
      version: groups[1]!.version,
      definition: { name: 'Second group', methods: { other: 'github:token' } },
    },
  });
  assert.equal(regrouped.statusCode, 200, regrouped.body);
  await f.resources.delete(owner.actor, groups[1]!);
  const current = await f.resources.get(row.id),
    view = await f.resources.view(owner.actor, current);
  assert.equal(view.kind, 'connection');
  if (view.kind !== 'connection') return;
  assert.deepEqual(view.data.services, [{ id: groups[0]!.id, name: 'Renamed group' }]);
  assert.equal(current.version, row.version);
  assert.deepEqual(await f.resources.grants(owner.actor, current), grants);
  assert.equal(
    await f.inputs.text(reader.actor, { kind: 'connection', id: row.id, output: 'API_KEY' }),
    'kept-value',
  );
  await assert.rejects(() => f.services.outputs(stranger.actor, current), { code: 'forbidden' });
  await assert.rejects(() => f.catalog.method(reader.actor, methodId), { code: 'forbidden' });
  const reconnect = await f.services.begin(
    reader.actor,
    row.owner_id,
    ConnectionInput.parse({ methodId, connectionId: row.id, fields: { token: 'new-value' } }),
    'reader-browser',
  );
  assert.equal(reconnect.kind, 'review');
  const definition = await app.inject({ url: '/api/connections/' + row.id + '/method', headers });
  assert.equal(definition.statusCode, 200, definition.body);
  assert.equal(definition.json().id, methodId);
  const replace = await app.inject({
    method: 'PATCH',
    url: '/api/resources/' + methodId,
    headers,
    payload: { version: created.json().version, definition: keyMethod('Changed', 'another') },
  });
  assert.equal(replace.statusCode, 409);
  assert.equal(replace.json().error.code, 'in_use');
  const renamed = await app.inject({
    method: 'PATCH',
    url: '/api/resources/' + methodId,
    headers,
    payload: {
      version: created.json().version,
      name: 'Renamed method',
      definition: keyMethod('Renamed method'),
    },
  });
  assert.equal(renamed.statusCode, 200, renamed.body);
  const methods = await app.inject({ url: '/api/connection-methods', headers });
  assert.equal(methods.statusCode, 200, methods.body);
  assert.ok(methods.json().items.some((item: { id: string }) => item.id === methodId));
});

test('名義を確認できない鍵の更新を承認して同じ接続へ反映し、取り消した変更は以前の値を保持する', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person(),
    reader = await f.person('Reader');
  const request = { methodId: 'github:token', name: 'My account', fields: { token: 'first-key' } };
  const initial = await f.services.begin(
    owner.actor,
    owner.actor.id,
    ConnectionInput.parse(request),
    'browser',
  );
  assert.equal(initial.kind, 'connected');
  if (initial.kind !== 'connected' || initial.resource.kind !== 'connection') return;
  assert.equal(initial.resource.data.accountVerified, false);
  assert.equal(initial.resource.data.scopesStatus, 'unknown');
  const row = await f.resources.get(initial.resource.id);
  await f.resources.grant(owner.actor, row, reader.actor.id, ['read', 'use']);
  for (const accept of [false, true]) {
    const pending = await f.services.begin(
      owner.actor,
      owner.actor.id,
      ConnectionInput.parse({ ...request, connectionId: row.id, fields: { token: 'replacement-key' } }),
      'browser',
    );
    assert.equal(pending.kind, 'review');
    if (pending.kind !== 'review') return;
    assert.equal(pending.after.accountVerified, false);
    assert.equal(pending.after.scopesStatus, 'unknown');
    assert.equal(
      (await f.services.outputs(reader.actor, await f.resources.get(row.id))).GH_TOKEN,
      'first-key',
    );
    await assert.rejects(() => f.services.pendingReview(owner.actor, pending.id, 'other-browser'), {
      code: 'invalid_state',
    });
    const result = await f.services.review(owner.actor, pending.id, 'browser', accept);
    assert.equal(result.kind, accept ? 'connected' : 'cancelled');
    if (result.kind === 'connected') assert.equal(result.resource.id, row.id);
  }
  assert.equal(
    (await f.services.outputs(reader.actor, await f.resources.get(row.id))).GH_TOKEN,
    'replacement-key',
  );
  await assert.rejects(
    () =>
      f.services.begin(
        owner.actor,
        owner.actor.id,
        ConnectionInput.parse({
          ...request,
          methodId: 'cloudflare:token',
          connectionId: row.id,
        }),
        'browser',
      ),
    { code: 'wrong_connection' },
  );
});

test('先に承認した接続の認証情報を保持し、古い確認画面からの上書きを拒否する', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person();
  const initial = await f.services.begin(owner.actor, owner.actor.id,
    ConnectionInput.parse({ methodId: 'github:token', fields: { token: 'initial-key' } }), 'browser');
  assert.equal(initial.kind, 'connected');
  if (initial.kind !== 'connected') return;
  const reviews = await Promise.all(['approved-key', 'other-key'].map(token => f.services.begin(
    owner.actor, owner.actor.id,
    ConnectionInput.parse({ methodId: 'github:token', connectionId: initial.resource.id, fields: { token } }),
    'browser',
  )));
  for (const review of reviews) {
    assert.equal(review.kind, 'review');
    if (review.kind !== 'review') return;
    await f.services.pendingReview(owner.actor, review.id, 'browser');
  }
  const [first, second] = reviews;
  if (first?.kind !== 'review' || second?.kind !== 'review') return;
  await f.services.review(owner.actor, first.id, 'browser', true);
  await assert.rejects(f.services.review(owner.actor, second.id, 'browser', true), { code: 'changed' });
  const saved = await f.resources.get(initial.resource.id);
  assert.equal((await f.services.outputs(owner.actor, saved)).GH_TOKEN, 'approved-key');
});

test('要求したスコープと報告されたスコープを区別し、更新時の権限拡大を再接続の確認まで保留する', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person();
  f.config.oauthApps.google = { clientId: 'client', clientSecret: 'secret' };
  let exchanges = 0,
    changedAccount = false;
  f.provider.respond = (request) =>
    request.url.includes('/token')
      ? json({
          access_token: 'key-' + ++exchanges,
          refresh_token: 'refresh',
          expires_in: exchanges === 1 ? 1 : 3600,
          ...(exchanges === 1
            ? {}
            : { scope: 'openid https://www.googleapis.com/auth/userinfo.email write' }),
        })
      : json({ sub: changedAccount ? 'other' : 'same', email: 'owner@example.com', email_verified: true });
  const authorize = async (connectionId?: string) => {
    const result = await f.services.begin(
      owner.actor,
      owner.actor.id,
      ConnectionInput.parse({ methodId: 'google:oauth', connectionId }),
      'browser',
    );
    assert.equal(result.kind, 'authorize');
    if (result.kind !== 'authorize') throw new Error('Expected authorization');
    return f.services.callback(new URL(result.url).searchParams.get('state')!, 'code', 'browser');
  };
  const initial = await authorize();
  assert.equal(initial.kind, 'connected');
  if (initial.kind !== 'connected' || initial.resource.kind !== 'connection') return;
  assert.equal(initial.resource.data.accountVerified, true);
  assert.equal(initial.resource.data.scopesStatus, 'requested');
  const row = await f.resources.get(initial.resource.id);
  await assert.rejects(() => f.services.outputs(owner.actor, row), { code: 'reconnect_required' });
  const blocked = await f.resources.get(row.id);
  assert.equal(blocked.data.state, 'reconnect');
  assert.deepEqual(blocked.data.scopes, row.data.scopes);
  const pending = await authorize(row.id);
  assert.equal(pending.kind, 'review');
  if (pending.kind !== 'review') return;
  assert.equal(pending.after.scopesStatus, 'reported');
  assert.ok((pending.after.scopes as string[]).includes('write'));
  await f.services.review(owner.actor, pending.id, 'browser', true);
  assert.equal(
    (await f.services.outputs(owner.actor, await f.resources.get(row.id))).GOOGLE_OAUTH_ACCESS_TOKEN,
    'key-3',
  );
  changedAccount = true;
  await assert.rejects(() => authorize(row.id), { code: 'account_changed' });
});

test('同方式のOAuthアプリを接続方法ごとに使い分け、名義を確認できない再認証を確認する', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person();
  const options = [];
  for (const name of ['First', 'Second']) {
    const method = await f.services.createDefinition(owner.actor, owner.actor.id, {
      kind: 'method',
      name,
      definition: MethodDefinition.parse({
        name,
        kind: 'oauth',
        config: {
          authorizeUrl: 'https://provider.example/' + name + '/authorize',
          tokenUrl: 'https://provider.example/' + name + '/token',
          fields: [{ name: 'tenant', label: 'Tenant' }],
          scopes: { default: ['read'] },
        },
      }),
    });
    const app = await f.services.createDefinition(owner.actor, owner.actor.id, {
      kind: 'app',
      name: name + ' application',
      methodId: method.id,
      clientId: name + '-client',
      clientSecret: name + '-secret',
      fields: { tenant: 'workspace' },
    });
    options.push({ method, app });
  }
  const first = options[0]!,
    second = options[1]!;
  await assert.rejects(
    () =>
      f.services.begin(
        owner.actor,
        owner.actor.id,
        ConnectionInput.parse({
          methodId: first.method.id,
          appId: second.app.id,
        }),
        'browser',
      ),
    { code: 'wrong_app' },
  );
  f.provider.respond = () => json({ access_token: 'unverified-account-key', scope: 'read' });
  const authorize = async (connectionId?: string) => {
    const result = await f.services.begin(
      owner.actor,
      owner.actor.id,
      ConnectionInput.parse({
        methodId: first.method.id,
        appId: first.app.id,
        connectionId,
      }),
      'browser',
    );
    assert.equal(result.kind, 'authorize');
    if (result.kind !== 'authorize') throw new Error('Expected authorization');
    assert.equal(new URL(result.url).searchParams.get('client_id'), 'First-client');
    return f.services.callback(new URL(result.url).searchParams.get('state')!, 'code', 'browser');
  };
  const initial = await authorize();
  assert.equal(initial.kind, 'connected');
  if (initial.kind !== 'connected' || initial.resource.kind !== 'connection') return;
  assert.equal(initial.resource.data.accountVerified, false);
  const review = await authorize(initial.resource.id);
  assert.equal(review.kind, 'review');
  if (review.kind !== 'review') return;
  await f.services.review(owner.actor, review.id, 'browser', true);
  assert.equal(
    (await f.services.outputs(owner.actor, await f.resources.get(initial.resource.id))).ACCESS_TOKEN,
    'unverified-account-key',
  );
});

test('IAMロールの再接続で同じ接続先を維持し、別のロールは新規接続として扱う', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person();
  f.config.FOUNDATION_AWS_PRINCIPAL_ARN = 'arn:aws:iam::111111111111:root';
  const services = new Services(f.resources, f.catalog, f.vault, f.oauth, f.config, {
    async obtain(_arn, _externalId, region) {
      return {
        AWS_ACCESS_KEY_ID: 'role-key',
        AWS_SECRET_ACCESS_KEY: 'role-secret',
        AWS_SESSION_TOKEN: 'role-session',
        AWS_DEFAULT_REGION: region,
      };
    },
  });
  const start = (connectionId?: string) =>
    services.begin(
      owner.actor,
      owner.actor.id,
      ConnectionInput.parse({ methodId: 'aws:role', connectionId }),
      'browser',
    );
  const begun = await start();
  assert.equal(begun.kind, 'role');
  if (begun.kind !== 'role') return;
  const arn = 'arn:aws:iam::222222222222:role/runner';
  const initial = await services.completeRole(owner.actor, begun.id, 'browser', arn, 'ap-northeast-1');
  assert.equal(initial.kind, 'connected');
  if (initial.kind !== 'connected' || initial.resource.kind !== 'connection') return;
  assert.equal(initial.resource.data.accountVerified, true);
  assert.equal(initial.resource.data.accountId, arn);
  assert.equal(initial.resource.data.scopesStatus, 'unknown');
  const changed = await start(initial.resource.id);
  if (changed.kind !== 'role') throw new Error('Expected role');
  await assert.rejects(
    () => services.completeRole(owner.actor, changed.id, 'browser', arn + '-other', 'ap-northeast-1'),
    { code: 'connection_target_changed' },
  );
  const same = await start(initial.resource.id);
  if (same.kind !== 'role') throw new Error('Expected role');
  const result = await services.completeRole(owner.actor, same.id, 'browser', arn, 'ap-northeast-1');
  assert.equal(result.kind, 'connected');
  if (result.kind !== 'connected') return;
  assert.equal(result.resource.id, initial.resource.id);
  assert.equal(
    (await services.outputs(owner.actor, await f.resources.get(result.resource.id))).AWS_ACCESS_KEY_ID,
    'role-key',
  );
});

test('既存のサービス定義と接続とOAuthアプリを移行し、共有と進行中の認証を引き継ぐ', async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const owner = await f.person(),
    reader = await f.person('Reader');
  const service = LegacyServiceDefinition.parse({
    name: 'Legacy service'.padEnd(200, 'x'),
    auth: {
      token: { fields: [{ name: 'key', label: 'Key', secret: true }], outputs: { OLD_KEY: '/key' } },
      oauth: {
        authorizeUrl: 'https://provider.example/authorize',
        tokenUrl: 'https://provider.example/token',
        identity: { from: 'token', id: '/user_id', name: '/user_id' },
      },
    },
  });
  const definition = await f.resources.insert(owner.actor.id, 'service', service.name, service);
  await f.resources.grant(owner.actor, definition, reader.actor.id, ['read', 'use']);
  const appId = randomUUID(),
    connectionId = randomUUID(),
    pendingId = randomUUID();
  await f.resources.insert(
    owner.actor.id,
    'app',
    'Legacy app',
    { serviceId: definition.id, clientId: 'legacy-client', fields: {} },
    {
      id: appId,
      privateData: await f.vault.encrypt({ clientSecret: 'legacy-secret' }, 'resource:' + appId),
      references: [definition.id],
    },
  );
  const old = await f.resources.insert(
    owner.actor.id,
    'connection',
    'Legacy connection',
    {
      serviceId: definition.id,
      scheme: 'token',
      account: 'Old account',
      scopes: [],
      outputs: ['OLD_KEY'],
      state: 'ready',
      appId: null,
    },
    {
      id: connectionId,
      privateData: await f.vault.encrypt(
        { service, app: { clientId: '', fields: {} }, fields: { key: 'legacy-value' } },
        'resource:' + connectionId,
      ),
      references: [definition.id],
    },
  );
  await f.resources.grant(owner.actor, old, reader.actor.id, ['read', 'use']);
  await f.db.pool.query(
    "INSERT INTO challenges(id,kind,principal_id,browser_hash,data,expires_at) VALUES($1,'service',$2,$3,$4,now()+interval '10 minutes')",
    [
      pendingId,
      owner.actor.id,
      digest('browser'),
      {
        sealed: await f.vault.encrypt(
          {
            actor: owner.actor,
            ownerId: owner.actor.id,
            input: ConnectionInput.parse({ serviceId: definition.id, scheme: 'oauth', appId }),
            service,
            app: { clientId: 'legacy-client', clientSecret: 'legacy-secret', fields: {}, version: 1 },
            verifier: 'verifier',
          },
          'consent:' + pendingId,
        ),
      },
    ],
  );
  await f.db.pool.query('ALTER TABLE resources DROP CONSTRAINT resources_kind_check');
  await f.db.pool.query(
    "ALTER TABLE resources ADD CONSTRAINT resources_kind_check CHECK(kind IN ('secret','connection','service','app','object','environment','function'))",
  );
  await f.db.pool.query("DELETE FROM schema_migrations WHERE name='connection-method-resources'");
  await f.db.initialize();
  const catalog = await Catalog.load(f.resources, f.config),
    provider = new Provider();
  provider.respond = () => json({ access_token: 'oauth-key', user_id: 'user-1' });
  const services = new Services(f.resources, catalog, f.vault, new OAuth(provider), f.config);
  await services.initialize();
  await services.initialize();
  const current = await f.resources.get(connectionId);
  assert.equal(current.version, old.version);
  assert.equal((await services.outputs(reader.actor, current)).OLD_KEY, 'legacy-value');
  const migrated = await catalog.get(owner.actor, definition.id);
  assert.equal(current.data.methodId, migrated.methods.token);
  assert.equal((await catalog.method(reader.actor, migrated.methods.token!)).kind, 'token');
  assert.equal((await f.resources.get(appId)).data.methodId, migrated.methods.oauth);
  assert.deepEqual(await f.vault.decrypt((await f.resources.get(appId)).private_data!, 'resource:' + appId), {
    clientSecret: 'legacy-secret',
  });
  const connected = await services.callback(pendingId, 'code', 'browser');
  assert.equal(connected.kind, 'connected');
  if (connected.kind !== 'connected') return;
  assert.equal(
    (await services.outputs(owner.actor, await f.resources.get(connected.resource.id))).ACCESS_TOKEN,
    'oauth-key',
  );
  const restarted = await Catalog.load(f.resources, f.config);
  assert.equal(await restarted.legacyMethodId(definition.id, 'token'), current.data.methodId);
  assert.deepEqual((await restarted.list(owner.actor)).find((item) => item.id === 'sakura')?.name, 'さくら');
  assert.equal(await restarted.legacyMethodId('sakura-vps', 'token'), 'sakura:vps-api-key');
});
