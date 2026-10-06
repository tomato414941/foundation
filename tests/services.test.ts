import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { Catalog } from '../server/catalog.js';
import { OAuth } from '../server/oauth.js';
import { Services } from '../server/services.js';
import { Inputs } from '../server/inputs.js';
import { HttpExecution } from '../server/http-execution.js';
import { publicAddress, publicUrl } from '../server/transport.js';
import type { Transport, OutboundRequest, OutboundResponse } from '../server/transport.js';
import { ConnectionInput, FunctionDefinition, HttpRequest } from '../shared/contracts.js';
import { encode, decode, seal, open } from '../shared/encryption.js';

class TestTransport implements Transport {
  requests: OutboundRequest[] = [];
  respond: (request: OutboundRequest) => OutboundResponse | Promise<OutboundResponse> = () => ({
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: encode('{}'),
  });
  async send(request: OutboundRequest) {
    this.requests.push(request);
    return this.respond(request);
  }
}
async function setup() {
  const base = await fixture(),
    transport = new TestTransport(),
    catalog = await Catalog.load(base.resources, base.config),
    oauth = new OAuth(transport),
    services = new Services(base.resources, catalog, base.vault, oauth, base.config),
    inputs = new Inputs(base.resources, services),
    http = new HttpExecution(base.resources, inputs, transport, base.config.origin);
  return { ...base, transport, catalog, oauth, services, inputs, http };
}

test('公開HTTPSの送信先を受け入れ、プライベートアドレスへの送信を拒否する', () => {
  for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111'])
    assert.equal(publicAddress(address), true, address);
  for (const address of [
    '127.0.0.1',
    '0.0.0.0',
    '10.1.1.1',
    '169.254.169.254',
    '172.16.1.1',
    '192.168.1.1',
    '100.64.0.1',
    '::1',
    '::ffff:127.0.0.1',
    'fc00::1',
    'fe80::1',
    '2001:db8::1',
  ])
    assert.equal(publicAddress(address), false, address);
  assert.equal(publicUrl('https://example.com/path').hostname, 'example.com');
  for (const url of [
    'http://example.com',
    'https://127.1',
    'https://[::ffff:127.0.0.1]',
    'https://example.com:8443',
    'https://name:password@example.com',
  ])
    assert.throws(() => publicUrl(url));
});

test('接続したサービスの値を委任先へ暗号化して渡し、委任解除後の利用を拒否する', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person(),
    agent = await f.person('Agent');
  await f.principals.relate(owner.actor, agent.actor.id, 'agent', owner.actor.id);
  const result = await f.services.begin(
    owner.actor,
    owner.actor.id,
    ConnectionInput.parse({
      serviceId: 'github',
      scheme: 'token',
      fields: { token: 'private-service-value' },
    }),
    'browser',
  );
  assert.equal(result.kind, 'connected');
  if (result.kind !== 'connected') return;
  const delivered = await f.inputs.deliver(agent.actor, [
    {
      name: 'GH_TOKEN',
      source: { kind: 'connection', id: result.resource.id, output: 'GH_TOKEN' },
      format: 'text',
    },
  ]);
  const content = JSON.parse(
    decode(await open(delivered.sealed, agent.keys.privateKey, agent.actor.id, delivered.context)),
  );
  assert.equal(content.environment.GH_TOKEN, 'private-service-value');
  const stored = await f.resources.get(result.resource.id);
  assert.ok(stored.private_data);
  assert.equal(JSON.stringify(stored.data).includes('private-service-value'), false);
  await f.principals.revoke(owner.actor, owner.actor.id, agent.actor.id);
  await assert.rejects(
    () =>
      f.inputs.deliver(agent.actor, [
        {
          name: 'GH_TOKEN',
          source: { kind: 'connection', id: result.resource.id, output: 'GH_TOKEN' },
          format: 'text',
        },
      ]),
    { code: 'forbidden' },
  );
});

test('同じ表示名で複数サービスへ接続し、それぞれの認証情報を使い分ける', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person();
  const connections = [];
  for (const serviceId of ['github', 'cloudflare']) {
    const result = await f.services.begin(
      owner.actor,
      owner.actor.id,
      ConnectionInput.parse({
        serviceId,
        scheme: 'token',
        name: 'My account',
        fields: { token: serviceId + '-private-token' },
      }),
      'browser',
    );
    assert.equal(result.kind, 'connected');
    if (result.kind !== 'connected') return;
    connections.push(await f.resources.get(result.resource.id));
  }
  assert.notEqual(connections[0]!.id, connections[1]!.id);
  assert.equal((await f.resources.list(owner.actor, owner.actor.id, { kind: 'connection' })).items.length, 2);
  assert.equal((await f.services.outputs(owner.actor, connections[0]!)).GH_TOKEN, 'github-private-token');
  assert.equal(
    (await f.services.outputs(owner.actor, connections[1]!)).CLOUDFLARE_API_TOKEN,
    'cloudflare-private-token',
  );
});

test('既存データベースを更新し、登録済み接続を保持したまま同名で接続を追加する', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  await f.db.pool.query(
    'ALTER TABLE resources ADD CONSTRAINT resources_owner_id_kind_name_key UNIQUE (owner_id,kind,name)',
  );
  const owner = await f.person();
  const connect = (serviceId: string) =>
    f.services.begin(
      owner.actor,
      owner.actor.id,
      ConnectionInput.parse({
        serviceId,
        scheme: 'token',
        name: 'My account',
        fields: { token: serviceId + '-private-token' },
      }),
      'browser',
    );
  const first = await connect('github');
  assert.equal(first.kind, 'connected');
  if (first.kind !== 'connected') return;
  await f.db.initialize();
  const second = await connect('cloudflare');
  assert.equal(second.kind, 'connected');
  if (second.kind !== 'connected') return;
  assert.notEqual(first.resource.id, second.resource.id);
  assert.equal(
    (await f.services.outputs(owner.actor, await f.resources.get(first.resource.id))).GH_TOKEN,
    'github-private-token',
  );
  assert.equal(
    (await f.services.outputs(owner.actor, await f.resources.get(second.resource.id))).CLOUDFLARE_API_TOKEN,
    'cloudflare-private-token',
  );
});

test('シークレットをHTTPヘッダーに渡し、返された秘密値を伏せて実行結果を返す', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person(),
    id = randomUUID(),
    secret = 'sensitive-http-credential';
  const sealed = await seal(
    encode(secret),
    [
      { id: owner.actor.id, publicKey: owner.keys.publicKey },
      { id: f.identity.id, publicKey: f.identity.publicKey },
    ],
    'resource:' + id,
  );
  await f.resources.createSecret(owner.actor, owner.actor.id, {
    kind: 'secret',
    id,
    name: 'HTTP key',
    sealed,
    bytes: secret.length,
    allowUse: true,
  });
  f.transport.respond = (request) => ({
    status: 200,
    headers: { authorization: request.headers!.authorization! },
    body: encode(JSON.stringify({ echo: secret, accepted: true })),
  });
  const result = (await f.http.request(
    owner.actor,
    owner.actor.id,
    HttpRequest.parse({
      url: 'https://api.example.com',
      headers: { authorization: '' },
      bindings: [{ pointer: '/headers/authorization', parts: ['Bearer ', { kind: 'secret', id }] }],
    }),
  )) as { body: string; headers: Record<string, string> };
  assert.equal(f.transport.requests[0]?.headers?.authorization, 'Bearer ' + secret);
  assert.deepEqual(JSON.parse(result.body), { echo: '[redacted]', accepted: true });
  assert.equal(result.headers.authorization, 'Bearer [redacted]');
  await f.resources.revoke(owner.actor, await f.resources.get(id), f.identity.id);
  await assert.rejects(() => f.inputs.text(owner.actor, { kind: 'secret', id }), { code: 'forbidden' });
});

test('共有された関数の実行を許可し、所有者の接続情報の取得を拒否する', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person(),
    caller = await f.person('Caller');
  const connection = await f.services.begin(
    owner.actor,
    owner.actor.id,
    ConnectionInput.parse({
      serviceId: 'github',
      scheme: 'token',
      fields: { token: 'function-private-token' },
    }),
    'browser',
  );
  assert.equal(connection.kind, 'connected');
  if (connection.kind !== 'connected') return;
  const definition = FunctionDefinition.parse({
    parameters: [{ name: 'issue', label: 'Issue' }],
    request: {
      url: 'https://api.github.com/repos/example/project/issues/{issue}',
      headers: { authorization: '' },
      bindings: [
        {
          pointer: '/headers/authorization',
          parts: ['Bearer ', { kind: 'connection', id: connection.resource.id, output: 'GH_TOKEN' }],
        },
      ],
    },
  });
  const fn = await f.http.create(owner.actor, owner.actor.id, 'Read issue', definition);
  await f.resources.grant(owner.actor, fn, caller.actor.id, ['read', 'execute']);
  f.transport.respond = (request) => ({
    status: 200,
    headers: {},
    body: encode(JSON.stringify({ url: request.url, title: 'Hello' })),
  });
  const result = (await f.http.invoke(caller.actor, fn, { issue: '123' })) as { body: string };
  assert.equal(JSON.parse(result.body).url, 'https://api.github.com/repos/example/project/issues/123');
  await assert.rejects(
    () => f.inputs.text(caller.actor, { kind: 'connection', id: connection.resource.id, output: 'GH_TOKEN' }),
    { code: 'forbidden' },
  );
  await assert.rejects(
    () =>
      f.http.create(
        owner.actor,
        owner.actor.id,
        'Bad destination',
        FunctionDefinition.parse({
          ...definition,
          request: { ...definition.request, url: 'https://{issue}/secret' },
        }),
      ),
    { code: 'variable_origin' },
  );
});

test('OAuthの応答を開始したブラウザーへ結び付け、接続後に更新したトークンを渡す', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person();
  f.config.oauthApps.google = { clientId: 'test-client', clientSecret: 'test-secret' };
  let exchanges = 0;
  f.transport.respond = (request) => {
    if (request.url === 'https://oauth2.googleapis.com/token') {
      exchanges++;
      return {
        status: 200,
        headers: {},
        body: encode(
          JSON.stringify({
            access_token: exchanges === 1 ? 'first-token' : 'refreshed-token',
            refresh_token: 'refresh-token',
            expires_in: exchanges === 1 ? 30 : 3600,
            token_type: 'Bearer',
            scope: 'openid https://www.googleapis.com/auth/userinfo.email',
          }),
        ),
      };
    }
    return {
      status: 200,
      headers: {},
      body: encode(
        JSON.stringify({ sub: 'google-account', email: 'owner@example.com', email_verified: true }),
      ),
    };
  };
  const started = await f.services.begin(
    owner.actor,
    owner.actor.id,
    ConnectionInput.parse({ serviceId: 'google', scheme: 'oauth' }),
    'right-browser',
  );
  assert.equal(started.kind, 'authorize');
  if (started.kind !== 'authorize') return;
  const state = new URL(started.url).searchParams.get('state')!;
  const parameters = new URLSearchParams({ state, code: 'authorization-code' });
  await assert.rejects(() => f.services.callback(parameters, 'other-browser'), {
    code: 'invalid_state',
  });
  const complete = await f.services.callback(parameters, 'right-browser');
  assert.equal(complete.kind, 'connected');
  if (complete.kind !== 'connected') return;
  assert.equal(
    await f.inputs.text(owner.actor, {
      kind: 'connection',
      id: complete.resource.id,
      output: 'GOOGLE_OAUTH_ACCESS_TOKEN',
    }),
    'refreshed-token',
  );
  assert.equal(exchanges, 2);
  await assert.rejects(() => f.services.callback(parameters, 'right-browser'), {
    code: 'invalid_state',
  });
});

test('同時に届いた利用要求に同じ更新済みトークンを渡す', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person();
  f.config.oauthApps.google = { clientId: 'test-client', clientSecret: 'test-secret' };
  let exchanges = 0;
  f.transport.respond = async (request) => {
    if (request.url === 'https://oauth2.googleapis.com/token') {
      exchanges++;
      await new Promise((resolve) => setTimeout(resolve, 20));
      return {
        status: 200,
        headers: {},
        body: encode(
          JSON.stringify({
            access_token: 'token-' + exchanges,
            refresh_token: 'refresh-' + exchanges,
            expires_in: exchanges === 1 ? 30 : 3600,
            token_type: 'Bearer',
          }),
        ),
      };
    }
    return {
      status: 200,
      headers: {},
      body: encode(JSON.stringify({ sub: 'same-account', email: 'owner@example.com', email_verified: true })),
    };
  };
  const begin = await f.services.begin(
    owner.actor,
    owner.actor.id,
    ConnectionInput.parse({ serviceId: 'google', scheme: 'oauth' }),
    'browser',
  );
  if (begin.kind !== 'authorize') throw new Error('Expected consent');
  const connected = await f.services.callback(
    new URLSearchParams({ state: new URL(begin.url).searchParams.get('state')!, code: 'code' }),
    'browser',
  );
  if (connected.kind !== 'connected') throw new Error('Expected connection');
  const values = await Promise.all(
    Array.from({ length: 4 }, () =>
      f.inputs.text(owner.actor, {
        kind: 'connection',
        id: connected.resource.id,
        output: 'GOOGLE_OAUTH_ACCESS_TOKEN',
      }),
    ),
  );
  assert.deepEqual(values, ['token-2', 'token-2', 'token-2', 'token-2']);
  assert.equal(exchanges, 2);
});

test('Renderの登録済みOAuthアプリで認可し、更新したトークンをMCPへ渡して接続を解除する', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person();
  const entry = (await f.catalog.list(owner.actor)).find((service) => service.id === 'render')!;
  assert.equal(entry.methods.oauth!.availability, 'app-required');
  await assert.rejects(
    () =>
      f.services.begin(
        owner.actor,
        owner.actor.id,
        ConnectionInput.parse({ methodId: entry.methods.oauth!.id }),
        'browser',
      ),
    { code: 'app_required' },
  );
  const app = await f.services.createDefinition(owner.actor, owner.actor.id, {
    kind: 'app',
    name: 'Registered Render application',
    methodId: entry.methods.oauth!.id,
    clientId: 'registered-foundation-client',
    fields: {},
  });
  const started = await f.services.begin(
    owner.actor,
    owner.actor.id,
    ConnectionInput.parse({ serviceId: 'render', scheme: 'oauth', appId: app.id }),
    'browser',
  );
  assert.equal(started.kind, 'authorize');
  if (started.kind !== 'authorize') return;
  const authorize = new URL(started.url);
  assert.equal(authorize.origin + authorize.pathname, 'https://api.render.com/v1/oauth/authorize');
  assert.equal(authorize.searchParams.get('client_id'), 'registered-foundation-client');
  assert.equal(authorize.searchParams.get('redirect_uri'), 'https://foundation.test/oauth/callback');
  assert.equal(authorize.searchParams.get('resource'), 'https://mcp.render.com/mcp');
  assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
  let exchanges = 0,
    revoked = false;
  f.transport.respond = (request) => {
    if (request.url === 'https://api.render.com/v1/oauth/token') {
      const form = new URLSearchParams(request.body);
      assert.equal(request.method, 'POST');
      assert.equal(request.headers?.['content-type']?.split(';')[0], 'application/x-www-form-urlencoded');
      assert.equal(request.headers?.authorization, undefined);
      assert.equal(form.get('client_id'), 'registered-foundation-client');
      assert.equal(form.get('client_secret'), null);
      assert.equal(form.get('resource'), 'https://mcp.render.com/mcp');
      exchanges++;
      if (exchanges === 1) {
        assert.equal(form.get('grant_type'), 'authorization_code');
        assert.equal(form.get('code'), 'render-authorization-code');
        assert.equal(form.get('redirect_uri'), authorize.searchParams.get('redirect_uri'));
        assert.equal(
          createHash('sha256').update(form.get('code_verifier')!).digest('base64url'),
          authorize.searchParams.get('code_challenge'),
        );
      } else {
        assert.equal(form.get('grant_type'), 'refresh_token');
        assert.equal(form.get('refresh_token'), 'render-refresh-1');
      }
      return {
        status: 200,
        headers: {},
        body: encode(
          JSON.stringify({
            access_token: 'render-access-' + exchanges,
            refresh_token: 'render-refresh-' + exchanges,
            expires_in: exchanges === 1 ? 30 : 3600,
            token_type: 'Bearer',
          }),
        ),
      };
    }
    if (request.url === 'https://mcp.render.com/mcp') {
      assert.equal(request.headers?.authorization, 'Bearer render-access-2');
      assert.equal(JSON.parse(request.body!).method, 'initialize');
      return {
        status: 200,
        headers: {},
        body: encode(JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} })),
      };
    }
    if (request.url === 'https://api.render.com/v1/oauth/token/revoke') {
      assert.equal(request.method, 'POST');
      assert.equal(request.headers?.['content-type']?.split(';')[0], 'application/x-www-form-urlencoded');
      assert.deepEqual(Object.fromEntries(new URLSearchParams(request.body)), {
        token: 'render-refresh-2',
        client_id: 'registered-foundation-client',
      });
      revoked = true;
      return { status: 200, headers: {}, body: encode('') };
    }
    throw new Error('Unexpected Render request: ' + request.url);
  };
  const connected = await f.services.callback(
    new URLSearchParams({ state: authorize.searchParams.get('state')!, code: 'render-authorization-code' }),
    'browser',
  );
  assert.equal(connected.kind, 'connected');
  if (connected.kind !== 'connected') return;
  assert.equal(connected.resource.kind, 'connection');
  if (connected.resource.kind !== 'connection') return;
  assert.equal(connected.resource.data.accountVerified, false);
  const result = await f.http.request(
    owner.actor,
    owner.actor.id,
    HttpRequest.parse({
      url: 'https://mcp.render.com/mcp',
      method: 'POST',
      headers: { authorization: '', accept: 'application/json, text/event-stream' },
      json: {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-11-25',
          capabilities: {},
          clientInfo: { name: 'Foundation', version: '1' },
        },
      },
      bindings: [
        {
          pointer: '/headers/authorization',
          parts: ['Bearer ', {
            kind: 'connection', id: connected.resource.id, output: 'RENDER_MCP_ACCESS_TOKEN',
          }],
        },
      ],
    }),
  );
  assert.equal((result as { status: number }).status, 200);
  const outputs = await f.services.outputs(owner.actor, await f.resources.get(connected.resource.id));
  assert.equal(outputs.RENDER_MCP_ACCESS_TOKEN, 'render-access-2');
  assert.ok(Number(outputs.RENDER_MCP_TOKEN_EXPIRES_AT) > Date.now());
  assert.equal(exchanges, 2);
  await f.services.remove(owner.actor, await f.resources.get(connected.resource.id));
  assert.equal(revoked, true);
});

test('RenderのAPIキーを接続し、REST APIの呼び出しに使う', async (t) => {
  const f = await setup();
  t.after(() => f.close());
  const owner = await f.person();
  const connected = await f.services.begin(
    owner.actor,
    owner.actor.id,
    ConnectionInput.parse({ serviceId: 'render', scheme: 'token', fields: { token: 'render-api-key' } }),
    'browser',
  );
  assert.equal(connected.kind, 'connected');
  if (connected.kind !== 'connected') return;
  f.transport.respond = (request) => {
    assert.equal(request.url, 'https://api.render.com/v1/services');
    assert.equal(request.headers?.authorization, 'Bearer render-api-key');
    return { status: 200, headers: {}, body: encode('[]') };
  };
  const result = await f.http.request(
    owner.actor,
    owner.actor.id,
    HttpRequest.parse({
      url: 'https://api.render.com/v1/services',
      headers: { authorization: '' },
      bindings: [
        {
          pointer: '/headers/authorization',
          parts: ['Bearer ', {
            kind: 'connection', id: connected.resource.id, output: 'RENDER_API_KEY',
          }],
        },
      ],
    }),
  );
  assert.deepEqual(result, { status: 200, headers: {}, body: '[]' });
});
