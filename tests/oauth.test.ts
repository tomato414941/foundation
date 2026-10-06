import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { OAuthDefinition } from '../shared/contracts.js';
import { OAuth } from '../server/oauth.js';
import type { OAuthApp, OAuthToken } from '../server/oauth.js';
import { PublicTransport } from '../server/transport.js';
import type { OutboundRequest, OutboundResponse, Transport } from '../server/transport.js';
import { DomainError } from '../server/errors.js';

const redirect = 'https://foundation.test/oauth/callback';
const verifier = 'a'.repeat(43);
const app: OAuthApp = { clientId: 'client: id', clientSecret: 'secret+ :/!', fields: {} };
const authorization = (code: string) => ({
  parameters: new URLSearchParams({ code, state: 'state-1' }),
  state: 'state-1',
});
const definition = (options: Record<string, unknown> = {}) =>
  OAuthDefinition.parse({
    authorizeUrl: 'https://provider.test/authorize',
    tokenUrl: 'https://provider.test/token',
    identity: { from: 'token', id: '/account_id', name: '/account_name' },
    revoke: { url: 'https://provider.test/revoke' },
    ...options,
  });
const response = (body: unknown, status = 200): OutboundResponse => ({
  status,
  headers: { 'content-type': 'application/json' },
  body: new TextEncoder().encode(typeof body === 'string' ? body : JSON.stringify(body)),
});
class Provider implements Transport {
  requests: OutboundRequest[] = [];
  constructor(readonly respond: (request: OutboundRequest) => OutboundResponse | Promise<OutboundResponse>) {}
  async send(request: OutboundRequest) {
    this.requests.push(request);
    return this.respond(request);
  }
}
async function builtin(name: string) {
  const service = JSON.parse(
    await readFile(new URL('../server/catalog/' + name + '.json', import.meta.url), 'utf8'),
  );
  return OAuthDefinition.parse(service.methods.oauth.config);
}
function existing(overrides: Partial<OAuthToken> = {}): OAuthToken {
  return JSON.parse(
    JSON.stringify({
      accessToken: 'saved-access',
      refreshToken: 'saved-refresh',
      expiresAt: 0,
      refreshExpiresAt: Date.now() + 600_000,
      scopes: ['read'],
      scopesStatus: 'reported',
      account: 'account-1',
      accountName: 'Existing account',
      accountVerified: true,
      extra: { instance_url: 'https://instance.test' },
      facts: {},
      ...overrides,
    }),
  );
}
function checkBasic(request: OutboundRequest) {
  const credentials = Buffer.from(request.headers!.authorization!.slice(6), 'base64').toString();
  assert.deepEqual(
    credentials.split(':').map((value) => new URLSearchParams('v=' + value).get('v')),
    [app.clientId, app.clientSecret],
  );
}

test('記号を含むアプリ認証情報で認可コードを交換し、更新後のトークンを失効する', async () => {
  const spec = definition({ clientAuth: 'basic' });
  let grants = 0;
  const provider = new Provider((request) => {
    checkBasic(request);
    const form = new URLSearchParams(String(request.body));
    if (request.url.endsWith('/revoke')) {
      assert.equal(form.get('token'), 'rotated-refresh');
      return response('');
    }
    if (++grants === 1) {
      assert.equal(form.get('grant_type'), 'authorization_code');
      assert.equal(form.get('code'), 'authorization-code');
      assert.equal(form.get('redirect_uri'), redirect);
      assert.equal(form.get('code_verifier'), verifier);
    } else {
      assert.equal(form.get('grant_type'), 'refresh_token');
      assert.equal(form.get('refresh_token'), 'first-refresh');
    }
    return response({
      access_token: 'access-' + grants,
      refresh_token: grants === 1 ? 'first-refresh' : 'rotated-refresh',
      token_type: 'Bearer',
      expires_in: 10,
      account_id: 'account-1',
      account_name: 'Account',
    });
  });
  const oauth = new OAuth(provider);
  const url = new URL(await oauth.authorize(spec, app, 'state-1', verifier, redirect, ['read', 'write']));
  assert.equal(url.searchParams.get('state'), 'state-1');
  assert.equal(url.searchParams.get('scope'), 'read write');
  assert.equal(
    url.searchParams.get('code_challenge'),
    createHash('sha256').update(verifier).digest('base64url'),
  );
  const token = await oauth.exchange(spec, app, authorization('authorization-code'), verifier, redirect, [
    'read',
  ]);
  assert.equal(token.accessToken, 'access-1');
  const refreshed = await oauth.refresh(spec, app, token);
  assert.equal(refreshed.accessToken, 'access-2');
  assert.equal(refreshed.account, 'account-1');
  await oauth.revoke(spec, app, refreshed);
  assert.equal(provider.requests.length, 3);
});

test('保存済みトークンを更新し、更新用トークンと権限を引き継いで期限を維持する', async () => {
  const old = existing();
  const provider = new Provider((request) => {
    const form = new URLSearchParams(String(request.body));
    assert.equal(form.get('client_id'), app.clientId);
    assert.equal(form.get('client_secret'), app.clientSecret);
    assert.equal(form.get('refresh_token'), old.refreshToken);
    return response({
      access_token: 'new-access',
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token_expires_in: 86_400,
    });
  });
  const updated = await new OAuth(provider).refresh(definition(), app, old);
  assert.equal(updated.accessToken, 'new-access');
  assert.equal(updated.refreshToken, old.refreshToken);
  assert.equal(updated.refreshExpiresAt, old.refreshExpiresAt);
  assert.deepEqual(updated.scopes, old.scopes);
  assert.equal(updated.scopesStatus, 'reported');
  assert.equal(updated.account, old.account);
  assert.deepEqual(updated.extra, old.extra);
  assert.ok(updated.expiresAt! > Date.now() + 3_500_000);
});

test('クライアント認証が必要なアプリではシークレットの設定を要求する', async () => {
  const provider = new Provider(() => response({}));
  const oauth = new OAuth(provider);
  for (const clientAuth of ['basic', 'body']) {
    await assert.rejects(
      oauth.exchange(
        definition({ clientAuth }),
        { clientId: 'client', fields: {} },
        authorization('code'),
        verifier,
        redirect,
        [],
      ),
      { code: 'app_required' },
    );
  }
  assert.equal(provider.requests.length, 0);
});

test('NotionのJSON形式で認可コードを交換し、応答のワークスペースを接続先として確認する', async () => {
  const spec = await builtin('notion');
  const provider = new Provider((request) => {
    checkBasic(request);
    assert.equal(request.headers?.['content-type'], 'application/json');
    const body = JSON.parse(String(request.body));
    assert.equal(body.code, 'notion-code');
    assert.equal(body.redirect_uri, redirect);
    return response({
      access_token: 'notion-access',
      token_type: 'bearer',
      refresh_token: null,
      workspace_id: 'workspace-1',
      workspace_name: 'Workspace',
      bot_id: 'bot-1',
    });
  });
  const token = await new OAuth(provider).exchange(
    spec,
    app,
    authorization('notion-code'),
    verifier,
    redirect,
    [],
  );
  assert.equal(token.accessToken, 'notion-access');
  assert.equal(token.account, 'workspace-1');
  assert.equal(token.accountVerified, true);
  assert.equal(token.refreshToken, undefined);
});

test('Shopifyの応答から接続し、更新用トークンで新しいアクセストークンを取得する', async () => {
  const spec = await builtin('shopify');
  const shopifyApp = { ...app, fields: { shop: 'example', name: 'Example shop' } };
  let exchanges = 0;
  const provider = new Provider((request) => {
    const form = new URLSearchParams(String(request.body));
    if (++exchanges === 1) assert.equal(form.get('code'), 'shopify-code');
    else assert.equal(form.get('refresh_token'), 'shopify-refresh-1');
    return response({
      access_token: 'shopify-access-' + exchanges,
      refresh_token: 'shopify-refresh-' + exchanges,
      scope: 'read_products,write_orders',
      expires_in: 10,
      refresh_token_expires_in: 7_776_000,
    });
  });
  const oauth = new OAuth(provider);
  const token = await oauth.exchange(spec, shopifyApp, authorization('shopify-code'), verifier, redirect, []);
  assert.equal(token.account, 'example');
  assert.deepEqual(token.scopes, ['read_products', 'write_orders']);
  const refreshed = await oauth.refresh(spec, shopifyApp, token);
  assert.equal(refreshed.accessToken, 'shopify-access-2');
  assert.equal(refreshed.refreshToken, 'shopify-refresh-2');
});

test('eBayのRuNameで認可し、独自のトークン種別と照会結果を使って更新と失効を実行する', async () => {
  const spec = await builtin('ebay');
  const ebayApp = { ...app, fields: { ruName: 'Foundation-Application-RuName' } };
  let exchanges = 0;
  const provider = new Provider((request) => {
    checkBasic(request);
    const form = new URLSearchParams(String(request.body));
    if (request.url.endsWith('/introspect'))
      return response({
        active: true,
        client_id: app.clientId,
        sub: 'seller-1',
        username: 'Seller',
        scope: 'read write',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
    if (request.url.endsWith('/revoke')) {
      assert.equal(form.get('token'), 'ebay-refresh');
      return response('');
    }
    if (++exchanges === 1) assert.equal(form.get('redirect_uri'), ebayApp.fields.ruName);
    else assert.equal(form.get('refresh_token'), 'ebay-refresh');
    return response({
      access_token: 'ebay-access-' + exchanges,
      token_type: 'User Access Token',
      expires_in: 10,
      ...(exchanges === 1 ? { refresh_token: 'ebay-refresh', refresh_token_expires_in: 3600 } : {}),
    });
  });
  const oauth = new OAuth(provider);
  const url = new URL(await oauth.authorize(spec, ebayApp, 'state-1', verifier, redirect, ['read']));
  assert.equal(url.searchParams.get('redirect_uri'), ebayApp.fields.ruName);
  const connected = await oauth.exchange(spec, ebayApp, authorization('ebay-code'), verifier, redirect, [
    'read',
  ]);
  assert.equal(connected.account, 'seller-1');
  assert.deepEqual(connected.scopes, ['read', 'write']);
  const refreshed = await oauth.refresh(spec, ebayApp, connected);
  assert.equal(refreshed.accessToken, 'ebay-access-2');
  assert.equal(refreshed.refreshToken, 'ebay-refresh');
  await oauth.revoke(spec, ebayApp, refreshed);
});

test('GitHubのJSON応答と報告された権限で接続し、専用APIで認可を解除する', async () => {
  const spec = await builtin('github');
  const githubApp = { clientId: 'github-client', clientSecret: 'github-secret', fields: {} };
  const provider = new Provider((request) => {
    if (request.url === spec.tokenUrl) {
      assert.equal(request.headers?.['content-type'], 'application/json');
      const body = JSON.parse(String(request.body));
      assert.equal(body.client_id, githubApp.clientId);
      assert.equal(body.client_secret, githubApp.clientSecret);
      return response({ access_token: 'github-access', token_type: 'bearer', scope: 'repo' });
    }
    if (request.url === spec.identity!.url)
      return {
        ...response({ id: 123, login: 'person' }),
        headers: { 'x-oauth-scopes': 'repo, read:org' },
      };
    assert.equal(request.url, 'https://api.github.com/applications/github-client/grant');
    assert.equal(request.method, 'DELETE');
    assert.equal(
      Buffer.from(request.headers!.authorization!.slice(6), 'base64').toString(),
      'github-client:github-secret',
    );
    assert.deepEqual(JSON.parse(String(request.body)), { access_token: 'github-access' });
    return response('', 204);
  });
  const oauth = new OAuth(provider);
  const token = await oauth.exchange(spec, githubApp, authorization('github-code'), verifier, redirect, [
    'repo',
  ]);
  assert.equal(token.account, '123');
  assert.equal(token.accountName, 'person');
  assert.deepEqual(token.scopes, ['read:org', 'repo']);
  assert.equal(token.scopesStatus, 'reported');
  await oauth.revoke(spec, githubApp, token);
});

test('Googleの接続名義をアカウントAPIで確認し、アプリ認証不要の失効要求を送信する', async () => {
  const spec = await builtin('google');
  const provider = new Provider((request) => {
    if (request.url === spec.tokenUrl)
      return response({
        access_token: 'google-access',
        token_type: 'Bearer',
        id_token: 'unused-identity-token',
        refresh_token: 'google-refresh',
        expires_in: 3600,
      });
    if (request.url === spec.identity!.url) {
      assert.equal(request.headers?.authorization, 'Bearer google-access');
      return response({ sub: 'google-account', email: 'person@example.com', email_verified: true });
    }
    assert.equal(request.url, spec.revoke!.url);
    assert.deepEqual(Object.fromEntries(new URLSearchParams(String(request.body))), {
      token: 'google-refresh',
    });
    return response('');
  });
  const oauth = new OAuth(provider);
  const token = await oauth.exchange(spec, app, authorization('google-code'), verifier, redirect, ['openid']);
  assert.equal(token.account, 'google-account');
  assert.equal(token.accountVerified, true);
  await oauth.revoke(spec, app, token);
});

test('OpenRouterのコードからAPIキーを取得し、キーの情報を接続へ反映する', async () => {
  const spec = await builtin('openrouter');
  const provider = new Provider((request) => {
    if (request.url === spec.tokenUrl) {
      assert.deepEqual(JSON.parse(String(request.body)), {
        code: 'openrouter-code',
        code_verifier: verifier,
        code_challenge_method: 'S256',
      });
      return response({ key: 'openrouter-key' });
    }
    assert.equal(request.headers?.authorization, 'Bearer openrouter-key');
    return response({ data: { label: 'Foundation', is_management_key: false } });
  });
  const oauth = new OAuth(provider),
    publicApp = { clientId: '', fields: {} };
  const url = new URL(await oauth.authorize(spec, publicApp, 'state-1', verifier, redirect, []));
  assert.equal(url.searchParams.get('callback_url'), redirect);
  const token = await oauth.exchange(
    spec,
    publicApp,
    authorization('openrouter-code'),
    verifier,
    redirect,
    [],
  );
  assert.equal(token.accessToken, 'openrouter-key');
  assert.equal(token.accountName, 'Foundation');
  assert.equal(token.facts.is_management_key, false);
});

test('開始時のstateと設定した発行者を照合し、異なる認可応答を拒否する', async () => {
  const spec = definition({ issuer: 'https://provider.test/tenant' });
  const provider = new Provider(() =>
    response({ access_token: 'valid-access', token_type: 'Bearer', account_id: 'account-1' }),
  );
  const oauth = new OAuth(provider);
  const parameters = new URLSearchParams({ code: 'code', state: 'state-1', iss: spec.issuer! });
  const token = await oauth.exchange(
    spec,
    app,
    {
      parameters,
      state: 'state-1',
    },
    verifier,
    redirect,
    [],
  );
  assert.equal(token.accessToken, 'valid-access');
  for (const changes of [{ state: 'wrong' }, { iss: 'https://another.test' }]) {
    const changed = new URLSearchParams(parameters);
    for (const [key, value] of Object.entries(changes)) changed.set(key, value);
    await assert.rejects(
      oauth.exchange(
        spec,
        app,
        {
          parameters: changed,
          state: 'state-1',
        },
        verifier,
        redirect,
        [],
      ),
      { code: 'invalid_state' },
    );
  }
  const duplicate = new URLSearchParams(parameters);
  duplicate.append('code', 'another-code');
  await assert.rejects(
    oauth.exchange(
      spec,
      app,
      {
        parameters: duplicate,
        state: 'state-1',
      },
      verifier,
      redirect,
      [],
    ),
    { code: 'invalid_state' },
  );
  assert.equal(provider.requests.length, 1);
});

test('無効なトークン応答を拒否し、更新不能と流量制限を区別して通知する', async () => {
  for (const values of [
    { access_token: '' },
    { access_token: 'bad token' },
    { token_type: 'DPoP' },
    { token_type: undefined },
    { token_type: 'User Access Token' },
    { token_type: 'constructor' },
    { token_type: '__proto__' },
    { expires_in: '10seconds' },
    { expires_in: -1 },
    { scope: ['read'] },
    { refresh_token: '' },
    { refresh_token: null },
  ]) {
    const oauth = new OAuth(
      new Provider(() =>
        response({ access_token: 'access', token_type: 'Bearer', account_id: 'account-1', ...values }),
      ),
    );
    await assert.rejects(oauth.exchange(definition(), app, authorization('code'), verifier, redirect, []), {
      code: 'invalid_response',
    });
  }
  for (const [body, status, code] of [
    [{ error: 'invalid_grant' }, 400, 'reconnect_required'],
    [{ error: 'invalid_token' }, 200, 'reconnect_required'],
    ['Too many requests', 429, 'service_rate_limit'],
  ] as const) {
    const oauth = new OAuth(new Provider(() => response(body, status)));
    await assert.rejects(oauth.refresh(definition(), app, existing()), { code });
  }
});

test('OAuthの要求にもFoundationの送信先制限と応答サイズ制限を適用する', async () => {
  const oauth = new OAuth(new PublicTransport('https://provider.test'));
  await assert.rejects(oauth.refresh(definition(), app, existing()), { code: 'invalid_url' });
  const limited = new OAuth(
    new Provider(() => {
      throw new DomainError(413, 'body_limit', 'The response body is too large.');
    }),
  );
  await assert.rejects(limited.refresh(definition(), app, existing()), { code: 'body_limit' });
});
