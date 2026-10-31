import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DEVICE_CODE_GRANT, OAuthDefinition } from '../shared/contracts.js';
import { OAuth } from '../shared/oauth.js';
import type { OAuthSpec } from '../shared/oauth.js';
import type { OutboundRequest, OutboundResponse, Transport } from '../shared/http.js';

const app = { clientId: 'device-client', fields: {} };
const specification = (changes: Record<string, unknown> = {}) => OAuthDefinition.parse({
  grantType: DEVICE_CODE_GRANT, deviceAuthorizationUrl: 'https://provider.test/device',
  tokenUrl: 'https://provider.test/token', clientAuth: 'none', ...changes,
});
const authorization = { device_code: 'private-device-code', user_code: 'ABCD-EFGH',
  verification_uri: 'https://provider.test/activate', expires_in: 900 };
const response = (body: unknown, status = 200): OutboundResponse => ({ status,
  headers: { 'content-type': 'application/json' }, body: new TextEncoder().encode(JSON.stringify(body)) });
class Provider implements Transport {
  requests: OutboundRequest[] = [];
  constructor(readonly respond: (request: OutboundRequest) => OutboundResponse | Promise<OutboundResponse>) {}
  async send(request: OutboundRequest) { this.requests.push(request); return this.respond(request); }
}
async function github(): Promise<OAuthSpec> {
  const catalog = JSON.parse(await readFile(new URL('../server/catalog/github.json', import.meta.url), 'utf8'));
  return OAuthDefinition.parse(catalog.methods.device.config);
}

test('GitHubのクライアントIDで確認コードを取得し、許可されたトークンを更新する', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const now = Date.now(), spec = await github();
  const provider = new Provider(request => {
    const body = JSON.parse(String(request.body));
    assert.equal(body.client_id, app.clientId);
    assert.equal(Object.hasOwn(body, 'client_secret'), false);
    if (request.url === 'https://github.com/login/device/code') {
      assert.equal(body.scope, 'repo gist');
      return response({ ...authorization, verification_uri: 'https://github.com/login/device', interval: 5 });
    }
    assert.equal(request.url, 'https://github.com/login/oauth/access_token');
    if (body.grant_type === 'refresh_token') {
      assert.equal(body.refresh_token, 'device-refresh');
      return response({ access_token: 'refreshed-device-access', token_type: 'bearer', expires_in: 3600 });
    }
    assert.equal(body.grant_type, DEVICE_CODE_GRANT);
    assert.equal(body.device_code, authorization.device_code);
    return response({ access_token: 'device-access', refresh_token: 'device-refresh', token_type: 'bearer',
      expires_in: 3600, refresh_token_expires_in: 7200, scope: 'gist,repo' });
  });
  const oauth = new OAuth(provider);
  const device = await oauth.deviceAuthorization(spec, { ...app, clientSecret: 'unused-secret' }, ['repo', 'gist']);
  assert.equal(device.userCode, 'ABCD-EFGH');
  assert.equal(device.verificationUri, 'https://github.com/login/device');
  assert.equal(device.expiresAt, now + 900_000);
  assert.equal(device.nextPollAt, now + 5_000);
  const connected = await oauth.deviceToken(spec, app, device.deviceCode, ['repo', 'gist']);
  if (connected.kind !== 'connected') throw new Error('Expected a token.');
  assert.equal(connected.token.accessToken, 'device-access');
  assert.deepEqual(connected.token.scopes, ['gist', 'repo']);
  assert.equal(connected.token.scopesStatus, 'reported');
  t.mock.timers.tick(3_600_000);
  const refreshed = await oauth.refresh(spec, app, connected.token);
  assert.equal(refreshed.accessToken, 'refreshed-device-access');
  assert.equal(refreshed.refreshToken, 'device-refresh');
  assert.deepEqual(refreshed.scopes, ['gist', 'repo']);
});

test('標準のデバイス認証でクライアントを認証し、コード入りURLと既定の確認間隔を受け取る', async () => {
  const provider = new Provider(request => {
    assert.equal(request.url, 'https://provider.test/device');
    const credentials = Buffer.from(request.headers!.authorization!.slice(6), 'base64').toString();
    assert.deepEqual(credentials.split(':').map(value => new URLSearchParams('value=' + value).get('value')),
      [app.clientId, 'application-secret']);
    assert.equal(new URLSearchParams(String(request.body)).get('scope'), 'read write');
    return response({ ...authorization, verification_uri_complete: 'https://provider.test/activate?user_code=ABCD-EFGH' });
  });
  const device = await new OAuth(provider).deviceAuthorization(specification({ clientAuth: 'basic' }),
    { ...app, clientSecret: 'application-secret' }, ['read', 'write']);
  assert.equal(device.intervalSeconds, 5);
  assert.equal(device.verificationUriComplete, 'https://provider.test/activate?user_code=ABCD-EFGH');
});

test('デバイス認証の許可待ちと確認間隔の延長を受け取る', async () => {
  for (const status of [200, 400]) for (const error of ['authorization_pending', 'slow_down']) {
    const oauth = new OAuth(new Provider(() => response({ error, ...(error === 'slow_down' ? { interval: 10 } : {}) }, status)));
    assert.deepEqual(await oauth.deviceToken(specification(), app, 'private-device-code', []), {
      kind: 'pending', slowDown: error === 'slow_down', ...(error === 'slow_down' ? { intervalSeconds: 10 } : {}),
    });
  }
});

test('デバイス認証の拒否・期限切れ・設定不備を区別し、不正な応答を拒否する', async () => {
  for (const [error, expected] of [
    ['access_denied', 'device_access_denied'], ['expired_token', 'device_code_expired'],
    ['device_flow_disabled', 'device_flow_disabled'], ['invalid_client', 'authorization_failed'],
  ]) {
    const oauth = new OAuth(new Provider(() => response({ error }, 400)));
    await assert.rejects(oauth.deviceToken(specification(), app, 'private-device-code', []), { code: expected });
  }
  const disabled = new OAuth(new Provider(() => response({ error: 'device_flow_disabled' }, 400)));
  await assert.rejects(disabled.deviceAuthorization(specification(), app, []), { code: 'device_flow_disabled' });
  for (const body of [
    { ...authorization, device_code: '' }, { ...authorization, user_code: '' }, { ...authorization, expires_in: 0 },
    { ...authorization, interval: -1 }, { ...authorization, verification_uri: 'javascript:alert(1)' },
    { ...authorization, verification_uri_complete: 'http://127.0.0.1/private' },
  ]) await assert.rejects(new OAuth(new Provider(() => response(body))).deviceAuthorization(specification(), app, []));
  const invalid = new OAuth(new Provider(() => response({ token_type: 'bearer' })));
  await assert.rejects(invalid.deviceToken(specification(), app, 'private-device-code', []), { code: 'invalid_response' });
});
