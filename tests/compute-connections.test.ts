import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { decode } from '../shared/encryption.js';
import { ConnectionMaterial } from '../shared/connections.js';
import { ConnectionClient } from '../shared/connection-client.js';
import { ExecutionClient } from '../shared/execution-client.js';
import { TokenConnection } from '../runtime/token-connection.js';
import { VultrRoleConnection } from '../runtime/vultr-role-connection.js';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

test('クラウドの接続を暗号化して保存し、選んだ接続のキーでAPIを呼び出す', async t => {
  for (const [serviceId, methodKey, output, url] of [
    ['vultr', 'token', 'VULTR_API_KEY', 'https://api.vultr.com/v2/instances'],
    ['runpod', 'token', 'RUNPOD_API_KEY', 'https://api.runpod.io/v2/pods'],
    ['hetzner', 'cloud-api-token', 'HCLOUD_TOKEN', 'https://api.hetzner.cloud/v1/servers'],
  ] as const) await t.test(serviceId, async t => {
    const token = serviceId + '-test-api-key';
    const f = await flowFixture(request => {
      assert.equal(request.url, url);
      assert.equal(request.headers?.authorization, 'Bearer ' + token);
      return jsonResponse({ resources: [] });
    });
    t.after(f.close);

    const service = (await f.context.catalog.list(f.owner.actor)).find(item => item.id === serviceId);
    assert.ok(service);
    const method = service.methods[methodKey];
    assert.ok(method);
    const saved = await f.saveConnection({ methodId: method.id, fields: { token } });
    assert.equal(saved.kind, 'connection');
    if (saved.kind !== 'connection') return;
    assert.deepEqual(saved.data.services, [{ id: serviceId, name: service.name }]);
    assert.equal(JSON.stringify(saved).includes(token), false);
    assert.equal((await f.http(saved.id, output, url))?.ok, true);
  });
});

test('S3接続を暗号化して保存し、その保存先と認証情報でファイル取得URLを署名する', async t => {
  for (const [service, endpoint, region] of [
    ['vultr', 'https://ewr1.vultrobjects.com', 'us-east-1'],
    ['runpod', 'https://s3api-eu-cz-1.runpod.io', 'EU-CZ-1'],
    ['hetzner', 'https://fsn1.your-objectstorage.com', 'fsn1'],
  ] as const) await t.test(service, async t => {
    const f = await flowFixture();
    t.after(f.close);
    const resource = await f.saveConnection({ methodId: service + ':s3',
      fields: { endpoint, region, accessKeyId: 'test-access-key', secretAccessKey: 'test-storage-secret' } });
    assert.equal(resource.kind, 'connection');
    assert.equal(JSON.stringify(resource).includes('test-storage-secret'), false);
    const material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(resource.id))));
    const outputs = await new TokenConnection().outputs(material);
    const client = new S3Client({ endpoint: outputs.AWS_ENDPOINT_URL_S3, region: outputs.AWS_REGION,
      forcePathStyle: true, credentials: { accessKeyId: outputs.AWS_ACCESS_KEY_ID!, secretAccessKey: outputs.AWS_SECRET_ACCESS_KEY! } });
    t.after(() => client.destroy());
    const signed = new URL(await getSignedUrl(client, new GetObjectCommand({ Bucket: 'model-files', Key: 'weights.bin' }), { expiresIn: 300 }));
    assert.equal(signed.origin, endpoint);
    assert.equal(signed.pathname, '/model-files/weights.bin');
    assert.match(signed.searchParams.get('X-Amz-Credential')!, new RegExp('^test-access-key/[0-9]+/' + region + '/s3/aws4_request$'));
    assert.ok(signed.searchParams.get('X-Amz-Signature'));
  });
});

test('RobotのWebサービス用認証情報を暗号化して保存し、Basic認証に使用する', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const resource = await f.saveConnection({ methodId: 'hetzner:robot-basic',
    fields: { username: 'web-service-user', password: 'robot-test-password' } });
  const material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(resource.id))));
  const outputs = await new TokenConnection().outputs(material);
  const authorization = 'Basic ' + Buffer.from(outputs.HETZNER_ROBOT_USERNAME + ':' + outputs.HETZNER_ROBOT_PASSWORD).toString('base64');
  assert.equal(Buffer.from(authorization.slice(6), 'base64').toString(), 'web-service-user:robot-test-password');
  assert.equal(JSON.stringify(resource).includes('robot-test-password'), false);
});

test('RunPod MCPのクライアントを登録し、PKCEで承認した接続を利用する', async t => {
  let registrations = 0;
  const f = await flowFixture(request => {
    if (request.url === 'https://mcp.getrunpod.io/register') {
      const input = JSON.parse(String(request.body));
      assert.deepEqual(input.redirect_uris, [f.config.origin + '/oauth/callback']);
      assert.equal(input.token_endpoint_auth_method, 'none');
      registrations++;
      return jsonResponse({ client_id: 'registered-mcp-client', token_endpoint_auth_method: 'none' });
    }
    if (request.url === 'https://mcp.getrunpod.io/token') {
      const parameters = new URLSearchParams(String(request.body));
      assert.equal(parameters.get('client_id'), 'registered-mcp-client');
      assert.equal(parameters.get('resource'), 'https://mcp.getrunpod.io/');
      assert.ok(parameters.get('code_verifier'));
      return jsonResponse({ access_token: 'test-mcp-access', token_type: 'Bearer', expires_in: 3600 });
    }
    assert.equal(request.url, 'https://mcp.getrunpod.io/');
    assert.equal(request.headers?.authorization, 'Bearer test-mcp-access');
    return jsonResponse({ tools: [] });
  });
  t.after(f.close);
  const started = await f.authorize({ methodId: 'runpod:mcp-oauth' });
  const url = new URL(started.url);
  assert.equal(url.searchParams.get('client_id'), 'registered-mcp-client');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  const completed = await f.connections.complete(started.flow.id, new URLSearchParams({ code: 'mcp-code',
    state: url.searchParams.get('state')! }).toString());
  assert.equal(completed.kind, 'connected');
  if (completed.kind !== 'connected') return;
  assert.equal((await f.http(completed.id, 'RUNPOD_MCP_ACCESS_TOKEN', 'https://mcp.getrunpod.io/'))?.ok, true);
  assert.equal(registrations, 1);
});

test('RunPod Flashでの承認を待ち、取得したAPIキーを暗号化してAPIに使用する', async t => {
  let polls = 0;
  const f = await flowFixture(request => {
    if (request.url === 'https://api.runpod.io/graphql') {
      const input = JSON.parse(String(request.body));
      const expiresAt = new Date(Date.now() + 600_000).toISOString();
      if (input.query.includes('mutation')) return jsonResponse({ data: {
        createFlashAuthRequest: { id: 'test-approval-request', status: 'PENDING', expiresAt },
      } });
      assert.equal(input.variables.flashAuthRequestId, 'test-approval-request');
      polls++;
      return jsonResponse({ data: { flashAuthRequestStatus: { id: 'test-approval-request', expiresAt,
        status: polls === 1 ? 'PENDING' : 'APPROVED', apiKey: polls === 1 ? null : 'approved-api-key' } } });
    }
    assert.equal(request.url, 'https://api.runpod.io/v2/pods');
    assert.equal(request.headers?.authorization, 'Bearer approved-api-key');
    return jsonResponse({ pods: [] });
  });
  t.after(f.close);
  const started = await f.authorize({ methodId: 'runpod:flash-approval' });
  assert.equal(new URL(started.url).hostname, 'console.runpod.io');
  assert.equal((await f.tick(started.flow.id)).kind, 'authorize');
  const completed = await f.tick(started.flow.id);
  assert.equal(completed.kind, 'connected');
  if (completed.kind !== 'connected') return;
  assert.equal((await f.http(completed.id, 'RUNPOD_API_KEY', 'https://api.runpod.io/v2/pods'))?.ok, true);
  const resource = await f.api(f.owner.token).json('/api/resources/' + completed.id);
  assert.equal(JSON.stringify(resource).includes('approved-api-key'), false);
});

test('RunPodの承認を同時に確認しても同じAPIキー接続を完了する', async t => {
  let polls = 0;
  const f = await flowFixture(request => {
    const input = JSON.parse(String(request.body));
    const expiresAt = new Date(Date.now() + 600_000).toISOString();
    if (input.query.includes('mutation')) return jsonResponse({ data: {
      createFlashAuthRequest: { id: 'parallel-approval', status: 'PENDING', expiresAt },
    } });
    polls++;
    return jsonResponse({ data: { flashAuthRequestStatus: { id: 'parallel-approval', status: 'APPROVED',
      expiresAt, apiKey: 'parallel-api-key' } } });
  });
  t.after(f.close);
  const started = await f.authorize({ methodId: 'runpod:flash-approval' });
  const results = await Promise.all([f.tick(started.flow.id), f.tick(started.flow.id)]);
  assert.equal(polls, 1);
  for (const result of results) assert.equal(result.kind, 'connected');
  assert.deepEqual(results[0], results[1]);
});

test('RunPodが拒否または期限切れにした承認には再接続を案内する', async t => {
  for (const status of ['DENIED', 'EXPIRED']) await t.test(status, async t => {
    const f = await flowFixture(request => {
      const input = JSON.parse(String(request.body));
      const expiresAt = new Date(Date.now() + 600_000).toISOString();
      return jsonResponse({ data: input.query.includes('mutation')
        ? { createFlashAuthRequest: { id: 'failed-approval', status: 'PENDING', expiresAt } }
        : { flashAuthRequestStatus: { id: 'failed-approval', status, expiresAt, apiKey: null } } });
    });
    t.after(f.close);
    const started = await f.authorize({ methodId: 'runpod:flash-approval' });
    await assert.rejects(f.tick(started.flow.id), { code: 'authorization_failed', message: 'Start the RunPod connection again.' });
  });
});

test('VultrのIAMロールで一時認証を取得し、有効なセッションでAPIを呼び出す', async t => {
  let assumptions = 0;
  const f = await flowFixture(request => {
    if (request.url.endsWith('/assumed-roles/assume')) {
      assumptions++;
      assert.equal(request.headers?.authorization, 'Bearer role-source-key');
      assert.deepEqual(JSON.parse(String(request.body)), { role_id: 'role-1', user_id: 'user-1',
        session_name: 'Foundation', duration: 3600, auth_method: 'api_key' });
      return jsonResponse({ session_token: 'role-session-token', role_id: 'role-1', user_id: 'user-1',
        expires_at: new Date(Date.now() + 3_600_000).toISOString() });
    }
    assert.equal(request.headers?.authorization, 'Bearer role-session-token');
    return jsonResponse({ instances: [] });
  });
  t.after(f.close);
  const saved = await f.saveConnection({ methodId: 'vultr:role',
    fields: { roleId: 'role-1', userId: 'user-1', token: 'role-source-key' } });
  for (let index = 0; index < 2; index++)
    assert.equal((await f.http(saved.id, 'VULTR_ACCESS_TOKEN', 'https://api.vultr.com/v2/instances'))?.ok, true);
  assert.equal(assumptions, 1);
});

test('VultrのOIDC認証元を再取得し、有効期限に応じてロールのセッションを更新する', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const saved = await f.saveConnection({ methodId: 'vultr:role', fields: {
    authentication: 'oidc', issuerId: 'issuer-1', roleId: 'role-1',
  } });
  const material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(saved.id))));
  let identities = 0, sessions = 0;
  const provider = new VultrRoleConnection({ async send(request) {
    sessions++;
    assert.equal(request.headers?.authorization, 'Bearer current-identity-' + sessions);
    const input = JSON.parse(String(request.body));
    assert.equal(input.oidc_issuer_id, 'issuer-1');
    assert.equal(input.auth_method, 'oidc');
    return jsonResponse({ role_id: 'role-1', session_token: 'session-' + sessions,
      expires_at: new Date(Date.now() + (sessions === 1 ? 30_000 : 3_600_000)).toISOString() });
  } }, async () => 'current-identity-' + ++identities);
  const signal = new AbortController().signal;
  assert.equal((await provider.outputs(material, null, signal)).VULTR_ACCESS_TOKEN, 'session-1');
  assert.equal((await provider.outputs(material, null, signal)).VULTR_ACCESS_TOKEN, 'session-2');
  assert.equal((await provider.outputs(material, null, signal)).VULTR_ACCESS_TOKEN, 'session-2');
  assert.equal(identities, 2);
});

test('異なる認証元の接続には、それぞれのロールセッションを返す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const saved = await f.saveConnection({ methodId: 'vultr:role', fields: {
    roleId: 'role-1', userId: 'user-1', token: 'source-one',
  } });
  const first = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(saved.id))));
  const second = ConnectionMaterial.parse({ ...first, fields: { ...first.fields, token: 'source-two' } });
  const provider = new VultrRoleConnection({ async send(request) {
    const source = request.headers!.authorization!.slice(7);
    return jsonResponse({ session_token: 'session-for-' + source, role_id: 'role-1', user_id: 'user-1',
      expires_at: new Date(Date.now() + 3_600_000).toISOString() });
  } });
  const signal = new AbortController().signal;
  assert.equal((await provider.outputs(first, null, signal)).VULTR_ACCESS_TOKEN, 'session-for-source-one');
  assert.equal((await provider.outputs(second, null, signal)).VULTR_ACCESS_TOKEN, 'session-for-source-two');
});

test('ブラウザでVultrのOAuth接続を準備し、CLIで認可を継続する', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const application = await f.saveApp('vultr:oauth', 'Vultr application', {
    providerId: 'provider-1', authorizationEndpoint: 'https://console.vultr.com/oauth/authorize',
  });
  const browser = new ConnectionClient(f.client, f.connections.store, f.transport, 'browser');
  const operations = new ExecutionClient(f.client, browser);
  const started = await operations.execute({ name: 'connection.connect', input: {
    ownerId: f.owner.actor.id, methodId: 'vultr:oauth', appId: application.id, name: 'Vultr',
  } });
  assert.equal(started.kind, 'cli');
  if (started.kind !== 'cli') return;
  assert.equal(started.command, 'foundation execution continue ' + started.flow.execution.id);
  const continued = await f.connections.progress(started.flow.id);
  assert.equal(continued.kind, 'authorize');
  if (continued.kind !== 'authorize') return;
  const url = new URL(continued.url);
  assert.equal(url.searchParams.get('client_id'), 'application-id');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
});

test('VultrでPKCE付きの認可を行い、更新したトークンでAPIを継続して呼び出す', async t => {
  let exchanges = 0;
  let renewals = 0;
  const f = await flowFixture(request => {
    if (request.url === 'https://api.vultr.com/v2/oidc/provider/provider-1/token') {
      const credentials = Buffer.from(request.headers!.authorization!.slice(6), 'base64').toString()
        .split(':').map(value => new URLSearchParams('value=' + value).get('value'));
      assert.deepEqual(credentials, ['application-id', 'application-secret']);
      const form = new URLSearchParams(String(request.body));
      if (form.get('grant_type') === 'authorization_code') {
        exchanges++;
        assert.equal(form.get('code'), 'vultr-code');
        assert.equal(form.get('redirect_url'), f.config.origin + '/oauth/callback');
        assert.ok(form.get('code_verifier'));
        return jsonResponse({ access_token: 'vultr-first-access', refresh_token: 'vultr-first-refresh',
          token_type: 'Bearer', expires_in: 10, scope: 'instances.read' });
      }
      assert.equal(form.get('grant_type'), 'refresh_token');
      assert.equal(form.get('refresh_token'), 'vultr-first-refresh');
      renewals++;
      return jsonResponse({ access_token: 'vultr-renewed-access', refresh_token: 'vultr-rotated-refresh',
        token_type: 'Bearer', expires_in: 3600, scope: 'instances.read' });
    }
    assert.equal(request.url, 'https://api.vultr.com/v2/instances');
    assert.equal(request.headers?.authorization, 'Bearer vultr-renewed-access');
    return jsonResponse({ instances: [] });
  });
  t.after(f.close);

  const application = await f.saveApp('vultr:oauth', 'Vultr application', {
    providerId: 'provider-1', authorizationEndpoint: 'https://console.vultr.com/oauth/authorize',
  });
  const step = await f.authorize({ methodId: 'vultr:oauth', appId: application.id });
  const url = new URL(step.url);
  assert.equal(url.origin, 'https://console.vultr.com');
  assert.equal(url.searchParams.get('client_id'), 'application-id');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(url.searchParams.get('code_challenge'));
  const completed = await f.connections.complete(step.flow.id, new URLSearchParams({
    state: url.searchParams.get('state')!, code: 'vultr-code',
  }).toString());
  assert.equal(completed.kind, 'connected');
  if (completed.kind !== 'connected') return;

  for (let index = 0; index < 2; index++)
    assert.equal((await f.http(completed.id, 'VULTR_ACCESS_TOKEN', 'https://api.vultr.com/v2/instances'))?.ok, true);
  const material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(completed.id))));
  assert.equal(material.method.kind, 'oauth');
  if (material.method.kind !== 'oauth') return;
  assert.equal(material.oauth?.refreshToken, 'vultr-rotated-refresh');
  assert.deepEqual(material.oauth?.scopes, ['instances.read']);
  assert.equal(exchanges, 1);
  assert.equal(renewals, 1);
});
