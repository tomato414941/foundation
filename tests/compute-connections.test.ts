import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { decode } from '../shared/encryption.js';
import { ConnectionMaterial } from '../shared/connections.js';
import { ConnectionClient } from '../shared/connection-client.js';
import { ExecutionClient } from '../shared/execution-client.js';

test('クラウドの接続を暗号化して保存し、選んだ接続のキーでAPIを呼び出す', async t => {
  for (const [serviceId, methodKey, output, url] of [
    ['vultr', 'token', 'VULTR_API_KEY', 'https://api.vultr.com/v2/instances'],
    ['runpod', 'token', 'RUNPOD_API_KEY', 'https://rest.runpod.io/v1/pods'],
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
