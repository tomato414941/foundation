import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { ConnectionMaterial, connectionMetadata } from '../shared/connections.js';
import { authorizeOperationContext } from '../shared/operation-authorization.js';
import { ovhAccessRules } from '../shared/ovh.js';
import { OvhApi, ovhSignature } from '../runtime/ovh.js';
import { canonical } from '../shared/authority.js';
import { decode } from '../shared/encryption.js';
import { Operations } from '../shared/custody.js';
import { Task } from '../shared/runtime-protocol.js';
import { DeliveryPending } from '../runtime/executor.js';
import type { OutboundRequest } from '../server/transport.js';

const keys = { applicationKey: 'application-id', applicationSecret: 'application-secret', consumerKey: 'consumer-key' };
const details = { account: 'aa12345-ovh', user: null, description: 'OVH account', roles: null,
  identities: ['urn:v1:ca:identity:account:aa12345-ovh'] };
const rules = [{ method: 'GET', path: '/auth/details' }, { method: 'GET', path: '/auth/currentCredential' },
  { method: 'GET', path: '/vps' }, { method: 'GET', path: '/vps/*' }];
const access = { credentialId: 123, status: 'validated', expiration: null, rules, allowedIPs: null };
const apiBases = { eu: 'https://eu.api.ovh.com/1.0', ca: 'https://ca.api.ovh.com/1.0', us: 'https://api.us.ovhcloud.com/1.0' };

function authenticated(request: OutboundRequest, base: string, consumerKey = keys.consumerKey) {
  assert.ok(request.url.startsWith(base + '/'));
  assert.equal(request.headers?.['X-Ovh-Application'], keys.applicationKey);
  assert.equal(request.headers?.['X-Ovh-Consumer'], consumerKey);
  const timestamp = Number(request.headers?.['X-Ovh-Timestamp']);
  assert.equal(request.headers?.['X-Ovh-Signature'], ovhSignature({ ...keys, consumerKey }, request, timestamp));
}

test('OVHの署名を送信するURL、メソッド、本文、時刻に結び付ける', () => {
  const request = { url: apiBases.ca + '/vps/vps-abc/reboot', method: 'POST', body: '{"type":"soft"}' };
  assert.equal(ovhSignature(keys, request, 1369159111), '$1$' + '62055bac5e31401ec6412d188cb3c698f91192a3');
});

test('OVHの時刻で署名したAPIリクエストを選択した接続先へ送信する', async () => {
  const requests: OutboundRequest[] = [];
  const api = new OvhApi({ async send(request) {
    requests.push(request);
    return request.url.endsWith('/auth/time') ? jsonResponse(1369159111) : jsonResponse(['vps-abc']);
  } });
  const sent = await api.send(apiBases.ca, keys, { url: apiBases.ca + '/vps', method: 'GET' });
  assert.equal(sent.status, 200);
  assert.equal(Number(requests[1]!.headers?.['X-Ovh-Timestamp']), 1369159111);
  authenticated(requests[1]!, apiBases.ca);
  await assert.rejects(api.send(apiBases.ca, keys, { url: apiBases.eu + '/vps' }), { code: 'invalid_destination' });
});

test('OVHのAPI Keysで接続先と権限を確認し、暗号化して保存する', async t => {
  for (const apiRegion of ['eu', 'ca', 'us'] as const) await t.test(apiRegion, async t => {
    const base = apiBases[apiRegion];
    const f = await flowFixture(request => {
      if (request.url.endsWith('/auth/time')) return jsonResponse(Math.floor(Date.now() / 1000));
      authenticated(request, base);
      return jsonResponse(request.url.endsWith('/auth/details') ? details : access);
    }); t.after(f.close);
    const started = await f.start({ methodId: 'ovh:api_key', fields: { apiRegion, ...keys } });
    const reviewed = await f.tick(started.flow.id);
    assert.equal(reviewed.kind, 'review', JSON.stringify(reviewed));
    if (reviewed.kind !== 'review') return;
    assert.equal(reviewed.metadata.accountVerified, true);
    assert.equal(reviewed.metadata.account, details.account);
    assert.deepEqual(reviewed.metadata.fields, { apiRegion });
    assert.equal(reviewed.metadata.scopesStatus, 'reported');
    assert.deepEqual(new Set(reviewed.metadata.scopes as string[]), new Set(rules.map(rule => rule.method + ' ' + rule.path)));
    const saved = await f.accept(started.flow.id);
    assert.equal(saved.kind, 'connection');
    if (saved.kind !== 'connection') return;
    assert.equal(saved.data.accountVerified, true);
    assert.deepEqual(saved.data.fields, { apiRegion });
    assert.ok(saved.data.outputs.includes('OVH_APPLICATION_SECRET'));
    const material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(saved.id))));
    assert.equal(material.fields!.consumerKey, keys.consumerKey);
    assert.equal(material.fields!.applicationSecret, keys.applicationSecret);
    const changed = ConnectionMaterial.parse({ ...material, fields: { ...material.fields, apiRegion: apiRegion === 'ca' ? 'eu' : 'ca' } });
    assert.notEqual((await connectionMetadata(changed)).authorizationDigest, reviewed.metadata.authorizationDigest);
  });
});

test('OVHのブラウザ承認で指定したAPI権限を取得し、Consumer Keyを暗号化して保存する', async t => {
  let redirection = '', requested: Array<{ method: string; path: string }> = [];
  const f = await flowFixture(request => {
    if (request.url.endsWith('/auth/credential')) {
      assert.equal(request.method, 'POST');
      assert.equal(request.headers?.['X-Ovh-Application'], keys.applicationKey);
      const body = JSON.parse(String(request.body));
      redirection = body.redirection; requested = body.accessRules;
      return jsonResponse({ consumerKey: 'browser-consumer-key', state: 'pendingValidation',
        validationUrl: 'https://auth.ca.ovhcloud.com/api/auth?credentialToken=validation-token' });
    }
    if (request.url.endsWith('/auth/time')) return jsonResponse(Math.floor(Date.now() / 1000));
    authenticated(request, apiBases.ca, 'browser-consumer-key');
    return jsonResponse(request.url.endsWith('/auth/details') ? details : { ...access, rules: requested });
  }); t.after(f.close);
  const app = await f.saveApp('ovh:consumer_key', 'OVH API application', { apiRegion: 'ca' });
  const started = await f.start({ methodId: 'ovh:consumer_key', appId: app.id,
    fields: { apiRegion: 'ca' }, scopes: ['POST /vps/*', 'GET /vps'] });
  const authorization = await f.tick(started.flow.id);
  assert.equal(authorization.kind, 'authorize', JSON.stringify(authorization));
  if (authorization.kind !== 'authorize') return;
  assert.deepEqual(requested, ovhAccessRules(['GET /auth/details', 'GET /auth/currentCredential', 'POST /vps/*', 'GET /vps']));
  assert.equal(new URL(redirection).pathname, '/oauth/callback');
  const state = new URL(redirection).searchParams.get('state')!;
  const exchanged = await f.connections.complete(started.flow.id, new URLSearchParams({ state }).toString());
  assert.equal(exchanged.kind, 'pending');
  const reviewed = await f.tick(started.flow.id);
  assert.equal(reviewed.kind, 'review', JSON.stringify(reviewed));
  const saved = await f.accept(started.flow.id);
  const material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(saved.id))));
  assert.equal(material.fields!.consumerKey, 'browser-consumer-key');
  assert.equal(material.appId, app.id);
  assert.equal(canonical(material).includes(keys.applicationSecret), false);
});

test('保存したOVHの資格情報を許可されたコマンドへ渡し、SDKで使う署名を生成する', async t => {
  const f = await flowFixture(request => request.url.endsWith('/auth/time') ? jsonResponse(Math.floor(Date.now() / 1000))
    : jsonResponse(request.url.endsWith('/auth/details') ? details : access));
  t.after(f.close);
  const started = await f.start({ methodId: 'ovh:api_key', fields: { apiRegion: 'ca', ...keys } });
  assert.equal((await f.tick(started.flow.id)).kind, 'review');
  const connection = await f.accept(started.flow.id);
  const script = "const e=process.env; if(e.OVH_ENDPOINT!=='ovh-ca'||e.OVH_APPLICATION_KEY!=='application-id') process.exit(1); " +
    "const text=[e.OVH_APPLICATION_SECRET,e.OVH_CONSUMER_KEY,'POST','https://ca.api.ovh.com/1.0/vps/vps-abc/reboot','{\\\"type\\\":\\\"soft\\\"}','1369159111'].join('+'); " +
    "console.log(require('node:crypto').createHash('sha1').update(text).digest('hex'));";
  const outputs = ['OVH_ENDPOINT', 'OVH_APPLICATION_KEY', 'OVH_APPLICATION_SECRET', 'OVH_CONSUMER_KEY'];
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, { kind: 'command',
    command: ['node', '-e', script], timeoutSeconds: 10,
    inputs: outputs.map(output => ({ source: { id: connection.id, output }, name: output })) });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  assert.equal(result!.ok, true, JSON.stringify(result!.error));
  const value = result!.result as { stdout: string; exitCode: number };
  assert.equal(value.exitCode, 0);
  assert.equal(value.stdout.trim(), '62055bac5e31401ec6412d188cb3c698f91192a3');
});

test('OVHの承認URLが届く前に実行が途切れても、発行済みのConsumer Keyで再開する', async t => {
  let issues = 0;
  const f = await flowFixture(() => {
    issues++;
    return jsonResponse({ consumerKey: 'issued-once', state: 'pendingValidation',
      validationUrl: 'https://auth.ca.ovhcloud.com/api/auth?credentialToken=issued-once' });
  }); t.after(f.close);
  const app = await f.saveApp('ovh:consumer_key', 'OVH app', { apiRegion: 'ca' });
  const started = await f.start({ methodId: 'ovh:consumer_key', appId: app.id });
  const register = f.runtimeConnections.broker.relay!;
  let registrations = 0;
  f.runtimeConnections.broker.relay = async input => {
    if (++registrations === 1) throw new DeliveryPending();
    return register(input);
  };
  await assert.rejects(f.tick(started.flow.id), DeliveryPending);
  await f.executor.reconcile();
  const recovered = await f.connections.progress(started.flow.id);
  assert.equal(recovered.kind, 'authorize', JSON.stringify(recovered));
  assert.ok(recovered.flow.authorizationState);
  assert.equal(issues, 1);
});

test('OVHのPATを選んだ地域で確認し、ローカルユーザーとして保存して利用する', async t => {
  for (const apiRegion of ['eu', 'ca', 'us'] as const) await t.test(apiRegion, async t => {
    const f = await flowFixture(request => {
      assert.equal(request.headers?.Authorization ?? request.headers?.authorization, 'Bearer local-user-pat');
      if (request.url.endsWith('/auth/details')) {
        assert.equal(request.url, apiBases[apiRegion] + '/auth/details');
        return jsonResponse({ ...details, identities: ['urn:v1:' + apiRegion + ':identity:user:aa12345-ovh/operator'],
          user: 'operator', description: 'Operations user' });
      }
      return jsonResponse(['vps-abc']);
    }); t.after(f.close);
    const pending = await f.operations.execute({ name: 'connection.connect', input: { ownerId: f.owner.actor.id,
      environmentId: f.environment.manifest.id, methodId: 'ovh:pat', name: 'OVH user', fields: { apiRegion } } },
      { fields: { apiRegion, token: 'local-user-pat' } });
    assert.equal('kind' in pending ? pending.kind : '', 'pending');
    if (!('flow' in pending)) return;
    const reviewed = await f.tick(pending.flow.id);
    assert.equal(reviewed.kind, 'review', JSON.stringify(reviewed));
    if (reviewed.kind !== 'review') return;
    assert.equal(reviewed.metadata.account, 'Operations user');
    assert.equal(reviewed.metadata.accountVerified, true);
    assert.equal(reviewed.metadata.scopesStatus, 'unknown');
    assert.deepEqual(reviewed.metadata.fields, { apiRegion });
    const saved = await f.accept(pending.flow.id);
    assert.equal((await f.http(saved.id, 'OVH_ACCESS_TOKEN', apiBases[apiRegion] + '/vps'))?.ok, true);
  });
});

test('依頼で指定したOVHのAPI権限に結び付けてブラウザ承認を実行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const method = await f.method('ovh:consumer_key'), flowId = crypto.randomUUID();
  const scopes = ['GET /vps'], requested = ovhAccessRules(scopes);
  assert.deepEqual(requested, [{ method: 'GET', path: '/vps' }]);
  const expected = { ownerId: f.owner.actor.id, environmentId: f.environment.manifest.id, methodId: 'ovh:consumer_key',
    name: 'Reviewed OVH access', appId: crypto.randomUUID(), fields: { apiRegion: 'ca' }, scopes };
  const input = { action: 'start', flowId, methodId: expected.methodId, method, name: expected.name, appId: expected.appId,
    fields: expected.fields, scopes: ['GET /auth/details', 'GET /auth/currentCredential', ...scopes] };
  const { hash } = await import('../shared/authority.js');
  const intent = { ...f.intent, operation: Operations.connect, environmentId: f.environment.manifest.id,
    operationContext: { id: crypto.randomUUID(), index: 0, continuationId: flowId,
      invocation: { name: 'connection.connect', input: { ...expected, methodDigest: await hash(method) } } } };
  await authorizeOperationContext(intent, { kind: 'connect', input });
  await assert.rejects(authorizeOperationContext(intent, { kind: 'connect', input: { ...input, scopes: ['POST /*'] } }),
    /reviewed service permissions/);
});
