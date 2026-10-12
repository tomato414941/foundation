import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { ConnectionMaterial, connectionMetadata } from '../shared/connections.js';
import { ovhAccessRules } from '../shared/ovh.js';
import { OvhApi, ovhSignature } from '../runtime/ovh.js';
import { decode } from '../shared/encryption.js';
import { Task } from '../shared/runtime-protocol.js';
import type { OutboundRequest } from '../server/transport.js';

const keys = { applicationKey: 'application-id', applicationSecret: 'application-secret', consumerKey: 'consumer-key' };
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

test('OVHのAPI Keysを各地域で暗号化して保存し、利用時に署名する', async t => {
  for (const apiRegion of ['eu', 'ca', 'us'] as const) await t.test(apiRegion, async t => {
    const f = await flowFixture(); t.after(f.close);
    const saved = await f.saveConnection({ methodId: 'ovh:api_key', fields: { apiRegion, ...keys } });
    const material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(saved.id))));
    assert.equal(material.fields!.consumerKey, keys.consumerKey);
    assert.equal(material.fields!.applicationSecret, keys.applicationSecret);
    const metadata = await connectionMetadata(material);
    assert.deepEqual(metadata.fields, { apiRegion });
    const changed = ConnectionMaterial.parse({ ...material, fields: { ...material.fields, apiRegion: apiRegion === 'ca' ? 'eu' : 'ca' } });
    assert.notEqual((await connectionMetadata(changed)).authorizationDigest, metadata.authorizationDigest);
    const request = { url: apiBases[apiRegion] + '/vps', method: 'GET' };
    assert.ok(ovhSignature({ applicationKey: material.fields!.applicationKey!, applicationSecret: material.fields!.applicationSecret!,
      consumerKey: material.fields!.consumerKey! }, request, 1369159111).startsWith('$1$'));
  });
});

test('OVHのブラウザ認可で指定したAPI権限のConsumer Keyを取得して保存する', async t => {
  const selected = ['GET /vps', 'POST /vps/*'];
  let redirect = '';
  const f = await flowFixture(request => {
    assert.equal(request.url, apiBases.ca + '/auth/credential');
    assert.equal(request.headers?.['X-Ovh-Application'], keys.applicationKey);
    const body = JSON.parse(String(request.body)); redirect = body.redirection;
    assert.deepEqual(body.accessRules, ovhAccessRules(selected));
    return jsonResponse({ state: 'pendingValidation', consumerKey: 'approved-consumer', validationUrl: 'https://auth.ca.ovhcloud.com/api/auth?credentialToken=test' });
  }); t.after(f.close);
  const app = await f.saveApp('ovh:consumer_key', 'OVH application', { apiRegion: 'ca' });
  const started = await f.authorize({ methodId: 'ovh:consumer_key', appId: app.id, scopes: selected });
  assert.equal(started.url, 'https://auth.ca.ovhcloud.com/api/auth?credentialToken=test');
  assert.equal((await f.app.inject('/oauth/callback?' + new URL(redirect).searchParams)).statusCode, 302);
  const saved = await f.saved(started.flow.id);
  const material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(saved.id))));
  assert.equal(material.appId, app.id); assert.equal(material.fields!.consumerKey, 'approved-consumer');
  assert.deepEqual((await connectionMetadata(material)).scopes, selected);
});

test('保存したOVHの資格情報を許可したコマンドへ渡し、SDKで署名する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const saved = await f.saveConnection({ methodId: 'ovh:api_key', fields: { apiRegion: 'ca', ...keys } });
  const program = "const c=require('node:crypto'); const v=[process.env.OVH_APPLICATION_SECRET,process.env.OVH_CONSUMER_KEY,'GET',process.env.OVH_API_BASE_URL+'/vps','','1369159111'].join('+'); console.log('$1$'+c.createHash('sha1').update(v).digest('hex'));";
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, { kind: 'command', command: ['node', '-e', program],
    timeoutSeconds: 10, inputs: ['OVH_APPLICATION_SECRET', 'OVH_CONSUMER_KEY', 'OVH_API_BASE_URL'].map(output => ({
      name: output, source: { id: saved.id, output },
    })) });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  assert.equal(result?.ok, true);
  assert.equal((result?.result as { stdout: string }).stdout.trim(), ovhSignature(keys, { url: apiBases.ca + '/vps', method: 'GET' }, 1369159111));
});

test('OVHのPATを保存し、選んだ地域のAPIを呼び出す', async t => {
  for (const apiRegion of ['eu', 'ca', 'us'] as const) await t.test(apiRegion, async t => {
    const f = await flowFixture(request => {
      assert.equal(request.url, apiBases[apiRegion] + '/vps'); assert.equal(request.headers?.authorization, 'Bearer personal-token');
      return jsonResponse(['vps-example']);
    }); t.after(f.close);
    const saved = await f.saveConnection({ methodId: 'ovh:pat', fields: { apiRegion, token: 'personal-token' } });
    assert.equal((await f.http(saved.id, 'OVH_ACCESS_TOKEN', apiBases[apiRegion] + '/vps'))?.ok, true);
  });
});
