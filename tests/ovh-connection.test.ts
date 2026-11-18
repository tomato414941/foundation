import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { ConnectionMaterial, connectionMetadata } from '../shared/connections.js';
import { ovhAccessRules } from '../shared/ovh.js';

const keys = { applicationKey: 'application-id', applicationSecret: 'application-secret', consumerKey: 'consumer-key' };
const apiBases = { eu: 'https://eu.api.ovh.com/1.0', ca: 'https://ca.api.ovh.com/1.0', us: 'https://api.us.ovhcloud.com/1.0' };

test('OVHのAPI Keysを各地域で暗号化して保存し、地域を認可の内容に含める', async t => {
  for (const apiRegion of ['eu', 'ca', 'us'] as const) await t.test(apiRegion, async t => {
    const f = await flowFixture(); t.after(f.close);
    const saved = await f.saveConnection({ methodId: 'ovh:api_key', fields: { apiRegion, ...keys } });
    const material = await f.client.connection(saved.id);
    assert.equal(material.fields!.consumerKey, keys.consumerKey);
    assert.equal(material.fields!.applicationSecret, keys.applicationSecret);
    const metadata = await connectionMetadata(material);
    assert.deepEqual(metadata.fields, { apiRegion });
    const changed = ConnectionMaterial.parse({ ...material, fields: { ...material.fields, apiRegion: apiRegion === 'ca' ? 'eu' : 'ca' } });
    assert.notEqual((await connectionMetadata(changed)).authorizationDigest, metadata.authorizationDigest);
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
  const material = await f.client.connection(saved.id);
  assert.equal(material.appId, app.id); assert.equal(material.fields!.consumerKey, 'approved-consumer');
  assert.deepEqual((await connectionMetadata(material)).scopes, selected);
});

test('保存したOVHの資格情報を手元のコマンドへ渡し、SDKが署名に使う値をそろえる', async t => {
  const f = await flowFixture(); t.after(f.close);
  const saved = await f.saveConnection({ methodId: 'ovh:api_key', fields: { apiRegion: 'ca', ...keys } });
  const used = await f.inputs(['OVH_APPLICATION_KEY', 'OVH_APPLICATION_SECRET', 'OVH_CONSUMER_KEY', 'OVH_API_BASE_URL'].map(output => ({
    name: output, source: { id: saved.id, output } })));
  assert.deepEqual(used.environment, { OVH_APPLICATION_KEY: keys.applicationKey, OVH_APPLICATION_SECRET: keys.applicationSecret,
    OVH_CONSUMER_KEY: keys.consumerKey, OVH_API_BASE_URL: apiBases.ca });
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
