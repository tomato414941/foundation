import test from 'node:test';
import assert from 'node:assert/strict';
import { cloudflareOauth } from '../src/connectors/cloudflare/index.mjs';
import { FakeCloudflare } from '../src/connectors/cloudflare/fixture.mjs';
import { openrouterOauth } from '../src/connectors/openrouter/index.mjs';
import { FakeOpenRouter } from '../src/connectors/openrouter/fixture.mjs';
import { fixture, USER_A } from './helpers.mjs';

const MINE = { client_id: 'my cloudflare app id', client_secret: 'my cloudflare app secret' };

// Foundation's own Cloudflare app is not configured here: only the holder's app can connect.
async function own(t) {
  const cloudflare = new FakeCloudflare();
  cloudflare.enabled = false; cloudflare.clientId = ''; cloudflare.clientSecret = '';
  cloudflare.scopes = 'offline_access user-details.read email-routing-rule.write';
  const f = await fixture(t, { connectors: [cloudflareOauth(cloudflare), openrouterOauth(new FakeOpenRouter())] });
  await f.request('/v1/holdings?kind=grant&name=' + encodeURIComponent(MINE.client_id), { method: 'PUT', raw: 'holder-client-id\n' });
  await f.request('/v1/holdings?kind=grant&name=' + encodeURIComponent(MINE.client_secret), { method: 'PUT', raw: 'holder-client-secret' });
  async function connect(input = {}) {
    const started = await f.request('/v1/connections', { method: 'POST', data: { connector: 'cloudflare.oauth', ...input } });
    assert.equal(started.status, 200, started.text);
    const url = new URL(started.json.url);
    return { url, done: await f.callback(url, 'personal') };
  }
  const tokenCalls = () => cloudflare.calls.filter(call => call.url.endsWith('/token')).map(call => call.options.body);
  return { ...f, cloudflare, connect, tokenCalls };
}

test('持ち主が預けた自分のOAuthアプリで、運営のアプリがなくても接続できる', async t => {
  const f = await own(t), { token } = await f.issueKey();
  assert.deepEqual((await f.request('/v1/connectors', { anonymous: true })).json.connectors.find(item => item.id === 'cloudflare.oauth').own_client, { fields: ['client_id', 'client_secret'] });
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: { kind: 'connect',
    input: { connector: 'cloudflare.oauth', client: MINE, scopes: ['email-routing-rule.write'] }, purpose: 'メールの転送を設定します。' } });
  assert.equal(asked.status, 201, asked.text);
  const started = await f.request('/v1/connections', { method: 'POST', data: { connector: 'cloudflare.oauth', request_id: asked.json.request.id } });
  assert.equal(started.status, 200, started.text);
  const url = new URL(started.json.url);
  assert.equal(url.searchParams.get('client_id'), 'holder-client-id');
  assert.match((await f.callback(url, 'personal')).headers.get('location'), /connection=connected/);
  assert.equal(f.tokenCalls()[0].get('client_id'), 'holder-client-id');
  assert.equal(f.tokenCalls()[0].get('client_secret'), 'holder-client-secret');
  const [connection] = (await f.request('/v1/holdings?kind=grant&method=authorized', { token })).json.holdings;
  assert.equal(connection.own_client, true);
  assert.equal(connection.facts.client_id, 'holder-client-id');
  assert.doesNotMatch(JSON.stringify(connection), /holder-client-secret/);
});

test('自分のアプリで作った接続は、更新・つなぎ直し・取り消しも同じアプリで行う', async t => {
  const f = await own(t), { done } = await f.connect({ client: MINE });
  assert.match(done.headers.get('location'), /connection=connected/);
  const connection = (await f.request('/v1/overview')).json.grants.find(item => item.method === 'authorized');
  f.expire(connection.id);
  assert.equal((await f.deliver(connection)).status, 200);
  assert.equal(f.tokenCalls().at(-1).get('grant_type'), 'refresh_token');
  assert.equal(f.tokenCalls().at(-1).get('client_secret'), 'holder-client-secret');
  const again = await f.connect({ connection_id: connection.id });
  assert.equal(again.url.searchParams.get('client_id'), 'holder-client-id', 'reconnecting keeps the app the connection was made with');
  const removed = await f.request('/v1/holdings/' + connection.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.json.service_revoked, true);
  const revoke = f.cloudflare.calls.find(call => call.url.endsWith('/revoke'));
  assert.equal(revoke.options.body.get('client_id'), 'holder-client-id');
});

test('自分のアプリを預けたものから消すと、その接続は渡さずに再接続待ちにする', async t => {
  const f = await own(t);
  await f.connect({ client: MINE });
  const connection = (await f.request('/v1/overview')).json.grants.find(item => item.method === 'authorized');
  const secret = f.app.grants.find(USER_A, MINE.client_secret);
  await f.request('/v1/holdings/' + secret.id, { method: 'DELETE', data: {} });
  f.expire(connection.id);
  const delivered = await f.deliver(connection);
  assert.equal(delivered.json.error.code, 'client_missing');
  assert.equal((await f.request('/v1/overview')).json.grants.find(item => item.id === connection.id).status, 'reconnect_required');
});

test('アプリの指定が正しくない場合や、自分のアプリを使えない接続では何も始めずに断る', async t => {
  const f = await own(t);
  for (const client of [{ client_id: MINE.client_id }, { ...MINE, extra: 'x' }, { ...MINE, client_secret: '' }, 'app']) {
    const started = await f.request('/v1/connections', { method: 'POST', data: { connector: 'cloudflare.oauth', client } });
    assert.equal(started.json.error.code, 'invalid_client', JSON.stringify(client));
  }
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { connector: 'cloudflare.oauth', client: { ...MINE, client_secret: 'nothing kept' } } })).json.error.code, 'client_missing');
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { connector: 'openrouter.oauth', client: MINE } })).json.error.code, 'client_unsupported');
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { connector: 'cloudflare.oauth' } })).status, 503, "without an app of the holder's, Foundation's unconfigured one is used");
});
