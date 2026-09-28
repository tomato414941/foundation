import test from 'node:test';
import assert from 'node:assert/strict';
import { serviceClient, configuration } from './index.mjs';
import { FakeSlack, definitionOf } from './fixture.mjs';
import { fixture, USER_A } from '../../../test/helpers.mjs';

const ASKED = ['channels:read', 'chat:write'];

async function slackFixture(t, slack = new FakeSlack()) {
  const f = await fixture(t, { connectors: [slack.connector()] });
  async function start(input = {}) {
    const result = await f.request('/v1/connections', { method: 'POST', data: { connector: 'slack.oauth', ...(input.request_id ? {} : { scopes: ASKED }), ...input } });
    assert.equal(result.status, 200, result.text);
    return new URL(result.json.url);
  }
  const connections = async () => (await f.request('/v1/overview')).json.grants;
  async function connect(code = 'personal', input = {}) {
    const ids = new Set((await connections()).map(item => item.id));
    const done = await f.callback(await start(input), code);
    assert.match(done.headers.get('location'), /connection=connected/, done.headers.get('location'));
    return (await connections()).find(item => input.connection_id ? item.id === input.connection_id : !ids.has(item.id));
  }
  const secret = connection => f.app.grants.state(f.app.grants.held(USER_A, connection.id)).private_state;
  return { ...f, slack, start, connect, connections, secret };
}

test('Slackの設定を読み込み、未設定なら運営のアプリなしとして案内する', async t => {
  assert.deepEqual(configuration(definitionOf('slack'), { FOUNDATION_SLACK_CLIENT_ID: 'id', FOUNDATION_SLACK_CLIENT_SECRET: 'secret' }), { clientId: 'id', clientSecret: 'secret' });
  for (const config of [{ clientId: 'id' }, { clientSecret: 'secret' }]) assert.throws(() => serviceClient(definitionOf('slack'), config), /Both Foundation Slack/);
  const f = await slackFixture(t, new FakeSlack({ configured: false }));
  const listed = (await f.request('/v1/connectors')).json.connectors[0];
  assert.equal(listed.available, false);
  assert.equal(listed.apps.foundation, false);
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { connector: 'slack.oauth' } })).status, 503);
});

test('頼まれたBotの権限をカンマ区切りでSlackに求め、ワークスペースごとの接続として保存する', async t => {
  const f = await slackFixture(t), url = await f.start();
  assert.equal(url.origin + url.pathname, 'https://slack.com/oauth/v2/authorize');
  assert.equal(url.searchParams.get('client_id'), 'test-slack-client');
  assert.equal(url.searchParams.get('scope'), 'channels:read,chat:write');
  assert.equal(url.searchParams.get('redirect_uri'), f.base + '/oauth/slack.oauth/callback');
  assert.match((await f.callback(url, 'personal')).headers.get('location'), /connection=connected/);
  const exchange = new URLSearchParams(f.slack.calls.find(call => call.url.endsWith('/oauth.v2.access')).options.body);
  assert.equal(exchange.get('client_secret'), 'test-slack-secret');
  assert.equal(exchange.get('code'), 'personal');
  const [connection] = await f.connections();
  assert.equal(connection.label, '個人のワークスペース');
  assert.equal(connection.facts.account, 'T0PERSONAL');
  assert.deepEqual(connection.facts.scopes, ASKED);
  assert.deepEqual(connection.facts.requested_scopes, ASKED);
  assert.deepEqual(connection.facts.missing_scopes, []);
  assert.equal(connection.facts.expiry_known, false);
  const delivery = await f.deliver(connection);
  assert.equal(delivery.status, 200, delivery.text);
  assert.deepEqual(delivery.json.delivery.environment, { SLACK_BOT_TOKEN: 'xoxb-personal-1-0', SLACK_TEAM_ID: 'T0PERSONAL' });
  assert.doesNotMatch(JSON.stringify(await f.connections()), /xoxb-|test-slack-secret/);
  const work = await f.connect('work');
  assert.notEqual(work.id, connection.id);
  assert.equal(work.label, '仕事のワークスペース');
});

test('Slackが許可しなかった権限を不足として報告する', async t => {
  const f = await slackFixture(t);
  f.slack.tokenHandler = () => ({ ok: true, access_token: 'xoxb-personal-x', scope: 'channels:read', team: { id: 'T0PERSONAL' } });
  const connection = await f.connect();
  assert.deepEqual(connection.facts.missing_scopes, ['chat:write']);
});

test('ローテーションするトークンは期限前に更新し、しないトークンは取り消されるまでそのまま渡す', async t => {
  const f = await slackFixture(t);
  f.slack.rotating = true;
  const connection = await f.connect();
  assert.equal(connection.facts.expiry_known, true);
  f.expire(connection.id);
  const delivery = await f.deliver(connection);
  assert.equal(delivery.status, 200, delivery.text);
  assert.equal(delivery.json.delivery.environment.SLACK_BOT_TOKEN, 'xoxb-personal-1-1');
  assert.ok(Number(delivery.json.delivery.environment.SLACK_TOKEN_EXPIRES_AT) > Date.now());
  const refresh = new URLSearchParams(f.slack.calls.filter(call => call.url.endsWith('/oauth.v2.access')).at(-1).options.body);
  assert.equal(refresh.get('grant_type'), 'refresh_token');
  assert.equal(refresh.get('refresh_token'), 'xoxe-refresh-personal-1-0');
  assert.deepEqual(f.secret(connection).scopes, ASKED, 'scopes carry over when a refresh does not name them');
  f.slack.rotating = false;
  const lasting = await f.connect('work');
  await f.deliver(lasting); await f.deliver(lasting);
  assert.equal(f.slack.refreshes, 1);
});

test('失効した更新トークンでは再接続を案内する', async t => {
  const f = await slackFixture(t);
  f.slack.rotating = true;
  const connection = await f.connect();
  f.slack.revoked.add('xoxe-refresh-personal-1-0');
  f.expire(connection.id);
  const refused = await f.deliver(connection);
  assert.equal(refused.status, 409);
  assert.equal((await f.connections())[0].status, 'reconnect_required');
});

test('別のワークスペースでつなぎ直そうとすると断り、同じワークスペースならIDを保ってつなぎ直す', async t => {
  const f = await slackFixture(t), connection = await f.connect();
  const other = await f.callback(await f.start({ connection_id: connection.id }), 'work');
  assert.match(other.headers.get('location'), /connection=wrong_account/);
  const again = await f.connect('personal', { connection_id: connection.id });
  assert.equal(again.id, connection.id);
});

test('接続解除時にSlackのトークンを取り消し、取り消しに失敗しても接続は外す', async t => {
  const f = await slackFixture(t), connection = await f.connect();
  const removed = await f.request('/v1/holdings/' + connection.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.json.service_revoked, true);
  assert.ok(f.slack.revoked.has('xoxb-personal-1-0'));
  const second = await f.connect('work');
  f.slack.revokeHandler = () => ({ ok: false, error: 'fatal_error' });
  const failed = await f.request('/v1/holdings/' + second.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(failed.status, 200, failed.text);
  assert.equal(failed.json.service_revoked, false);
  assert.deepEqual(await f.connections(), []);
});

test('Slackの不正な応答とクライアント認証の失敗を安全なエラーとして返す', async t => {
  const f = await slackFixture(t);
  for (const answer of [{ ok: true, access_token: 'has\nnewline' }, '<html>', { ok: false, error: 'bad_client_secret' }]) {
    f.slack.tokenHandler = () => answer;
    const done = await f.callback(await f.start(), 'personal');
    assert.match(done.headers.get('location'), /connection=failed/);
  }
  assert.deepEqual(await f.connections(), []);
});

test('利用者自身のSlackアプリで接続し、そのアプリのクライアントで交換する', async t => {
  const f = await slackFixture(t, new FakeSlack({ configured: false }));
  const app = (await f.request('/v1/holdings?kind=app&name=' + encodeURIComponent('自分のBot'), { method: 'PUT', data: { connector: 'slack.oauth', client_id: 'own-id', client_secret: 'own-secret' } })).json.holding;
  const connection = await f.connect('personal', { app: app.id });
  assert.deepEqual(connection.app, { id: app.id, name: '自分のBot', foundation: false });
  const exchange = new URLSearchParams(f.slack.calls.find(call => call.url.endsWith('/oauth.v2.access')).options.body);
  assert.equal(exchange.get('client_id'), 'own-id');
  assert.equal(exchange.get('client_secret'), 'own-secret');
});
