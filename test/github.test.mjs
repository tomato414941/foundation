import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubClient } from '../src/services/github.mjs';
import { FakeGitHub } from './github-helper.mjs';
import { githubOauth, gmailReadonly, gmailMetadata } from '../src/adapters.mjs';
import { FakeGmail, fixture } from './helpers.mjs';

async function githubFixture(t, github = new FakeGitHub()) {
  const gmail = new FakeGmail(), f = await fixture(t, { gmail, adapters: [githubOauth(github), gmailReadonly(gmail), gmailMetadata(gmail)] });
  async function start(extra = {}) {
    const result = await f.request('/v1/connections', { method: 'POST', data: { connector: 'github.oauth', name: '', ...extra } });
    assert.equal(result.status, 200, result.text);
    return new URL(result.json.url);
  }
  const back = (url, code) => f.request(new URL(url.searchParams.get('redirect_uri')).pathname + '?state=' + url.searchParams.get('state') + '&code=' + code);
  const connections = async () => (await f.request('/v1/state')).json.connections.filter(item => item.connector === 'github.oauth');
  return { ...f, github, start, back, connections };
}

test('GitHub authorization asks for the repository scopes with state and PKCE', async t => {
  const f = await githubFixture(t), url = await f.start();
  assert.equal(url.origin + url.pathname, 'https://github.com/login/oauth/authorize');
  assert.equal(url.searchParams.get('client_id'), 'Iv1.fixture');
  assert.equal(url.searchParams.get('scope'), 'gist read:org repo workflow');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(url.searchParams.get('state') && url.searchParams.get('code_challenge'));
  assert.equal(url.searchParams.has('client_secret'), false);
});

test('A connected GitHub account is named by its login and delivered to an approved key as GH_TOKEN and GITHUB_TOKEN', async t => {
  const f = await githubFixture(t);
  const done = await f.back(await f.start(), 'octo');
  assert.match(done.headers.get('location'), /connection=connected/);
  const [connection] = await f.connections();
  assert.equal(connection.label, 'octo');
  assert.ok(connection.id);
  assert.deepEqual(connection.outputs, ['GH_TOKEN', 'GITHUB_TOKEN']);
  assert.doesNotMatch(JSON.stringify(await f.request('/v1/state')), /gho_/);
  const agent = await f.issueKey();
  const delivered = await f.deliver((await f.connections())[0], { token: agent.token, anonymous: true });
  assert.equal(delivered.status, 200, delivered.text);
  assert.deepEqual(delivered.json.delivery.environment, { GH_TOKEN: 'gho_octo', GITHUB_TOKEN: 'gho_octo' });
});

test('A grant without repository access is refused and nothing is registered', async t => {
  const f = await githubFixture(t);
  f.github.scopes = 'read:org';
  const done = await f.back(await f.start(), 'octo');
  assert.match(done.headers.get('location'), /connection=scope/);
  assert.deepEqual(await f.connections(), []);
});

test('A token revoked at GitHub stops delivery and asks the owner to register again', async t => {
  const f = await githubFixture(t);
  await f.back(await f.start(), 'octo');
  const agent = await f.issueKey();
  f.github.revoked.add('gho_octo');
  const refused = await f.deliver((await f.connections())[0], { token: agent.token, anonymous: true });
  assert.equal(refused.status, 409);
  assert.equal((await f.connections())[0].status, 'reconnect_required');
});

test('Registering again must use the same GitHub account', async t => {
  const f = await githubFixture(t);
  await f.back(await f.start(), 'octo');
  const [connection] = await f.connections();
  const other = await f.back(await f.start({ connection_id: connection.id }), 'other');
  assert.match(other.headers.get('location'), /connection=wrong_account/);
  const same = await f.back(await f.start({ connection_id: connection.id }), 'octo');
  assert.match(same.headers.get('location'), /connection=connected/);
  assert.equal((await f.connections()).length, 1);
});

test('Disconnecting revokes the grant at GitHub', async t => {
  const f = await githubFixture(t);
  await f.back(await f.start(), 'octo');
  const [connection] = await f.connections();
  const removed = await f.request('/v1/connections/' + encodeURIComponent(connection.id), { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.status, 200, removed.text);
  assert.ok(f.github.revoked.has('gho_octo'));
  assert.deepEqual(await f.connections(), []);
  assert.equal(removed.json.service_revoked, true);
});

test('Without a client ID and secret GitHub is offered as unavailable', async t => {
  const gmail = new FakeGmail(), f = await fixture(t, { gmail, adapters: [githubOauth(new GitHubClient()), gmailReadonly(gmail), gmailMetadata(gmail)] });
  const adapter = (await f.request('/v1/state')).json.connectors.find(item => item.id === 'github.oauth');
  assert.equal(adapter.available, false);
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { connector: 'github.oauth' } })).status, 503);
});
