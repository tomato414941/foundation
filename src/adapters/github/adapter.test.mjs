import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubClient } from './client.mjs';
import { FakeGitHub } from './fixture.mjs';
import { githubOauth } from './index.mjs';
import { googleOauth } from '../google/index.mjs';
import { FakeGoogle, fixture, entry } from '../../../test/helpers.mjs';

async function githubFixture(t, github = new FakeGitHub()) {
  const google = new FakeGoogle(), f = await fixture(t, { google, services: [entry('github', { oauth: githubOauth(github) }), entry('google', { oauth: googleOauth(google) })] });
  async function start(extra = {}) {
    const result = await f.request('/v1/connections', { method: 'POST', data: { service: 'github', name: '', ...extra } });
    assert.equal(result.status, 200, result.text);
    return new URL(result.json.url);
  }
  const back = (url, code) => f.request(new URL(url.searchParams.get('redirect_uri')).pathname + '?state=' + url.searchParams.get('state') + '&code=' + code);
  const connections = async () => (await f.request('/v1/principals/me/resources?kind=connection')).json.resources.filter(item => item.service?.id === 'github');
  return { ...f, github, start, back, connections };
}

test('GitHubには、頼まれた権限だけをstateとPKCE付きで要求する', async t => {
  const f = await githubFixture(t), url = await f.start({ scopes: ['workflow', 'repo'] });
  assert.equal(url.origin + url.pathname, 'https://github.com/login/oauth/authorize');
  assert.equal(url.searchParams.get('client_id'), 'Iv1.fixture');
  assert.equal(url.searchParams.get('scope'), 'repo workflow');
  assert.equal((await f.start()).searchParams.get('scope'), '');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(url.searchParams.get('state') && url.searchParams.get('code_challenge'));
  assert.equal(url.searchParams.has('client_secret'), false);
});

test('A connected GitHub account is named by its login and delivered to an approved key as GH_TOKEN and GITHUB_TOKEN', async t => {
  const f = await githubFixture(t);
  const done = await f.back(await f.start(), 'octo');
  assert.match(done.headers.get('location'), /result=connected/);
  const [connection] = await f.connections();
  assert.equal(connection.label, 'octo');
  assert.ok(connection.id);
  assert.deepEqual(connection.variables, ['GH_TOKEN', 'GITHUB_TOKEN']);
  assert.doesNotMatch(await f.visible(), /gho_/);
  const agent = await f.issueKey();
  const delivered = await f.inject((await f.connections())[0], { token: agent.token, anonymous: true });
  assert.equal(delivered.status, 200, delivered.text);
  assert.deepEqual(delivered.json.injection.environment, { GH_TOKEN: 'gho_octo', GITHUB_TOKEN: 'gho_octo' });
});

test('頼んだGitHub権限に対する不足と追加を接続一覧で確認し、認証情報を取得する', async t => {
  const f = await githubFixture(t);
  f.github.scopes = 'read:org, admin:org';
  const done = await f.back(await f.start({ scopes: ['gist', 'read:org', 'repo', 'workflow'] }), 'octo');
  assert.match(done.headers.get('location'), /result=connected/);
  const agent = await f.issueKey(), [connection] = await f.connections();
  const result = await f.inject(connection, { token: agent.token });
  assert.equal(result.status, 200, result.text);
  const facts = await f.connectionFacts(connection, { token: agent.token });
  assert.deepEqual(facts.missing_scopes, ['gist', 'repo', 'workflow']);
  assert.deepEqual(facts.additional_scopes, ['admin:org']);
  assert.equal(result.json.injection.environment.GH_TOKEN, 'gho_octo');
});

test('A token revoked at GitHub stops delivery and asks the owner to register again', async t => {
  const f = await githubFixture(t);
  await f.back(await f.start(), 'octo');
  const agent = await f.issueKey();
  f.github.revoked.add('gho_octo');
  const refused = await f.inject((await f.connections())[0], { token: agent.token, anonymous: true });
  assert.equal(refused.status, 409);
  assert.equal((await f.connections())[0].status, 'reconnect_required');
});

test('Registering again must use the same GitHub account', async t => {
  const f = await githubFixture(t);
  await f.back(await f.start(), 'octo');
  const [connection] = await f.connections();
  const other = await f.back(await f.start({ connection_id: connection.id }), 'other');
  assert.match(other.headers.get('location'), /result=wrong_account/);
  const same = await f.back(await f.start({ connection_id: connection.id }), 'octo');
  assert.match(same.headers.get('location'), /result=connected/);
  assert.equal((await f.connections()).length, 1);
});

test('Disconnecting revokes the grant at GitHub', async t => {
  const f = await githubFixture(t);
  await f.back(await f.start(), 'octo');
  const [connection] = await f.connections();
  const removed = await f.request('/v1/resources/' + encodeURIComponent(connection.id), { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.status, 200, removed.text);
  assert.ok(f.github.revoked.has('gho_octo'));
  assert.deepEqual(await f.connections(), []);
  assert.equal(removed.json.service_revoked, true);
});

test('Without a client ID and secret GitHub is offered as unavailable', async t => {
  const google = new FakeGoogle(), f = await fixture(t, { google, services: [entry('github', { oauth: githubOauth(new GitHubClient()) }), entry('google', { oauth: googleOauth(google) })] });
  const scheme = (await f.request('/v1/services')).json.services.find(item => item.id === 'github').auth_schemes.oauth;
  assert.equal(scheme.available, false);
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { service: 'github' } })).status, 503);
});
