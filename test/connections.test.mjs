import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Holdings } from '../src/holdings.mjs';
import { Connections } from '../src/connections.mjs';
import { Connectors } from '../src/connectors.mjs';
import { builtins } from '../src/connectors/index.mjs';
import { gmailReadonly } from '../src/connectors/gmail/index.mjs';
import { gcpOauth } from '../src/connectors/gcp/index.mjs';
import { githubOauth } from '../src/connectors/github/index.mjs';
import { openrouterOauth } from '../src/connectors/openrouter/index.mjs';
import { FakeGcp } from '../src/connectors/gcp/fixture.mjs';
import { FakeGitHub } from '../src/connectors/github/fixture.mjs';
import { FakeOpenRouter } from '../src/connectors/openrouter/fixture.mjs';
import { fixture, FakeGmail, KEY, USER_A } from './helpers.mjs';

const value = (subject, state = 'opaque-0') => ({ subject, privateState: state, facts: { label: subject }, expiresAt: null,
  credentials: { environment: { EXAMPLE_KEY: 'usable-' + state } } });
const example = obtain => ({ id: 'example.authorization', available: true, variables: ['EXAMPLE_KEY'],
  authorization: { kind: 'oauth', begin() {}, complete() {} }, obtain });
function setup(t, obtain) {
  const store = new Store(':memory:', KEY), connections = new Connections(store, new Connectors([example(obtain)]), new Holdings(store));
  t.after(() => store.close());
  const row = connections.save(USER_A, 'example.authorization', value('account-one'));
  return { store, connections, row };
}

test('各接続の設定を個別に読み込み、利用可否と出力を公開する', () => {
  const registry = new Connectors(builtins({ FOUNDATION_GCP_CLIENT_ID: 'test-id', FOUNDATION_GCP_CLIENT_SECRET: 'test-secret' }));
  assert.deepEqual(registry.ids(), ['github.oauth', 'openrouter.oauth', 'gcp.oauth', 'gmail.readonly', 'gmail.metadata', 'gmail.read-send', 'ebay.oauth', 'cloudflare.oauth']);
  const catalog = registry.ids().map(id => registry.describe(id));
  assert.equal(catalog.find(item => item.id === 'gcp.oauth').available, true);
  assert.equal(catalog.find(item => item.id === 'gmail.readonly').available, false);
  assert.equal(catalog.find(item => item.id === 'openrouter.oauth').can_revoke, false);
  assert.deepEqual(catalog.find(item => item.id === 'github.oauth').variables, ['GH_TOKEN', 'GITHUB_TOKEN']);
  assert.doesNotMatch(JSON.stringify(catalog), /test-secret|test-id/);
});

test('重複する接続IDや解釈できない出力宣言を起動時に検出する', () => {
  const connector = example(async ({ subject }) => value(subject));
  assert.throws(() => new Connectors([connector, connector]), /duplicate/);
  for (const variables of [['EXAMPLE_KEY', 'EXAMPLE_KEY'], ['not an environment variable']]) {
    assert.throws(() => new Connectors([{ ...connector, variables }]), /contract/);
  }
});

test('同じ接続の同時取得を一度にまとめ、次の取得に更新済みの非公開状態を渡す', async t => {
  let release, calls = 0;
  const seen = [];
  const { store, connections, row } = setup(t, async ({ subject, privateState }) => {
    seen.push(privateState); calls++;
    if (calls === 1) await new Promise(resolve => release = resolve);
    return value(subject, 'opaque-' + calls);
  });
  const one = connections.obtain(row), two = connections.obtain(row);
  assert.equal(calls, 1);
  release();
  const results = await Promise.all([one, two]);
  assert.deepEqual(results[0], results[1]);
  assert.equal(connections.state(connections.get(USER_A, row.id)).private_state, 'opaque-1');
  const next = await connections.obtain(row);
  assert.deepEqual(seen, ['opaque-0', 'opaque-1']);
  assert.equal(next.values.get('EXAMPLE_KEY').content.toString(), 'usable-opaque-2');
});

test('異なる接続の取得を互いに待たせず個別に実行する', async t => {
  const releases = new Map();
  const { connections, row } = setup(t, ({ subject }) => new Promise(resolve => releases.set(subject, () => resolve(value(subject)))));
  const second = connections.save(USER_A, 'example.authorization', value('account-two'));
  const one = connections.obtain(row), two = connections.obtain(second);
  assert.deepEqual([...releases.keys()], ['account-one', 'account-two']);
  releases.get('account-two')(); await two;
  releases.get('account-one')(); await one;
});

test('出力を渡せない場合も回転済みの非公開状態を保存する', async t => {
  const { store, connections, row } = setup(t, async ({ subject }) => ({ ...value(subject, 'rotated'), credentials: { environment: { UNDECLARED: 'private' } } }));
  await assert.rejects(connections.obtain(row), { code: 'service_response' });
  assert.equal(connections.state(connections.get(USER_A, row.id)).private_state, 'rotated');
});

test('別アカウントの結果を保存せず元の接続を再接続待ちにする', async t => {
  const { store, connections, row } = setup(t, async () => value('account-two', 'wrong-account'));
  await assert.rejects(connections.obtain(row), { code: 'account_changed' });
  const current = connections.get(USER_A, row.id);
  assert.equal(current.status, 'reconnect_required');
  assert.equal(connections.state(current).private_state, 'opaque-0');
});

test('取得中に再接続した場合は新しい認証状態を維持する', async t => {
  let release;
  const { store, connections, row } = setup(t, ({ subject }) => new Promise(resolve => release = () => resolve(value(subject, 'stale'))));
  const pending = connections.obtain(row);
  connections.save(USER_A, 'example.authorization', value(row.subject, 'reconnected'), { previous: row });
  release();
  await assert.rejects(pending, { code: 'connection_changed' });
  const current = connections.get(USER_A, row.id);
  assert.equal(current.status, 'connected');
  assert.equal(connections.state(current).private_state, 'reconnected');
});

test('既存の4サービスの暗号化状態・接続ID・保存名を再起動後も利用する', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-connection-compat-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const makeConnectors = () => [gmailReadonly(new FakeGmail()), gcpOauth(new FakeGcp()), githubOauth(new FakeGitHub()), openrouterOauth(new FakeOpenRouter())];
  const database = join(directory, 'state.sqlite'), first = await fixture(t, { database, connectors: makeConnectors() });
  const specs = [ ['gmail.readonly', 'personal-readonly', 'GOOGLE_OAUTH_ACCESS_TOKEN'], ['gcp.oauth', 'personal', 'CLOUDSDK_AUTH_ACCESS_TOKEN'],
    ['github.oauth', 'octo', 'GH_TOKEN'], ['openrouter.oauth', 'personal', 'OPENROUTER_API_KEY'] ];
  const identities = [];
  for (const [connector, code, output] of specs) {
    const start = await first.request('/v1/connections', { method: 'POST', data: { connector } });
    assert.equal(start.status, 200, start.text);
    const url = new URL(start.json.url), callback = new URL(url.searchParams.get('redirect_uri') || url.searchParams.get('callback_url'));
    callback.searchParams.set('state', url.searchParams.get('state') || callback.searchParams.get('state'));
    callback.searchParams.set('code', code);
    const completed = await first.request(callback.pathname + callback.search);
    assert.match(completed.headers.get('location'), /connection=connected/);
    const row = first.app.connections.list(USER_A).find(item => item.connector === connector), state = first.app.connections.state(row);
    identities.push({ id: row.id, subject: row.subject, generation: row.generation, connector, output });
  }
  const agent = await first.issueKey();
  await first.request('/v1/holdings?kind=secret&name=a%2Faa%2Faaa', { method: 'PUT', raw: 'independent-snapshot' });
  await first.close();
  const second = await fixture(t, { database, connectors: makeConnectors() });
  for (const identity of identities) {
    const before = second.app.connections.get(USER_A, identity.id);
    assert.equal(before.subject, identity.subject); assert.equal(before.generation, identity.generation);
    assert.ok(second.app.connections.state(before).private_state);
    const delivered = await second.deliver(identity, { token: agent.token, as: USER_A });
    assert.equal(delivered.status, 200, delivered.text);
    assert.ok(delivered.json.delivery.environment[identity.output]);
    const state = second.app.connections.state(second.app.connections.get(USER_A, identity.id));
    assert.ok(state.private_state.access_token);
    assert.doesNotMatch(JSON.stringify(delivered.json.facts), /"access_token":|refresh_token|gho_|sk-or-v1-/);
  }
  assert.equal((await second.read('secret', 'a/aa/aaa')).text, 'independent-snapshot');
});
