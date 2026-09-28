import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { DEFINITIONS, builtins } from '../src/catalog.mjs';
import { Services } from '../src/services.mjs';
import { Resources } from '../src/resources.mjs';
import { googleOauth } from '../src/adapters/google/index.mjs';
import { githubOauth } from '../src/adapters/github/index.mjs';
import { openrouterOauth } from '../src/adapters/openrouter/index.mjs';
import { FakeGitHub } from '../src/adapters/github/fixture.mjs';
import { FakeOpenRouter } from '../src/adapters/openrouter/fixture.mjs';
import { fixture, FakeGoogle, KEY, USER_A, modules, entry } from './helpers.mjs';
import { fail } from '../src/errors.mjs';

const value = (subject, state = 'opaque-0') => ({ subject, privateState: state, facts: { label: subject }, expiresAt: null,
  credentials: { environment: { EXAMPLE_KEY: 'usable-' + state } } });
// A service whose one scheme is the test's own.
const example = obtain => ({ definition: { version: 1, id: 'example', name: 'Example', auth_schemes: { oauth: { adapter: 'example' } } },
  schemes: { oauth: { kind: 'oauth', available: true, variables: ['EXAMPLE_KEY'], authorization: { begin() {}, complete() {} }, obtain } } });
function setup(t, obtain) {
  const store = new Store(':memory:', KEY), { credentials: connections } = modules(store, [example(obtain)]);
  t.after(() => store.close());
  const row = connections.save(USER_A, 'example', 'oauth', value('account-one'));
  return { store, connections, row };
}

test('カタログのサービスごとに設定を読み込み、Foundation側の用意と渡す変数を公開する', t => {
  const store = new Store(':memory:', KEY); t.after(() => store.close());
  const services = new Services(store, new Resources(store), builtins({ FOUNDATION_GOOGLE_CLIENT_ID: 'test-id', FOUNDATION_GOOGLE_CLIENT_SECRET: 'test-secret' }));
  assert.deepEqual(services.catalogIds(), DEFINITIONS.map(definition => definition.id));
  const catalog = services.catalogView(), scheme = (id, kind = 'oauth') => catalog.find(item => item.id === id).auth_schemes[kind];
  assert.equal(scheme('google').foundation_app, true);
  assert.equal(scheme('github').foundation_app, false);
  assert.equal(scheme('openrouter').can_revoke, false);
  assert.deepEqual(scheme('github').variables, ['GH_TOKEN', 'GITHUB_TOKEN']);
  assert.deepEqual(scheme('github', 'token').variables, ['GH_TOKEN', 'GITHUB_TOKEN']);
  assert.doesNotMatch(JSON.stringify(catalog), /test-secret|test-id/);
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
  assert.equal(connections.state(connections.held(USER_A, row.id)).private_state, 'opaque-1');
  const next = await connections.obtain(row);
  assert.deepEqual(seen, ['opaque-0', 'opaque-1']);
  assert.equal(next.values.get('EXAMPLE_KEY').content.toString(), 'usable-opaque-2');
});

test('異なる接続の取得を互いに待たせず個別に実行する', async t => {
  const releases = new Map();
  const { connections, row } = setup(t, ({ subject }) => new Promise(resolve => releases.set(subject, () => resolve(value(subject)))));
  const second = connections.save(USER_A, 'example', 'oauth', value('account-two'));
  const one = connections.obtain(row), two = connections.obtain(second);
  assert.deepEqual([...releases.keys()], ['account-one', 'account-two']);
  releases.get('account-two')(); await two;
  releases.get('account-one')(); await one;
});

test('出力を渡せない場合も回転済みの非公開状態を保存する', async t => {
  const { store, connections, row } = setup(t, async ({ subject }) => ({ ...value(subject, 'rotated'), credentials: { environment: { UNDECLARED: 'private' } } }));
  await assert.rejects(connections.obtain(row), { code: 'service_response' });
  assert.equal(connections.state(connections.held(USER_A, row.id)).private_state, 'rotated');
});

test('コネクターが本人確認の不一致を報告した接続を再接続待ちにする', async t => {
  const { store, connections, row } = setup(t, async () => fail(409, 'account_changed', 'Account changed'));
  await assert.rejects(connections.obtain(row), { code: 'account_changed' });
  const current = connections.held(USER_A, row.id);
  assert.equal(current.status, 'reconnect_required');
  assert.equal(connections.state(current).private_state, 'opaque-0');
});

test('コネクターが確認した識別情報を更新し、同じ接続IDで取得を続ける', async t => {
  const { connections, row } = setup(t, async () => value('updated-identity', 'renewed'));
  const result = await connections.obtain(row);
  const current = connections.held(USER_A, row.id);
  assert.equal(current.subject, 'updated-identity');
  assert.equal(current.id, row.id);
  assert.equal(result.values.get('EXAMPLE_KEY').content.toString(), 'usable-renewed');
});

test('取得中に再接続した場合は新しい認証状態を維持する', async t => {
  let release;
  const { store, connections, row } = setup(t, ({ subject }) => new Promise(resolve => release = () => resolve(value(subject, 'stale'))));
  const pending = connections.obtain(row);
  connections.save(USER_A, 'example', 'oauth', value(row.subject, 'reconnected'), { previous: row });
  release();
  await assert.rejects(pending, { code: 'credential_changed' });
  const current = connections.held(USER_A, row.id);
  assert.equal(current.status, 'usable');
  assert.equal(connections.state(current).private_state, 'reconnected');
});

test('各サービスの暗号化状態・接続ID・保存名を再起動後も利用する', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-connection-compat-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const makeServices = () => [entry('google', { oauth: googleOauth(new FakeGoogle()) }), entry('github', { oauth: githubOauth(new FakeGitHub()) }), entry('openrouter', { oauth: openrouterOauth(new FakeOpenRouter()) })];
  const database = join(directory, 'state.sqlite'), first = await fixture(t, { database, services: makeServices() });
  const specs = [ ['google', 'personal', 'GOOGLE_OAUTH_ACCESS_TOKEN'],
    ['github', 'octo', 'GH_TOKEN'], ['openrouter', 'personal', 'OPENROUTER_API_KEY'] ];
  const identities = [];
  for (const [service, code, output] of specs) {
    const start = await first.request('/v1/credentials', { method: 'POST', data: { service } });
    assert.equal(start.status, 200, start.text);
    const url = new URL(start.json.url), callback = new URL(url.searchParams.get('redirect_uri') || url.searchParams.get('callback_url'));
    callback.searchParams.set('state', url.searchParams.get('state') || callback.searchParams.get('state'));
    callback.searchParams.set('code', code);
    const completed = await first.request(callback.pathname + callback.search);
    assert.match(completed.headers.get('location'), /result=connected/);
    const row = first.app.credentials.forServices(USER_A).find(item => item.service === service);
    identities.push({ id: row.id, subject: row.subject, generation: row.generation, service, output });
  }
  const agent = await first.issueKey();
  await first.request('/v1/resources?kind=credential&name=a%2Faa%2Faaa', { method: 'PUT', raw: 'independent-snapshot' });
  await first.close();
  const second = await fixture(t, { database, services: makeServices() });
  for (const identity of identities) {
    const before = second.app.credentials.held(USER_A, identity.id);
    assert.equal(before.subject, identity.subject); assert.equal(before.generation, identity.generation);
    assert.ok(second.app.credentials.state(before).private_state);
    const delivered = await second.inject(identity, { token: agent.token, as: USER_A });
    assert.equal(delivered.status, 200, delivered.text);
    assert.ok(delivered.json.injection.environment[identity.output]);
    const state = second.app.credentials.state(second.app.credentials.held(USER_A, identity.id));
    assert.ok(state.private_state.access_token);
    assert.doesNotMatch(JSON.stringify(delivered.json), /refresh_token|private_state/, 'what renews the credential never leaves');
  }
  assert.equal((await second.read('credential', 'a/aa/aaa')).text, 'independent-snapshot');
});
