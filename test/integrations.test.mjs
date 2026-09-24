import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';

// A product (ai-simplicity) holds a Foundation account for each of its users. Its credential makes accounts and keys,
// hands a user to one request through a single-use link, and reads usage; it never reaches what an account holds.
async function setup(t) {
  const f = await fixture(t);
  const made = await f.request('/api/integrations', { method: 'POST', data: { name: 'ai-simplicity', return_url: 'https://simplicity.example.test/foundation' } });
  assert.equal(made.status, 201, made.text);
  const product = made.json.integration.token;
  const call = (path, options = {}) => f.request('/v1/integration' + path, { anonymous: true, token: product, ...options });
  const account = async external => {
    const ensured = await call('/accounts/' + external, { method: 'PUT', data: {} });
    assert.equal(ensured.status, 200, ensured.text);
    const key = await call('/accounts/' + external + '/keys', { method: 'POST', data: { name: 'ai-simplicity' } });
    assert.equal(key.status, 201, key.text);
    return { account: ensured.json.account, key: key.json.key };
  };
  const ask = async key => {
    const asked = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: key.token, data: { store: { name: 'npm-token', label: 'npm のトークン' }, purpose: '公開に使います', steps: ['トークンを作ります', 'ここに貼ります'] } });
    assert.equal(asked.status, 201, asked.text);
    return asked.json.request;
  };
  // A browser with no Foundation login: it carries only what the link leaves behind.
  const visitor = () => {
    let cookie = '';
    const go = async (path, options = {}) => {
      const response = await fetch(f.base + path, { method: options.method || 'GET', redirect: 'manual',
        headers: { ...(cookie ? { cookie } : {}), ...(options.data ? { 'content-type': 'application/json', origin: f.base } : {}) }, ...(options.data ? { body: JSON.stringify(options.data) } : {}) });
      const set = response.headers.getSetCookie().find(value => value.startsWith('fdn_link='));
      if (set) cookie = set.split(';')[0];
      const text = await response.text(); let json; try { json = JSON.parse(text); } catch {}
      return { status: response.status, json, text, cookie: set };
    };
    return go;
  };
  return { f, product, call, account, ask, visitor };
}

test('A product makes one account per user, and each account keeps to itself', async t => {
  const { f, call, account, product } = await setup(t);
  const first = await account('user-1'), second = await account('user-2');
  assert.notEqual(first.account.id, second.account.id);
  assert.notEqual(first.account.id, USER_A);
  assert.equal((await call('/accounts/user-1', { method: 'PUT', data: {} })).json.account.id, first.account.id, 'the same user is the same account');
  assert.equal((await f.request('/v1/secrets/npm-token?secret=true', { method: 'PUT', anonymous: true, token: first.key.token, raw: 'tok-1', type: 'text/plain' })).status, 200);
  assert.deepEqual((await f.request('/v1/secrets', { anonymous: true, token: second.key.token })).json.secrets, []);
  assert.deepEqual((await f.request('/api/state')).json.secrets, [], 'nor are they the owner\'s who registered the product');
  // The product's own credential reaches no account's contents.
  assert.equal((await f.request('/v1/secrets', { anonymous: true, token: product })).status, 401);
  const usage = await call('/accounts/user-1/usage');
  assert.equal(usage.json.usage.secrets.count, 1);
  assert.equal((await call('/accounts/nobody/usage')).status, 404);
  assert.equal((await call('/accounts/bad id', { method: 'PUT', data: {} })).json.error.code, 'invalid_external_id');
});

test('Replacing a key revokes the one it replaces, and a product revokes only its own accounts\' keys', async t => {
  const { f, call, account } = await setup(t);
  const { key } = await account('user-1');
  const next = await call('/accounts/user-1/keys', { method: 'POST', data: { name: 'conversation 2', replaces: key.id } });
  assert.equal(next.status, 201, next.text);
  assert.equal((await f.request('/v1/me', { anonymous: true, token: key.token })).status, 401);
  assert.equal((await f.request('/v1/me', { anonymous: true, token: next.json.key.token })).status, 200);
  const ownKey = await f.issueKey();
  assert.equal((await call('/accounts/user-1/keys/' + ownKey.id, { method: 'DELETE', data: {} })).status, 404);
  assert.equal((await f.request('/v1/me', { anonymous: true, token: ownKey.token })).status, 200);
  assert.equal((await call('/accounts/user-1/keys/' + next.json.key.id, { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/me', { anonymous: true, token: next.json.key.token })).status, 401);
});

test('A request from such an account is opened on the product\'s page, and a single-use link reaches that request alone', async t => {
  const { f, call, account, ask, visitor } = await setup(t);
  const { key } = await account('user-1');
  const request = await ask(key), other = await ask(await (async () => (await account('user-2')).key)());
  assert.equal(request.verification_uri, 'https://simplicity.example.test/foundation?foundation_request=' + request.id);
  const made = await call('/links', { method: 'POST', data: { request_id: request.id } });
  assert.equal(made.status, 201, made.text);
  const url = new URL(made.json.url);
  assert.equal(url.pathname, '/requests/' + request.id);
  const link = new URLSearchParams(url.hash.slice(1)).get('link');
  assert.equal(url.search, '', 'the link travels in the fragment, never to a server log');
  const go = visitor();
  assert.equal((await go('/api/requests/' + request.id)).status, 401, 'nothing before the link is spent');
  const claimed = await go('/api/request-links', { method: 'POST', data: { request_id: request.id, link } });
  assert.equal(claimed.status, 200, claimed.text);
  assert.match(claimed.cookie, /HttpOnly/); assert.match(claimed.cookie, new RegExp('Path=/api/requests/' + request.id));
  assert.equal((await go('/api/requests/' + request.id)).json.request.id, request.id);
  assert.equal((await go('/api/state')).status, 401, 'the link reaches no other screen');
  assert.equal((await go('/api/requests/' + other.id)).status, 401);
  const stored = await go('/api/requests/' + request.id + '/store', { method: 'POST', data: { contents: { 'npm-token': 'npm_value' } } });
  assert.equal(stored.status, 200, stored.text);
  const delivered = await f.request('/v1/deliver', { method: 'POST', anonymous: true, token: key.token, data: { names: [{ name: 'npm-token', as: 'NPM_TOKEN' }] } });
  assert.equal(delivered.json.delivery.environment.NPM_TOKEN, 'npm_value');
  // Spent once; another visitor gets nowhere with it.
  assert.equal((await visitor()('/api/request-links', { method: 'POST', data: { request_id: request.id, link } })).status, 410);
});

test('A link is made only for the product\'s own accounts\' open store requests, and expires', async t => {
  const { f, call, account, ask, visitor } = await setup(t);
  const { key } = await account('user-1');
  const ownKey = await f.issueKey();
  const outside = await ask(ownKey);
  assert.equal((await call('/links', { method: 'POST', data: { request_id: outside.id } })).status, 404, 'not for an owner the product does not hold');
  const request = await ask(key);
  const made = await call('/links', { method: 'POST', data: { request_id: request.id } });
  const link = new URLSearchParams(new URL(made.json.url).hash.slice(1)).get('link');
  f.app.store.db.prepare('UPDATE request_links SET expires_at=0').run();
  assert.equal((await visitor()('/api/request-links', { method: 'POST', data: { request_id: request.id, link } })).status, 410);
  const connect = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: key.token, data: { adapter: 'gmail.readonly', purpose: '確認' } });
  assert.equal((await call('/links', { method: 'POST', data: { request_id: connect.json.request.id } })).json.error.code, 'link_unsupported');
});

test('Removing an account takes what it holds with it; removing the product stops its credential but not its accounts', async t => {
  const { f, call, account, product } = await setup(t);
  const { key } = await account('user-1');
  await f.request('/v1/secrets/npm-token?secret=true', { method: 'PUT', anonymous: true, token: key.token, raw: 'tok', type: 'text/plain' });
  const kept = await account('user-2');
  assert.equal((await call('/accounts/user-1', { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/me', { anonymous: true, token: key.token })).status, 401);
  assert.equal((await call('/accounts/user-1/usage')).status, 404);
  const listed = (await f.request('/api/integrations')).json.integrations;
  assert.equal(listed.length, 1); assert.equal(listed[0].accounts, 1);
  assert.doesNotMatch(JSON.stringify(listed), /fdni_/);
  assert.equal((await f.request('/api/integrations/' + listed[0].id, { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/integration/accounts/user-2', { anonymous: true, token: product })).status, 401);
  assert.equal((await f.request('/v1/me', { anonymous: true, token: kept.key.token })).status, 200, 'the account and its key stay with the user');
});
