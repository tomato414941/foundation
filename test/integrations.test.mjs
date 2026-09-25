import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';

// A product (ai-simplicity) holds a Foundation account for each of its users. Its credential makes accounts and keys,
// hands a user to one request through a single-use link, and reads usage; it never reaches what an account holds.
async function setup(t) {
  const f = await fixture(t);
  const made = await f.request('/v1/apps', { method: 'POST', data: { name: 'ai-simplicity', return_url: 'https://simplicity.example.test/foundation' } });
  assert.equal(made.status, 201, made.text);
  const product = made.json.app.token;
  const call = (path, options = {}) => f.request('/v1' + path, { anonymous: true, token: product, ...options });
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
  assert.equal((await f.request('/v1/secrets?name=npm-token&secret=true', { method: 'PUT', anonymous: true, token: first.key.token, raw: 'tok-1', type: 'text/plain' })).status, 200);
  assert.deepEqual((await f.request('/v1/secrets', { anonymous: true, token: second.key.token })).json.secrets, []);
  assert.deepEqual((await f.request('/v1/state')).json.secrets, [], 'nor are they the owner\'s who registered the product');
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
  assert.equal((await f.request('/v1/keys/current', { anonymous: true, token: key.token })).status, 401);
  assert.equal((await f.request('/v1/keys/current', { anonymous: true, token: next.json.key.token })).status, 200);
  const ownKey = await f.issueKey();
  assert.equal((await call('/accounts/user-1/keys/' + ownKey.id, { method: 'DELETE', data: {} })).status, 404);
  assert.equal((await f.request('/v1/keys/current', { anonymous: true, token: ownKey.token })).status, 200);
  assert.equal((await call('/accounts/user-1/keys/' + next.json.key.id, { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/keys/current', { anonymous: true, token: next.json.key.token })).status, 401);
});

test('A request from such an account is opened on the product\'s page, and a single-use link reaches that request alone', async t => {
  const { f, call, account, ask, visitor } = await setup(t);
  const { key } = await account('user-1');
  const request = await ask(key), other = await ask(await (async () => (await account('user-2')).key)());
  assert.equal(request.verification_uri, 'https://simplicity.example.test/foundation?foundation_request=' + request.id);
  const made = await call('/request-links', { method: 'POST', data: { request_id: request.id } });
  assert.equal(made.status, 201, made.text);
  const url = new URL(made.json.url);
  assert.equal(url.pathname, '/requests/' + request.id);
  const link = new URLSearchParams(url.hash.slice(1)).get('link');
  assert.equal(url.search, '', 'the link travels in the fragment, never to a server log');
  const go = visitor();
  assert.equal((await go('/v1/requests/' + request.id)).status, 401, 'nothing before the link is spent');
  const claimed = await go('/v1/request-links/claim', { method: 'POST', data: { request_id: request.id, link } });
  assert.equal(claimed.status, 200, claimed.text);
  assert.match(claimed.cookie, /HttpOnly/); assert.match(claimed.cookie, new RegExp('Path=/v1/requests/' + request.id));
  assert.equal((await go('/v1/requests/' + request.id)).json.request.id, request.id);
  assert.equal((await go('/v1/state')).status, 401, 'the link reaches no other screen');
  assert.equal((await go('/v1/requests/' + other.id)).status, 401);
  const stored = await go('/v1/requests/' + request.id + '/done', { method: 'POST', data: { entries: [{ name: 'npm-api-token', content: 'npm_value' }] } });
  assert.equal(stored.status, 200, stored.text);
  assert.deepEqual((await go('/v1/requests/' + request.id)).json.request.result.names, ['npm-api-token']);
  const delivered = await f.request('/v1/deliveries', { method: 'POST', anonymous: true, token: key.token, data: { names: [{ name: 'npm-api-token', as: 'NPM_TOKEN' }] } });
  assert.equal(delivered.json.delivery.environment.NPM_TOKEN, 'npm_value');
  // Spent once; another visitor gets nowhere with it.
  assert.equal((await visitor()('/v1/request-links/claim', { method: 'POST', data: { request_id: request.id, link } })).status, 410);
});

test('A link is made only for the product\'s own accounts\' open store requests, and expires', async t => {
  const { f, call, account, ask, visitor } = await setup(t);
  const { key } = await account('user-1');
  const ownKey = await f.issueKey();
  const outside = await ask(ownKey);
  assert.equal((await call('/request-links', { method: 'POST', data: { request_id: outside.id } })).status, 404, 'not for an owner the product does not hold');
  const theirs = await ask(key);
  assert.equal((await call('/request-links', { method: 'POST', data: { request_id: theirs.id, external_id: 'user-2' } })).status, 404, 'not for another of its users');
  assert.equal((await call('/request-links', { method: 'POST', data: { request_id: theirs.id, external_id: 'user-1' } })).status, 201);
  const request = await ask(key);
  const made = await call('/request-links', { method: 'POST', data: { request_id: request.id } });
  const link = new URLSearchParams(new URL(made.json.url).hash.slice(1)).get('link');
  f.app.store.db.prepare('UPDATE request_links SET expires_at=0').run();
  assert.equal((await visitor()('/v1/request-links/claim', { method: 'POST', data: { request_id: request.id, link } })).status, 410);
  const connect = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: key.token, data: { connector: 'gmail.readonly', purpose: '確認' } });
  assert.equal((await call('/request-links', { method: 'POST', data: { request_id: connect.json.request.id } })).json.error.code, 'link_unsupported');
});

test('Removing an account takes what it holds with it; removing the product stops its credential but not its accounts', async t => {
  const { f, call, account, product } = await setup(t);
  const { key } = await account('user-1');
  await f.request('/v1/secrets?name=npm-token&secret=true', { method: 'PUT', anonymous: true, token: key.token, raw: 'tok', type: 'text/plain' });
  const kept = await account('user-2');
  assert.equal((await call('/accounts/user-1', { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/keys/current', { anonymous: true, token: key.token })).status, 401);
  assert.equal((await call('/accounts/user-1/usage')).status, 404);
  const listed = (await f.request('/v1/apps')).json.apps;
  assert.equal(listed.length, 1); assert.equal(listed[0].accounts, 1);
  assert.doesNotMatch(JSON.stringify(listed), /fdni_/);
  assert.equal((await f.request('/v1/apps/' + listed[0].id, { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/accounts/user-2', { anonymous: true, token: product })).status, 401);
  assert.equal((await f.request('/v1/keys/current', { anonymous: true, token: kept.key.token })).status, 200, 'the account and its key stay with the user');
});

// A product's webhook, played by a local HTTPS server with its own certificate, reached as a public host would be.
async function hook(t) {
  const { execFileSync } = await import('node:child_process');
  const { mkdtemp, readFile, rm } = await import('node:fs/promises');
  const { createServer } = await import('node:https');
  const { connect } = await import('node:tls');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = await mkdtemp(join(tmpdir(), 'foundation-hook-')); t.after(() => rm(dir, { recursive: true, force: true }));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key'), '-out', join(dir, 'cert'), '-days', '1',
    '-subj', '/CN=hook.example.test', '-addext', 'subjectAltName=DNS:hook.example.test'], { stdio: 'ignore' });
  const cert = await readFile(join(dir, 'cert')), received = [];
  const server = createServer({ key: await readFile(join(dir, 'key')), cert }, (req, res) => {
    const chunks = []; req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => { received.push({ signature: req.headers['foundation-signature'], body: Buffer.concat(chunks).toString('utf8') }); res.writeHead(200); res.end('ok'); });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); t.after(() => server.close());
  const outbound = { resolve: async host => { if (host !== 'hook.example.test') throw new Error('unknown'); return [{ address: '93.184.216.34', family: 4 }]; },
    createConnection: options => connect({ host: '127.0.0.1', port: server.address().port, servername: options.servername, ca: cert }), ca: cert, retryDelay: 50 };
  return { received, outbound };
}
const arrived = async (received, count) => { for (let i = 0; i < 100 && received.length < count; i++) await new Promise(resolve => setTimeout(resolve, 20)); return received; };

test('As with Stripe, a product gives a return page, a refresh page and a signed webhook, and the secrets are shown once', async t => {
  const { received, outbound } = await hook(t);
  const f = await fixture(t, { outbound });
  for (const bad of ['http://hook.example.test/x', 'https://127.0.0.1/x', 'https://hook.example.test:8443/x']) {
    const refused = await f.request('/v1/apps', { method: 'POST', data: { name: 'x', return_url: 'https://simplicity.example.test/foundation', webhook_url: bad } });
    assert.equal(refused.status, 400, bad);
  }
  const made = (await f.request('/v1/apps', { method: 'POST', data: { name: 'ai-simplicity', return_url: 'https://simplicity.example.test/foundation?from=foundation',
    refresh_url: 'https://simplicity.example.test/foundation/again', webhook_url: 'https://hook.example.test/foundation' } })).json.app;
  assert.match(made.webhook_secret, /^whsec_/);
  assert.doesNotMatch(JSON.stringify((await f.request('/v1/state')).json.apps), /whsec_|fdni_/);
  const call = (path, options = {}) => f.request('/v1' + path, { anonymous: true, token: made.token, ...options });
  await call('/accounts/user-1', { method: 'PUT', data: {} });
  const key = (await call('/accounts/user-1/keys', { method: 'POST', data: {} })).json.key;
  const ask = async (name = 'npm-token') => (await f.request('/v1/requests', { method: 'POST', anonymous: true, token: key.token, data: { store: { name, label: 'npm' }, purpose: 'p', steps: [] } })).json.request;
  const first = await ask();
  const back = (await f.request('/v1/request-links/' + first.id, { anonymous: true })).json.back;
  assert.equal(back.name, 'ai-simplicity');
  assert.equal(back.refresh_url, 'https://simplicity.example.test/foundation/again?foundation_request=' + first.id);
  assert.equal(new URL(back.return_url).searchParams.get('from'), 'foundation', 'the product\'s own query is kept');
  const own = await f.issueKey('own');
  const unheld = (await f.request('/v1/requests', { method: 'POST', anonymous: true, token: own.token, data: { store: { name: 'x', label: 'x' }, purpose: 'p' } })).json.request;
  assert.equal((await f.request('/v1/request-links/' + unheld.id, { anonymous: true })).status, 404, 'no way back for a request no product holds');
  // Done and cancelled: each is told to the product, signed with the secret it was given.
  const link = new URLSearchParams(new URL((await call('/request-links', { method: 'POST', data: { request_id: first.id } })).json.url).hash.slice(1)).get('link');
  const claimed = await fetch(f.base + '/v1/request-links/claim', { method: 'POST', headers: { 'content-type': 'application/json', origin: f.base }, body: JSON.stringify({ request_id: first.id, link }) });
  const cookie = claimed.headers.getSetCookie()[0].split(';')[0];
  assert.equal((await f.request('/v1/requests/' + first.id + '/done', { method: 'POST', anonymous: true, headers: { cookie }, data: { entries: [{ name: 'npm-token', content: 'value' }] } })).status, 200);
  // The first request's name is now taken, so the next asks for another.
  const second = await ask('npm-token-next');
  await f.request('/v1/requests/' + second.id, { method: 'DELETE', anonymous: true, token: key.token, data: {} });
  await arrived(received, 2);
  const events = received.map(item => ({ ...item, event: JSON.parse(item.body) }));
  assert.deepEqual(events.map(item => item.event.type).sort(), ['request.cancelled', 'request.done']);
  const { createHmac } = await import('node:crypto');
  for (const item of events) {
    const [, at, signature] = item.signature.match(/^t=(\d+),v1=([0-9a-f]{64})$/);
    assert.equal(signature, createHmac('sha256', made.webhook_secret).update(at + '.' + item.body).digest('hex'));
    assert.equal(item.event.account, 'user-1');
    assert.doesNotMatch(item.body, /value|fdn_/, 'what was kept never leaves in a notice');
  }
  assert.equal(events.find(item => item.event.type === 'request.done').event.data.request.id, first.id);
});
