import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';

// An app is a principal its developer made and gave settings and a key. With that key it makes a principal for
// each of its own users (calling them by names of its own), issues them keys, hands one of them to one request
// through a single-use link, and reads what they use. It reaches nothing they hold.
async function setup(t) {
  const f = await fixture(t);
  const made = await f.request('/v1/principals', { method: 'POST', data: { name: 'ai-simplicity' } });
  assert.equal(made.status, 201, made.text);
  const app = made.json.principal;
  assert.equal((await f.request('/v1/principals/' + app.id + '/settings', { method: 'PUT', data: { return_url: 'https://simplicity.example.test/foundation' } })).status, 200);
  const issued = await f.request('/v1/principals/' + app.id + '/credentials', { method: 'POST', data: { kind: 'key' } });
  assert.equal(issued.status, 201, issued.text);
  const product = issued.json.token;
  const call = (path, options = {}) => f.request('/v1' + path, { anonymous: true, token: product, ...options });
  // A user of the app: a principal the app makes and calls by the user's own id, with a key of the user's own.
  const account = async external => {
    const ensured = await call('/principals', { method: 'POST', data: { alias: external } });
    assert.equal(ensured.status, 201, ensured.text);
    const key = await call('/principals/' + ensured.json.principal.id + '/credentials', { method: 'POST', data: { kind: 'key' } });
    assert.equal(key.status, 201, key.text);
    return { account: ensured.json.principal, key: { id: key.json.credential.id, token: key.json.token } };
  };
  const ask = async key => {
    const asked = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: key.token, data: { store: { name: 'npm-token', label: 'npm のトークン' }, purpose: '公開に使います', steps: ['トークンを作る'] } });
    assert.equal(asked.status, 201, asked.text);
    return asked.json.request;
  };
  const link = (account, requestId) => call('/principals/' + account.id + '/credentials', { method: 'POST', data: { kind: 'link', request_id: requestId } });
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
  return { f, app, product, call, account, ask, link, visitor };
}

test('An app makes one principal per user, and each keeps to itself', async t => {
  const { f, call, account, product } = await setup(t);
  const first = await account('user-1'), second = await account('user-2');
  assert.notEqual(first.account.id, second.account.id);
  assert.notEqual(first.account.id, USER_A);
  assert.equal((await call('/principals', { method: 'POST', data: { alias: 'user-1' } })).json.principal.id, first.account.id, 'the same user is the same principal');
  assert.equal((await f.request('/v1/secrets?name=npm-token', { method: 'PUT', anonymous: true, token: first.key.token, raw: 'tok-1', type: 'text/plain' })).status, 200);
  assert.deepEqual((await f.request('/v1/secrets', { anonymous: true, token: second.key.token })).json.secrets, []);
  assert.deepEqual((await f.request('/v1/overview')).json.secrets, [], 'nor are they the developer\'s who made the app');
  // The app's own key reaches none of its users' contents: the app acts for nobody.
  assert.deepEqual((await f.request('/v1/secrets', { anonymous: true, token: product })).json.secrets, []);
  assert.equal((await f.request('/v1/secrets?as=' + first.account.id, { anonymous: true, token: product })).status, 403);
  const usage = await call('/usage?as=' + first.account.id);
  assert.equal(usage.status, 200, usage.text); assert.equal(usage.json.secrets.count, 1);
  assert.equal((await call('/usage?as=' + USER_A)).status, 403, 'and not the developer\'s either');
  assert.equal((await call('/principals', { method: 'POST', data: { alias: '' } })).status, 400);
  const listed = (await call('/principals')).json.principals;
  assert.deepEqual(listed.map(item => item.alias).sort(), ['user-1', 'user-2']);
});

test('Replacing a key revokes the one it replaces, and an app revokes only its own users\' keys', async t => {
  const { f, call, account } = await setup(t);
  const { account: user, key } = await account('user-1');
  const next = await call('/principals/' + user.id + '/credentials', { method: 'POST', data: { kind: 'key', replaces: key.id } });
  assert.equal(next.status, 201, next.text);
  assert.equal((await f.request('/v1/principals/me', { anonymous: true, token: key.token })).status, 401);
  assert.equal((await f.request('/v1/principals/me', { anonymous: true, token: next.json.token })).status, 200);
  const ownKey = await f.issueKey();
  assert.equal((await call('/principals/' + ownKey.id + '/credentials/' + ownKey.credential_id, { method: 'DELETE', data: {} })).status, 403);
  assert.equal((await f.request('/v1/principals/me', { anonymous: true, token: ownKey.token })).status, 200);
  assert.equal((await call('/principals/' + user.id + '/credentials/' + next.json.credential.id, { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/principals/me', { anonymous: true, token: next.json.token })).status, 401);
});

test('A request from such a user is opened on the app\'s page, and a single-use link reaches that request alone', async t => {
  const { f, account, ask, link, visitor } = await setup(t);
  const { account: user, key } = await account('user-1');
  const request = await ask(key), other = await ask(await (async () => (await account('user-2')).key)());
  assert.equal(request.verification_uri, 'https://simplicity.example.test/foundation?foundation_request=' + request.id);
  const made = await link(user, request.id);
  assert.equal(made.status, 201, made.text);
  const url = new URL(made.json.url);
  assert.equal(url.pathname, '/requests/' + request.id);
  const token = new URLSearchParams(url.hash.slice(1)).get('link');
  assert.equal(url.search, '', 'the link travels in the fragment, never to a server log');
  const go = visitor();
  assert.equal((await go('/v1/requests/' + request.id)).status, 401, 'nothing before the link is spent');
  const claimed = await go('/v1/credentials/exchange', { method: 'POST', data: { request_id: request.id, link: token } });
  assert.equal(claimed.status, 200, claimed.text);
  assert.match(claimed.cookie, /HttpOnly/); assert.match(claimed.cookie, new RegExp('Path=/v1/requests/' + request.id));
  assert.equal((await go('/v1/requests/' + request.id)).json.request.id, request.id);
  assert.equal((await go('/v1/overview')).status, 401, 'the link reaches no other screen');
  assert.equal((await go('/v1/requests/' + other.id)).status, 401);
  const stored = await go('/v1/requests/' + request.id + '/done', { method: 'POST', data: { entries: [{ name: 'npm-api-token', content: 'npm_value' }] } });
  assert.equal(stored.status, 200, stored.text);
  assert.deepEqual((await go('/v1/requests/' + request.id)).json.request.result.names, ['npm-api-token']);
  const delivered = await f.request('/v1/deliveries', { method: 'POST', anonymous: true, token: key.token, data: { names: [{ name: 'npm-api-token', as: 'NPM_TOKEN' }] } });
  assert.equal(delivered.json.delivery.environment.NPM_TOKEN, 'npm_value');
  // Spent once; another visitor gets nowhere with it.
  assert.equal((await visitor()('/v1/credentials/exchange', { method: 'POST', data: { request_id: request.id, link: token } })).status, 410);
});

test('A link is made only for the app\'s own users\' open store requests, and expires', async t => {
  const { f, call, account, ask, link, visitor } = await setup(t);
  const { account: user, key } = await account('user-1');
  const ownKey = await f.issueKey();
  const outside = await ask(ownKey);
  assert.equal((await call('/principals/' + USER_A + '/credentials', { method: 'POST', data: { kind: 'link', request_id: outside.id } })).status, 403, 'not for a principal the app does not own');
  const theirs = await ask(key);
  const another = await account('user-2');
  assert.equal((await link(another.account, theirs.id)).status, 404, 'not for another of its users');
  assert.equal((await link(user, theirs.id)).status, 201);
  const request = await ask(key);
  const made = await link(user, request.id);
  const token = new URLSearchParams(new URL(made.json.url).hash.slice(1)).get('link');
  f.app.store.db.prepare("UPDATE credentials SET expires_at=0 WHERE kind='link'").run();
  assert.equal((await visitor()('/v1/credentials/exchange', { method: 'POST', data: { request_id: request.id, link: token } })).status, 410);
  const connect = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: key.token, data: { connector: 'gmail.readonly', purpose: '確認' } });
  assert.equal((await link(user, connect.json.request.id)).json.error.code, 'link_unsupported');
});

test('Removing a user takes what they hold with it; removing the app stops its key but not its users', async t => {
  const { f, app, call, account, product } = await setup(t);
  const { account: user, key } = await account('user-1');
  await f.request('/v1/secrets?name=npm-token', { method: 'PUT', anonymous: true, token: key.token, raw: 'tok', type: 'text/plain' });
  const kept = await account('user-2');
  assert.equal((await call('/principals/' + user.id, { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/principals/me', { anonymous: true, token: key.token })).status, 401);
  assert.equal((await call('/usage?as=' + user.id)).status, 403);
  const listed = (await f.request('/v1/principals')).json.principals;
  assert.equal(listed.length, 1); assert.equal(listed[0].id, app.id);
  assert.doesNotMatch(JSON.stringify(listed), /fdn_/);
  assert.equal((await f.request('/v1/principals/' + app.id, { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/principals/me', { anonymous: true, token: product })).status, 401);
  assert.equal((await f.request('/v1/principals/me', { anonymous: true, token: kept.key.token })).status, 200, 'the user and their key stay with the user');
});

// An app's webhook, played by a local HTTPS server with its own certificate, reached as a public host would be.
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

test('As with Stripe, an app gives a return page, a refresh page and a signed webhook, and the secrets are shown once', async t => {
  const { received, outbound } = await hook(t);
  const f = await fixture(t, { outbound });
  const app = (await f.request('/v1/principals', { method: 'POST', data: { name: 'ai-simplicity' } })).json.principal;
  const settingsOf = data => f.request('/v1/principals/' + app.id + '/settings', { method: 'PUT', data });
  for (const bad of ['http://hook.example.test/x', 'https://127.0.0.1/x', 'https://hook.example.test:8443/x']) {
    assert.equal((await settingsOf({ return_url: 'https://simplicity.example.test/foundation', webhook_url: bad })).status, 400, bad);
  }
  const settings = (await settingsOf({ return_url: 'https://simplicity.example.test/foundation?from=foundation',
    refresh_url: 'https://simplicity.example.test/foundation/again', webhook_url: 'https://hook.example.test/foundation' })).json.settings;
  assert.match(settings.webhook_secret, /^whsec_/);
  assert.doesNotMatch(JSON.stringify((await f.request('/v1/overview')).json), /whsec_|fdn_/);
  const product = (await f.request('/v1/principals/' + app.id + '/credentials', { method: 'POST', data: { kind: 'key' } })).json.token;
  const call = (path, options = {}) => f.request('/v1' + path, { anonymous: true, token: product, ...options });
  const user = (await call('/principals', { method: 'POST', data: { alias: 'user-1' } })).json.principal;
  const key = (await call('/principals/' + user.id + '/credentials', { method: 'POST', data: { kind: 'key' } })).json;
  const ask = async (name = 'npm-token') => (await f.request('/v1/requests', { method: 'POST', anonymous: true, token: key.token, data: { store: { name, label: 'npm' }, purpose: 'p', steps: [] } })).json.request;
  const first = await ask();
  const back = (await f.request('/v1/requests/' + first.id + '/return', { anonymous: true })).json.back;
  assert.equal(back.name, 'ai-simplicity');
  assert.equal(back.refresh_url, 'https://simplicity.example.test/foundation/again?foundation_request=' + first.id);
  assert.equal(new URL(back.return_url).searchParams.get('from'), 'foundation', 'the app\'s own query is kept');
  const own = await f.issueKey('own');
  const unheld = (await f.request('/v1/requests', { method: 'POST', anonymous: true, token: own.token, data: { store: { name: 'x', label: 'x' }, purpose: 'p' } })).json.request;
  assert.equal((await f.request('/v1/requests/' + unheld.id + '/return', { anonymous: true })).status, 404, 'no way back for a request no app handles');
  // Done and cancelled: each is told to the app, signed with the secret it was given.
  const made = (await call('/principals/' + user.id + '/credentials', { method: 'POST', data: { kind: 'link', request_id: first.id } })).json;
  const link = new URLSearchParams(new URL(made.url).hash.slice(1)).get('link');
  const claimed = await fetch(f.base + '/v1/credentials/exchange', { method: 'POST', headers: { 'content-type': 'application/json', origin: f.base }, body: JSON.stringify({ request_id: first.id, link }) });
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
    assert.equal(signature, createHmac('sha256', settings.webhook_secret).update(at + '.' + item.body).digest('hex'));
    assert.equal(item.event.principal, user.id); assert.equal(item.event.alias, 'user-1');
    assert.doesNotMatch(item.body, /value|fdn_/, 'what was kept never leaves in a notice');
  }
  assert.equal(events.find(item => item.event.type === 'request.done').event.data.request.id, first.id);
});
