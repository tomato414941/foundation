import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:https';
import { connect } from 'node:tls';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { fixture } from './helpers.mjs';

const TOKEN = 'sk-fetch-fixture-value-1234567890';
const authorization = (name = 'api/token', prefix = '') => ({ headers: { authorization: '' },
  bindings: [{ target: '/headers/authorization', parts: [prefix, { name }] }] });

// A service on the public internet, played by a local HTTPS server with its own certificate. What it received
// is kept so the test can see what really went out; what it answers reflects the request back.
async function service(t) {
  const dir = await mkdtemp(join(tmpdir(), 'foundation-fetch-')); t.after(() => rm(dir, { recursive: true, force: true }));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key'), '-out', join(dir, 'cert'), '-days', '1',
    '-subj', '/CN=api.example.test', '-addext', 'subjectAltName=DNS:api.example.test'], { stdio: 'ignore' });
  const key = await readFile(join(dir, 'key')), cert = await readFile(join(dir, 'cert'));
  const received = [];
  const server = createServer({ key, cert }, (req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      received.push({ method: req.method, path: req.url, headers: req.headers, body });
      if (req.url === '/redirect') { res.writeHead(302, { location: 'https://elsewhere.example.test/?seen=' + encodeURIComponent(req.headers.authorization) }); return res.end(); }
      if (req.url === '/gzip') { res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' }); return res.end(gzipSync(JSON.stringify({ authorization: req.headers.authorization }))); }
      if (req.url === '/compress') { res.writeHead(200, { 'content-type': 'text/plain', 'content-encoding': 'compress' }); return res.end('opaque'); }
      if (req.url === '/large') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('x'.repeat(1024 * 1024 + 1)); }
      if (req.url === '/bytes') { res.writeHead(200, { 'content-type': 'application/octet-stream' }); return res.end(Buffer.from([0, 255, 1])); }
      res.writeHead(200, { 'content-type': 'application/json', 'x-echo': req.headers.authorization || '' });
      res.end(JSON.stringify({ authorization: req.headers.authorization, encoded: Buffer.from(req.headers.authorization || '').toString('base64'), body }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  // Every name resolves to what the test says; the connection itself always reaches the local server.
  const addresses = new Map([['api.example.test', [{ address: '93.184.216.34', family: 4 }]]]);
  const outbound = {
    resolve: async host => { if (!addresses.has(host)) throw new Error('unknown'); return addresses.get(host); },
    createConnection: options => connect({ host: '127.0.0.1', port: server.address().port, servername: options.servername, ca: cert }),
    ca: cert,
  };
  return { received, addresses, outbound };
}

async function setup(t) {
  const api = await service(t);
  const f = await fixture(t, { outbound: api.outbound });
  const key = await f.issueKey();
  const put = await f.request('/v1/resources?kind=secret&name=api/token', { method: 'PUT', token: key.token, raw: TOKEN, type: 'text/plain' });
  assert.equal(put.status, 200, put.text);
  const call = request => f.request('/v1/functions/http.request', { method: 'POST', token: key.token, data: request });
  return { ...api, f, key, call };
}

test('A request goes out with what is kept in its headers and body, and comes back without it', async t => {
  const { received, call, f } = await setup(t);
  const answer = await call({ url: 'https://api.example.test/echo?q=1', method: 'POST', headers: { authorization: '' }, json: { token: '' },
    bindings: [{ target: '/headers/authorization', parts: ['Bearer ', { name: 'api/token' }] }, { target: '/json/token', parts: [{ name: 'api/token' }] }] });
  assert.equal(answer.status, 200, answer.text);
  assert.equal(received[0].headers.authorization, 'Bearer ' + TOKEN);
  assert.equal(received[0].body, '{"token":"' + TOKEN + '"}');
  assert.equal(received[0].path, '/echo?q=1');
  assert.equal(received[0].headers['user-agent'], 'Foundation', 'many services refuse a request that does not say what sent it');
  assert.equal(answer.json.response.status, 200);
  assert.equal(answer.json.response.body_encoding, 'utf8');
  const echoed = JSON.parse(answer.json.response.body);
  assert.equal(echoed.authorization, 'Bearer [redacted]');
  assert.equal(echoed.body, '{"token":"[redacted]"}');
  assert.equal(answer.json.response.headers['x-echo'], 'Bearer [redacted]');
  assert.doesNotMatch(answer.text, new RegExp(TOKEN));
  assert.doesNotMatch(answer.text, new RegExp(Buffer.from(TOKEN).toString('base64').slice(0, 20)));
});

test('A redirect comes back as it is, with what is kept taken out, and is not followed', async t => {
  const { received, call } = await setup(t);
  const answer = await call({ url: 'https://api.example.test/redirect', ...authorization() });
  assert.equal(answer.json.response.status, 302);
  assert.equal(answer.json.response.headers.location, 'https://elsewhere.example.test/?seen=[redacted]');
  assert.equal(received.length, 1);
});

test('Only the public internet is reachable: never this host, its network, the metadata service or a name that points inside', async t => {
  const { addresses, call, f } = await setup(t);
  addresses.set('private.example.test', [{ address: '10.0.0.5', family: 4 }]);
  addresses.set('metadata.example.test', [{ address: '169.254.169.254', family: 4 }]);
  addresses.set('loopback.example.test', [{ address: '::1', family: 6 }]);
  addresses.set('mapped.example.test', [{ address: '::ffff:127.0.0.1', family: 6 }]);
  addresses.set('mixed.example.test', [{ address: '93.184.216.34', family: 4 }, { address: '192.168.1.1', family: 4 }]);
  for (const host of ['private', 'metadata', 'loopback', 'mapped', 'mixed']) {
    const refused = await call({ url: `https://${host}.example.test/` });
    assert.equal(refused.status, 400, host); assert.equal(refused.json.error.code, 'invalid_destination', host);
  }
  const own = new URL(f.base).hostname;
  for (const url of ['http://api.example.test/', 'https://api.example.test:8443/', 'https://127.0.0.1/', 'https://[::1]/', 'https://2130706433/', 'https://localhost/', 'https://metadata.internal/', `https://${own}/`, 'ftp://api.example.test/']) {
    const refused = await call({ url });
    assert.equal(refused.status, 400, url); assert.match(refused.json.error.code, /^invalid_(url|destination)$/, url);
  }
  const inUrl = await call({ url: 'https://api.example.test/', bindings: [{ target: '/url', parts: [{ name: 'api/token' }] }] });
  assert.equal(inUrl.json.error.code, 'invalid_input');
});

test('What goes out is checked: the key may use each path, headers are its own, and a value must fit where it goes', async t => {
  const { call, f, key, received } = await setup(t);
  assert.equal((await call({ url: 'https://api.example.test/', ...authorization('api/missing') })).status, 404);
  for (const name of ['host', 'Content-Length', 'accept-encoding', 'proxy-authorization', 'x-forwarded-for']) {
    assert.equal((await call({ url: 'https://api.example.test/', headers: { [name]: 'x' } })).json.error.code, 'invalid_headers', name);
  }
  await f.request('/v1/resources?kind=secret&name=api/multiline', { method: 'PUT', token: key.token, raw: 'line1\nline2', type: 'text/plain' });
  assert.equal((await call({ url: 'https://api.example.test/', ...authorization('api/multiline') })).json.error.code, 'invalid_headers');
  await f.request('/v1/resources?kind=secret&name=api/binary', { method: 'PUT', token: key.token, raw: Buffer.from([0xff, 0xfe, 0x00]), type: 'application/octet-stream' });
  assert.equal((await call({ url: 'https://api.example.test/', method: 'POST', body: '', bindings: [{ target: '/body', parts: [{ name: 'api/binary' }] }] })).json.error.code, 'not_text');
  assert.equal((await call({ url: 'https://api.example.test/', method: 'GET', body: 'x' })).json.error.code, 'invalid_body');
  assert.equal(received.length, 0, 'nothing refused ever went out');
  await f.request('/v1/principals/' + key.id, { method: 'DELETE', data: {} });
  assert.equal((await call({ url: 'https://api.example.test/', ...authorization() })).status, 401);
});

test('An answer larger than 1MB is cut off rather than passed on', async t => {
  const { call } = await setup(t);
  const answer = await call({ url: 'https://api.example.test/large' });
  assert.equal(answer.status, 502); assert.equal(answer.json.error.code, 'response_too_large');
});

test('A compressed answer is opened here, so what is kept is taken out of what the agent reads; one that cannot be opened is not passed on', async t => {
  const { call, received } = await setup(t);
  const opened = await call({ url: 'https://api.example.test/gzip', ...authorization() });
  assert.equal(opened.status, 200, opened.text);
  assert.equal(received[0].headers['accept-encoding'], 'identity');
  assert.equal(opened.json.response.headers['content-encoding'], undefined);
  assert.deepEqual(JSON.parse(opened.json.response.body), { authorization: '[redacted]' });
  const opaque = await call({ url: 'https://api.example.test/compress', ...authorization() });
  assert.equal(opaque.status, 502); assert.equal(opaque.json.error.code, 'unsupported_encoding');
});

test('Foundation itself is not reachable under another name that points at its own address', async t => {
  const api = await service(t);
  api.addresses.set('foundation.example.test', [{ address: '198.35.26.96', family: 4 }]);
  api.addresses.set('alias.example.test', [{ address: '198.35.26.96', family: 4 }]);
  const f = await fixture(t, { outbound: api.outbound, publicOrigin: 'https://foundation.example.test' });
  const key = await f.issueKey();
  const refused = await f.request('/v1/functions/http.request', { method: 'POST', token: key.token, data: { url: 'https://alias.example.test/v1/keys/current' } });
  assert.equal(refused.status, 400); assert.equal(refused.json.error.code, 'invalid_destination');
  assert.equal(api.received.length, 0);
  const allowed = await f.request('/v1/functions/http.request', { method: 'POST', token: key.token, data: { url: 'https://api.example.test/echo' } });
  assert.equal(allowed.json.response.status, 200, allowed.text);
});

test('The HTTPS function binds opaque stored names explicitly and saves only its selected response body', async t => {
  const { f, key, received } = await setup(t), connection = await f.connection();
  const inputName = '{{入力}} /..,=x', outputName = '結果 /?';
  const input = await f.request('/v1/resources?kind=secret&name=' + encodeURIComponent(inputName) + '', { method: 'PUT', token: key.token, raw: TOKEN });
  assert.equal(input.status, 200);
  f.expire(connection.id);
  const calls = f.google.calls.length;
  const saved = await f.request('/v1/functions/http.request', { method: 'POST', token: key.token, data: {
    url: 'https://api.example.test/echo', ...authorization(inputName, 'Bearer '), save: outputName,
  } });
  assert.equal(saved.status, 200, saved.text);
  assert.equal(received[0].headers.authorization, 'Bearer ' + TOKEN);
  assert.deepEqual(saved.json.saved.map(row => row.name), [outputName]);
  assert.equal(saved.json.response.status, 200);
  assert.equal(saved.json.response.body, undefined);
  const body = await f.read('secret', (outputName));
  assert.equal(JSON.parse(body.text).authorization, 'Bearer [redacted]');
  assert.equal(f.google.calls.length, calls, 'using a saved value does not process any connection');
  assert.equal((await f.read('secret', (outputName), { token: key.token })).status, 403);
  assert.doesNotMatch(saved.text, new RegExp(TOKEN));

  const binary = await f.request('/v1/functions/http.request', { method: 'POST', token: key.token, data: { url: 'https://api.example.test/bytes', save: 'binary' } });
  assert.equal(binary.status, 200);
  const owner = f.app.principals.actsFor(key.id)[0];
  assert.deepEqual(f.app.secrets.content(f.app.secrets.find(owner, 'binary')), Buffer.from([0, 255, 1]));
});

test('The HTTPS function retains destination and owner checks, and validates output names before sending', async t => {
  const { f, key, received } = await setup(t);
  const call = (data, token = key.token) => f.request('/v1/functions/http.request', { method: 'POST', token, data });
  assert.equal((await call({ url: 'https://127.0.0.1/' })).json.error.code, 'invalid_destination');
  assert.equal((await call({ url: 'https://api.example.test/', save: '' })).json.error.code, 'invalid_name');
  await f.login('second@example.test');
  const other = await f.issueKey();
  const refused = await call({ url: 'https://api.example.test/', ...authorization() }, other.token);
  assert.equal(refused.status, 404);
  assert.equal(received.length, 0);
});

test('記号入りの保存名を完全一致で参照し、通常の文字列と秘密値を再解釈せずに送信する', async t => {
  const { f, call, received } = await setup(t);
  const literal = '{{foundation:api/token}}', secret = 'private-' + literal;
  await f.keep('secret', 'api/token#work', secret);
  const answer = await call({ url: 'https://api.example.test/echo', method: 'POST',
    headers: { authorization: '', 'x-literal': literal }, body: literal,
    bindings: [{ target: '/headers/authorization', parts: ['Bearer ', { name: 'api/token#work' }] }] });
  assert.equal(answer.status, 200, answer.text);
  assert.equal(received[0].headers.authorization, 'Bearer ' + secret);
  assert.equal(received[0].headers['x-literal'], literal);
  assert.equal(received[0].body, literal);
  assert.equal(JSON.parse(answer.json.response.body).authorization, 'Bearer [redacted]');
});

test('JSON Pointerで選んだ値を差し込み、JSONとフォームをそれぞれ安全にエンコードする', async t => {
  const { f, call, received } = await setup(t);
  const value = 'value="quoted"&scope=admin + / あ\n';
  await f.keep('secret', 'json/value', value);
  const answer = await call({ url: 'https://api.example.test/echo', method: 'POST', json: { 'a/b': [{ 'm~n': '' }], 'literal.dot': 'untouched' },
    bindings: [{ target: '/json/a~1b/0/m~0n', parts: [{ name: 'json/value' }] }] });
  assert.equal(answer.status, 200, answer.text);
  assert.deepEqual(JSON.parse(received[0].body), { 'a/b': [{ 'm~n': value }], 'literal.dot': 'untouched' });
  assert.equal(received[0].headers['content-type'], 'application/json');
  assert.equal(JSON.parse(JSON.parse(answer.json.response.body).body)['a/b'][0]['m~n'], '[redacted]');
  const form = await call({ url: 'https://api.example.test/echo', method: 'POST', form: { token: '', scope: 'read' },
    bindings: [{ target: '/form/token', parts: [{ name: 'json/value' }] }] });
  assert.equal(form.status, 200, form.text);
  assert.deepEqual(Object.fromEntries(new URLSearchParams(received[1].body)), { token: value, scope: 'read' });
  assert.equal(received[1].headers['content-type'], 'application/x-www-form-urlencoded');
  assert.equal(JSON.parse(form.json.response.body).body, 'token=[redacted]&scope=read');
});

test('接続から明示した出力を一度の取得で揃え、複数の差し込み先に送信する', async t => {
  const { f, call, received } = await setup(t), connection = await f.connection();
  let obtains = 0;
  const derive = f.app.connections.derive.bind(f.app.connections);
  f.app.connections.derive = async row => { obtains++; return derive(row); };
  const answer = await call({ url: 'https://api.example.test/echo', headers: { authorization: '', 'x-account': '' }, bindings: [
    { target: '/headers/authorization', parts: ['Bearer ', { id: connection.id, output: 'GOOGLE_OAUTH_ACCESS_TOKEN' }] },
    { target: '/headers/x-account', parts: [{ id: connection.id, output: 'GOOGLE_ACCOUNT_EMAIL' }] },
  ] });
  assert.equal(answer.status, 200, answer.text);
  assert.equal(obtains, 1);
  assert.equal(received[0].headers.authorization, 'Bearer google-access-personal');
  assert.equal(received[0].headers['x-account'], 'personal@example.test');
});

test('差し込み先とすべての参照を送信前に検証し、不正な要求では接続を更新しない', async t => {
  const { f, call, received } = await setup(t), connection = await f.connection();
  f.expire(connection.id);
  const calls = f.google.calls.length, good = { id: connection.id, output: 'GOOGLE_OAUTH_ACCESS_TOKEN' };
  const base = { url: 'https://api.example.test/echo', method: 'POST', headers: { authorization: '' }, json: { list: [''], number: 1 } };
  for (const target of ['/url', '/method', '/headers/missing', '/json/list/01', '/json/list/-', '/json/number', '/json/constructor', '/json/bad~2']) {
    const answer = await call({ ...base, bindings: [{ target, parts: [good] }] });
    assert.equal(answer.status, 400, target);
  }
  for (const reference of [{ id: connection.id }, { id: connection.id, output: 'UNKNOWN' }, { name: 'api/token', id: connection.id }]) {
    const answer = await call({ ...base, bindings: [{ target: '/headers/authorization', parts: [good, reference] }] });
    assert.equal(answer.status, 400, JSON.stringify(reference));
  }
  const missing = await call({ ...base, bindings: [{ target: '/headers/authorization', parts: [good, { name: 'missing' }] }] });
  assert.equal(missing.status, 404);
  const duplicate = { target: '/headers/authorization', parts: [good] };
  assert.equal((await call({ ...base, bindings: [duplicate, duplicate] })).status, 400);
  assert.equal((await call({ ...base, body: 'other' })).status, 400);
  assert.equal((await call({ url: base.url, method: 'POST', body: '', body_encoding: 'base64', bindings: [{ target: '/body', parts: [good] }] })).status, 400);
  assert.equal(received.length, 0);
  assert.equal(f.google.calls.length, calls);
});
