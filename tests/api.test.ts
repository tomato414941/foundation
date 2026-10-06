import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { newEncryptionKey, seal, encode, unwrap, wrap } from '../shared/encryption.js';

test('HTTP APIで登録し、シークレットを保存して同じ権限で一覧を取得する', async (t) => {
  const f = await fixture(),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const keys = await newEncryptionKey();
  const enrolled = await app.inject({
    method: 'POST',
    url: '/api/auth/enroll',
    payload: { name: 'API caller', publicKey: keys.publicKey },
  });
  assert.equal(enrolled.statusCode, 201, enrolled.body);
  const identity = enrolled.json(),
    headers = { authorization: 'Bearer ' + identity.token },
    id = randomUUID();
  const content = await seal(
    encode('api-secret'),
    [{ id: identity.principal.id, publicKey: keys.publicKey }],
    'resource:' + id,
  );
  const created = await app.inject({
    method: 'POST',
    url: '/api/principals/' + identity.principal.id + '/resources',
    headers,
    payload: { kind: 'secret', id, name: 'API secret', sealed: content, bytes: 10 },
  });
  assert.equal(created.statusCode, 201, created.body);
  assert.equal(created.json().kind, 'secret');
  const list = await app.inject({
    url: '/api/principals/' + identity.principal.id + '/resources?kind=secret',
    headers,
  });
  assert.equal(list.statusCode, 200, list.body);
  assert.equal(list.json().items[0].id, id);
  const read = await app.inject({ url: '/api/resources/' + id + '/secret', headers });
  assert.equal(read.statusCode, 200, read.body);
  assert.equal(read.json().sealed.ciphertext, content.ciphertext);
  const changed = await app.inject({
    method: 'PATCH',
    url: '/api/resources/' + id,
    headers,
    payload: { version: 7, name: 'Concurrent edit' },
  });
  assert.equal(changed.statusCode, 409);
});

test('JWEで保護した暗号鍵を保存し、不正な更新があっても復号できる鍵を保持する', async (t) => {
  const f = await fixture(),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const owner = await f.person(), credentialId = randomUUID();
  await f.db.pool.query(
    "INSERT INTO credentials(id,principal_id,kind,name,identifier) VALUES($1,$2,'passkey','Passkey',$3)",
    [credentialId, owner.actor.id, randomUUID()],
  );
  const prf = crypto.getRandomValues(new Uint8Array(32));
  const wrappedKey = await wrap(owner.keys.privateKey, prf, owner.actor.id);
  const request = {
    method: 'PUT' as const,
    url: `/api/principals/${owner.actor.id}/credentials/${credentialId}/wrap`,
    headers: { authorization: 'Bearer ' + owner.token },
  };
  assert.equal((await app.inject({ ...request, payload: { wrappedKey, publicKey: owner.keys.publicKey } })).statusCode, 200);
  const parts = wrappedKey.split('.');
  parts[0] = Buffer.from(JSON.stringify({ alg: 'dir', enc: 'A128GCM', sub: owner.actor.id })).toString('base64url');
  const malformed = await app.inject({ ...request, payload: { wrappedKey: parts.join('.'), publicKey: owner.keys.publicKey } });
  assert.equal(malformed.statusCode, 400);
  const stored = await f.db.one<{ private_wrap: string }>('SELECT private_wrap FROM credentials WHERE id=$1', [credentialId]);
  assert.deepEqual(await unwrap(stored!.private_wrap, prf, owner.actor.id), owner.keys.privateKey);
});

test('MCPで初期化し、認証したプリンシパルとして共通APIを呼び出す', async (t) => {
  const f = await fixture(),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const owner = await f.person();
  const headers = {
    authorization: 'Bearer ' + owner.token,
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': '2025-11-25',
  };
  const initialize = await app.inject({
    method: 'POST',
    url: '/api/mcp',
    headers,
    payload: {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } },
    },
  });
  assert.equal(initialize.statusCode, 200, initialize.body);
  assert.equal(initialize.json().result.serverInfo.name, 'Foundation');
  const result = await app.inject({
    method: 'POST',
    url: '/api/mcp',
    headers,
    payload: {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'foundation_api', arguments: { method: 'GET', path: '/api/session' } },
    },
  });
  assert.equal(result.statusCode, 200, result.body);
  assert.equal(JSON.parse(result.json().result.content[0].text).body.principal.id, owner.actor.id);
});

test('メールの確認でセッションを開始し、同一オリジンの操作を受け入れる', async (t) => {
  const f = await fixture(),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const requested = await app.inject({
    method: 'POST',
    url: '/api/auth/email',
    payload: { email: 'api@example.com' },
  });
  assert.equal(requested.statusCode, 200, requested.body);
  const fragment = new URLSearchParams(new URL(f.mailer.sent[0]!.link).hash.slice(1));
  const signed = await app.inject({
    method: 'POST',
    url: '/api/auth/email/verify',
    payload: { challengeId: fragment.get('challenge'), token: fragment.get('token') },
  });
  assert.equal(signed.statusCode, 200, signed.body);
  const cookie = signed.cookies.find((cookie) => cookie.name === 'foundation_session')!;
  assert.ok(cookie);
  const headers = { cookie: cookie.name + '=' + cookie.value };
  const session = await app.inject({ url: '/api/session', headers });
  const principal = session.json().principal;
  assert.ok(principal.id);
  const cross = await app.inject({
    method: 'PATCH',
    url: '/api/principals/' + principal.id,
    headers: { ...headers, origin: 'https://other.example' },
    payload: { name: 'Changed' },
  });
  assert.equal(cross.statusCode, 403, cross.body);
  const changed = await app.inject({
    method: 'PATCH',
    url: '/api/principals/' + principal.id,
    headers: { ...headers, origin: f.config.origin },
    payload: { name: 'Renamed' },
  });
  assert.equal(changed.statusCode, 200, changed.body);
  assert.equal(changed.json().name, 'Renamed');
});

test('APIの入力を検証し、公開したOpenAPIに呼び出し方法を示す', async (t) => {
  const f = await fixture(),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const bad = await app.inject({ method: 'POST', url: '/api/auth/enroll', payload: { name: '' } });
  assert.equal(bad.statusCode, 400, bad.body);
  const unauthorized = await app.inject({ url: '/api/principals' });
  assert.equal(unauthorized.statusCode, 401, unauthorized.body);
  const schema = await app.inject({ url: '/api/openapi.json' });
  assert.equal(schema.statusCode, 200, schema.body);
  assert.ok(schema.json().paths['/api/principals/{id}/resources'].post.requestBody);
});
