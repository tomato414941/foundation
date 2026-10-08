import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { MemoryObjects } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { newEncryptionKey, encode, decode, open, seal, unwrap, wrap } from '../shared/encryption.js';
import { delegatedFixture } from './delegation-support.js';
import { AccessPolicy, prepareRun, protect } from '../shared/custody.js';
import { bindKeys, hash, newIdentityKeys, publicPart, signBinding } from '../shared/authority.js';

test('OAuthの認可応答を開始した依頼者と実行先へ暗号化して中継し、同じ応答を一度だけ受け付ける', async (t) => {
  const f = await delegatedFixture();
  const context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const input = { kind: 'connect', input: { action: 'start' } };
  const intent = { ...f.intent, operation: 'connect' as const, operationDigest: await hash(input), sources: [] };
  await f.delegation.submit(f.owner.actor, await prepareRun(intent, input, f.owner.keys));
  const claim = (await f.delegation.claim(f.executor.actor, f.environment.manifest.id))!;
  await f.delegation.dispatch(f.executor.actor, intent.id, claim.lease);
  const id = randomUUID(), state = 'runtime-generated-state';
  const registered = await app.inject({ method: 'POST', url: '/api/oauth/relays',
    headers: { authorization: 'Bearer ' + f.executor.token }, payload: {
      id, runId: intent.id, stateDigest: await hash(state), expiresAt: new Date(Date.now() + 300_000).toISOString(),
    } });
  assert.equal(registered.statusCode, 201, registered.body);
  const parameters = new URLSearchParams({ state, code: 'authorization-code', iss: 'https://accounts.google.com' });
  const callback = await app.inject({ url: '/oauth/callback?' + parameters });
  assert.equal(callback.statusCode, 302, callback.body);
  assert.equal(callback.headers.location, '/connections/complete?flow=' + id);
  const relayed = await app.inject({ url: '/api/oauth/relays/' + id, headers: { authorization: 'Bearer ' + f.owner.token } });
  assert.equal(relayed.statusCode, 200, relayed.body);
  const result = relayed.json();
  assert.equal(decode(await open(result.sealed, f.owner.keys.encryption, f.owner.binding.id, result.context)), parameters.toString());
  assert.equal(decode(await open(result.sealed, f.executor.keys.encryption, f.executor.binding.id, result.context)), parameters.toString());
  assert.equal((await app.inject({ url: '/oauth/callback?' + parameters })).headers.location, callback.headers.location);
  parameters.set('code', 'another-code');
  assert.equal((await app.inject({ url: '/oauth/callback?' + parameters })).headers.location, '/connections/complete?error=connection_expired');
  assert.equal((await app.inject({ url: '/api/oauth/relays/' + id,
    headers: { authorization: 'Bearer ' + f.stranger.token } })).statusCode, 403);
});

test('HTTP APIで登録し、シークレットを保存して同じ権限で一覧を取得する', async (t) => {
  const f = await fixture(),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const keys = await newIdentityKeys();
  const enrolled = await app.inject({ method: 'POST', url: '/api/auth/enroll',
    payload: { name: 'API caller', publicKey: publicPart(keys.encryption) } });
  assert.equal(enrolled.statusCode, 201, enrolled.body);
  const identity = enrolled.json(), headers = { authorization: 'Bearer ' + identity.token }, id = randomUUID();
  const binding = bindKeys(identity.principal.id, keys);
  const bound = await app.inject({ method: 'PUT', url: '/api/principals/' + identity.principal.id + '/binding',
    headers, payload: await signBinding(binding, keys) });
  assert.equal(bound.statusCode, 200, bound.body);
  const content = await protect(encode('api-secret'), AccessPolicy.parse({ format: 1, id, origin: f.config.origin,
    ownerId: identity.principal.id, kind: 'secret', revision: 1, authorities: [binding], readers: [binding], grants: [] }),
    1, binding, keys);
  const created = await app.inject({ method: 'PUT', url: '/api/resources/' + id + '/custody',
    headers, payload: { name: 'API secret', content } });
  assert.equal(created.statusCode, 200, created.body);
  assert.equal(created.json().kind, 'secret');
  const list = await app.inject({ url: '/api/principals/' + identity.principal.id + '/resources?kind=secret', headers });
  assert.equal(list.statusCode, 200, list.body);
  assert.equal(list.json().items[0].id, id);
  const read = await app.inject({ url: '/api/resources/' + id + '/custody', headers });
  assert.equal(read.statusCode, 200, read.body);
  assert.equal(read.json().content.sealed.ciphertext, content.sealed.ciphertext);
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
  const stale = await newEncryptionKey();
  const changed = await app.inject({ ...request, payload: {
    wrappedKey: await wrap(stale.privateKey, prf, owner.actor.id), publicKey: stale.publicKey,
  } });
  assert.equal(changed.statusCode, 409);
  assert.equal(changed.json().error.code, 'encryption_key_changed');
  const stored = await f.db.one<{ private_wrap: string }>('SELECT private_wrap FROM credentials WHERE id=$1', [credentialId]);
  assert.deepEqual(await unwrap(stored!.private_wrap, prf, owner.actor.id), owner.keys.privateKey);
});

test('キーにも暗号鍵の包みを置き、そのキーで入ったセッションが包みを受け取る', async (t) => {
  const f = await fixture(),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const owner = await f.person();
  const headers = { authorization: 'Bearer ' + owner.token };
  const issued = await app.inject({
    method: 'POST',
    url: `/api/principals/${owner.actor.id}/credentials`,
    headers,
    payload: { name: 'Laptop' },
  });
  assert.equal(issued.statusCode, 201);
  const { credential, token } = issued.json();
  const before = await app.inject({ url: '/api/session', headers: { authorization: 'Bearer ' + token } });
  assert.equal(before.json().credentialId, credential.id);
  assert.equal(before.json().wrappedKey, null);
  const unlock = crypto.getRandomValues(new Uint8Array(32));
  const wrappedKey = await wrap(owner.keys.privateKey, unlock, owner.actor.id);
  const placed = await app.inject({
    method: 'PUT',
    url: `/api/principals/${owner.actor.id}/credentials/${credential.id}/wrap`,
    headers,
    payload: { wrappedKey, publicKey: owner.keys.publicKey },
  });
  assert.equal(placed.statusCode, 200);
  const session = await app.inject({ url: '/api/session', headers: { authorization: 'Bearer ' + token } });
  assert.equal(session.json().wrappedKey, wrappedKey);
  assert.deepEqual(await unwrap(session.json().wrappedKey, unlock, owner.actor.id), owner.keys.privateKey);
  const missing = await app.inject({
    method: 'PUT',
    url: `/api/principals/${owner.actor.id}/credentials/${randomUUID()}/wrap`,
    headers,
    payload: { wrappedKey, publicKey: owner.keys.publicKey },
  });
  assert.equal(missing.statusCode, 404);
});

test('デバイスの依頼をブラウザで承認すると、デバイスがそのプリンシパルの鍵を受け取る', async (t) => {
  const f = await fixture(),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const person = await f.person('Person');
  const headers = { authorization: 'Bearer ' + person.token };
  const device = await newEncryptionKey();
  const begun = await app.inject({ method: 'POST', url: '/api/auth/devices', payload: { name: 'Laptop', publicKey: device.publicKey } });
  assert.equal(begun.statusCode, 201, begun.body);
  const { id, code, poll, url } = begun.json();
  assert.match(code, /^[A-Z0-9]{8}$/);
  assert.equal(url, 'https://foundation.test/devices/' + id);
  const waiting = await app.inject({ url: `/api/auth/devices/${id}?poll=${poll}` });
  assert.deepEqual(waiting.json(), { state: 'pending', principalId: null, sealed: null });
  assert.equal((await app.inject({ url: `/api/auth/devices/${id}?poll=wrong` })).statusCode, 403);
  const shown = await app.inject({ url: '/api/auth/devices/' + id, headers });
  assert.equal(shown.json().name, 'Laptop');
  const wrongCode = await app.inject({ method: 'POST', url: `/api/auth/devices/${id}/approve`, headers, payload: { code: 'AAAAAAAA', principalId: person.actor.id } });
  assert.equal(wrongCode.statusCode, 400);
  const approved = await app.inject({ method: 'POST', url: `/api/auth/devices/${id}/approve`, headers, payload: { code, principalId: person.actor.id } });
  assert.equal(approved.statusCode, 200, approved.body);
  assert.equal(approved.json().state, 'approving');
  const issued = await app.inject({ method: 'POST', url: `/api/principals/${person.actor.id}/credentials`, headers, payload: { name: 'Laptop' } });
  const { credential, token } = issued.json();
  await app.inject({
    method: 'PUT',
    url: `/api/principals/${person.actor.id}/credentials/${credential.id}/wrap`,
    headers,
    payload: { wrappedKey: await wrap(person.keys.privateKey, encode(token), person.actor.id), publicKey: person.keys.publicKey },
  });
  const sealed = await seal(encode(token), [{ id, publicKey: device.publicKey }], 'device:' + id);
  const completed = await app.inject({ method: 'POST', url: `/api/auth/devices/${id}/complete`, headers, payload: { sealed } });
  assert.equal(completed.statusCode, 200, completed.body);
  const done = await app.inject({ url: `/api/auth/devices/${id}?poll=${poll}` });
  assert.equal(done.json().state, 'approved');
  assert.equal(done.json().principalId, person.actor.id);
  const received = decode(await open(done.json().sealed, device.privateKey, id, 'device:' + id));
  assert.equal(received, token);
  const session = await app.inject({ url: '/api/session', headers: { authorization: 'Bearer ' + received } });
  assert.equal(session.json().principal.id, person.actor.id);
  assert.deepEqual(await unwrap(session.json().wrappedKey, encode(received), person.actor.id), person.keys.privateKey);
  assert.equal((await app.inject({ url: `/api/auth/devices/${id}?poll=${poll}` })).statusCode, 404);
});

test('サーバーは動いているコミットをセッションで名乗る', async (t) => {
  const commit = 'a'.repeat(40);
  const f = await fixture({ FOUNDATION_COMMIT: commit }),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const session = await app.inject({ url: '/api/session' });
  assert.equal(session.json().server.commit, commit);
  assert.equal(session.json().server.name, 'Foundation');
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

test('AWSのIAMロールを作るテンプレートを置き場に出し、一時的なリンクで渡す', async (t) => {
  const f = await fixture(), storage = new MemoryObjects();
  const context = await createContext(f.config, { db: f.db, mailer: f.mailer, storage }), app = await buildApp(context);
  t.after(async () => { await app.close(); await f.close(); });
  const person = await f.person();
  assert.equal((await app.inject({ url: '/api/aws/role-template' })).statusCode, 401);
  const response = await app.inject({ url: '/api/aws/role-template', headers: { authorization: 'Bearer ' + person.token } });
  assert.equal(response.statusCode, 200, response.body);
  assert.equal(response.json().url, 'https://objects.example/published/aws-connection.yaml?expires=3600');
  const template = new TextDecoder().decode(storage.files.get('published/aws-connection.yaml'));
  assert.match(template, /AWS::IAM::Role/);
  assert.match(template, /sts:ExternalId/);
  assert.match(template, /Default: arn:aws:iam::aws:policy\/ReadOnlyAccess/);
});
