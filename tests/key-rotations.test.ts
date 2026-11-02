import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { delegatedFixture, MemoryJournal } from './delegation-support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { bindKeys, hash, newIdentityKeys, sign, signBinding, verifiesReplacement } from '../shared/authority.js';
import { decode, encode, unwrap, wrap } from '../shared/encryption.js';
import { AccessPolicy, ContentTypes, Operations, ProtectedContent, approvePolicy, prepareRun, protect, reveal } from '../shared/custody.js';
import { prepareRotatedContent, signRotationPreparation } from '../shared/key-rotations.js';
import type { PreparedRotationPayload } from '../shared/key-rotations.js';
import { FUNCTION_RUNTIME_VERSION, HTTP_RUNTIME_VERSION, makeReceipt, readReceipt, signEnvironment } from '../shared/runtime-protocol.js';
import { openKeyring, signKeyring } from '../shared/keyring.js';
import { approveFunctionSettings, publishFunction, verifyFunctionSettings } from '../shared/function-api.js';
import { FunctionDefinition } from '../shared/contracts.js';
import { CustodyClient } from '../shared/client.js';
import { JournalTrust } from '../runtime/trust.js';
import type { z } from 'zod';

async function apiFixture() {
  const f = await delegatedFixture();
  const context = await createContext(f.config, { db: f.db, mailer: f.mailer });
  const app = await buildApp(context);
  async function api(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: object, token = f.owner.token) {
    return app.inject({ method, url: path, headers: { authorization: 'Bearer ' + token },
      ...(body === undefined ? {} : { payload: body }) });
  }
  async function ok(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: object) {
    const response = await api(method, path, body);
    assert.ok(response.statusCode >= 200 && response.statusCode < 300, response.body);
    return response.json();
  }
  async function start() {
    const keys = await newIdentityKeys();
    const binding = { ...bindKeys(f.owner.actor.id, keys), generation: f.owner.binding.generation + 1,
      previous: await hash(f.owner.binding) };
    const input = { id: randomUUID(), replacement: await signBinding(binding, keys),
      previousSignature: await sign(binding, f.owner.keys.signing, 'key-replacement') };
    const path = '/api/principals/' + f.owner.actor.id + '/key-rotations';
    const result = await ok('POST', path, input);
    return { keys, binding, input, result, path: path + '/' + input.id };
  }
  async function prepare(rotation: Awaited<ReturnType<typeof start>>, item: any, prfs = new Map<string, Uint8Array>()) {
    let payload: PreparedRotationPayload;
    switch (item.kind) {
      case 'content':
      case 'result':
        payload = { kind: item.kind, content: await prepareRotatedContent(
          ProtectedContent.parse(item.source.content ?? item.source.receipt.content),
          f.owner.binding, rotation.binding, f.owner.binding, f.owner.keys, rotation.keys) };
        break;
      case 'credential':
        assert.ok(prfs.has(item.id));
        payload = { kind: 'credential', wrappedKey: await wrap(rotation.keys, prfs.get(item.id)!, f.owner.actor.id) };
        break;
      case 'environment':
        payload = { kind: 'environment', registration: await signEnvironment({ ...item.source.registration.manifest,
          executor: rotation.binding, revision: item.source.registration.manifest.revision + 1 }, rotation.keys) };
        break;
      case 'keyring': {
        const previous = await openKeyring(item.source.signature, f.owner.binding);
        payload = { kind: 'keyring', signature: await signKeyring({ ...previous,
          signerId: rotation.binding.id, revision: previous.revision + 1 }, rotation.keys.signing) };
        break;
      }
      case 'functionSettings': {
        const { signature: _signature, ...previous } = item.source.approval;
        payload = { kind: 'functionSettings', approval: await approveFunctionSettings({ ...previous,
          revision: previous.revision + 1, executor: rotation.binding, author: rotation.binding }, rotation.keys) };
        break;
      }
      default: throw new Error('Unknown rotation item.');
    }
    const input = await signRotationPreparation(rotation.input.id, f.owner.actor.id, rotation.binding.id,
      item.id, item.sourceDigest, payload, f.owner.keys.signing);
    await ok('PUT', rotation.path + '/items/' + item.kind + '/' + item.id, input);
    return input;
  }
  async function close() { await app.close(); await f.close(); }
  const jsonApi = (token: string) => ({
    async json<T>(path: string, options: { method?: string; body?: unknown } = {}, schema?: z.ZodType<T>): Promise<T> {
      const response = await api((options.method ?? 'GET') as 'GET', path, options.body as object | undefined, token);
      assert.ok(response.statusCode >= 200 && response.statusCode < 300, response.body);
      return schema ? schema.parse(response.json()) : response.json() as T;
    },
  });
  return { ...f, context, app, api, ok, start, prepare, close, jsonApi };
}

test('鍵交換APIは旧鍵で利用を続けながら準備し、同じデータと共有範囲を新鍵へ移す', async t => {
  const f = await apiFixture(); t.after(f.close);
  const prf = crypto.getRandomValues(new Uint8Array(32));
  await f.authentication.setWrap(f.owner.actor, f.owner.actor.id, f.owner.actor.credentialId!,
    await wrap(f.owner.keys, prf, f.owner.actor.id), f.owner.binding.encryption);
  const additional = await f.authentication.issueKey(f.owner.actor.id, 'Another sign-in key');
  const otherPrf = crypto.getRandomValues(new Uint8Array(32));
  await f.authentication.setWrap(f.owner.actor, f.owner.actor.id, additional.credential.id,
    await wrap(f.owner.keys, otherPrf, f.owner.actor.id), f.owner.binding.encryption);
  const prfs = new Map([[f.owner.actor.credentialId!, prf], [additional.credential.id, otherPrf]]);
  const rotation = await f.start();
  assert.equal(rotation.result.total, 3);
  const pending = await f.ok('GET', rotation.path);
  assert.equal(pending.items.length, 3);
  assert.equal((await f.ok('POST', rotation.path.slice(0, rotation.path.lastIndexOf('/')), rotation.input)).id, rotation.input.id);
  for (const item of pending.items) await f.prepare(rotation, item, prfs);
  assert.equal((await f.ok('GET', rotation.path)).prepared, 3);
  const previous = await f.custody.read(f.owner.actor, f.resource.id);
  assert.equal(decode(await reveal(previous.content, f.owner.binding, f.owner.keys.encryption)), 'confidential-value');
  const completed = await f.ok('POST', rotation.path + '/commit');
  assert.equal(completed.state, 'committed');
  assert.equal((await f.ok('POST', rotation.path + '/commit')).state, 'committed');
  assert.deepEqual((await f.bindings.current(f.owner.actor.id)).binding, rotation.binding);
  const current = await f.custody.read(f.owner.actor, f.resource.id);
  assert.equal(decode(await reveal(current.content, rotation.binding, rotation.keys.encryption)), 'confidential-value');
  assert.equal(decode(await reveal(current.content, f.executor.binding, f.executor.keys.encryption)), 'confidential-value');
  assert.deepEqual(current.content.policy.readers.map(reader => reader.principalId), previous.content.policy.readers.map(reader => reader.principalId));
  const credential = await f.db.one<{ private_wrap: string }>('SELECT private_wrap FROM credentials WHERE id=$1', [f.owner.actor.credentialId]);
  assert.deepEqual(await unwrap(credential!.private_wrap, prf, f.owner.actor.id), rotation.keys);
  const second = await f.db.one<{ private_wrap: string }>('SELECT private_wrap FROM credentials WHERE id=$1', [additional.credential.id]);
  assert.deepEqual(await unwrap(second!.private_wrap, otherPrf, f.owner.actor.id), rotation.keys);
  assert.equal(await f.authentication.authenticate(f.owner.token).then(actor => actor?.id), f.owner.actor.id);
  await assert.rejects(reveal(current.content, f.owner.binding, f.owner.keys.encryption));
  const ownerClient = new CustodyClient(f.jsonApi(f.owner.token), f.config.origin, rotation.binding, rotation.keys,
    new JournalTrust(new MemoryJournal()));
  assert.equal(decode(await ownerClient.reveal(f.resource.id)), 'confidential-value');
  const specification = (await f.ok('GET', '/api/openapi.json')).paths;
  assert.ok(specification['/api/principals/{id}/key-rotations']);
  assert.ok(specification['/api/principals/{id}/key-rotations/{rotationId}/commit']);
});

test('準備後に更新または追加されたデータは再準備を求め、すべて揃ってから鍵交換を確定する', async t => {
  const f = await apiFixture(); t.after(f.close);
  const rotation = await f.start();
  await f.prepare(rotation, (await f.ok('GET', rotation.path)).items[0]);
  const old = await f.custody.read(f.owner.actor, f.resource.id);
  await f.custody.put(f.owner.actor, { name: 'Updated', version: old.version,
    content: await protect(encode('updated-value'), old.content.policy, old.content.materialRevision + 1,
      f.owner.binding, f.owner.keys, { bytes: 13 }, old.content) });
  const changed = await f.api('POST', rotation.path + '/commit');
  assert.equal(changed.statusCode, 409, changed.body);
  assert.equal(changed.json().error.code, 'rotation_not_ready');
  assert.equal((await f.ok('GET', rotation.path)).items[0].state, 'stale');
  assert.equal((await f.bindings.current(f.owner.actor.id)).binding.id, f.owner.binding.id);
  const another = randomUUID(), policy = AccessPolicy.parse({ ...f.policy, id: another, revision: 1 });
  await f.custody.put(f.owner.actor, { name: 'Added during rotation',
    content: await protect(encode('second'), policy, 1, f.owner.binding, f.owner.keys) });
  const page = await f.ok('GET', rotation.path + '?limit=1');
  assert.ok(page.next);
  const next = await f.ok('GET', rotation.path + '?limit=1&after=' + encodeURIComponent(page.next));
  assert.notEqual(next.items[0].id, page.items[0].id);
  for (const item of (await f.ok('GET', rotation.path)).items) await f.prepare(rotation, item);
  await f.ok('POST', rotation.path + '/commit');
  const value = await f.custody.read(f.owner.actor, f.resource.id);
  assert.equal(decode(await reveal(value.content, rotation.binding, rotation.keys.encryption)), 'updated-value');
});

test('鍵交換を取り消すと元の鍵とデータで利用でき、別の交換を開始する', async t => {
  const f = await apiFixture(); t.after(f.close);
  const rotation = await f.start(), pending = await f.ok('GET', rotation.path);
  await f.prepare(rotation, pending.items[0]);
  await f.ok('DELETE', rotation.path);
  await f.ok('DELETE', rotation.path);
  assert.equal((await f.ok('GET', rotation.path)).state, 'cancelled');
  assert.equal((await f.api('POST', rotation.path + '/commit')).statusCode, 409);
  assert.equal((await f.bindings.current(f.owner.actor.id)).binding.id, f.owner.binding.id);
  const current = await f.custody.read(f.owner.actor, f.resource.id);
  assert.equal(decode(await reveal(current.content, f.owner.binding, f.owner.keys.encryption)), 'confidential-value');
  assert.notEqual((await f.start()).input.id, rotation.input.id);
});

test('他人や旧鍵の署名を持たない呼出しは鍵交換を開始または準備しない', async t => {
  const f = await apiFixture(); t.after(f.close);
  const rotation = await f.start();
  const path = rotation.path.slice(0, rotation.path.lastIndexOf('/'));
  assert.equal((await f.api('POST', path, { ...rotation.input, id: randomUUID() }, f.stranger.token)).statusCode, 403);
  assert.equal((await f.api('GET', rotation.path, undefined, f.stranger.token)).statusCode, 403);
  const invalid = { ...rotation.input, id: randomUUID(),
    previousSignature: await sign(rotation.binding, f.stranger.keys.signing, 'key-replacement') };
  assert.equal((await f.api('POST', path, invalid)).statusCode, 400);
  const item = (await f.ok('GET', rotation.path)).items[0];
  const prepared = await f.prepare(rotation, item);
  const forged = await signRotationPreparation(rotation.input.id, f.owner.actor.id, rotation.binding.id,
    item.id, item.sourceDigest, prepared.payload, f.stranger.keys.signing);
  assert.equal((await f.api('PUT', rotation.path + '/items/' + item.kind + '/' + item.id, forged)).statusCode, 400);
});

test('実行環境と関数設定と検証済み鍵一覧を、設定と信頼先を維持して新しい署名へ切り替える', async t => {
  const f = await apiFixture(); t.after(f.close);
  const environment = await signEnvironment({
    format: 3, id: randomUUID(), origin: f.config.origin, ownerId: f.owner.actor.id,
    name: 'Local execution environment', executor: f.owner.binding, operatorId: f.owner.actor.id,
    driver: 'attached', capabilities: [Operations.function, Operations.http],
    functionVersion: FUNCTION_RUNTIME_VERSION, httpVersion: HTTP_RUNTIME_VERSION, isolation: 'process', revision: 1,
  }, f.owner.keys);
  await f.context.delegation.register(f.owner.actor, environment);
  const verifiedAt = new Date().toISOString();
  await f.context.keyrings.put(f.owner.actor, f.owner.actor.id, { version: null, signature: await signKeyring({
    origin: f.config.origin, ownerId: f.owner.actor.id, signerId: f.owner.binding.id, revision: 1,
    keys: [{ binding: f.executor.binding, verifiedAt }],
  }, f.owner.keys.signing) });
  const definition = FunctionDefinition.parse({ program: { kind: 'http',
    request: { url: 'https://service.example/items', method: 'GET' } } });
  const functionId = randomUUID(), publication = await publishFunction({
    format: 2, functionId, ownerId: f.owner.actor.id, revision: 1, definition,
    author: f.owner.binding, createdAt: new Date().toISOString(),
  }, f.owner.keys);
  const fn = await f.context.functions.save(f.owner.actor, { ownerId: f.owner.actor.id, name: 'Saved HTTP request', definition },
    { functionId, publication }, f.context.custody);
  const approval = await approveFunctionSettings({ format: 1, functionId, ownerId: f.owner.actor.id,
    definitionDigest: await hash(definition), revision: 1, environmentId: environment.manifest.id,
    inputAccess: { expiresAt: null }, author: f.owner.binding, executor: f.owner.binding,
    createdAt: new Date().toISOString(),
  }, f.owner.keys);
  await f.context.functions.configure(f.owner.actor, { functionId, functionVersion: fn.version, version: 0,
    environmentId: environment.manifest.id, inputAccess: { expiresAt: null } },
  { approval, contents: {} }, f.context.custody, f.context.delegation);
  const rotation = await f.start(), pending = await f.ok('GET', rotation.path);
  assert.deepEqual(pending.items.map((item: any) => item.kind).sort(),
    ['content', 'environment', 'functionSettings', 'keyring'].sort());
  for (const item of pending.items) await f.prepare(rotation, item);
  await f.ok('POST', rotation.path + '/commit');
  const registration = await f.context.delegation.environment(environment.manifest.id);
  assert.deepEqual(registration.registration.manifest.executor, rotation.binding);
  assert.equal(registration.registration.manifest.revision, 2);
  const keyring = await f.context.keyrings.get(f.owner.actor, f.owner.actor.id);
  const verified = await openKeyring(keyring.keyring!.signature, rotation.binding);
  assert.deepEqual(verified.keys, [{ binding: f.executor.binding, verifiedAt }]);
  const settings = await f.db.one<{ approval: typeof approval }>('SELECT approval FROM function_settings WHERE function_id=$1', [functionId]);
  await verifyFunctionSettings(settings!.approval, rotation.binding);
  const executable = await f.context.functions.execution(f.owner.actor, functionId, f.context.custody, f.context.delegation);
  assert.deepEqual(executable.definition, definition);
});

test('保存済みの実行結果を、新鍵と共有相手の鍵で元の実行証明を検証して読み取る', async t => {
  const f = await apiFixture(); t.after(f.close);
  const resultPolicy = AccessPolicy.parse({ format: 2, origin: f.config.origin, id: f.intent.id,
    ownerId: f.owner.actor.id, contentType: ContentTypes.executionResult, revision: 1,
    authorities: [f.owner.binding], readers: [f.owner.binding, f.executor.binding], grants: [],
    producers: [{ executor: f.executor.binding, runId: f.intent.id, expiresAt: f.intent.expiresAt, materialRevision: 1 }],
  });
  const intent = { ...f.intent, resultApproval: await approvePolicy(resultPolicy, f.owner.binding, f.owner.keys) };
  await f.delegation.submit(f.owner.actor, await prepareRun(intent, f.operation, f.owner.keys));
  const claim = (await f.delegation.claim(f.executor.actor, f.environment.manifest.id))!;
  await f.delegation.dispatch(f.executor.actor, intent.id, claim.lease);
  const receipt = await makeReceipt(intent, 'succeeded', { ok: true, result: 'preserved result', error: null }, f.executor.keys);
  await f.delegation.finish(f.executor.actor, claim.lease, receipt);
  const rotation = await f.start(), pending = await f.ok('GET', rotation.path);
  assert.ok(pending.items.some((item: any) => item.kind === 'result'));
  for (const item of pending.items) await f.prepare(rotation, item);
  await f.ok('POST', rotation.path + '/commit');
  const task = await f.delegation.get(f.owner.actor, intent.id);
  assert.equal((await readReceipt(task.receipt!, intent, rotation.binding.id, rotation.keys)).result, 'preserved result');
  assert.equal((await readReceipt(task.receipt!, intent, f.executor.binding.id, f.executor.keys)).result, 'preserved result');
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.executor.binding);
  const owner = new CustodyClient(f.jsonApi(f.owner.token), f.config.origin, rotation.binding, rotation.keys, trust);
  assert.equal((await owner.result(task))!.result, 'preserved result');
});

test('準備後に開始した実行を待ってから鍵を交換し、失敗中も旧鍵でデータを読み取る', async t => {
  const f = await apiFixture(); t.after(f.close);
  const rotation = await f.start();
  for (const item of (await f.ok('GET', rotation.path)).items) await f.prepare(rotation, item);
  await f.delegation.submit(f.owner.actor, f.request);
  const blocked = await f.ok('GET', rotation.path);
  assert.equal(blocked.blockers[0].reason, 'execution_active');
  const commit = await f.api('POST', rotation.path + '/commit');
  assert.equal(commit.statusCode, 409);
  assert.equal(commit.json().error.code, 'rotation_blocked');
  const current = await f.custody.read(f.owner.actor, f.resource.id);
  assert.equal(decode(await reveal(current.content, f.owner.binding, f.owner.keys.encryption)), 'confidential-value');
  await f.delegation.cancel(f.owner.actor, f.intent.id);
  await f.ok('POST', rotation.path + '/commit');
});

test('鍵交換の途中で保存に失敗すると、鍵と暗号文の更新をすべて取り消して再試行する', async t => {
  const f = await apiFixture(); t.after(f.close);
  const rotation = await f.start();
  for (const item of (await f.ok('GET', rotation.path)).items) await f.prepare(rotation, item);
  await f.db.pool.query("CREATE FUNCTION reject_rotation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Temporary write failure'; END $$");
  await f.db.pool.query("CREATE TRIGGER reject_rotation BEFORE UPDATE ON key_rotations FOR EACH ROW WHEN (NEW.state='committed') EXECUTE FUNCTION reject_rotation()");
  assert.equal((await f.api('POST', rotation.path + '/commit')).statusCode, 500);
  assert.equal((await f.bindings.current(f.owner.actor.id)).binding.id, f.owner.binding.id);
  assert.equal((await f.ok('GET', rotation.path)).state, 'preparing');
  const old = await f.custody.read(f.owner.actor, f.resource.id);
  assert.equal(decode(await reveal(old.content, f.owner.binding, f.owner.keys.encryption)), 'confidential-value');
  await f.db.pool.query('DROP TRIGGER reject_rotation ON key_rotations');
  const committed = await Promise.all([f.ok('POST', rotation.path + '/commit'), f.ok('POST', rotation.path + '/commit')]);
  assert.ok(committed.every(result => result.state === 'committed'));
});

test('鍵交換の準備では新しい読み手を追加する変更を拒否し、元の共有範囲を維持する', async t => {
  const f = await apiFixture(); t.after(f.close);
  const rotation = await f.start(), item = (await f.ok('GET', rotation.path)).items[0];
  const legitimate = await f.prepare(rotation, item);
  assert.equal(legitimate.payload.kind, 'content');
  const next = legitimate.payload as { kind: 'content'; content: any };
  const content = await protect(encode('confidential-value'), { ...next.content.policy,
    readers: [...next.content.policy.readers, f.stranger.binding] }, next.content.materialRevision,
  f.owner.binding, f.owner.keys, next.content.metadata, item.source.content);
  const forged = await signRotationPreparation(rotation.input.id, f.owner.actor.id, rotation.binding.id,
    item.id, item.sourceDigest, { kind: 'content', content }, f.owner.keys.signing);
  const response = await f.api('PUT', rotation.path + '/items/content/' + item.id, forged);
  assert.equal(response.statusCode, 400);
  assert.equal(response.json().error.code, 'invalid_rotation_content');
  await f.ok('POST', rotation.path + '/commit');
  await assert.rejects(f.custody.read(f.stranger.actor, f.resource.id), { code: 'forbidden' });
});

test('既存のデータベースへ鍵交換の保存領域を移行し、元のプリンシパルと鍵を引き継ぐ', async t => {
  const f = await fixture(); t.after(f.close);
  const person = await f.person();
  await f.db.pool.query('DROP TABLE key_rotation_items,key_rotations');
  await f.db.pool.query("DELETE FROM schema_migrations WHERE name='008-key-rotations'");
  await assert.rejects(f.db.assertReady(), /Apply database migrations/);
  await f.db.migrate();
  await f.db.assertReady();
  assert.deepEqual((await f.bindings.current(person.actor.id)).binding, person.binding);
  const context = await createContext(f.config, { db: f.db, mailer: f.mailer });
  const keys = await newIdentityKeys(), binding = { ...bindKeys(person.actor.id, keys),
    generation: 2, previous: await hash(person.binding) };
  const rotation = await context.keyRotations.start(person.actor, person.actor.id, {
    id: randomUUID(), replacement: await signBinding(binding, keys),
    previousSignature: await sign(binding, person.keys.signing, 'key-replacement'),
  });
  assert.equal((await context.keyRotations.commit(person.actor, person.actor.id, rotation.id)).state, 'committed');
});

test('共有先は信頼済みの旧鍵による交換証明をたどり、複数回交換後も同じデータを読み続ける', async t => {
  const f = await apiFixture(); t.after(f.close);
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.owner.binding);
  const reader = new CustodyClient(f.jsonApi(f.executor.token), f.config.origin, f.executor.binding, f.executor.keys, trust);
  assert.equal(decode(await reader.reveal(f.resource.id)), 'confidential-value');
  const old = f.owner.binding;
  for (let index = 0; index < 2; index++) {
    const rotation = await f.start();
    for (const item of (await f.ok('GET', rotation.path)).items) await f.prepare(rotation, item);
    await f.ok('POST', rotation.path + '/commit');
    f.owner.binding = rotation.binding;
    f.owner.keys = rotation.keys;
  }
  assert.equal(decode(await reader.reveal(f.resource.id)), 'confidential-value');
  assert.equal((await trust.binding(f.owner.actor.id))!.id, f.owner.binding.id);
  await assert.rejects(reader.trusted(old));
});

test('鍵リセットの申請中は通常の鍵交換を待機し、申請を取り消した後に確定する', async t => {
  const f = await apiFixture(); t.after(f.close);
  const rotation = await f.start();
  for (const item of (await f.ok('GET', rotation.path)).items) await f.prepare(rotation, item);
  await f.keyResets.request(f.owner.actor, f.owner.actor.id);
  assert.ok((await f.ok('GET', rotation.path)).blockers.some((item: any) => item.reason === 'key_reset_pending'));
  const pending = await f.api('POST', rotation.path + '/commit');
  assert.equal(pending.statusCode, 409);
  assert.equal(pending.json().error.code, 'key_reset_pending');
  await f.keyResets.cancel(f.owner.actor, f.owner.actor.id);
  await f.ok('POST', rotation.path + '/commit');
});

test('鍵交換の信頼を引き継ぐときは旧鍵の署名と世代の連続性を検証する', async t => {
  const f = await apiFixture(); t.after(f.close);
  const rotation = await f.start();
  const proof = { previous: await signBinding(f.owner.binding, f.owner.keys),
    replacement: rotation.input.replacement, previousSignature: rotation.input.previousSignature };
  assert.equal(await verifiesReplacement(f.owner.binding, rotation.binding, [proof]), true);
  await assert.rejects(verifiesReplacement(f.owner.binding, rotation.binding, [{ ...proof,
    previousSignature: await sign(rotation.binding, f.stranger.keys.signing, 'key-replacement') }]));
  assert.equal(await verifiesReplacement(f.stranger.binding, rotation.binding, [proof]), false);
});
