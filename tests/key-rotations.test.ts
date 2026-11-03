import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { delegatedFixture, MemoryJournal } from './delegation-support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { bindKeys, hash, newIdentityKeys, sign, signBinding, verifiesReplacement } from '../shared/authority.js';
import { decode, encode, seal, unwrap, wrap } from '../shared/encryption.js';
import { AccessPolicy, ContentTypes, Operations, ProtectedContent, approvePolicy, prepareRun, protect, reveal } from '../shared/custody.js';
import {
  RotationHandoff, followKeys, openHandoff, prepareRotatedContent, rotateKeys, sealHandoff, signRotationPreparation,
} from '../shared/key-rotations.js';
import type { PreparedRotationPayload } from '../shared/key-rotations.js';
import { FUNCTION_RUNTIME_VERSION, HTTP_RUNTIME_VERSION, makeReceipt, readReceipt, signEnvironment } from '../shared/runtime-protocol.js';
import { openKeyring, signKeyring } from '../shared/keyring.js';
import { approveFunctionSettings, publishFunction, verifyFunctionSettings } from '../shared/function-api.js';
import { FunctionDefinition } from '../shared/contracts.js';
import { CustodyClient } from '../shared/client.js';
import { JournalTrust } from '../runtime/trust.js';
import type { z } from 'zod';
import { rotationStart } from './key-rotation-support.js';

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
    const { keys, binding, input } = await rotationStart(f.owner);
    const path = '/api/principals/' + f.owner.actor.id + '/key-rotations';
    const result = await ok('POST', path, input);
    return { keys, binding, input, result, path: path + '/' + input.id };
  }
  async function prepare(rotation: Awaited<ReturnType<typeof start>>, item: any) {
    let payload: PreparedRotationPayload;
    switch (item.kind) {
      case 'content':
      case 'result':
        payload = { kind: item.kind, content: await prepareRotatedContent(
          ProtectedContent.parse(item.source.content ?? item.source.receipt.content),
          f.owner.binding, rotation.binding, f.owner.binding, f.owner.keys, rotation.keys) };
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
  const rotation = await f.start();
  assert.equal(rotation.result.total, 1);
  const pending = await f.ok('GET', rotation.path);
  assert.equal(pending.items.length, 1);
  assert.equal((await f.ok('POST', rotation.path.slice(0, rotation.path.lastIndexOf('/')), rotation.input)).id, rotation.input.id);
  for (const item of pending.items) await f.prepare(rotation, item);
  assert.equal((await f.ok('GET', rotation.path)).prepared, 1);
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
  const claim = (await f.delegation.claim(f.executor.actor, f.environment.manifest.id, f.executor.binding.id))!;
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
    handoff: await sealHandoff(person.binding, binding, keys),
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

test('旧鍵を開けるサインインキーは、交換後に旧鍵あての受け渡しから新しい鍵を受け取る', async t => {
  const f = await apiFixture(); t.after(f.close);
  const issued = await f.authentication.issueKey(f.owner.actor.id, 'Laptop');
  const unlock = crypto.getRandomValues(new Uint8Array(32));
  const wrappedKey = await wrap(f.owner.keys, unlock, f.owner.actor.id);
  await f.authentication.setWrap(await f.confirmed(f.owner, { action: 'credential.wrap', principalId: f.owner.actor.id,
    credentialId: issued.credential.id, wrappedKey, publicKey: f.owner.binding.encryption }), f.owner.actor.id, issued.credential.id,
    wrappedKey, f.owner.binding.encryption);
  const rotation = await f.start();
  for (const item of (await f.ok('GET', rotation.path)).items) await f.prepare(rotation, item);
  await f.ok('POST', rotation.path + '/commit');
  const held = await f.db.one<{ private_wrap: string }>('SELECT private_wrap FROM credentials WHERE id=$1', [issued.credential.id]);
  const previous = await unwrap(held!.private_wrap, unlock, f.owner.actor.id);
  assert.deepEqual(previous, f.owner.keys);
  const response = await f.api('GET', '/api/principals/' + f.owner.actor.id + '/key-handoffs/' + f.owner.binding.id,
    undefined, issued.token);
  assert.equal(response.statusCode, 200, response.body);
  const next = await openHandoff(RotationHandoff.parse(response.json()), f.owner.binding, f.owner.keys.encryption);
  assert.deepEqual(next, { binding: rotation.binding, keys: rotation.keys });
  const other = await f.api('GET', '/api/principals/' + f.owner.actor.id + '/key-handoffs/' + f.owner.binding.id,
    undefined, f.stranger.token);
  assert.equal(other.statusCode, 403);
});

test('現在の鍵以外にあてた受け渡しでは鍵交換を開始しない', async t => {
  const f = await apiFixture(); t.after(f.close);
  const { keys, binding, input } = await rotationStart(f.owner);
  for (const handoff of [await sealHandoff(f.stranger.binding, binding, keys),
    await seal(encode(JSON.stringify(keys)), [{ id: f.owner.binding.id, publicKey: f.owner.binding.encryption }], 'another context')]) {
    const response = await f.api('POST', '/api/principals/' + f.owner.actor.id + '/key-rotations', { ...input, handoff });
    assert.equal(response.statusCode, 400);
    assert.equal(response.json().error.code, 'invalid_key_handoff');
  }
});

test('受け渡しの鍵が交換証明の公開鍵と合わなければ受け取らない', async t => {
  const f = await apiFixture(); t.after(f.close);
  const rotation = await f.start(), other = await rotationStart(f.owner);
  const proof = { previous: await signBinding(f.owner.binding, f.owner.keys),
    replacement: rotation.input.replacement, previousSignature: rotation.input.previousSignature };
  await assert.rejects(openHandoff({ replacement: proof, handoff: await sealHandoff(f.owner.binding, rotation.binding, other.keys) },
    f.owner.binding, f.owner.keys.encryption));
  assert.deepEqual(await openHandoff({ replacement: proof, handoff: rotation.input.handoff }, f.owner.binding, f.owner.keys.encryption),
    { binding: rotation.binding, keys: rotation.keys });
});

test('鍵交換を最後まで行い、旧鍵を持つ別の端末は次に使うとき新しい鍵へ移って同じデータを読む', async t => {
  const f = await apiFixture(); t.after(f.close);
  const laptop = await f.authentication.issueKey(f.owner.actor.id, 'Laptop');
  const result = await rotateKeys(f.jsonApi(f.owner.token), { binding: f.owner.binding, keys: f.owner.keys });
  assert.equal(result.state, 'committed');
  if (result.state !== 'committed') return;
  assert.deepEqual((await f.bindings.current(f.owner.actor.id)).binding, result.binding);
  const followed = await followKeys(f.jsonApi(laptop.token), { binding: f.owner.binding, keys: f.owner.keys });
  assert.deepEqual(followed, { binding: result.binding, keys: result.keys });
  assert.equal(await followKeys(f.jsonApi(laptop.token), followed!), null);
  const client = new CustodyClient(f.jsonApi(laptop.token), f.config.origin, followed!.binding, followed!.keys,
    new JournalTrust(new MemoryJournal()));
  assert.equal(decode(await client.reveal(f.resource.id)), 'confidential-value');
});

test('途中で止まった鍵交換は、旧鍵を持つ端末が同じ新しい鍵で続きから確定する', async t => {
  const f = await apiFixture(); t.after(f.close);
  const rotation = await f.start();
  const result = await rotateKeys(f.jsonApi(f.owner.token), { binding: f.owner.binding, keys: f.owner.keys });
  assert.equal(result.state, 'committed');
  if (result.state === 'committed') assert.deepEqual(result.keys, rotation.keys);
});

async function readOnlyItem(f: Awaited<ReturnType<typeof apiFixture>>) {
  const policy = AccessPolicy.parse({ format: 2, id: randomUUID(), origin: f.config.origin, ownerId: f.owner.actor.id,
    contentType: ContentTypes.value, revision: 1, authorities: [f.owner.binding],
    readers: [f.owner.binding, f.executor.binding], grants: [] });
  const content = await protect(encode('owner-signed-value'), policy, 1, f.owner.binding, f.owner.keys);
  return f.custody.put(f.owner.actor, { name: 'Owner signed', content, data: { bytes: 18 } });
}

test('読み手として含まれるだけの項目は署名者を示して待ち、署名者が自分の鍵で準備すると鍵交換を確定する', async t => {
  const f = await apiFixture(); t.after(f.close);
  const item = await readOnlyItem(f);
  const executor = { binding: f.executor.binding, keys: f.executor.keys };
  const waiting = await rotateKeys(f.jsonApi(f.executor.token), executor);
  assert.equal(waiting.state, 'waiting');
  if (waiting.state !== 'waiting') return;
  assert.deepEqual(waiting.waiting.map(value => [value.id, value.signers]), [[item.id, [f.owner.actor.id]]]);
  assert.equal((await f.api('POST', '/api/principals/' + f.executor.actor.id + '/key-rotations/' + waiting.rotationId + '/commit',
    undefined, f.executor.token)).json().error.code, 'rotation_not_ready');
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.executor.binding);
  const owner = new CustodyClient(f.jsonApi(f.owner.token), f.config.origin, f.owner.binding, f.owner.keys, trust);
  assert.deepEqual(await owner.endorseKeyRotations(), { done: [item.id], failed: [] });
  const result = await rotateKeys(f.jsonApi(f.executor.token), executor);
  assert.equal(result.state, 'committed');
  if (result.state !== 'committed') return;
  const content = await f.custody.read(f.executor.actor, item.id);
  assert.equal(decode(await reveal(content.content, result.binding, result.keys.encryption)), 'owner-signed-value');
  assert.equal(decode(await owner.reveal(item.id)), 'owner-signed-value');
});

test('交換される鍵を確かめていない署名者や署名者でない者は、他人の鍵交換の項目を準備しない', async t => {
  const f = await apiFixture(); t.after(f.close);
  const item = await readOnlyItem(f);
  const waiting = await rotateKeys(f.jsonApi(f.executor.token), { binding: f.executor.binding, keys: f.executor.keys });
  assert.equal(waiting.state, 'waiting');
  if (waiting.state !== 'waiting') return;
  const owner = new CustodyClient(f.jsonApi(f.owner.token), f.config.origin, f.owner.binding, f.owner.keys,
    new JournalTrust(new MemoryJournal()));
  assert.deepEqual(await owner.endorseKeyRotations(), { done: [], failed: [{ id: item.id, code: 'identity_untrusted' }] });
  const { items } = await f.ok('GET', '/api/key-rotations/requests');
  const payload = { sourceDigest: items[0].sourceDigest, payload: { kind: 'content', content: await prepareRotatedContent(
    ProtectedContent.parse(items[0].source.content), f.executor.binding, items[0].rotation.replacement.binding,
    f.owner.binding, f.owner.keys) } };
  const path = '/api/principals/' + f.executor.actor.id + '/key-rotations/' + waiting.rotationId + '/items/content/' + item.id + '/endorsement';
  assert.equal((await f.api('PUT', path, payload, f.stranger.token)).statusCode, 403);
  assert.equal((await f.api('PUT', path, payload, f.executor.token)).statusCode, 403);
  assert.equal((await f.api('GET', '/api/key-rotations/requests', undefined, f.stranger.token)).json().items.length, 0);
});

test('鍵交換の確定は、その鍵を使う書き込みだけを待ち、他のプリンシパルの書き込みを止めない', async t => {
  const f = await apiFixture(); t.after(f.close);
  const rotation = await f.start();
  for (const item of (await f.ok('GET', rotation.path)).items) await f.prepare(rotation, item);
  const writer = await f.db.pool.connect();
  try {
    await writer.query('BEGIN');
    await writer.query('SELECT id FROM principal_key_bindings WHERE id=$1 FOR SHARE', [f.owner.binding.id]);
    let finished = false;
    const commit = f.ok('POST', rotation.path + '/commit').then(value => { finished = true; return value; });
    await new Promise(resolve => setTimeout(resolve, 200));
    assert.equal(finished, false);
    const other = await f.resources.insert(f.stranger.actor.id, 'variable', 'Other value', {}, {});
    await f.db.pool.query('UPDATE credentials SET last_used_at=now() WHERE principal_id=$1', [f.stranger.actor.id]);
    await f.resources.update(other, { name: 'Renamed value' });
    await writer.query('COMMIT');
    assert.equal((await commit).state, 'committed');
  } finally { writer.release(); }
});

test('秘密鍵だけを包んだパスキーは、公開鍵から交換の受け渡しをたどって新しい鍵を受け取る', async t => {
  const f = await apiFixture(); t.after(f.close);
  const first = await rotateKeys(f.jsonApi(f.owner.token), { binding: f.owner.binding, keys: f.owner.keys });
  assert.equal(first.state, 'committed');
  if (first.state !== 'committed') return;
  const second = await rotateKeys(f.jsonApi(f.owner.token), first);
  assert.equal(second.state, 'committed');
  if (second.state !== 'committed') return;
  assert.deepEqual(await followKeys(f.jsonApi(f.owner.token), { principalId: f.owner.actor.id, keys: f.owner.keys }),
    { binding: second.binding, keys: second.keys });
  assert.equal(await followKeys(f.jsonApi(f.owner.token), { principalId: f.owner.actor.id, keys: second.keys }), null);
  const other = await rotationStart(f.stranger);
  await assert.rejects(followKeys(f.jsonApi(f.owner.token), { principalId: f.owner.actor.id, keys: other.keys }));
});

test('鍵の交換後は旧鍵を名乗る実行環境に依頼を渡さず、新しい鍵の実行環境に渡す', async t => {
  const f = await apiFixture(); t.after(f.close);
  const id = f.environment.manifest.id;
  const result = await rotateKeys(f.jsonApi(f.executor.token), { binding: f.executor.binding, keys: f.executor.keys });
  assert.equal(result.state, 'committed');
  if (result.state !== 'committed') return;
  for (const path of ['/claim', '/invocations/claim', '/processes/claim']) {
    const stale = await f.api('POST', '/api/environments/' + id + path, { executor: f.executor.binding.id }, f.executor.token);
    assert.equal(stale.statusCode, 409, path);
    assert.equal(stale.json().error.code, 'key_binding_changed');
  }
  assert.equal((await f.api('POST', '/api/environments/' + id + '/claim', { executor: result.binding.id }, f.executor.token)).statusCode, 200);
});

test('前のリリースの実行環境は登録も依頼の受け取りもできず、生存確認を更新しない', async t => {
  const f = await apiFixture(); t.after(f.close);
  const id = f.environment.manifest.id;
  await f.db.pool.query("UPDATE executor_environments SET heartbeat_at=now()-interval '10 minutes' WHERE resource_id=$1", [id]);
  for (const path of ['/claim', '/invocations/claim', '/processes/claim']) {
    const response = await f.api('POST', '/api/environments/' + id + path, {}, f.executor.token);
    assert.equal(response.statusCode, 426, path);
    assert.equal(response.json().error.code, 'executor_update_required');
  }
  const outdated = await signEnvironment({ ...f.environment.manifest, functionVersion: FUNCTION_RUNTIME_VERSION - 1,
    httpVersion: HTTP_RUNTIME_VERSION - 1, revision: f.environment.manifest.revision + 1 }, f.executor.keys);
  const registered = await f.api('PUT', '/api/environments/' + id + '/registration', outdated, f.executor.token);
  assert.equal(registered.statusCode, 426);
  const row = await f.db.one<{ stale: boolean }>(
    "SELECT heartbeat_at<now()-interval '5 minutes' AS stale FROM executor_environments WHERE resource_id=$1", [id]);
  assert.equal(row!.stale, true);
});

test('鍵の照合直後に交換が確定しても、旧鍵の実行環境は同じ受け取りで依頼を取得しない', async t => {
  const f = await apiFixture(); t.after(f.close);
  const id = f.environment.manifest.id, previous = f.executor.binding;
  await await f.api('PUT', '/api/environments/' + id + '/processes/registration', { workingDirectory: f.config.dataDirectory }, f.executor.token);
  const heartbeat = f.context.delegation.heartbeat.bind(f.context.delegation);
  let rotated = false;
  f.context.delegation.heartbeat = async (actor, environmentId, executor) => {
    const value = await heartbeat(actor, environmentId, executor);
    if (!rotated) {
      rotated = true;
      const result = await rotateKeys(f.jsonApi(f.executor.token), { binding: f.executor.binding, keys: f.executor.keys });
      assert.equal(result.state, 'committed');
    }
    return value;
  };
  for (const claim of [() => f.context.delegation.claim(f.executor.actor, id, previous.id),
    () => f.context.processes.claim(f.executor.actor, id, previous.id),
    () => f.context.invocations.claim(f.executor.actor, id, previous.id)]) {
    rotated = false;
    await assert.rejects(claim(), { code: 'key_binding_changed' });
  }
});

test('権限の引き継ぎ履歴が上限に達した項目は、理由を示して鍵交換を確定させない', async t => {
  const f = await apiFixture(); t.after(f.close);
  let held = { binding: f.executor.binding, keys: f.executor.keys };
  for (let index = 0; index < 16; index++) {
    const result = await rotateKeys(f.jsonApi(f.executor.token), held);
    assert.equal(result.state, 'committed');
    if (result.state !== 'committed') return;
    held = result;
  }
  assert.equal((await f.custody.read(f.owner.actor, f.resource.id)).content.lineage?.length, 16);
  const blocked = await rotateKeys(f.jsonApi(f.executor.token), held);
  assert.equal(blocked.state, 'blocked');
  if (blocked.state !== 'blocked') return;
  assert.deepEqual(blocked.blockers, [{ kind: 'content', id: f.resource.id, reason: 'authority_history_full' }]);
  const path = '/api/principals/' + f.executor.actor.id + '/key-rotations/' + blocked.rotationId;
  const commit = await f.api('POST', path + '/commit', undefined, f.executor.token);
  assert.equal(commit.json().error.code, 'rotation_blocked');
  assert.equal((await f.api('DELETE', path, undefined, f.executor.token)).statusCode, 200);
  assert.deepEqual((await f.bindings.current(f.executor.actor.id)).binding, held.binding);
});
