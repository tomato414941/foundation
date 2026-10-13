import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { flowFixture, jsonResponse } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { FunctionDefinition, Resource } from '../shared/contracts.js';
import type { FunctionSpec } from '../shared/contracts.js';
import { CustodyClient } from '../shared/client.js';
import { FunctionClient, InvocationSubmissionError } from '../shared/function-client.js';
import { FunctionBroker, FunctionExecutor } from '../runtime/functions.js';
import { InvocationCompletion } from '../shared/function-api.js';
import { DeliveryPending } from '../runtime/executor.js';
import { JournalTrust } from '../runtime/trust.js';
import { canonical, hash, sign } from '../shared/authority.js';
import { ContentTypes, Operations, authorizeUse, protect, reveal } from '../shared/custody.js';
import { DomainError } from '../server/errors.js';
import { decode, encode } from '../shared/encryption.js';
import { functionArguments, functionProgram } from '../shared/functions.js';

const script = 'let text="";process.stdin.on("data",c=>text+=c);process.stdin.on("end",()=>{const args=JSON.parse(text);console.log(JSON.stringify({message:args.message,configured:!!process.env.TOKEN}));});';
const definition = (environmentId: string, sourceId?: string, command = script) => FunctionDefinition.parse({
  environmentId, program: { kind: 'command', command: ['node', '-e', command],
    inputs: sourceId ? [{ name: 'TOKEN', source: { id: sourceId } }] : [], timeoutSeconds: 5 },
  parameters: [{ name: 'message', label: 'Message', default: 'Hello' }], result: 'json',
});
async function save(f: Awaited<ReturnType<typeof flowFixture>>, spec: FunctionSpec) {
  const result = await f.functions.save({ ownerId: f.owner.actor.id, name: 'Processor ' + crypto.randomUUID(), definition: spec });
  if (result.kind !== 'function') throw new Error('Expected a function.');
  return { ...result, data: FunctionDefinition.parse(result.data) };
}
async function caller(f: Awaited<ReturnType<typeof flowFixture>>) {
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.executor.binding); await trust.rememberBinding(f.owner.binding);
  const client = new CustodyClient(f.api(f.stranger.token), f.config.origin, f.stranger.binding, f.stranger.keys, trust);
  return { client, functions: new FunctionClient(f.api(f.stranger.token), client) };
}

test('引数の必須項目と既定値を検証し、宣言した引数だけを固定処理へ渡す', () => {
  const spec = definition(crypto.randomUUID());
  assert.deepEqual(functionArguments(spec, {}), { message: 'Hello' });
  assert.throws(() => functionArguments(spec, { other: 'x' }));
  assert.throws(() => functionArguments(spec, { message: '' }));
  const program = functionProgram(spec, { message: '$(rm -rf anything)' });
  assert.equal(program.kind, 'command');
  if (program.kind === 'command') {
    assert.deepEqual(program.command, spec.program.kind === 'command' ? spec.program.command : []);
    assert.deepEqual(JSON.parse(program.stdin!), { message: '$(rm -rf anything)' });
  }
});

test('数値・真偽値・JSONの型と既定値を保って関数の引数を検証する', () => {
  const spec = FunctionDefinition.parse({ environmentId: crypto.randomUUID(),
    program: { kind: 'command', command: ['node', '-e', ''] }, parameters: [
      { name: 'count', label: 'Count', type: 'number', default: 0 },
      { name: 'enabled', label: 'Enabled', type: 'boolean', default: false },
      { name: 'payload', label: 'Payload', type: 'json', default: null },
      { name: 'constructor', label: 'Constructor', required: false },
    ] });
  assert.deepEqual(functionArguments(spec, {}), { count: 0, enabled: false, payload: null });
  assert.deepEqual(functionArguments(spec, { count: 2.5, enabled: true, payload: { items: [1, false, null] } }),
    { count: 2.5, enabled: true, payload: { items: [1, false, null] } });
  assert.throws(() => functionArguments(spec, { count: '2' }));
  assert.throws(() => functionArguments(spec, { enabled: 'false' }));
  assert.throws(() => functionArguments(spec, { count: Infinity }));
});

test('呼び出し権限だけを持つ利用者がAPIトークンで関数を実行し、秘密を開示せず結果を受け取る', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id, f.resource.id));
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id });
  const functions = new FunctionClient(f.api(f.stranger.token));
  const view = await functions.get(fn.id);
  assert.deepEqual(view.data, { description: '', parameters: fn.data.parameters, result: 'json', inputAccess: { expiresAt: null } });
  assert.deepEqual(view.permissions, ['execute']);
  const { client } = await caller(f);
  await assert.rejects(client.read(f.resource.id));
  await assert.rejects(client.environment(f.environment.manifest.id));
  await assert.rejects(f.authorization.requireResource(f.stranger.actor, await f.resources.get(fn.id), 'read'));
  const text = '\"; process.exit(99); //';
  const invocation = await functions.invoke(fn.id, { message: text });
  await f.functionExecutor.tick();
  const result = await functions.result(invocation.id);
  assert.equal(result.state, 'succeeded', JSON.stringify(result));
  assert.deepEqual(result.results[0], { message: text, configured: true });
  await assert.rejects(reveal(await f.context.custody.get(f.resource.id), f.stranger.binding, f.stranger.keys.encryption));
  await assert.rejects(client.submit(f.stranger.actor.id, f.environment.manifest.id, {
    kind: 'command', command: ['node', '-e', 'console.log(process.env.TOKEN)'],
    inputs: [{ name: 'TOKEN', source: { id: f.resource.id }, format: 'text' }], timeoutSeconds: 5 }));
});

test('コードを読む権限と呼び出す権限を別々に渡し、管理APIから関数を更新して削除する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id));
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'reader', objectId: fn.id });
  const functions = new FunctionClient(f.api(f.stranger.token));
  assert.deepEqual((await functions.get(fn.id)).data, fn.data);
  await assert.rejects(functions.invoke(fn.id), error => (error as { status: number }).status === 403);
  const updated = await f.functions.save({ ownerId: fn.ownerId, name: 'Updated function', definition: fn.data,
    resourceId: fn.id, version: fn.version });
  assert.equal(updated.name, 'Updated function'); assert.equal(updated.version, fn.version + 1);
  await assert.rejects(f.functions.save({ ownerId: fn.ownerId, name: fn.name, definition: fn.data,
    resourceId: fn.id, version: fn.version }), error => (error as { status: number }).status === 409);
  await f.functions.remove(fn.id);
  await assert.rejects(functions.get(fn.id), error => (error as { status: number }).status === 404);
});

test('JSONの引数の型を保ち、宣言と一致しない入力を受付時に検証する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'command', command: ['node', '-e', 'let text="";process.stdin.on("data",c=>text+=c);process.stdin.on("end",()=>console.log(JSON.stringify(JSON.parse(text))));'] },
    parameters: [{ name: 'count', label: 'Count', type: 'number' }, { name: 'enabled', label: 'Enabled', type: 'boolean' },
      { name: 'payload', label: 'Payload', type: 'json' }], result: 'json' }));
  const args = { count: 0, enabled: false, payload: { values: [1, 'two', null], nested: { ready: true } } };
  await assert.rejects(f.functions.invoke(fn.id, { ...args, count: '0' }), error => (error as { status: number }).status === 400);
  const invocation = await f.functions.invoke(fn.id, args);
  await f.functionExecutor.tick();
  assert.deepEqual((await f.functions.result(invocation.id)).results[0], args);
});

test('HTTP関数のJSON本文に数値・真偽値・JSONの引数をその型のまま設定する', async t => {
  const f = await flowFixture(request => jsonResponse(JSON.parse(String(request.body)))); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/items{?count}', method: 'POST',
      json: { count: '{{count}}', enabled: '{{enabled}}', payload: '{{payload}}', caption: 'Count {{count}}', constructor: '{{constructor}}' } } },
    parameters: [{ name: 'count', label: 'Count', type: 'number' }, { name: 'enabled', label: 'Enabled', type: 'boolean' },
      { name: 'payload', label: 'Payload', type: 'json' }, { name: 'constructor', label: 'Constructor', required: false }], result: 'json' }));
  const args = { count: 0, enabled: false, payload: [1, { name: 'item' }, null] };
  const invocation = await f.functions.invoke(fn.id, args);
  await f.functionExecutor.tick();
  assert.deepEqual((await f.functions.result(invocation.id)).results[0], { status: 200, headers: { 'content-type': 'application/json' }, body: { ...args, caption: 'Count 0', constructor: null } });
  assert.equal(new URL(f.requests[0]!.url).searchParams.get('count'), '0');
});

test('承認された定義だけを実行し、変更後の関数を再承認して呼び出す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id, f.resource.id));
  const queued = await f.functions.invoke(fn.id);
  const changed = definition(f.environment.manifest.id, f.resource.id, 'console.log(JSON.stringify({changed:true}))');
  await f.functions.save({ ownerId: fn.ownerId, name: fn.name, resourceId: fn.id, version: fn.version, definition: changed });
  assert.equal(await f.functionExecutor.tick(), false);
  assert.equal((await f.functions.result(queued.id)).state, 'failed');
  const invocation = await f.functions.invoke(fn.id);
  await f.functionExecutor.tick();
  assert.deepEqual((await f.functions.result(invocation.id)).results[0], { changed: true });
});

test('共有許可を取り消した関数の待機中の呼び出しを開始前に止める', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id));
  const line = { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id };
  await f.relations.draw(f.owner.actor, line);
  const functions = new FunctionClient(f.api(f.stranger.token)), invocation = await functions.invoke(fn.id);
  await f.relations.erase(f.owner.actor, line);
  assert.equal(await f.functionExecutor.tick(), false);
  assert.equal((await functions.result(invocation.id)).state, 'failed');
});

test('入力の利用許可の期限を確認し、所有者が再承認した関数を呼び出す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id, f.resource.id));
  const previous = await f.client.read(f.resource.id);
  await f.client.save(f.resource.name, await f.client.reveal(f.resource.id), { ...previous.content.policy,
    revision: previous.content.policy.revision + 1, grants: previous.content.policy.grants.map(grant =>
      'function' in grant && grant.function.id === fn.id ? { ...grant, expiresAt: new Date(Date.now() - 1000).toISOString() } : grant) }, { previous });
  await assert.rejects(f.functions.invoke(fn.id), error => (error as { code: string }).code === 'function_not_approved');
  await f.functions.save({ ownerId: fn.ownerId, name: fn.name, resourceId: fn.id, version: fn.version, definition: fn.data });
  const invocation = await f.functions.invoke(fn.id);
  await f.functionExecutor.tick();
  assert.equal((await f.functions.result(invocation.id)).state, 'succeeded');
});

test('共有された関数の結果を呼び出す人の暗号化された変数へ保存する', async t => {
  const f = await flowFixture(() => jsonResponse({ count: 7 })); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/items{?query}',
      bindings: [{ pointer: '/headers/authorization', parts: ['Bearer ', { id: f.resource.id }] }] } },
    parameters: [{ name: 'query', label: 'Query' }], result: 'json' }));
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id });
  const { client, functions } = await caller(f);
  const invocation = await functions.invoke(fn.id, { query: 'hello world' }, { save: { '/body/count': 'Count' } });
  await f.functionExecutor.tick();
  const result = await functions.result(invocation.id);
  assert.equal(result.state, 'succeeded', JSON.stringify(result));
  const output = result.results[0] as { saved: Record<string, string> };
  assert.equal(decode(await client.reveal(output.saved.Count!)), '7');
  assert.equal(f.requests[0]!.headers!.authorization, 'Bearer confidential-value');
  assert.equal(new URL(f.requests[0]!.url).searchParams.get('query'), 'hello world');
});

test('HTTP送信の応答が失われた場合は結果不明を返し、同じ呼び出しIDで状態を確認する', async t => {
  const f = await flowFixture(() => { throw new DomainError(502, 'service_unavailable', 'Response lost'); }); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/action', method: 'POST' } } }));
  const id = crypto.randomUUID(), call = await f.functions.invoke(fn.id, {}, { id });
  await f.functionExecutor.tick();
  const result = await f.functions.result(call.id);
  assert.equal(result.state, 'uncertain');
  assert.equal(result.error?.code, 'execution_uncertain');
  assert.equal((await f.functions.invoke(fn.id, {}, { id })).state, 'uncertain');
  assert.equal(await f.functionExecutor.tick(), false);
  assert.equal(f.requests.length, 1);
});

test('HTTP関数の成功応答をステータス・ヘッダー・本文として返し、受付済みの応答を確認する', async t => {
  const f = await flowFixture(() => ({ status: 202, headers: { 'content-type': 'application/json', 'x-request-id': 'accepted' }, body: encode('{"queued":true}') })); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/action', method: 'POST' } } }));
  const call = await f.functions.invoke(fn.id); await f.functionExecutor.tick();
  const result = await f.functions.result(call.id);
  assert.equal(result.state, 'succeeded');
  assert.deepEqual(result.results[0], { status: 202, headers: { 'content-type': 'application/json', 'x-request-id': 'accepted' }, body: { queued: true } });
});

test('HTTP関数の転送やエラー応答を失敗として返し、応答のステータスを知らせる', async t => {
  let status = 302;
  const f = await flowFixture(() => ({ status, headers: {}, body: encode('response') })); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', responseFormat: 'text', request: { url: 'https://service.example/action', method: 'POST' } } }));
  for (status of [302, 401, 500]) {
    const call = await f.functions.invoke(fn.id); await f.functionExecutor.tick();
    const result = await f.functions.result(call.id);
    assert.equal(result.state, 'failed'); assert.equal(result.error?.code, 'service_response');
    assert.equal(result.error?.message, 'The service returned HTTP ' + status + '.');
  }
  assert.equal(f.requests.length, 3);
});

test('HTTPのテキスト本文と本文のない成功応答を指定した形式で返す', async t => {
  let status = 200;
  const f = await flowFixture(() => ({ status, headers: {}, body: encode(status === 200 ? 'plain text' : '') })); t.after(f.close);
  const text = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', responseFormat: 'text', request: { url: 'https://service.example/action' } } }));
  let call = await f.functions.invoke(text.id); await f.functionExecutor.tick();
  assert.deepEqual((await f.functions.result(call.id)).results[0], { status: 200, headers: {}, body: 'plain text' });
  status = 204;
  const empty = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/action' } } }));
  call = await f.functions.invoke(empty.id); await f.functionExecutor.tick();
  assert.deepEqual((await f.functions.result(call.id)).results[0], { status: 204, headers: {}, body: null });
});

test('関数のJSON結果の数値・真偽値・文字列をその型のまま返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const policy = await f.client.policy(f.owner.actor.id, ContentTypes.value);
  const input = await f.client.save('Limit', encode('1'), policy);
  const fn = await save(f, definition(f.environment.manifest.id, input.id,
    'console.log(JSON.stringify({count:Number(process.env.TOKEN),ok:true,label:"item1"}))'));
  const call = await f.functions.invoke(fn.id); await f.functionExecutor.tick();
  const result = await f.functions.result(call.id);
  assert.equal(result.state, 'succeeded');
  assert.deepEqual(result.results[0], { count: 1, ok: true, label: 'item1' });
});

test('関数の非公開の出力を元の値のまま暗号化して保存し、保存先を返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id, f.resource.id,
    'console.log(JSON.stringify({credential:process.env.TOKEN}))'));
  const call = await f.functions.invoke(fn.id, {}, { save: { '/credential': 'Private credential' } });
  await f.functionExecutor.tick();
  const result = await f.functions.result(call.id), output = result.results[0] as { saved: Record<string, string> };
  assert.equal(result.state, 'succeeded');
  assert.deepEqual(result.results[0], { saved: { 'Private credential': output.saved['Private credential'] } });
  assert.equal(decode(await f.client.reveal(output.saved['Private credential']!)), 'confidential-value');
});

test('継続許可された関数の入力を30日後も使い、所有者が撤回した許可を確認する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id, f.resource.id));
  const previous = await f.client.read(f.resource.id), content = previous.content;
  const intent = { ...f.intent, operation: Operations.function, functionId: fn.id, functionDigest: await hash(fn.data),
    sources: [{ id: content.policy.id, policyDigest: await hash(content.policy), materialRevision: content.materialRevision }] };
  await authorizeUse(content, intent, { now: Date.now() + 35 * 86_400_000 });
  await f.client.save(f.resource.name, await f.client.reveal(f.resource.id), { ...content.policy,
    revision: content.policy.revision + 1, grants: content.policy.grants.filter(grant => !('function' in grant && grant.function.id === fn.id)) }, { previous });
  await assert.rejects(f.functions.invoke(fn.id), { code: 'function_not_approved' });
});

test('関数の入力に指定した利用期限を適用し、期限切れの呼び出しを止める', async t => {
  const f = await flowFixture(); t.after(f.close);
  const expiresAt = new Date(Date.now() + 40 * 86_400_000).toISOString();
  const spec = definition(f.environment.manifest.id, f.resource.id); spec.inputAccess.expiresAt = expiresAt;
  const fn = await save(f, spec), content = (await f.client.read(f.resource.id)).content;
  const grant = content.policy.grants.find(grant => 'function' in grant && grant.function.id === fn.id);
  assert.equal(grant?.expiresAt, expiresAt);
  const call = await f.functions.invoke(fn.id); await f.functionExecutor.tick();
  assert.equal((await f.functions.result(call.id)).state, 'succeeded');
  t.mock.method(Date, 'now', () => Date.parse(expiresAt) + 1);
  await assert.rejects(f.functions.invoke(fn.id), { code: 'function_not_approved' });
  t.mock.restoreAll();
});

test('関数で生成した秘密を暗号化して保存し、呼び出す人へ保存先のIDを返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id, undefined,
    'console.log(JSON.stringify({credential:require("crypto").randomBytes(16).toString("hex")}))'));
  const invocation = await f.functions.invoke(fn.id, {}, { save: { '/credential': 'Generated credential' } });
  await f.functionExecutor.tick();
  const result = await f.functions.result(invocation.id);
  assert.equal(result.state, 'succeeded', JSON.stringify(result));
  const output = result.results[0] as { saved: Record<string, string> }, id = output.saved['Generated credential']!;
  assert.deepEqual(result.results[0], { saved: { 'Generated credential': id } });
  assert.match(decode(await f.client.reveal(id)), /^[a-f0-9]{32}$/);
});

test('処理の終了コードと結果の形式を検証し、失敗の理由を返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  for (const [command, code, timeout] of [['process.stderr.write("problem");process.exit(3)', 'function_failed', 5], ['console.log("invalid JSON")', 'invalid_function_result', 5], ['setInterval(()=>{},1000)', 'function_timeout', 1]] as const) {
    const spec = definition(f.environment.manifest.id, undefined, command);
    if (spec.program.kind === 'command') spec.program.timeoutSeconds = timeout;
    const fn = await save(f, spec), invocation = await f.functions.invoke(fn.id);
    await f.functionExecutor.tick();
    const result = await f.functions.result(invocation.id);
    assert.equal(result.state, 'failed'); assert.equal(result.error!.code, code);
  }
});

test('関数の入力を更新して新しい値を使い、呼び出しごとに作業ファイルを用意する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const program = 'const fs=require("fs");const count=(fs.existsSync("counter")?Number(fs.readFileSync("counter")):0)+1;fs.writeFileSync("counter",String(count));console.log(JSON.stringify({count,length:process.env.TOKEN.length}));';
  const fn = await save(f, definition(f.environment.manifest.id, f.resource.id, program));
  const policy = await f.client.policy(f.owner.actor.id, ContentTypes.value);
  const newSource = await f.client.save('New input', encode('new-private-token-value'), policy);
  await f.functions.save({ ownerId: fn.ownerId, resourceId: fn.id, version: fn.version, name: fn.name,
    definition: definition(f.environment.manifest.id, newSource.id, program) });
  for (let index = 0; index < 2; index++) {
    const invocation = await f.functions.invoke(fn.id);
    await f.functionExecutor.tick();
    assert.deepEqual((await f.functions.result(invocation.id)).results[0], { count: 1, length: 'new-private-token-value'.length });
  }
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'confidential-value');
});

test('同じ呼び出しIDで再試行しても処理を一度だけ実行する', async t => {
  const f = await flowFixture(() => jsonResponse({ done: true })); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/action', method: 'POST' } } }));
  const id = crypto.randomUUID(), first = await f.functions.invoke(fn.id, {}, { id });
  assert.equal((await f.functions.invoke(fn.id, {}, { id })).id, first.id);
  await f.functionExecutor.tick();
  assert.equal((await f.functions.invoke(fn.id, {}, { id })).state, 'succeeded');
  assert.equal(f.requests.length, 1);
  await assert.rejects(f.functions.invoke(fn.id, { different: true }, { id }), error => (error as { status: number }).status === 409);
});

test('受付後に通信が途切れても呼び出しIDから確認し、同じ処理を再実行せず再試行する', async t => {
  const f = await flowFixture(() => jsonResponse({ done: true })); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/action', method: 'POST' } } }));
  const api = f.api(f.owner.token);
  const functions = new FunctionClient({ async json(path, options, schema) {
    await api.json(path, options, schema);
    throw new Error('The response was lost.');
  } });
  let id = '';
  await assert.rejects(functions.invoke(fn.id), error => {
    assert.ok(error instanceof InvocationSubmissionError); id = error.invocationId; return true;
  });
  assert.equal((await f.functions.result(id)).state, 'running');
  assert.equal((await f.functions.invoke(fn.id, {}, { id })).id, id);
  await f.functionExecutor.tick();
  assert.equal((await f.functions.result(id)).state, 'succeeded');
  assert.equal(f.requests.length, 1);
});

test('所有者の署名で承認したプログラムを確認してから秘密を使う処理を開始する', async t => {
  const f = await flowFixture(() => jsonResponse({ done: true })); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/action', method: 'POST',
      bindings: [{ pointer: '/headers/authorization', parts: [{ id: f.resource.id }] }] } } }));
  const invocation = await f.functions.invoke(fn.id);
  class AlteredBroker extends FunctionBroker {
    override async claim(id: string) {
      const value = await super.claim(id);
      if (value?.publication.definition.program.kind === 'http')
        value.publication.definition.program.request.url = 'https://other.example/action';
      return value;
    }
  }
  const broker = new AlteredBroker(f.functionExecutor.broker.api);
  await new FunctionExecutor(f.executor, broker, f.journal).tick();
  assert.equal((await f.functions.result(invocation.id)).error?.code, 'invalid_function');
  assert.equal(f.requests.length, 0);
  const approved = await f.functions.invoke(fn.id);
  await f.functionExecutor.tick();
  assert.equal((await f.functions.result(approved.id)).state, 'succeeded');
  assert.equal(f.requests.length, 1);
});

test('結果の送信が途切れても保存した署名付きの結果を再送し、処理を一度だけ実行する', async t => {
  const f = await flowFixture(() => jsonResponse({ done: true })); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/action', method: 'POST' } } }));
  const invocation = await f.functions.invoke(fn.id);
  class LostResponseBroker extends FunctionBroker {
    lose = true;
    override async finish(lease: string, completion: Parameters<FunctionBroker['finish']>[1]) {
      const value = await super.finish(lease, completion);
      if (this.lose) { this.lose = false; throw new Error('The result response was lost.'); }
      return value;
    }
  }
  const worker = new FunctionExecutor(f.executor, new LostResponseBroker(f.functionExecutor.broker.api), f.journal);
  await assert.rejects(worker.tick(), DeliveryPending);
  assert.equal((await f.functions.result(invocation.id)).state, 'succeeded');
  assert.deepEqual(await worker.reconcile(), []);
  assert.equal(await worker.tick(), false);
  assert.equal(f.requests.length, 1);
});

test('開始前に期限が切れた処理を別のリースで引き受け、古いリースでの実行を拒否する', async t => {
  const f = await flowFixture(() => jsonResponse({ done: true })); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/action', method: 'POST' } } }));
  const invocation = await f.functions.invoke(fn.id), broker = f.functionExecutor.broker;
  const expired = (await broker.claim(f.environment.manifest.id))!;
  await f.db.pool.query("UPDATE function_invocations SET lease_until=now()-interval '1 second' WHERE id=$1", [invocation.id]);
  await f.context.invocations.recover();
  assert.equal((await f.functions.result(invocation.id)).state, 'running');
  await assert.rejects(broker.dispatch(invocation.id, expired.lease), error => (error as { code: string }).code === 'lease_lost');
  await f.functionExecutor.tick();
  assert.equal((await f.functions.result(invocation.id)).state, 'succeeded');
  assert.equal(f.requests.length, 1);
});

test('開始後に実行主体が停止した処理は結果不明として返し、自動でやり直さない', async t => {
  const f = await flowFixture(() => jsonResponse({ done: true })); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/action', method: 'POST' } } }));
  const invocation = await f.functions.invoke(fn.id), claim = (await f.functionExecutor.broker.claim(f.environment.manifest.id))!;
  await f.functionExecutor.broker.dispatch(invocation.id, claim.lease);
  await f.journal.write('invocation_' + invocation.id, { id: invocation.id, digest: await hash(claim.request),
    lease: claim.lease, phase: 'dispatched', delivered: false, completion: null });
  await f.db.pool.query("UPDATE function_invocations SET lease_until=now()-interval '1 second' WHERE id=$1", [invocation.id]);
  await f.context.invocations.recover();
  assert.equal((await f.functions.result(invocation.id)).state, 'uncertain');
  assert.deepEqual(await f.functionExecutor.reconcile(), []);
  assert.equal((await f.functions.invoke(fn.id, {}, { id: invocation.id })).state, 'uncertain');
  assert.equal(await f.functionExecutor.tick(), false);
  assert.equal(f.requests.length, 0);
});

test('呼び出しに対応する実行主体の署名を検証して結果を保存する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id));
  const invocation = await f.functions.invoke(fn.id), broker = f.functionExecutor.broker;
  const claim = (await broker.claim(f.environment.manifest.id))!;
  await broker.dispatch(invocation.id, claim.lease);
  const value = { id: invocation.id, requestDigest: await hash(claim.request), state: 'succeeded' as const,
    result: { done: true }, error: null, finishedAt: new Date().toISOString() };
  const forged = InvocationCompletion.parse({ ...value, signature: await sign(value, f.owner.keys.signing, 'function-result') });
  await assert.rejects(broker.finish(claim.lease, forged), error => (error as { code: string }).code === 'invalid_result');
  const approved = InvocationCompletion.parse({ ...value, signature: await sign(value, f.executor.keys.signing, 'function-result') });
  assert.equal((await broker.finish(claim.lease, approved)).state, 'succeeded');
  await assert.rejects(new FunctionClient(f.api(f.stranger.token)).result(invocation.id), error => (error as { status: number }).status === 403);
});

test('開始前の中止と実行開始が競合しても中止を確定し、次の呼び出しを実行する', async t => {
  const f = await flowFixture(() => jsonResponse({ done: true })); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/action', method: 'POST' } } }));
  const invocation = await f.functions.invoke(fn.id);
  class CancelledBroker extends FunctionBroker {
    override async dispatch(id: string, lease: string) { await f.functions.cancel(id); return super.dispatch(id, lease); }
  }
  const worker = new FunctionExecutor(f.executor, new CancelledBroker(f.functionExecutor.broker.api), f.journal);
  await worker.tick();
  assert.equal((await f.functions.result(invocation.id)).state, 'cancelled');
  assert.deepEqual(await worker.reconcile(), []);
  assert.equal(f.requests.length, 0);
  const next = await f.functions.invoke(fn.id);
  await f.functionExecutor.tick();
  assert.equal((await f.functions.result(next.id)).state, 'succeeded');
  assert.equal(f.requests.length, 1);
});

test('待機中に期限が切れた呼び出しと削除された関数の呼び出しを失敗として確定する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id));
  const expired = await f.functions.invoke(fn.id);
  await f.db.pool.query("UPDATE function_invocations SET request=jsonb_set(request,'{expiresAt}',to_jsonb($2::text)) WHERE id=$1",
    [expired.id, new Date(Date.now() - 1000).toISOString()]);
  await f.context.invocations.recover();
  assert.equal((await f.functions.result(expired.id)).state, 'failed');
  const deleted = await f.functions.invoke(fn.id);
  await f.functions.remove(fn.id);
  await f.context.invocations.recover();
  assert.equal((await f.functions.result(deleted.id)).state, 'failed');
  assert.equal(await f.functionExecutor.tick(), false);
});

test('中止の応答が途切れた場合は結果不明として確定し、遅れて届いた署名付き結果を受け取る', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id));
  const invocation = await f.functions.invoke(fn.id), broker = f.functionExecutor.broker;
  const claim = (await broker.claim(f.environment.manifest.id))!;
  await broker.dispatch(invocation.id, claim.lease);
  await f.functions.cancel(invocation.id);
  assert.equal((await f.functions.result(invocation.id)).error?.code, 'cancellation_pending');
  assert.equal((await f.delegation.maintenance({ id: f.executor.binding.principalId }, f.environment.manifest.id)).active, 1);
  await f.db.pool.query("UPDATE function_invocations SET lease_until=now()-interval '1 second' WHERE id=$1", [invocation.id]);
  await f.context.invocations.recover();
  const interrupted = await f.functions.result(invocation.id);
  assert.equal(interrupted.state, 'uncertain'); assert.ok((await f.context.invocations.get(f.owner.actor, invocation.id)).finishedAt);
  assert.equal(interrupted.error?.code, 'execution_interrupted');
  const value = { id: invocation.id, requestDigest: await hash(claim.request), state: 'cancelled' as const,
    result: null, error: { code: 'invocation_cancelled', message: 'The invocation was cancelled.' }, finishedAt: new Date().toISOString() };
  const completion = InvocationCompletion.parse({ ...value, signature: await sign(value, f.executor.keys.signing, 'function-result') });
  assert.equal((await broker.finish(claim.lease, completion)).state, 'cancelled');
});

test('待機中の呼び出しを中止し、実行中の処理も中止して最終状態を返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id, undefined, 'setInterval(()=>{},1000)'));
  const queued = await f.functions.invoke(fn.id);
  assert.equal((await f.functions.cancel(queued.id)).state, 'cancelled');
  const active = await f.functions.invoke(fn.id);
  const worker = new FunctionExecutor(f.executor, f.functionExecutor.broker, f.journal, 10);
  const running = worker.tick();
  for (let attempt = 0; attempt < 200; attempt++) {
    if ((await f.context.invocations.get(f.owner.actor, active.id)).startedAt) break;
    await delay(5);
  }
  assert.ok((await f.context.invocations.get(f.owner.actor, active.id)).startedAt);
  const cancellation = await f.functions.cancel(active.id);
  // The worker may deliver its signed cancellation before the cancel response is read.
  assert.ok(['uncertain', 'cancelled'].includes(cancellation.state));
  await running;
  assert.equal((await f.functions.result(active.id)).state, 'cancelled');
});
test('共有した関数がOAuth接続を更新して使用し、認証情報を呼び出す人へ渡さずに結果を返す', async t => {
  const f = await flowFixture(request => request.url.includes('/token') ? jsonResponse({ access_token: 'renewed-token',
    refresh_token: 'refresh-next', token_type: 'Bearer', expires_in: 3600, scope: 'read' }) : jsonResponse({ id: 'account', name: 'Account' }));
  t.after(f.close);
  const method = await f.client.api.json('/api/principals/' + f.owner.actor.id + '/resources', { method: 'POST', body: {
    kind: 'method', name: 'Function OAuth', definition: {
    name: 'Function OAuth', kind: 'oauth', config: { authorizeUrl: 'https://service.example/authorize', tokenUrl: 'https://service.example/token',
      scopes: { default: ['read'] } },
  } } }, Resource);
  const app = await f.saveApp(method.id, 'Function application');
  if (app.kind !== 'app') throw new Error('Expected an application.');
  const spec = await f.method(method.id), connectionId = crypto.randomUUID();
  const { ConnectionMaterial, connectionMetadata } = await import('../shared/connections.js');
  const material = ConnectionMaterial.parse({ format: 2, methodId: method.id, method: spec,
    generation: crypto.randomUUID(), appId: app.id, appGeneration: app.data.generation,
    oauth: { accessToken: 'expired-token', refreshToken: 'refresh-token', expiresAt: Date.now() - 1000,
      scopes: ['read'], account: 'account', accountName: 'Account', accountVerified: true,
      scopesStatus: 'reported', extra: {}, facts: {} } });
  const connectionPolicy = await f.client.policy(f.owner.actor.id, ContentTypes.tokenSet, [], { id: connectionId });
  await f.context.custody.put(f.owner.actor, { name: 'Function connection',
    content: await protect(encode(canonical(material)), connectionPolicy, 1, f.owner.binding, f.owner.keys, await connectionMetadata(material)),
    labels: { methodName: 'Function OAuth', account: 'Account' } });
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id, result: 'json',
    program: { kind: 'command', command: ['node', '-e', 'console.log(JSON.stringify({configured:!!process.env.TOKEN}))'],
      inputs: [{ name: 'TOKEN', source: { id: connectionId, output: 'ACCESS_TOKEN' } }], timeoutSeconds: 5 } }));
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id });
  const { client, functions } = await caller(f);
  const task = await functions.invoke(fn.id);
  await f.functionExecutor.tick();
  const result = await functions.result(task.id);
  assert.equal(result.state, 'succeeded', JSON.stringify(result));
  assert.deepEqual(result!.results[0], { configured: true });
  const renewed = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(connectionId))));
  assert.equal(renewed.oauth?.accessToken, 'renewed-token');
  await assert.rejects(client.read(app.id));
});



test('Pythonの処理へ引数とファイル・JSONの入力を渡し、テキストの結果を受け取る', async t => {
  const f = await flowFixture(); t.after(f.close);
  const policy = await f.client.policy(f.owner.actor.id, ContentTypes.value);
  const factor = await f.client.save('Factor', encode('{"factor":3}'), policy);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id, result: 'text',
    parameters: [{ name: 'number', label: 'Number' }], program: { kind: 'command',
      command: ['python3', '-c', 'import json,os,sys; args=json.load(sys.stdin); product=int(args["number"])*int(os.environ["FACTOR"]); length=len(open(os.environ["INPUT"],"rb").read()); print(f"Product {product}, file bytes {length}")'],
      inputs: [{ name: 'FACTOR', source: { id: factor.id }, format: 'json', pointer: '/factor' },
        { name: 'INPUT', source: { id: f.resource.id }, format: 'file' }], timeoutSeconds: 5 } }));
  const invocation = await f.functions.invoke(fn.id, { number: '5' });
  await f.functionExecutor.tick();
  const result = await f.functions.result(invocation.id);
  assert.equal(result.state, 'succeeded', JSON.stringify(result));
  assert.equal(result.results[0], 'Product 15, file bytes 18\n');
});
