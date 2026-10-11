import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { FunctionDefinition, JsonObject, Resource } from '../shared/contracts.js';
import type { FunctionSpec } from '../shared/contracts.js';
import { CustodyClient } from '../shared/client.js';
import { ConnectionClient } from '../shared/connection-client.js';
import { OperationClient } from '../shared/operation-client.js';
import { JournalTrust } from '../runtime/trust.js';
import { canonical, hash } from '../shared/authority.js';
import { ContentTypes, prepareRun, protect, reveal } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';
import { Task } from '../shared/execution.js';
import { functionArguments, functionProgram } from '../shared/functions.js';

const script = 'let text=""; process.stdin.on("data", c => text += c); process.stdin.on("end", () => { const args = JSON.parse(text); console.log(JSON.stringify({ message: args.message, configured: Boolean(process.env.TOKEN), secret: process.env.TOKEN })); });';
const definition = (environmentId: string, sourceId?: string, command = script) => FunctionDefinition.parse({
  environmentId, program: { kind: 'command', command: ['node', '-e', command],
    inputs: sourceId ? [{ name: 'TOKEN', source: { id: sourceId } }] : [], timeoutSeconds: 5 },
  parameters: [{ name: 'message', label: 'Message', default: 'Hello' }], result: 'json',
});
async function save(f: Awaited<ReturnType<typeof flowFixture>>, spec: FunctionSpec) {
  const result = await f.operations.execute({ name: 'function.save', input: JsonObject.parse({ ownerId: f.owner.actor.id,
    name: 'Processor ' + crypto.randomUUID(), definition: spec }) });
  assert.ok('kind' in result && result.kind === 'saved', JSON.stringify(result));
  if (!('kind' in result) || result.kind !== 'saved' || result.resource.kind !== 'function') throw new Error('Expected a saved function.');
  return result.resource;
}
async function caller(f: Awaited<ReturnType<typeof flowFixture>>) {
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.executor.binding); await trust.rememberBinding(f.owner.binding);
  const client = new CustodyClient(f.api(f.stranger.token), f.config.origin, f.stranger.binding, f.stranger.keys, trust);
  const connections = new ConnectionClient(client, { async get() { return null; }, async put() {} });
  return { client, operations: new OperationClient(client, connections) };
}

test('関数だけを共有して秘密を使う固定処理を実行し、呼び出した人へ結果を返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id, f.resource.id));
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id });
  const { client, operations } = await caller(f);
  await assert.rejects(client.read(f.resource.id));
  await assert.rejects(client.environment(f.environment.manifest.id));
  await assert.rejects(f.authorization.requireResource(f.stranger.actor, f.resource, 'use'));
  const text = '"; process.exit(99); //';
  const started = await operations.execute({ name: 'run.execute', input: { ownerId: f.stranger.actor.id,
    operation: { kind: 'function', functionId: fn.id, arguments: { message: text } } } });
  assert.ok('kind' in started && started.kind === 'run');
  if (!('kind' in started) || started.kind !== 'run') throw new Error('Expected an execution.');
  await f.executor.tick();
  const task = await client.api.json('/api/executions/' + started.task.id, {}, Task);
  assert.equal(task.state, 'succeeded', JSON.stringify(await client.result(task)));
  assert.deepEqual((await client.result(task))!.result, { message: text, configured: true, secret: '[redacted]' });
  const content = await f.context.custody.get(f.resource.id);
  await assert.rejects(reveal(content, f.stranger.binding, f.stranger.keys.encryption));
  await assert.rejects(client.submit(f.stranger.actor.id, f.environment.manifest.id,
    { kind: 'command', command: ['node', '-e', 'console.log(process.env.TOKEN)'], inputs: [{ name: 'TOKEN', source: { id: f.resource.id }, format: 'text' }], timeoutSeconds: 5 }));
});

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

test('JSONの引数を文字列化せず任意の処理に渡し、構造化した結果を受け取る', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'command', command: ['node', '-e', 'let text="";process.stdin.on("data",c=>text+=c);process.stdin.on("end",()=>console.log(JSON.stringify(JSON.parse(text))));'] },
    parameters: [{ name: 'count', label: 'Count', type: 'number' }, { name: 'enabled', label: 'Enabled', type: 'boolean' },
      { name: 'payload', label: 'Payload', type: 'json' }], result: 'json' }));
  const args = { count: 0, enabled: false, payload: { values: [1, 'two', null], nested: { ready: true } } };
  const task = await f.client.submit(f.owner.actor.id, fn.data.environmentId, { kind: 'function', functionId: fn.id,
    definition: fn.data, arguments: args, outputs: {} });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/executions/' + task.id, {}, Task));
  assert.equal(result!.ok, true, JSON.stringify(result));
  assert.deepEqual(result!.result, args);
});

test('HTTP関数のJSON本文に数値・真偽値・JSONの引数をその型のまま設定する', async t => {
  const f = await flowFixture(request => jsonResponse(JSON.parse(String(request.body)))); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/items{?count}', method: 'POST',
      json: { count: '{{count}}', enabled: '{{enabled}}', payload: '{{payload}}', caption: 'Count {{count}}', constructor: '{{constructor}}' } } },
    parameters: [{ name: 'count', label: 'Count', type: 'number' }, { name: 'enabled', label: 'Enabled', type: 'boolean' },
      { name: 'payload', label: 'Payload', type: 'json' }, { name: 'constructor', label: 'Constructor', required: false }], result: 'json' }));
  const args = { count: 0, enabled: false, payload: [1, { name: 'item' }, null] };
  const task = await f.client.submit(f.owner.actor.id, fn.data.environmentId, { kind: 'function', functionId: fn.id,
    definition: fn.data, arguments: args, outputs: {} });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/executions/' + task.id, {}, Task));
  assert.equal(result!.ok, true, JSON.stringify(result));
  assert.deepEqual(result!.result, { ...args, caption: 'Count 0', constructor: null });
  assert.equal(new URL(f.requests[0]!.url).searchParams.get('count'), '0');
});

test('関数の定義と実行先を署名した依頼へ結びつけ、変更後は再承認して実行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id, f.resource.id));
  const operation = { kind: 'function' as const, functionId: fn.id, definition: fn.data, arguments: {}, outputs: {} };
  const prepared = await f.client.prepare(f.owner.actor.id, fn.data.environmentId, operation);
  const changed = { ...operation, definition: definition(fn.data.environmentId, f.resource.id, 'console.log(JSON.stringify({changed:true}))') };
  const forged = await prepareRun({ ...prepared.intent, id: crypto.randomUUID(), operationDigest: await hash(changed),
    functionId: fn.id, functionDigest: await hash(changed.definition) }, changed, f.owner.keys);
  await assert.rejects(f.client.submitPrepared(forged));
  const substituted = await prepareRun({ ...prepared.intent, id: crypto.randomUUID(), operationDigest: await hash(changed) }, changed, f.owner.keys);
  const substitutedTask = await f.client.submitPrepared(substituted);
  await f.executor.tick();
  assert.equal((await f.client.api.json('/api/executions/' + substitutedTask.id, {}, Task)).state, 'failed');
  const edited = await f.operations.execute({ name: 'function.save', input: JsonObject.parse({ ownerId: f.owner.actor.id,
    resourceId: fn.id, version: fn.version, name: fn.name, definition: changed.definition }) });
  assert.ok('kind' in edited && edited.kind === 'saved');
  await assert.rejects(f.client.submitPrepared(prepared));
  const current = await f.client.api.json('/api/resources/' + fn.id, {}, Resource);
  assert.equal(current.kind, 'function');
  if (current.kind !== 'function') throw new Error('Expected a function.');
  const task = await f.client.submit(f.owner.actor.id, current.data.environmentId, { ...operation, definition: current.data });
  await f.executor.tick();
  assert.deepEqual((await f.client.result(await f.client.api.json('/api/executions/' + task.id, {}, Task)))!.result, { changed: true });
});

test('共有許可を取り消した関数の待機中の実行を開始前に止める', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id));
  const line = { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id };
  await f.relations.draw(f.owner.actor, line);
  const { client } = await caller(f);
  const task = await client.submit(f.stranger.actor.id, fn.data.environmentId, { kind: 'function', functionId: fn.id,
    definition: fn.data, arguments: {}, outputs: {} });
  await f.relations.erase(f.owner.actor, line);
  assert.equal(await f.executor.tick(), false);
  assert.equal((await client.api.json('/api/executions/' + task.id, {}, Task)).state, 'failed');
});

test('入力の利用許可が有効な間に関数を実行し、期限が切れたら所有者が再承認する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id, f.resource.id));
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id });
  const { client } = await caller(f);
  const changeExpiry = async (expiresAt: string) => {
    const previous = await f.client.read(f.resource.id);
    await f.client.save(f.resource.name, await f.client.reveal(f.resource.id), { ...previous.content.policy,
      revision: previous.content.policy.revision + 1, grants: previous.content.policy.grants.map(grant =>
        'function' in grant && grant.function.id === fn.id ? { ...grant, expiresAt } : grant) }, { previous });
  };
  const expiresAt = new Date(Date.now() + 300_000).toISOString();
  await changeExpiry(expiresAt);
  const operation = { kind: 'function' as const, functionId: fn.id, definition: fn.data, arguments: {}, outputs: {} };
  const prepared = await client.prepare(f.stranger.actor.id, fn.data.environmentId, operation);
  assert.equal(prepared.intent.expiresAt, expiresAt);
  const task = await client.submitPrepared(prepared);
  await f.executor.tick();
  assert.equal((await client.api.json('/api/executions/' + task.id, {}, Task)).state, 'succeeded');
  await changeExpiry(new Date(Date.now() - 1000).toISOString());
  await assert.rejects(client.prepare(f.stranger.actor.id, fn.data.environmentId, operation));
  const renewed = await f.operations.execute({ name: 'function.save', input: JsonObject.parse({ ownerId: f.owner.actor.id,
    resourceId: fn.id, version: fn.version, name: fn.name, definition: fn.data }) });
  assert.ok('kind' in renewed && renewed.kind === 'saved');
  const next = await client.submit(f.stranger.actor.id, fn.data.environmentId, operation);
  await f.executor.tick();
  assert.equal((await client.api.json('/api/executions/' + next.id, {}, Task)).state, 'succeeded');
});

test('HTTP処理を関数として実行し、JSONの結果を暗号化した変数にも保存する', async t => {
  const f = await flowFixture(() => jsonResponse({ count: 7 })); t.after(f.close);
  const fn = await save(f, FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { url: 'https://service.example/items{?query}',
      bindings: [{ pointer: '/headers/authorization', parts: ['Bearer ', { id: f.resource.id }] }] } },
    parameters: [{ name: 'query', label: 'Query' }], result: 'json' }));
  const task = await f.client.submit(f.owner.actor.id, fn.data.environmentId, { kind: 'function', functionId: fn.id,
    definition: fn.data, arguments: { query: 'hello world' }, outputs: {} }, { save: { '/count': 'Count' } });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/executions/' + task.id, {}, Task));
  assert.equal(result?.ok, true, JSON.stringify(result));
  const output = result!.result as { saved: Record<string, string> };
  assert.equal(new TextDecoder().decode(await f.client.reveal(output.saved.Count!)), '7');
  assert.equal(f.requests[0]!.headers!.authorization, 'Bearer confidential-value');
  assert.equal(new URL(f.requests[0]!.url).searchParams.get('query'), 'hello world');
});

test('関数で生成した秘密を暗号化して保存し、呼び出す人へ保存先のIDを返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, definition(f.environment.manifest.id, undefined,
    'console.log(JSON.stringify({credential:require("crypto").randomBytes(16).toString("hex")}))'));
  const task = await f.client.submit(f.owner.actor.id, fn.data.environmentId, { kind: 'function', functionId: fn.id,
    definition: fn.data, arguments: {}, outputs: {} }, { save: { '/credential': 'Generated credential' } });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/executions/' + task.id, {}, Task));
  assert.equal(result!.ok, true, JSON.stringify(result));
  const output = result!.result as { saved: Record<string, string> };
  const id = output.saved['Generated credential']!;
  assert.deepEqual(result!.result, { saved: { 'Generated credential': id } });
  const credential = decode(await f.client.reveal(id));
  assert.match(credential, /^[a-f0-9]{32}$/);
});

test('処理の終了コードと結果の形式を検証し、失敗を検証済みの結果として返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  for (const [command, code, timeout] of [['process.stderr.write("problem");process.exit(3)', 'function_failed', 5], ['console.log("invalid JSON")', 'invalid_function_result', 5], ['setInterval(()=>{},1000)', 'function_timeout', 1]] as const) {
    const spec = definition(f.environment.manifest.id, undefined, command);
    if (spec.program.kind === 'command') spec.program.timeoutSeconds = timeout;
    const fn = await save(f, spec);
    const task = await f.client.submit(f.owner.actor.id, fn.data.environmentId, { kind: 'function', functionId: fn.id,
      definition: fn.data, arguments: {}, outputs: {} });
    await f.executor.tick();
    const completed = await f.client.api.json('/api/executions/' + task.id, {}, Task);
    assert.equal(completed.state, 'failed');
    assert.equal((await f.client.result(completed))!.error!.code, code);
  }
});

test('関数の入力を更新して新しい値を使い、呼び出しごとに作業ファイルを用意する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const program = 'const fs=require("fs");const count=(fs.existsSync("counter")?Number(fs.readFileSync("counter")):0)+1;fs.writeFileSync("counter",String(count));console.log(JSON.stringify({count,length:process.env.TOKEN.length}));';
  const fn = await save(f, definition(f.environment.manifest.id, f.resource.id, program));
  const policy = await f.client.policy(f.owner.actor.id, ContentTypes.value);
  const newSource = await f.client.save('New input', encode('new-private-token-value'), policy);
  const result = await f.operations.execute({ name: 'function.save', input: JsonObject.parse({ ownerId: f.owner.actor.id,
    resourceId: fn.id, version: fn.version, name: fn.name, definition: definition(f.environment.manifest.id, newSource.id, program) }) });
  assert.ok('kind' in result && result.kind === 'saved');
  const current = await f.client.api.json('/api/resources/' + fn.id, {}, Resource);
  if (current.kind !== 'function') throw new Error('Expected a function.');
  for (let invocation = 0; invocation < 2; invocation++) {
    const task = await f.client.submit(f.owner.actor.id, current.data.environmentId, { kind: 'function', functionId: fn.id,
      definition: current.data, arguments: {}, outputs: {} });
    await f.executor.tick();
    assert.deepEqual((await f.client.result(await f.client.api.json('/api/executions/' + task.id, {}, Task)))!.result,
      { count: 1, length: 'new-private-token-value'.length });
  }
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'confidential-value');
});

test('共有した関数がOAuth接続を更新して使用し、認証情報を呼び出す人へ渡さずに結果を返す', async t => {
  const f = await flowFixture(request => request.url.includes('/token') ? jsonResponse({ access_token: 'renewed-token',
    refresh_token: 'refresh-next', token_type: 'Bearer', expires_in: 3600, scope: 'read' }) : jsonResponse({ id: 'account', name: 'Account' }));
  t.after(f.close);
  const method = await f.client.api.json('/api/principals/' + f.owner.actor.id + '/resources', { method: 'POST', body: {
    kind: 'method', name: 'Function OAuth', definition: {
    name: 'Function OAuth', kind: 'oauth', config: { authorizeUrl: 'https://service.example/authorize', tokenUrl: 'https://service.example/token',
      scopes: { default: ['read'] }, identity: { url: 'https://service.example/account', id: '/id', name: '/name' } },
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
    program: { kind: 'command', command: ['node', '-e', 'console.log(JSON.stringify({configured:!!process.env.TOKEN,secret:process.env.TOKEN}))'],
      inputs: [{ name: 'TOKEN', source: { id: connectionId, output: 'ACCESS_TOKEN' } }], timeoutSeconds: 5 } }));
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id });
  const { client } = await caller(f);
  const task = await client.submit(f.stranger.actor.id, fn.data.environmentId, { kind: 'function', functionId: fn.id,
    definition: fn.data, arguments: {}, outputs: {} });
  await f.executor.tick();
  const result = await client.result(await client.api.json('/api/executions/' + task.id, {}, Task));
  assert.equal(result?.ok, true, JSON.stringify(result));
  assert.deepEqual(result!.result, { configured: true, secret: '[redacted]' });
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
  const task = await f.client.submit(f.owner.actor.id, fn.data.environmentId, { kind: 'function', functionId: fn.id,
    definition: fn.data, arguments: { number: '5' }, outputs: {} });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/executions/' + task.id, {}, Task));
  assert.equal(result!.ok, true, JSON.stringify(result));
  assert.equal(result!.result, 'Product 15, file bytes 18\n');
});
