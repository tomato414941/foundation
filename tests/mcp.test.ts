import test from 'node:test';
import assert from 'node:assert/strict';
import { Client as McpClient } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { FunctionDefinition } from '../shared/contracts.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createLocalMcp } from '../cli/src/mcp.js';
import { Client } from '../cli/src/client.js';
import { flowFixture } from './flow-support.js';
import { fixture } from './support.js';
import { MemoryObjects } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';

test('MCPで利用可能なAPIを調べ、手元の鍵で選択した実行先へ依頼して検証済み結果を読む', async t => {
  const f = await flowFixture(); t.after(f.close);
  const api = new Client({ origin: f.config.origin, principalId: f.owner.actor.id,
    token: f.owner.token, keys: f.owner.keys, binding: f.owner.binding });
  api.json = f.client.api.json;
  api.response = async (path, options = {}) => {
    const result = await f.app.inject({ method: (options.method ?? 'GET') as 'GET', url: path,
      headers: { authorization: 'Bearer ' + f.owner.token },
      ...(options.body === undefined ? {} : { payload: options.body as object }) });
    return new Response(result.body, { status: result.statusCode, headers: { 'content-type': 'application/json' } });
  };
  const server = createLocalMcp(api, () => f.client), client = new McpClient({ name: 'protocol-test', version: '1' });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport); await client.connect(clientTransport);
  t.after(async () => { await client.close(); await server.close(); });
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const result = await client.callTool({ name, arguments: args });
    assert.notEqual(result.isError, true, JSON.stringify(result));
    return result.structuredContent!.data as Record<string, unknown>;
  };
  const listed = await client.listTools();
  assert.equal(listed.tools.find(tool => tool.name === 'foundation_execution_result')!.annotations!.readOnlyHint, true);
  const schema = await call('foundation_schema');
  assert.ok((schema.paths as string[]).includes('/api/runtime/runs'));
  const path = await call('foundation_schema', { path: '/api/runtime/runs' });
  assert.ok(path.post);
  const metadata = await call('foundation_api', { method: 'GET', path: '/api/session' });
  assert.equal((metadata.body as { principal: { id: string } }).principal.id, f.owner.actor.id);
  const found = await call('foundation_schema', { query: 'runtime runs' }) as unknown as { path: string; method: string }[];
  assert.ok(found.some(entry => entry.path === '/api/runtime/runs' && entry.method === 'POST'));
  assert.equal(listed.tools.find(tool => tool.name === 'foundation_read')!.annotations!.readOnlyHint, true);
  const read = await call('foundation_read', { path: '/api/session' });
  assert.equal((read.body as { principal: { id: string } }).principal.id, f.owner.actor.id);
  const run = await call('foundation_run', { environmentId: f.environment.manifest.id,
    operation: { kind: 'command', command: ['node', '-e', 'process.stdout.write("MCP result")'], inputs: [], timeoutSeconds: 5 } });
  assert.equal(run.state, 'running');
  await f.executor.tick();
  const result = await call('foundation_execution_result', { id: run.id });
  assert.equal(result.state, 'succeeded');
  assert.equal(JSON.parse(result.text as string)[0].stdout, 'MCP result');
  assert.equal((await call('foundation_resume_execution', { id: run.id })).id, run.id);
  assert.equal(await f.executor.tick(), false);
  const fn = await call('foundation_save_function', { ownerId: f.owner.actor.id, name: 'MCP function',
    definition: { result: 'json',
      parameters: [{ name: 'message', label: 'Message' }], program: { kind: 'command',
        command: ['node', '-e', 'let text="";process.stdin.on("data",c=>text+=c);process.stdin.on("end",()=>console.log(JSON.stringify({message:JSON.parse(text).message,configured:!!process.env.TOKEN})));'],
        inputs: [{ name: 'TOKEN', source: { id: f.resource.id } }], timeoutSeconds: 5 } } });
  await call('foundation_configure_function', { functionId: fn.id, environmentId: f.environment.manifest.id });
  const invocation = await call('foundation_invoke_function', { functionId: fn.id, arguments: { message: 'From MCP' } });
  await f.functionExecutor.tick();
  const functionResult = await call('foundation_execution_result', { id: (invocation.body as { id: string }).id });
  assert.equal(functionResult.state, 'succeeded');
  assert.deepEqual(JSON.parse(functionResult.text as string)[0], { message: 'From MCP', configured: true });
  const invalid = await client.callTool({ name: 'foundation_api', arguments: { method: 'GET', path: '/api/../auth/signin' } });
  assert.equal(invalid.isError, true);
});


test('URL接続のMCPで共有された関数を見つけ、APIトークンだけで呼び出して結果を読む', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await f.functions.save({ ownerId: f.owner.actor.id, name: 'Shared MCP function', definition: FunctionDefinition.parse({
    program: { kind: 'command',
      command: ['node', '-e', 'console.log(JSON.stringify({configured:!!process.env.TOKEN}))'],
      inputs: [{ name: 'TOKEN', source: { id: f.resource.id } }] }, result: 'json' }) });
  await f.functions.configure(fn.id, { environmentId: f.environment.manifest.id });
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id });
  const origin = await f.app.listen({ host: '127.0.0.1', port: 0 });
  const client = new McpClient({ name: 'remote-function-caller', version: '1' });
  await client.connect(new StreamableHTTPClientTransport(new URL(origin + '/api/mcp'), {
    requestInit: { headers: { authorization: 'Bearer ' + f.stranger.token } },
  }));
  t.after(() => client.close());
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const result = await client.callTool({ name, arguments: args });
    assert.notEqual(result.isError, true, JSON.stringify(result));
    return result.structuredContent!.data as Record<string, unknown>;
  };
  const available = await call('foundation_functions');
  const found = (available.body as { items: Array<{ id: string; data: unknown }> }).items.find(item => item.id === fn.id)!;
  assert.deepEqual(found.data, { description: '', parameters: [], result: 'json' });
  const invoked = await call('foundation_invoke_function', { functionId: fn.id });
  const id = (invoked.body as { id: string }).id;
  await f.functionExecutor.tick();
  const result = await call('foundation_execution_result', { id });
  assert.equal(result.state, 'succeeded');
  assert.deepEqual(JSON.parse(result.text as string)[0], { configured: true });
});

test('MCPからオブジェクトのAPIを調べ、オブジェクトを保存して一覧とダウンロードリンクを取得する', async t => {
  const f = await fixture({ FOUNDATION_BILLING_MODE: 'included' });
  const context = await createContext(f.config, { db: f.db, storage: new MemoryObjects() }), app = await buildApp(context);
  t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('File owner'), origin = await app.listen({ host: '127.0.0.1', port: 0 });
  const client = new McpClient({ name: 'file-client', version: '1' });
  await client.connect(new StreamableHTTPClientTransport(new URL(origin + '/api/mcp'), {
    requestInit: { headers: { authorization: 'Bearer ' + owner.token } },
  }));
  t.after(() => client.close());
  const call = async (name: string, args: Record<string, unknown>) => {
    const result = await client.callTool({ name, arguments: args });
    assert.notEqual(result.isError, true, JSON.stringify(result));
    return result.structuredContent!.data as Record<string, unknown>;
  };
  const schema = await call('foundation_schema', {});
  assert.ok((schema.paths as string[]).includes('/api/principals/{id}/objects'));
  const saved = await call('foundation_api', { method: 'POST', path: '/api/definitions/object.create/executions', body: {
    ownerId: owner.actor.id, name: 'mcp.txt', contentType: 'text/plain', bytes: Buffer.from('From MCP').toString('base64url'),
  } });
  const execution = saved.body as { state: string; results: Array<{ id: string; kind: string }> };
  assert.equal(execution.state, 'succeeded'); assert.equal(execution.results[0]!.kind, 'object');
  const file = execution.results[0]!;
  const listed = await call('foundation_api', { method: 'GET', path: '/api/principals/' + owner.actor.id + '/resources?kind=object' });
  assert.equal((listed.body as { items: Array<{ id: string }> }).items[0]?.id, file.id);
  const link = await call('foundation_api', { method: 'POST', path: '/api/definitions/object.link/executions', body: { id: file.id } });
  const linked = link.body as { state: string; results: Array<{ url: string }> };
  assert.equal(linked.state, 'succeeded'); assert.ok(linked.results[0]?.url.startsWith('https://files.example/'));
});
