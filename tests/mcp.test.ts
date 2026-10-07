import test from 'node:test';
import assert from 'node:assert/strict';
import { Client as McpClient } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createLocalMcp } from '../cli/src/mcp.js';
import { Client } from '../cli/src/client.js';
import { flowFixture } from './flow-support.js';

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
  assert.ok((schema.paths as string[]).includes('/api/executions'));
  const path = await call('foundation_schema', { path: '/api/executions' });
  assert.ok(path.post);
  const metadata = await call('foundation_api', { method: 'GET', path: '/api/session' });
  assert.equal((metadata.body as { principal: { id: string } }).principal.id, f.owner.actor.id);
  const run = await call('foundation_run', { environmentId: f.environment.manifest.id,
    operation: { kind: 'command', command: ['node', '-e', 'process.stdout.write("MCP result")'], inputs: [], timeoutSeconds: 5 } });
  assert.equal(run.state, 'queued');
  await f.executor.tick();
  const result = await call('foundation_execution_result', { id: run.id });
  assert.equal(result.state, 'succeeded');
  assert.equal(JSON.parse(result.text as string).result.stdout, 'MCP result');
  assert.equal((await call('foundation_resume_execution', { id: run.id })).id, run.id);
  assert.equal(await f.executor.tick(), false);
  const invalid = await client.callTool({ name: 'foundation_api', arguments: { method: 'GET', path: '/api/../auth/signin' } });
  assert.equal(invalid.isError, true);
});
