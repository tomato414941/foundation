import test from 'node:test';
import assert from 'node:assert/strict';
import { Client as McpClient } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createLocalMcp } from '../cli/src/mcp.js';
import { Client } from '../cli/src/client.js';
import { flowFixture } from './flow-support.js';
import { fixture } from './support.js';
import { MemoryObjects } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';

test('手元のMCPで利用可能なAPIを調べ、CLIの身元で読み出して変更する', async t => {
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
  const server = createLocalMcp(api), client = new McpClient({ name: 'protocol-test', version: '1' });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport); await client.connect(clientTransport);
  t.after(async () => { await client.close(); await server.close(); });
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const result = await client.callTool({ name, arguments: args });
    assert.notEqual(result.isError, true, JSON.stringify(result));
    return result.structuredContent!.data as Record<string, unknown>;
  };
  const listed = await client.listTools();
  assert.equal(listed.tools.find(tool => tool.name === 'foundation_read')!.annotations!.readOnlyHint, true);
  const schema = await call('foundation_schema');
  assert.ok((schema.paths as string[]).includes('/api/principals/{id}/principals'));
  const found = await call('foundation_schema', { query: 'principals' }) as unknown as { path: string; method: string }[];
  assert.ok(found.some(entry => entry.path === '/api/principals/{id}/principals' && entry.method === 'POST'));
  const read = await call('foundation_read', { path: '/api/session' });
  assert.equal((read.body as { principal: { id: string } }).principal.id, f.owner.actor.id);
  const created = await call('foundation_api', { method: 'POST', path: '/api/principals/' + f.owner.actor.id + '/principals',
    body: { name: 'Made from MCP' } });
  assert.equal(created.status, 201);
  assert.equal((created.body as { name: string }).name, 'Made from MCP');
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
  const saved = await call('foundation_api', { method: 'POST', path: '/api/operations', body: { name: 'object.create', input: {
    ownerId: owner.actor.id, name: 'mcp.txt', contentType: 'text/plain', bytes: Buffer.from('From MCP').toString('base64url'),
  } } });
  const made = saved.body as { state: string; result: { id: string; kind: string } };
  assert.equal(made.state, 'succeeded'); assert.equal(made.result.kind, 'object');
  const file = made.result;
  const listed = await call('foundation_api', { method: 'GET', path: '/api/principals/' + owner.actor.id + '/resources?kind=object' });
  assert.equal((listed.body as { items: Array<{ id: string }> }).items[0]?.id, file.id);
  const link = await call('foundation_api', { method: 'POST', path: '/api/operations', body: { name: 'object.link', input: { id: file.id } } });
  const linked = link.body as { state: string; result: { url: string } };
  assert.equal(linked.state, 'succeeded'); assert.ok(linked.result.url.startsWith('https://files.example/'));
});
