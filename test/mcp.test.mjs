import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';
import { LATEST, SUPPORTED } from '../src/mcp.mjs';

let KEY;
const META = 'io.modelcontextprotocol/';
const meta = (version = LATEST) => ({ [META + 'protocolVersion']: version, [META + 'clientCapabilities']: {}, [META + 'clientInfo']: { name: 'test', version: '1' } });

// A modern call carries its protocol metadata in the body and mirrors the routed fields into headers.
async function modern(f, message, { token = KEY, version = LATEST, headers = {} } = {}) {
  const named = message.method === 'tools/call' ? { 'mcp-name': message.params.name } : {};
  const params = message.params === undefined ? undefined : { ...message.params, _meta: meta(version) };
  return f.request('/mcp', { method: 'POST', token, data: { ...message, ...(params ? { params } : {}) },
    headers: { 'mcp-protocol-version': version, 'mcp-method': message.method, ...named, ...headers } });
}

async function connected(t) {
  const f = await fixture(t);
  KEY = (await f.approveKey()).token;
  return f;
}

test('公開APIを操作するツールを承認済みキーに提示する', async (t) => {
  const f = await connected(t);
  const result = await modern(f, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
  assert.equal(result.status, 200, result.text);
  assert.equal(result.json.result.resultType, 'complete');
  assert.deepEqual(result.json.result.tools.map(tool => tool.name), ['foundation_api']);
  assert.equal(result.json.result._meta[META + 'serverInfo'].name, 'foundation');
});

test('MCPで文字列とバイナリの保存値を指定の符号化で共通APIへ渡す', async t => {
  const f = await connected(t);
  const call = args => modern(f, { jsonrpc: '2.0', id: 40, method: 'tools/call', params: { name: 'foundation_api', arguments: args } });
  const bytes = Buffer.from([0, 255, 1, 10]);
  const stored = await call({ method: 'PUT', path: '/v1/resources?kind=secret&name=file', body: bytes.toString('base64'), body_encoding: 'base64' });
  assert.equal(stored.json.result.isError, undefined, stored.text);
  const id = stored.json.result.structuredContent.resource.id;
  const delivered = await call({ method: 'POST', path: '/v1/injections', body: { names: [{ id, as: 'CONFIG_FILE', filename: 'config.bin' }] } });
  assert.deepEqual(Buffer.from(delivered.json.result.structuredContent.injection.files[0].content, 'base64'), bytes);
  for (const [body, body_encoding] of [['%%%', 'base64'], [42, 'text'], ['x', 'unknown']]) {
    const refused = await call({ method: 'PUT', path: '/v1/resources?kind=secret&name=file', body, body_encoding });
    assert.equal(refused.json.result.isError, true, refused.text);
  }
  const preserved = await call({ method: 'POST', path: '/v1/injections', body: { names: [{ id, as: 'CONFIG_FILE', filename: 'config.bin' }] } });
  assert.deepEqual(Buffer.from(preserved.json.result.structuredContent.injection.files[0].content, 'base64'), bytes);
});

test('refuses a key that was never approved', async (t) => {
  const f = await fixture(t);
  const result = await modern(f, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }, { token: 'fdn_' + 'z'.repeat(43) });
  assert.equal(result.status, 401);
  assert.equal(result.json.error.code, 'not_approved');
});

test('共通APIツールで最新のOpenAPI仕様を取得する', async (t) => {
  const f = await connected(t);
  const result = await modern(f, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'foundation_api', arguments: { method: 'GET', path: '/openapi.json' } } });
  assert.equal(result.status, 200, result.text);
  const published = await f.request('/openapi.json', { anonymous: true });
  assert.deepEqual(result.json.result.structuredContent, published.json);
  assert.deepEqual(JSON.parse(result.json.result.content[0].text), published.json);
  assert.equal(result.json.result.isError, undefined);
});

test('makes an API call with the caller\'s own key and returns what it said', async (t) => {
  const f = await connected(t);
  const stored = await f.request('/v1/resources?kind=secret&name=notes/plan', { method: 'PUT', token: KEY, raw: 'one line', type: 'text/plain' });
  assert.equal(stored.status, 200, stored.text);
  const result = await modern(f, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'foundation_api', arguments: { method: 'GET', path: '/v1/resources?kind=secret' } } });
  assert.equal(result.status, 200, result.text);
  assert.deepEqual(result.json.result.structuredContent.resources.map(entry => entry.name), ['notes/plan']);
});

test('MCP delivers what a connected grant yields, and never its renewal state', async t => {
  const f = await connected(t), connection = await f.credential();
  const call = (method, path, body) => modern(f, { jsonrpc: '2.0', id: 20, method: 'tools/call', params: { name: 'foundation_api', arguments: { method, path, body } } });
  const catalog = await call('GET', '/v1/functions');
  assert.deepEqual(catalog.json.result.structuredContent.functions.map(fn => fn.id), ['http.request']);
  const delivered = await call('POST', '/v1/injections', { names: [{ id: connection.id }] });
  assert.equal(delivered.json.result.structuredContent.injection.environment.GOOGLE_ACCOUNT_EMAIL, 'personal@example.test');
  assert.doesNotMatch(delivered.text, /refresh-personal/);
  const content = await call('GET', '/v1/resources/' + connection.id + '/content');
  assert.equal(content.json.result.structuredContent.error.code, 'method_not_allowed');
});

test('reports a refused API call as a tool error the model can act on', async (t) => {
  const f = await connected(t);
  const result = await modern(f, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'foundation_api', arguments: { method: 'GET', path: '/v1/resources?kind=secret&name=missing/thing' } } });
  assert.equal(result.status, 200, result.text);
  assert.equal(result.json.result.isError, true);
  assert.equal(result.json.result.structuredContent.error.code, 'not_found');
});

test('keeps foundation_api to the API', async (t) => {
  const f = await connected(t);
  for (const path of ['/v1/overview', '/health', 'v1/grants', '/v1/../health', '/v1/%2e%2e/openapi.json', '/openapi.json?url=https://elsewhere.example']) {
    const result = await modern(f, { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'foundation_api', arguments: { method: 'GET', path } } });
    assert.equal(result.json.result.isError, true, path);
  }
});

test('answers an unknown tool with a protocol error', async (t) => {
  const f = await connected(t);
  const result = await modern(f, { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'foundation_delete_everything', arguments: {} } });
  assert.equal(result.status, 404);
  assert.equal(result.json.error.code, -32602);
});

test('rejects a header that disagrees with the body', async (t) => {
  const f = await connected(t);
  const result = await modern(f, { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'foundation_api', arguments: { method: 'GET', path: '/openapi.json' } } }, { headers: { 'mcp-name': 'another_tool' } });
  assert.equal(result.status, 400);
  assert.equal(result.json.error.code, -32020);
});

test('rejects a modern request that omits its metadata', async (t) => {
  const f = await connected(t);
  const result = await f.request('/mcp', { method: 'POST', token: KEY, data: { jsonrpc: '2.0', id: 8, method: 'tools/list', params: {} },
    headers: { 'mcp-protocol-version': LATEST, 'mcp-method': 'tools/list' } });
  assert.equal(result.status, 400);
  assert.equal(result.json.error.code, -32602);
});

test('names the versions it supports when asked for another', async (t) => {
  const f = await connected(t);
  const result = await modern(f, { jsonrpc: '2.0', id: 9, method: 'tools/list', params: {} }, { version: '2099-01-01' });
  assert.equal(result.status, 400);
  assert.equal(result.json.error.code, -32022);
  assert.deepEqual(result.json.error.data.supported, SUPPORTED);
});

test('serves a client that still opens with initialize', async (t) => {
  const f = await connected(t);
  const opened = await f.request('/mcp', { method: 'POST', token: KEY,
    data: { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'old', version: '1' } } } });
  assert.equal(opened.status, 200, opened.text);
  assert.equal(opened.json.result.protocolVersion, '2025-06-18');
  assert.deepEqual(opened.json.result.capabilities, { tools: {} });
  assert.equal(opened.json.result.resultType, undefined);
  assert.match(opened.json.result.instructions, /GET \/openapi.json/);

  const ready = await f.request('/mcp', { method: 'POST', token: KEY, data: { jsonrpc: '2.0', method: 'notifications/initialized' }, headers: { 'mcp-protocol-version': '2025-06-18' } });
  assert.equal(ready.status, 202);
  assert.equal(ready.text, '');

  const listed = await f.request('/mcp', { method: 'POST', token: KEY, data: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, headers: { 'mcp-protocol-version': '2025-06-18' } });
  assert.equal(listed.status, 200, listed.text);
  assert.equal(listed.json.result.tools[0].name, 'foundation_api');
});

test('tells a modern client that initialize is gone', async (t) => {
  const f = await connected(t);
  const result = await modern(f, { jsonrpc: '2.0', id: 10, method: 'initialize', params: { protocolVersion: LATEST } });
  assert.equal(result.status, 404, result.text);
  assert.equal(result.json.error.code, -32601);
});

test('answers only POST at the MCP endpoint', async (t) => {
  const f = await connected(t);
  for (const method of ['GET', 'DELETE']) {
    const result = await f.request('/mcp', { method, token: KEY });
    assert.equal(result.status, 405, method);
  }
});

test('refuses the endpoint to another site', async (t) => {
  const f = await connected(t);
  const result = await modern(f, { jsonrpc: '2.0', id: 11, method: 'tools/list', params: {} }, { headers: { origin: 'https://elsewhere.example' } });
  assert.equal(result.status, 403);
});
