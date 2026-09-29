import test from 'node:test';
import assert from 'node:assert/strict';
import SwaggerParser from '@apidevtools/swagger-parser';
import { fixture } from './helpers.mjs';
import { validateSchema } from '../src/api.mjs';

test('公開仕様を標準OpenAPIとして解析し、すべての操作の入力と応答を参照する', async t => {
  const f = await fixture(t, { login: false });
  const fetched = await f.request('/openapi.json', { anonymous: true });
  assert.equal(fetched.status, 200);
  const spec = await SwaggerParser.validate(structuredClone(fetched.json));
  assert.equal(spec.info.title, 'Foundation API');
  const ids = new Set();
  for (const [path, item] of Object.entries(spec.paths)) for (const [method, operation] of Object.entries(item)) {
    assert.ok(operation.operationId, `${method} ${path} has a stable operationId`);
    assert.ok(!ids.has(operation.operationId), `unambiguous operation ${operation.operationId}`);
    ids.add(operation.operationId);
    assert.ok(Object.keys(operation.responses).some(status => /^[23]\d\d$/.test(status)), `${method} ${path} describes success`);
    for (const parameter of operation.parameters) if (parameter.in === 'path') {
      assert.equal(parameter.required, true);
      assert.ok(path.includes('{' + parameter.name + '}'));
    }
  }
  // Compilation also resolves the component references used by the runtime JSON reader.
  for (const name of Object.keys(fetched.json.components.schemas)) validateSchema(name, {});
});

test('公開仕様から操作を見つけ、初回接続・承認・保存・受け渡しを同じHTTP APIで行う', async t => {
  const f = await fixture(t, { login: false });
  const spec = (await f.request('/openapi.json', { anonymous: true })).json;
  const call = (operationId, { params = {}, query = {}, ...options } = {}) => {
    for (const [template, item] of Object.entries(spec.paths)) for (const [method, operation] of Object.entries(item)) {
      if (operation.operationId !== operationId) continue;
      const path = template.replace(/\{(\w+)\}/g, (_, name) => encodeURIComponent(params[name]));
      return f.request(path + (Object.keys(query).length ? '?' + new URLSearchParams(query) : ''), { method: method.toUpperCase(), ...options });
    }
    throw new Error('Unknown operation ' + operationId);
  };
  const created = await call('createPrincipal', { anonymous: true, data: { name: 'API reader' } });
  assert.equal(created.status, 201);
  const token = created.json.token;
  const asked = await call('createRequest', { anonymous: true, token, data: { kind: 'actor', input: { name: 'API reader' } } });
  assert.equal(asked.status, 201);
  const request = asked.json.request;
  assert.equal(new URL(request.verification_uri).pathname, '/requests/' + request.id);
  await f.login();
  const accepted = await call('completeRequest', { params: { requestId: request.id }, data: { confirmation_code: request.confirmation_code } });
  assert.equal(accepted.json.request.status, 'done');
  const me = await call('getMe', { token });
  const as = me.json.acts_for[0];
  assert.ok(as);
  const saved = await call('putResource', { token, query: { as, kind: 'secret', name: 'api/config' }, raw: '{"demo":"value"}', type: 'application/json' });
  assert.equal(saved.status, 200);
  const resourceId = saved.json.resource.id;
  const content = await call('getContent', { token, params: { resourceId } });
  assert.equal(content.text, '{"demo":"value"}');
  const etag = content.headers.get('etag');
  const updated = await call('putContent', { token, params: { resourceId }, raw: 'next', headers: { 'if-match': etag } });
  assert.equal(updated.status, 200);
  const conflict = await call('putContent', { token, params: { resourceId }, raw: 'stale', headers: { 'if-match': etag } });
  assert.equal(conflict.status, 412);
  assert.equal(conflict.json.error.code, 'secret_changed');
  const delivered = await call('inject', { token, query: { as }, data: { names: [{ name: resourceId, as: 'CONFIG_FILE', filename: 'config.json' }] } });
  assert.equal(Buffer.from(delivered.json.injection.files[0].content, 'base64').toString(), 'next');
});

test('JSON定義を検証し、バイナリ保存とJSONリソースの入力を種類によって扱う', async t => {
  const f = await fixture(t);
  const made = await f.request('/v1/resources?kind=service&name=notes', { method: 'PUT', data: { version: 1, name: 'Notes' } });
  assert.equal(made.status, 200);
  const refused = await f.request('/v1/resources?kind=service&name=notes', { method: 'PUT', data: { version: 1, name: 123 } });
  assert.equal(refused.status, 400);
  const kept = await f.request('/v1/resources/' + made.json.resource.id);
  assert.equal(kept.json.resource.definition.name, 'Notes');
  const binary = Buffer.from([0, 255, 10, 1]);
  const saved = await f.request('/v1/resources?kind=secret&name=binary', { method: 'PUT', raw: binary });
  assert.equal(saved.status, 200);
  assert.equal(saved.json.resource.size, binary.length);
  const delivery = await f.request('/v1/injections', { method: 'POST', data: { names: [{ name: 'binary', as: 'BINARY_FILE', filename: 'data.bin' }] } });
  assert.deepEqual(Buffer.from(delivery.json.injection.files[0].content, 'base64'), binary);
});

test('省略可能な値にnullを渡した場合も従来の既定値で依頼と接続を扱う', async t => {
  const f = await fixture(t), key = await f.become('defaults');
  const asked = await f.request('/v1/requests', { method: 'POST', token: key.token, data: { kind: 'actor', input: { name: 'defaults' }, steps: null, valid_minutes: null } });
  assert.equal(asked.status, 201);
  assert.deepEqual(asked.json.request.steps, []);
  assert.equal(asked.json.request.expires_at - asked.json.request.created_at, 30 * 60_000);
  const started = await f.request('/v1/credentials', { method: 'POST', data: { service: 'google', scopes: null, app: null } });
  assert.equal(started.status, 200);
  assert.equal(new URL(started.json.url).protocol, 'https:');
});

test('API仕様のHTMLと自己ホストしたアセットをキャッシュ再検証付きで配信する', async t => {
  const f = await fixture(t, { login: false });
  const page = await f.request('/docs', { anonymous: true });
  for (const path of [...page.text.matchAll(/(?:src|href)="(\/docs\/[^"?#]+)"/g)].map(match => match[1])) {
    const asset = await f.request(path, { anonymous: true });
    assert.equal(asset.status, 200);
    assert.equal(asset.headers.get('cache-control'), 'no-cache');
    const reused = await f.request(path, { anonymous: true, headers: { 'if-none-match': asset.headers.get('etag') } });
    assert.equal(reused.status, 304);
  }
  const head = await f.request('/docs', { method: 'HEAD', anonymous: true });
  assert.equal(head.status, 200);
  assert.match(head.headers.get('content-type'), /^text\/html/);
});
