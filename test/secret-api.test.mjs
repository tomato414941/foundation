import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, USER_A } from './helpers.mjs';

test('WebとAPIキーが同じAPIで固定トークンを保存・更新し、呼び出し側の変数名で渡す', async t => {
  const f = await fixture(t), key = await f.issueKey();
  for (const [name, options] of [['Web', {}], ['API', { token: key.token, anonymous: true }]]) {
    const kept = await f.keep('secret', name, 'private-' + name, options);
    assert.equal(kept.status, 200, kept.text);
    assert.equal(kept.json.resource.kind, 'secret');
    const path = '/v1/resources/' + kept.json.resource.id;
    assert.equal((await f.request(path + '/content', options)).text, 'private-' + name);
    const updated = await f.request(path + '/content', { ...options, method: 'PUT', raw: 'updated-' + name });
    assert.equal(updated.status, 200, updated.text);
    assert.equal(updated.json.resource.id, kept.json.resource.id);
    const delivered = await f.request('/v1/injections', { ...options, method: 'POST', data: { names: [{ id: kept.json.resource.id, as: 'MY_TOKEN' }] } });
    assert.deepEqual(delivered.json.injection.environment, { MY_TOKEN: 'updated-' + name });
    assert.doesNotMatch(kept.text + updated.text, /private-|updated-/);
  }
});

test('APIキーだけの主体も自分のシークレットを持ち、他の主体の値を保護する', async t => {
  const f = await fixture(t), key = await f.become(), options = { token: key.token, anonymous: true };
  const response = await f.request('/v1/resources?kind=secret&name=token', { ...options, method: 'PUT', raw: 'private-token' });
  assert.equal(response.status, 200, response.text);
  const saved = response.json.resource;
  assert.equal(saved.holder_id, key.id);
  assert.equal((await f.read('secret', 'token', options)).text, 'private-token');
  assert.equal((await f.request('/v1/resources/' + saved.id + '/content')).status, 403);
  const owner = (await f.keep('secret', 'token', 'owner-private')).json.resource;
  assert.equal(owner.holder_id, USER_A);
  assert.equal((await f.request('/v1/resources/' + owner.id + '/content', options)).status, 401);
});

test('複数の値を個別のシークレットとして保存し、一度に指定先へ渡す', async t => {
  const f = await fixture(t), key = await f.issueKey();
  await f.keep('secret', 'account', 'account-one');
  await f.keep('secret', 'api token', 'private-token');
  const delivered = await f.request('/v1/injections', { method: 'POST', token: key.token, anonymous: true, data: {
    names: [{ name: 'account', as: 'ACCOUNT_ID' }, { name: 'api token', as: 'API_TOKEN' }],
  } });
  assert.deepEqual(delivered.json.injection.environment, { ACCOUNT_ID: 'account-one', API_TOKEN: 'private-token' });
});

test('CLIは封をして、MCPはFoundationに封をさせて固定トークンを保存し、同じIDの値を取得・利用する', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const directory = await mkdtemp(join(tmpdir(), 'foundation-secret-api-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const keyPath = join(directory, 'key'), input = join(directory, 'input');
  await writeFile(keyPath, key.token, { mode: 0o600 });
  await writeFile(input, 'cli-private', { mode: 0o600 });
  const cli = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['cli/runtime.mjs', 'keep', 'CLI', '--from', input], {
      env: { ...process.env, FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath },
    });
    let out = '', err = '';
    child.stdout.on('data', part => { out += part; }); child.stderr.on('data', part => { err += part; });
    child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
  });
  assert.equal(cli.code, 0, cli.err);
  const id = JSON.parse(cli.out).resource.id;
  assert.doesNotMatch(cli.out + cli.err, /cli-private/);
  const call = (method, path, body, body_encoding = 'json') => f.request('/mcp', { method: 'POST', token: key.token, anonymous: true, data: {
    jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'foundation_api', arguments: { method, path, body, body_encoding } },
  } });
  const mcp = await call('PUT', '/v1/resources?kind=secret&name=MCP', { plain: Buffer.from('mcp-private').toString('base64url') });
  assert.equal(mcp.json.result.isError, undefined, mcp.text);
  const saved = mcp.json.result.structuredContent.resource;
  assert.equal(saved.kind, 'secret');
  assert.equal((await f.read('secret', 'MCP')).text, 'mcp-private');
  const delivered = await call('POST', '/v1/injections', { names: [{ id, as: 'CLI_TOKEN' }, { id: saved.id, as: 'MCP_TOKEN' }] });
  assert.deepEqual(delivered.json.result.structuredContent.injection.environment, { CLI_TOKEN: 'cli-private', MCP_TOKEN: 'mcp-private' });
});
