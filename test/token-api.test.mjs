import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, USER_A, USER_B } from './helpers.mjs';

const tokenSpec = { fields: [{ name: 'token', label: 'トークン', secret: true }], injection: { API_TOKEN: '{token}' } };
const identity = { url: 'https://service.example/me', headers: { authorization: 'Bearer {token}' }, id: 'id', label: 'name' };
const reply = (status = 200) => ({ ok: status === 200, status, text: JSON.stringify({ id: 'account-one', name: 'Account One' }) });
async function service(f, spec = tokenSpec, options = {}) {
  const registered = await f.request('/v1/resources?kind=service&name=Notes', {
    method: 'PUT', data: { version: 1, name: 'Notes', auth_schemes: { token: spec } }, ...options,
  });
  assert.equal(registered.status, 200, registered.text);
  return registered.json.resource.id;
}
const register = (f, data, options = {}) => f.request('/v1/credentials', { method: 'POST', data, ...options });
const keyOptions = key => ({ token: key.token, anonymous: true });

test('WebのセッションとAPIキーから同じAPIでシークレットをサービスへ登録する', async t => {
  const f = await fixture(t), key = await f.issueKey(), target = await service(f);
  for (const [name, options] of [['Web', {}], ['API', keyOptions(key)]]) {
    const kept = (await f.keep('credential', name, 'saved-' + name)).json.resource;
    const adopted = await register(f, { service: target, auth_scheme: 'token', credential_id: kept.id }, options);
    assert.equal(adopted.status, 200, adopted.text);
    assert.equal(adopted.json.credential.id, kept.id);
    assert.equal(adopted.json.credential.name, name);
    assert.equal(adopted.json.credential.service.id, target);
    assert.equal(adopted.json.credential.facts.checked_at, null);
    assert.doesNotMatch(adopted.text, /saved-/);
    assert.deepEqual((await f.inject(adopted.json.credential, options)).json.injection.environment, { API_TOKEN: 'saved-' + name });
  }
  assert.equal(f.app.credentials.list(USER_A, { service: target }).length, 2);
});

test('APIキーで新しいトークンを登録し、同じIDで値を更新する', async t => {
  const f = await fixture(t), key = await f.issueKey(), target = await service(f), options = keyOptions(key);
  // An HTTP client has no browser cookie or Origin header.
  const response = await fetch(f.base + '/v1/credentials?as=' + USER_A, { method: 'POST',
    headers: { authorization: 'Bearer ' + key.token, 'content-type': 'application/json' },
    body: JSON.stringify({ service: target, auth_scheme: 'token', fields: { token: 'first-private' } }) });
  assert.equal(response.status, 200, await response.clone().text());
  const made = (await response.json()).credential;
  const renewed = await register(f, { service: target, auth_scheme: 'token', credential_id: made.id, fields: { token: 'second-private' } }, options);
  assert.equal(renewed.status, 200, renewed.text);
  assert.equal(renewed.json.credential.id, made.id);
  assert.deepEqual((await f.inject(made, options)).json.injection.environment, { API_TOKEN: 'second-private' });
});

test('主体自身のAPIキーで自分のサービスとシークレットを登録する', async t => {
  const f = await fixture(t), key = await f.become(), options = keyOptions(key);
  const target = await service(f, tokenSpec, options);
  const kept = (await f.keep('credential', 'personal', 'private-value', options)).json.resource;
  const adopted = await register(f, { service: target, credential_id: kept.id }, options);
  assert.equal(adopted.status, 200, adopted.text);
  assert.equal(f.app.credentials.get(kept.id).holder_id, key.id);
  assert.deepEqual((await f.inject(adopted.json.credential, options)).json.injection.environment, { API_TOKEN: 'private-value' });
});

test('保存済みの値を使い、追加のアカウント情報とともに受け渡す', async t => {
  const f = await fixture(t), key = await f.issueKey(), options = keyOptions(key);
  const target = await service(f, { ...tokenSpec, fields: [...tokenSpec.fields, { name: 'account_id', label: 'アカウント' }], injection: { API_TOKEN: '{token}', ACCOUNT_ID: '{account_id}' } });
  const kept = (await f.keep('credential', 'account token', 'saved-private')).json.resource;
  const adopted = await register(f, { service: target, credential_id: kept.id, fields: { account_id: 'one', token: 'ignored-private' } }, options);
  assert.equal(adopted.status, 200, adopted.text);
  assert.deepEqual((await f.inject(adopted.json.credential, options)).json.injection.environment, { API_TOKEN: 'saved-private', ACCOUNT_ID: 'one' });
});

test('サービスがトークンを拒否した場合はエラーをAPIに返し、元のシークレットを維持する', async t => {
  const f = await fixture(t, { serviceFetcher: async () => reply(401) }), key = await f.issueKey();
  const target = await service(f, { ...tokenSpec, identity });
  const kept = (await f.keep('credential', 'refused', 'refused-private')).json.resource;
  const refused = await register(f, { service: target, credential_id: kept.id }, keyOptions(key));
  assert.equal(refused.status, 400, refused.text);
  assert.equal(refused.json.error.code, 'token_refused');
  assert.equal((await f.read('credential', 'refused')).text, 'refused-private');
});

test('持ち主の代わりに動く権限を確認し、他人のシークレットとサービスを保護する', async t => {
  const f = await fixture(t), key = await f.become(), actor = await f.issueKey(), target = await service(f);
  const kept = (await f.keep('credential', 'protected', 'protected-private')).json.resource;
  for (const relation of ['viewer', 'editor']) {
    f.app.principals.relate(key.id, relation, 'resource', kept.id);
    const refused = await register(f, { service: target, credential_id: kept.id }, { ...keyOptions(key), as: USER_A });
    assert.equal(refused.status, 403, refused.text);
    f.app.principals.unrelate(key.id, relation, 'resource', kept.id);
  }
  await f.login('other@example.test');
  const otherService = await service(f);
  const other = (await f.keep('credential', 'other', 'other-private')).json.resource;
  assert.equal((await register(f, { service: target, credential_id: other.id }, keyOptions(actor))).status, 404);
  assert.equal((await register(f, { service: otherService, credential_id: kept.id }, keyOptions(actor))).status, 404);
  assert.equal(f.app.credentials.content(f.app.credentials.get(kept.id)).toString(), 'protected-private');
  assert.equal(f.app.credentials.content(f.app.credentials.get(other.id)).toString(), 'other-private');
});

test('依頼の承認は持ち主が行い、APIキーによるトークン登録とは区別する', async t => {
  const f = await fixture(t), key = await f.issueKey(), target = await service(f);
  const asked = await f.request('/v1/requests', { method: 'POST', ...keyOptions(key), data: { kind: 'connect', input: { service: target, auth_scheme: 'token' } } });
  assert.equal(asked.status, 201, asked.text);
  const input = { request_id: asked.json.request.id, fields: { token: 'approved-private' } };
  const refused = await register(f, input, keyOptions(key));
  assert.equal(refused.status, 403, refused.text);
  assert.equal((await f.request('/v1/requests/' + asked.json.request.id, keyOptions(key))).json.request.status, 'pending');
  const accepted = await register(f, input);
  assert.equal(accepted.status, 200, accepted.text);
  assert.equal((await f.request('/v1/requests/' + asked.json.request.id, keyOptions(key))).json.request.status, 'done');
});

// Pause the service's answer while another operation changes the authority or the value being registered.
for (const change of ['key', 'actor', 'put', 'write', 'remove', 'service', 'service-access', 'session']) {
  test(`トークン検証中の変更を検出し、現在の権限とデータを保護する (${change})`, async t => {
    const entered = Promise.withResolvers(), release = Promise.withResolvers();
    const f = await fixture(t, { serviceFetcher: async () => { entered.resolve(); await release.promise; return reply(); } });
    const key = await f.issueKey(), target = await service(f, { ...tokenSpec, identity });
    const kept = (await f.keep('credential', 'during-check', 'original-private')).json.resource;
    if (change === 'service-access') {
      f.app.principals.ensure(USER_B);
      f.app.store.db.prepare('UPDATE resources SET holder_id=? WHERE id=?').run(USER_B, target);
      f.app.principals.relate(USER_A, 'viewer', 'resource', target);
    }
    const running = register(f, { service: target, credential_id: kept.id }, change === 'session' ? {} : keyOptions(key));
    try {
      await Promise.race([entered.promise, running.then(result => assert.fail('検証の開始前に終了: ' + result.text))]);
      if (change === 'key') f.app.principals.revokeKey(key.id, key.key_id);
      if (change === 'actor') f.app.principals.unrelate(key.id, 'actor', 'principal', USER_A);
      if (change === 'put') await f.keep('credential', kept.name, 'replacement-private');
      if (change === 'write') await f.request('/v1/resources/' + kept.id + '/content', { method: 'PUT', raw: 'replacement-private' });
      if (change === 'remove') f.app.credentials.remove(f.app.credentials.get(kept.id));
      if (change === 'service') f.app.services.write(f.app.services.row(target), { version: 1, name: 'Changed', auth_schemes: { token: tokenSpec } });
      if (change === 'service-access') f.app.principals.unrelate(USER_A, 'viewer', 'resource', target);
      if (change === 'session') {
        const loggedOut = await f.request('/v1/session', { method: 'DELETE', data: {} });
        assert.equal(loggedOut.status, 200, loggedOut.text);
      }
    } finally { release.resolve(); }
    const refused = await running;
    const expected = ['key', 'actor', 'session'].includes(change) ? 401 : change === 'service-access' ? 404 : 409;
    assert.equal(refused.status, expected, refused.text);
    const current = f.app.credentials.get(kept.id);
    if (change === 'remove') assert.equal(current, undefined);
    else {
      assert.equal(current.service, null);
      assert.equal(f.app.credentials.content(current).toString(), ['put', 'write'].includes(change) ? 'replacement-private' : 'original-private');
    }
  });
}

test('CLIとMCPがWebと同じAPIでシークレットをサービスへ登録する', async t => {
  const f = await fixture(t), key = await f.issueKey(), target = await service(f);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-token-api-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'key');
  await writeFile(keyPath, key.token, { mode: 0o600 });
  const cliSecret = (await f.keep('credential', 'CLI', 'cli-private')).json.resource;
  const cli = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['cli/runtime.mjs', 'api', 'POST', '/v1/credentials', '--json', JSON.stringify({ service: target, credential_id: cliSecret.id })], {
      env: { ...process.env, FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath },
    });
    let out = '', err = '';
    child.stdout.on('data', part => { out += part; }); child.stderr.on('data', part => { err += part; });
    child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
  });
  assert.equal(cli.code, 0, cli.err);
  assert.equal(JSON.parse(cli.out).credential.id, cliSecret.id);
  assert.doesNotMatch(cli.out + cli.err, /cli-private/);
  const mcpSecret = (await f.keep('credential', 'MCP', 'mcp-private')).json.resource;
  const mcp = await f.request('/mcp', { method: 'POST', ...keyOptions(key), data: { jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'foundation_api', arguments: { method: 'POST', path: '/v1/credentials', body: { service: target, credential_id: mcpSecret.id } } } } });
  assert.equal(mcp.status, 200, mcp.text);
  assert.equal(mcp.json.result.isError, undefined, mcp.text);
  assert.equal(mcp.json.result.structuredContent.credential.id, mcpSecret.id);
  assert.doesNotMatch(mcp.text, /mcp-private/);
  assert.deepEqual((await f.inject(cliSecret, keyOptions(key))).json.injection.environment, { API_TOKEN: 'cli-private' });
  assert.deepEqual((await f.inject(mcpSecret, keyOptions(key))).json.injection.environment, { API_TOKEN: 'mcp-private' });
});
