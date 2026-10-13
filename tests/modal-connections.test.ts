import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { Task } from '../shared/runtime-protocol.js';

test('ModalのAPIトークンを暗号化して保存し、SDK用の環境変数として実行環境へ届ける', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'modal:token',
    fields: { tokenId: 'ak-test-account', tokenSecret: 'as-test-account-secret' } });
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'command', command: [process.execPath, '-e',
      'const assert=require("node:assert/strict");assert.equal(process.env.MODAL_TOKEN_ID,"ak-test-account");' +
      'assert.equal(process.env.MODAL_TOKEN_SECRET,"as-test-account-secret");console.log("Modal credentials delivered");'],
    inputs: ['MODAL_TOKEN_ID', 'MODAL_TOKEN_SECRET'].map(name => ({ name, source: { id: connection.id, output: name } })),
    timeoutSeconds: 10,
  });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  assert.equal(result?.ok, true);
  assert.match(JSON.stringify(result), /Modal credentials delivered/);
  assert.equal(JSON.stringify(connection).includes('as-test-account-secret'), false);
  assert.equal(JSON.stringify(connection).includes('ak-test-account'), false);
});

test('ModalのProxy Tokenを暗号化して保存し、Bearer認証と2つのヘッダーでHTTP APIを呼び出す', async t => {
  const url = 'https://test-workspace--model.modal.run/v1/responses';
  const f = await flowFixture(request => {
    assert.equal(request.url, url);
    if (request.headers?.authorization) assert.equal(request.headers.authorization, 'Bearer wk-test.ws-test/secret+=');
    else {
      assert.equal(request.headers?.['modal-key'], 'wk-test');
      assert.equal(request.headers?.['modal-secret'], 'ws-test/secret+=');
    }
    return jsonResponse({ generated: 'Test response' });
  });
  t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'modal:proxy-token',
    fields: { proxyTokenId: 'wk-test', proxyTokenSecret: 'ws-test/secret+=' } });
  assert.equal((await f.http(connection.id, 'MODAL_PROXY_TOKEN', url))?.ok, true);
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'http', request: { url, method: 'GET', headers: {}, bindings: [
      { pointer: '/headers/modal-key', parts: [{ id: connection.id, output: 'MODAL_PROXY_TOKEN_ID' }] },
      { pointer: '/headers/modal-secret', parts: [{ id: connection.id, output: 'MODAL_PROXY_TOKEN_SECRET' }] },
    ] }, save: {},
  });
  await f.executor.tick();
  assert.equal((await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task)))?.ok, true);
  assert.equal(JSON.stringify(connection).includes('ws-test/secret+='), false);
  assert.equal(JSON.stringify(connection).includes('wk-test'), false);
});

test('ModalのProxy Tokenを更新し、同じ接続で新しい認証情報を使用する', async t => {
  let secret = 'ws-first-secret';
  const f = await flowFixture(request => {
    assert.equal(request.headers?.authorization, 'Bearer wk-test.' + secret);
    return jsonResponse({ generated: 'Test response' });
  });
  t.after(f.close);
  const first = await f.saveConnection({ methodId: 'modal:proxy-token',
    fields: { proxyTokenId: 'wk-test', proxyTokenSecret: secret } });
  assert.equal((await f.http(first.id, 'MODAL_PROXY_TOKEN'))?.ok, true);
  secret = 'ws-updated-secret';
  const updated = await f.saveConnection({ methodId: 'modal:proxy-token', connectionId: first.id,
    fields: { proxyTokenId: 'wk-test', proxyTokenSecret: secret } });
  assert.equal(updated.id, first.id);
  assert.equal((await f.http(updated.id, 'MODAL_PROXY_TOKEN'))?.ok, true);
});
