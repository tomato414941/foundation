import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';

test('ModalのAPIトークンを暗号化して保存し、SDK用の環境変数として手元のコマンドへ渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'modal:token',
    fields: { tokenId: 'ak-test-account', tokenSecret: 'as-test-account-secret' } });
  const used = await f.inputs(['MODAL_TOKEN_ID', 'MODAL_TOKEN_SECRET'].map(name => ({ name, source: { id: connection.id, output: name } })));
  assert.deepEqual(used.environment, { MODAL_TOKEN_ID: 'ak-test-account', MODAL_TOKEN_SECRET: 'as-test-account-secret' });
  assert.equal(JSON.stringify(connection).includes('as-test-account-secret'), false);
  assert.equal(JSON.stringify(connection).includes('ak-test-account'), false);
});

test('ModalのProxy Tokenを暗号化して保存し、Bearer用のトークンと2つのヘッダー用の値を手元のコマンドへ渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'modal:proxy-token',
    fields: { proxyTokenId: 'wk-test', proxyTokenSecret: 'ws-test/secret+=' } });
  const used = await f.inputs(['MODAL_PROXY_TOKEN', 'MODAL_PROXY_TOKEN_ID', 'MODAL_PROXY_TOKEN_SECRET']
    .map(name => ({ name, source: { id: connection.id, output: name } })));
  assert.deepEqual(used.environment, { MODAL_PROXY_TOKEN: 'wk-test.ws-test/secret+=', MODAL_PROXY_TOKEN_ID: 'wk-test',
    MODAL_PROXY_TOKEN_SECRET: 'ws-test/secret+=' });
  assert.equal(JSON.stringify(connection).includes('ws-test/secret+='), false);
  assert.equal(JSON.stringify(connection).includes('wk-test'), false);
});

test('ModalのProxy Tokenを更新し、同じ接続で新しい認証情報を使用する', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const token = async (id: string) =>
    (await f.inputs([{ name: 'MODAL_PROXY_TOKEN', source: { id, output: 'MODAL_PROXY_TOKEN' } }])).environment.MODAL_PROXY_TOKEN;
  const first = await f.saveConnection({ methodId: 'modal:proxy-token',
    fields: { proxyTokenId: 'wk-test', proxyTokenSecret: 'ws-first-secret' } });
  assert.equal(await token(first.id), 'wk-test.ws-first-secret');
  const updated = await f.saveConnection({ methodId: 'modal:proxy-token', connectionId: first.id,
    fields: { proxyTokenId: 'wk-test', proxyTokenSecret: 'ws-updated-secret' } });
  assert.equal(updated.id, first.id);
  assert.equal(await token(updated.id), 'wk-test.ws-updated-secret');
});
