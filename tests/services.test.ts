import test from 'node:test';
import assert from 'node:assert/strict';
import { publicAddress, publicUrl } from '../server/transport.js';
import { flowFixture, jsonResponse } from './flow-support.js';
import { ConnectionMaterial } from '../shared/connections.js';
import { decode } from '../shared/encryption.js';
import { Task } from '../shared/execution.js';

test('公開HTTPSの送信先を受け入れ、プライベートアドレスへの送信を拒否する', () => {
  for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111'])
    assert.equal(publicAddress(address), true, address);
  for (const address of [
    '127.0.0.1',
    '0.0.0.0',
    '10.1.1.1',
    '169.254.169.254',
    '172.16.1.1',
    '192.168.1.1',
    '100.64.0.1',
    '::1',
    '::ffff:127.0.0.1',
    'fc00::1',
    'fe80::1',
    '2001:db8::1',
  ])
    assert.equal(publicAddress(address), false, address);
  assert.equal(publicUrl('https://example.com/path').hostname, 'example.com');
  for (const url of [
    'http://example.com',
    'https://127.1',
    'https://[::ffff:127.0.0.1]',
    'https://example.com:8443',
    'https://name:password@example.com',
  ])
    assert.throws(() => publicUrl(url));
});


test('同じ表示名で複数サービスへ接続し、それぞれの実行先で認証情報を使う', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const saved = [];
  for (const [methodId, output] of [['github:token', 'GH_TOKEN'], ['cloudflare:token', 'CLOUDFLARE_API_TOKEN']]) {
    const started = await f.start({ methodId: methodId!, fields: { token: methodId + '-private-value' } });
    assert.equal((await f.tick(started.flow.id)).kind, 'review');
    const connection = await f.accept(started.flow.id);
    saved.push(connection.id);
    assert.equal((await f.http(connection.id, output!))?.ok, true);
    assert.equal(f.requests.at(-1)!.headers.authorization, 'Bearer ' + methodId + '-private-value');
  }
  assert.notEqual(saved[0], saved[1]);
});

test('RenderのOAuth応答を暗号化して中継し、実行先で接続・更新・解除を行う', async t => {
  let exchange = 0;
  const f = await flowFixture(request => {
    if (request.url.endsWith('/oauth/token')) {
      exchange++;
      return jsonResponse({ access_token: 'render-access-' + exchange, refresh_token: 'render-refresh-' + exchange,
        token_type: 'bearer', expires_in: exchange === 1 ? 1 : 3600 });
    }
    return jsonResponse({ ok: true });
  });
  t.after(f.close);
  const application = await f.saveApp('render:oauth');
  const started = await f.start({ methodId: 'render:oauth', appId: application.id });
  const authorized = await f.tick(started.flow.id);
  assert.equal(authorized.kind, 'authorize');
  if (authorized.kind !== 'authorize') return;
  const url = new URL(authorized.url);
  assert.equal(url.searchParams.get('resource'), 'https://mcp.render.com/mcp');
  const callback = await f.app.inject({ url: '/oauth/callback?' + new URLSearchParams({
    state: url.searchParams.get('state')!, code: 'render-code',
  }) });
  assert.equal(callback.statusCode, 302);
  assert.equal((await f.connections.progress(started.flow.id)).kind, 'pending');
  const review = await f.tick(started.flow.id);
  assert.equal(review.kind, 'review', JSON.stringify('error' in review ? review.error : review.kind));
  const saved = await f.accept(started.flow.id);
  assert.equal((await f.http(saved.id, 'RENDER_MCP_ACCESS_TOKEN', 'https://mcp.render.com/mcp'))?.ok, true);
  assert.equal(exchange, 2);
  assert.equal(f.requests.at(-1)!.headers.authorization, 'Bearer render-access-2');
  const form = new URLSearchParams(String(f.requests.find(request =>
    request.url.endsWith('/oauth/token') && String(request.body).includes('refresh_token'))!.body));
  assert.equal(form.get('resource'), 'https://mcp.render.com/mcp');
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id,
    { kind: 'revoke', input: { action: 'revoke', id: saved.id } }, { sourceIds: [saved.id] });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/executions/' + task.id, {}, Task));
  assert.equal(result?.ok, true);
  assert.deepEqual(result?.result, { kind: 'revoked', id: saved.id });
  assert.equal(new URLSearchParams(String(f.requests.at(-1)!.body)).get('token'), 'render-refresh-2');
});

test('APIキーの更新を確認して同じ接続へ反映し、取り消した更新は元の値を保つ', async t => {
  const f = await flowFixture(); t.after(f.close);
  const started = await f.start({ methodId: 'render:token', fields: { token: 'original' } });
  await f.tick(started.flow.id);
  const saved = await f.accept(started.flow.id);
  const cancelled = await f.start({ methodId: 'render:token', connectionId: saved.id, fields: { token: 'discarded' } });
  await f.tick(cancelled.flow.id);
  await f.connections.cancel(cancelled.flow.id);
  let material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(saved.id))));
  assert.equal(material.fields!.token, 'original');
  const replacement = await f.start({ methodId: 'render:token', connectionId: saved.id, fields: { token: 'updated' } });
  await f.tick(replacement.flow.id);
  assert.equal((await f.accept(replacement.flow.id)).id, saved.id);
  material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(saved.id))));
  assert.equal(material.fields!.token, 'updated');
});

test('OpenRouterの公開PKCEフローを選んだ実行先で完了し、承認したキーでAPIを呼び出す', async t => {
  const f = await flowFixture(request => {
    if (request.url.endsWith('/auth/keys')) return jsonResponse({ key: 'openrouter-private-key' });
    if (request.url.endsWith('/key')) return jsonResponse({ data: { label: 'Selected key' } });
    return jsonResponse({ ok: true });
  });
  t.after(f.close);
  const started = await f.start({ methodId: 'openrouter:oauth' });
  const authorize = await f.tick(started.flow.id);
  assert.equal(authorize.kind, 'authorize');
  if (authorize.kind !== 'authorize') return;
  const url = new URL(authorize.url);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  await f.connections.complete(started.flow.id, new URLSearchParams({
    state: url.searchParams.get('state')!, code: 'openrouter-code',
  }).toString());
  const review = await f.tick(started.flow.id);
  assert.equal(review.kind, 'review', JSON.stringify(review));
  const saved = await f.accept(started.flow.id);
  const material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(saved.id))));
  assert.equal(material.oauth!.accountName, 'Selected key');
  assert.equal((await f.http(saved.id, 'OPENROUTER_API_KEY', 'https://openrouter.ai/api/v1/chat/completions'))?.ok, true);
  assert.equal(f.requests.at(-1)!.headers.authorization, 'Bearer openrouter-private-key');
});

test('先に承認した接続を保持し、古い確認画面には最新の権限の再確認を求める', async t => {
  const f = await flowFixture(); t.after(f.close);
  const started = await f.start({ methodId: 'github:token', fields: { token: 'initial' } });
  await f.tick(started.flow.id);
  const saved = await f.accept(started.flow.id);
  const first = await f.start({ methodId: 'github:token', connectionId: saved.id, fields: { token: 'first' } });
  const second = await f.start({ methodId: 'github:token', connectionId: saved.id, fields: { token: 'second' } });
  await f.tick(first.flow.id); await f.tick(second.flow.id);
  await f.accept(first.flow.id);
  await assert.rejects(f.connections.accept(second.flow.id), /recipients changed/);
  assert.equal(ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(saved.id)))).fields!.token, 'first');
});

test('選択した実行先のワークロード権限でIAMロールを引き受ける', async t => {
  const obtained: string[] = [];
  const f = await flowFixture(undefined, { async obtain(arn, externalId, region) {
    obtained.push(arn + ':' + externalId);
    return { AWS_ACCESS_KEY_ID: 'role-key', AWS_SECRET_ACCESS_KEY: 'role-secret',
      AWS_SESSION_TOKEN: 'role-session', AWS_DEFAULT_REGION: region };
  } });
  t.after(f.close);
  const role = { arn: 'arn:aws:iam::123456789012:role/Example', region: 'ap-northeast-1', externalId: 'exclusive-external-id' };
  const started = await f.start({ methodId: 'aws:role', role });
  assert.equal((await f.tick(started.flow.id)).kind, 'review');
  const saved = await f.accept(started.flow.id);
  assert.equal((await f.http(saved.id, 'AWS_ACCESS_KEY_ID'))?.ok, true);
  assert.equal(f.requests.at(-1)!.headers.authorization, 'Bearer role-key');
  assert.ok(obtained.every(item => item === role.arn + ':' + role.externalId));
});
