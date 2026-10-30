import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { HttpRequest } from '../shared/contracts.js';
import { Task } from '../shared/runtime-protocol.js';

type Fixture = Awaited<ReturnType<typeof flowFixture>>;

async function send(f: Fixture, connectionId: string, url: string) {
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'http', request: HttpRequest.parse({ connectionId, url, method: 'GET' }), save: {},
  });
  await f.executor.tick();
  const completed = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  return { task: completed, result: await f.client.result(completed) };
}

test('Supabaseのアクセストークンを暗号化して保存し、Management APIを呼び出す', async t => {
  const f = await flowFixture(() => jsonResponse([]));
  t.after(f.close);
  const token = 'sbp_' + 'a'.repeat(40);
  const connection = await f.saveConnection({ methodId: 'supabase:token', fields: { token } });
  assert.equal(connection.kind, 'connection');
  if (connection.kind !== 'connection') return;
  assert.deepEqual(connection.data.services, [{ id: 'supabase', name: 'Supabase' }]);
  const stored = await f.client.read(connection.id);
  assert.equal(JSON.stringify({ connection, content: stored.content }).includes(token), false);
  const { task, result } = await send(f, connection.id, 'https://api.supabase.com/v1/projects');
  assert.equal(task.state, 'succeeded', JSON.stringify(result));
  assert.equal(f.requests.at(-1)?.headers?.Authorization, 'Bearer ' + token);
  const other = await send(f, connection.id, 'https://api.supabase.com.other.example/v1/projects');
  assert.equal(other.result?.error?.code, 'invalid_destination');
});

test('Supabaseのシークレットキーを、そのプロジェクトのURLにだけapikeyヘッダーで送る', async t => {
  const f = await flowFixture(() => jsonResponse([]));
  t.after(f.close);
  const secretKey = 'sb_secret_private-test-key';
  const connection = await f.saveConnection({ methodId: 'supabase:secret-key',
    fields: { url: 'https://example-ref.supabase.co', secretKey } });
  const { task, result } = await send(f, connection.id, 'https://example-ref.supabase.co/rest/v1/items');
  assert.equal(task.state, 'succeeded', JSON.stringify(result));
  assert.equal(f.requests.at(-1)?.headers?.apikey, secretKey);
  const requests = f.requests.length;
  const other = await send(f, connection.id, 'https://other-ref.supabase.co/rest/v1/items');
  assert.equal(other.result?.error?.code, 'invalid_destination');
  assert.equal(f.requests.length, requests);
});

// Delivers the outputs to a command that compares them with the expected values itself, since output is redacted.
async function command(f: Fixture, id: string, expected: Record<string, string>) {
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'command', timeoutSeconds: 10, command: [process.execPath, '-e',
      `require("node:assert/strict").deepEqual(Object.fromEntries(${JSON.stringify(Object.keys(expected))}` +
      `.map(name => [name, process.env[name]])), ${JSON.stringify(expected)});console.log("Supabase values delivered");`],
    inputs: Object.keys(expected).map(name => ({ name, source: { id, output: name } })),
  });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  assert.equal(result?.ok, true, JSON.stringify(result));
  assert.match(JSON.stringify(result), /Supabase values delivered/);
}

test('Supabaseのプロジェクトの場所とキーを、コマンドに環境変数で渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'supabase:secret-key', fields: {
    url: 'https://example-ref.supabase.co', secretKey: 'sb_secret_private-test-key', publishableKey: 'sb_publishable_test' } });
  await command(f, connection.id, { SUPABASE_URL: 'https://example-ref.supabase.co',
    SUPABASE_SECRET_KEY: 'sb_secret_private-test-key', SUPABASE_PUBLISHABLE_KEY: 'sb_publishable_test' });
});

test('Supabaseのデータベースのパスワードを、プロジェクトIDとともにコマンドに環境変数で渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'supabase:database-password',
    fields: { projectId: 'exampleref', password: 'private-db-password' } });
  assert.equal(connection.kind, 'connection');
  assert.equal(JSON.stringify(connection).includes('private-db-password'), false);
  await command(f, connection.id, { SUPABASE_PROJECT_ID: 'exampleref', SUPABASE_DB_PASSWORD: 'private-db-password' });
});
