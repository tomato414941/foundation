import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';

type Fixture = Awaited<ReturnType<typeof flowFixture>>;

async function delivered(f: Fixture, id: string, names: string[]) {
  return (await f.inputs(names.map(name => ({ name, source: { id, output: name } })))).environment;
}

test('Supabaseのアクセストークンを暗号化して保存し、手元のコマンドへ環境変数で渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const token = 'sbp_' + 'a'.repeat(40);
  const connection = await f.saveConnection({ methodId: 'supabase:token', fields: { token } });
  assert.equal(connection.kind, 'connection');
  if (connection.kind !== 'connection') return;
  assert.deepEqual(connection.data.services, [{ id: 'supabase', name: 'Supabase' }]);
  const stored = await f.client.read(connection.id);
  assert.equal(JSON.stringify({ connection, content: stored.content }).includes(token), false);
  assert.deepEqual(await delivered(f, connection.id, ['SUPABASE_ACCESS_TOKEN']), { SUPABASE_ACCESS_TOKEN: token });
});

test('Supabaseのプロジェクトの場所とキーを、手元のコマンドへ環境変数で渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'supabase:secret-key', fields: {
    url: 'https://example-ref.supabase.co', secretKey: 'sb_secret_private-test-key', publishableKey: 'sb_publishable_test' } });
  const expected = { SUPABASE_URL: 'https://example-ref.supabase.co',
    SUPABASE_SECRET_KEY: 'sb_secret_private-test-key', SUPABASE_PUBLISHABLE_KEY: 'sb_publishable_test' };
  assert.deepEqual(await delivered(f, connection.id, Object.keys(expected)), expected);
});

test('Supabaseのデータベースのパスワードを、プロジェクトIDとともに手元のコマンドへ環境変数で渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'supabase:database-password',
    fields: { projectId: 'exampleref', password: 'private-db-password' } });
  assert.equal(connection.kind, 'connection');
  assert.equal(JSON.stringify(connection).includes('private-db-password'), false);
  const expected = { SUPABASE_PROJECT_ID: 'exampleref', SUPABASE_DB_PASSWORD: 'private-db-password' };
  assert.deepEqual(await delivered(f, connection.id, Object.keys(expected)), expected);
});
