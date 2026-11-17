import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';

const key = JSON.stringify({
  type: 'service_account', project_id: 'example-project', private_key_id: 'key-id-1',
  private_key: '-----BEGIN PRIVATE KEY-----\ntest-private-key\n-----END PRIVATE KEY-----\n',
  client_email: 'robot@example-project.iam.gserviceaccount.com', client_id: '1234567890',
  token_uri: 'https://oauth2.googleapis.com/token',
}, null, 2);
const names = ['GOOGLE_APPLICATION_CREDENTIALS', 'CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE'];
const robot = 'robot@example-project.iam.gserviceaccount.com';

async function delivered(f: Awaited<ReturnType<typeof flowFixture>>, id: string, format?: 'text') {
  return f.inputs(names.map(name => ({ name, source: { id, output: name }, ...(format ? { format } : {}) })));
}

test('Googleのサービスアカウントの鍵を接続として保存し、ロボットのメールアドレスを表示する', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const resource = await f.saveConnection({ methodId: 'google:service_account', fields: { credentials: key } });
  assert.equal(resource.kind, 'connection');
  if (resource.kind !== 'connection') return;
  assert.equal(resource.data.account, 'robot@example-project.iam.gserviceaccount.com');
  assert.deepEqual(resource.data.services, [{ id: 'google', name: 'Google' }]);
  assert.equal(JSON.stringify(resource).includes('test-private-key'), false);
});

test('サービスアカウントではないJSONやJSONでない値は、接続として保存しない', async t => {
  const f = await flowFixture();
  t.after(f.close);
  for (const credentials of [JSON.stringify({ type: 'authorized_user', client_id: 'id' }),
    '"type": "service_account" but not JSON', JSON.stringify({ type: 'service_account' })])
    await assert.rejects(f.saveConnection({ methodId: 'google:service_account', fields: { credentials } }));
});

test('サービスアカウントの鍵を、形式を指定しない入力にはファイルとして渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const resource = await f.saveConnection({ methodId: 'google:service_account', fields: { credentials: key } });
  const used = await delivered(f, resource.id);
  assert.deepEqual(used.environment, {});
  for (const name of names) assert.equal(JSON.parse(Buffer.from(used.files[name]!, 'base64').toString('utf8')).client_email, robot);
});

test('入力がテキストを指定したときは、サービスアカウントの鍵を値のまま渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const resource = await f.saveConnection({ methodId: 'google:service_account', fields: { credentials: key } });
  const used = await delivered(f, resource.id, 'text');
  assert.deepEqual(used.files, {});
  for (const name of names) assert.equal(JSON.parse(used.environment[name]!).client_email, robot);
});
