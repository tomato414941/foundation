import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { Task } from '../shared/runtime-protocol.js';

const key = JSON.stringify({
  type: 'service_account', project_id: 'example-project', private_key_id: 'key-id-1',
  private_key: '-----BEGIN PRIVATE KEY-----\ntest-private-key\n-----END PRIVATE KEY-----\n',
  client_email: 'robot@example-project.iam.gserviceaccount.com', client_id: '1234567890',
  token_uri: 'https://oauth2.googleapis.com/token',
}, null, 2);
// Prints the service account each variable leads to, and whether it named a file.
const report = `const fs = require('node:fs');
const read = name => { const value = process.env[name]; const file = fs.existsSync(value);
  return (file ? 'file:' : 'text:') + JSON.parse(file ? fs.readFileSync(value, 'utf8') : value).client_email; };
process.stdout.write(read('GOOGLE_APPLICATION_CREDENTIALS') + ' ' + read('CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE'));`;

async function command(f: Awaited<ReturnType<typeof flowFixture>>, id: string, format?: 'text') {
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, { kind: 'command',
    command: ['node', '-e', report], timeoutSeconds: 10, inputs: ['GOOGLE_APPLICATION_CREDENTIALS',
      'CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE'].map(name => ({ name, source: { id, output: name }, ...(format ? { format } : {}) })) });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  assert.equal(result?.ok, true, JSON.stringify(result));
  return (result!.result as { stdout: string }).stdout;
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

test('サービスアカウントの鍵を、形式を指定しない入力にはファイルとその場所で渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const resource = await f.saveConnection({ methodId: 'google:service_account', fields: { credentials: key } });
  assert.equal(await command(f, resource.id),
    'file:robot@example-project.iam.gserviceaccount.com file:robot@example-project.iam.gserviceaccount.com');
});

test('入力がテキストを指定したときは、サービスアカウントの鍵を値のまま渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const resource = await f.saveConnection({ methodId: 'google:service_account', fields: { credentials: key } });
  assert.equal(await command(f, resource.id, 'text'),
    'text:robot@example-project.iam.gserviceaccount.com text:robot@example-project.iam.gserviceaccount.com');
});
