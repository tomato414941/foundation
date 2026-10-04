import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { fixture, USER_A } from './helpers.mjs';

test('APIの認証成功をキーの最終利用として記録する', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const mine = async () => (await f.request('/v1/principals/' + key.id)).json.principal.keys[0];
  // Issued and used once already: the machine published its key with it.
  const first = (await mine()).last_used_at;
  assert.ok(first);
  await new Promise(resolve => setTimeout(resolve, 5));
  const before = Date.now();
  assert.equal((await f.request('/v1/principals/' + USER_A + '/resources?kind=connection', { token: key.token })).status, 200);
  const current = await mine();
  assert.ok(Date.parse(current.last_used_at) >= before);
  assert.ok(Date.parse(current.last_used_at) > Date.parse(first));
  assert.ok(Date.parse(current.last_used_at) <= Date.now());
  assert.equal((await mine()).last_used_at, current.last_used_at);
});

for (const identity of ['キー', 'セッション']) test(`アップロード中に${identity}が失効した場合は保存を拒否して元の値を維持する`, async t => {
  const f = await fixture(t), key = await f.issueKey();
  await f.request('/v1/principals/me/resources?kind=secret&name=value', { method: 'PUT', raw: 'original' });
  const started = new Promise(resolve => f.app.server.once('request', req => req.once('readable', resolve)));
  let upload;
  const completed = new Promise((resolve, reject) => {
    upload = httpRequest(f.base + '/v1/principals/me/resources?kind=secret&name=value', { method: 'PUT', headers: {
      'content-type': 'application/json',
      ...(identity === 'キー' ? { authorization: 'Bearer ' + key.token } : { cookie: f.cookie(), origin: f.base }),
    } }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString() }));
      res.on('error', reject);
    });
    upload.on('error', reject);
  });
  t.after(() => upload.destroy());
  upload.write('{"plain":"cmVwbGFjZW1lbnQt');
  await started;
  if (identity === 'キー') await f.request('/v1/principals/' + key.id, { method: 'DELETE', data: {} });
  else await f.request('/v1/session', { method: 'DELETE' });
  upload.end('dmFsdWU"}');
  const result = await completed;
  assert.equal(result.status, 401, result.text);
  assert.equal(f.app.secrets.open(f.app.secrets.at(USER_A, 'value')).toString(), 'original');
});

