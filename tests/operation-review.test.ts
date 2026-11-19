import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { knownResult, reviewer } from '../web/app/operation-review.js';

const approver = { id: randomUUID(), name: 'Approver' }, requester = { id: randomUUID(), name: 'Requester' };
const rows = reviewer({ approver, requester, principals: [], inspect: false, signal: new AbortController().signal });
const field = (items: Awaited<ReturnType<typeof rows>>, name: string) => items.find(row => row.field === name)?.value;

test('参照するIDの位置だけを名前に置き換え、名前や入力欄の値に書かれたUUIDはそのまま表示する', async () => {
  const written = randomUUID();
  const items = await rows({ ownerId: '$approver', principalId: requester.id, name: written,
    fields: { owner: '$approver', note: written, ids: [requester.id] } });
  assert.deepEqual(field(items, 'ownerId'), { kind: 'principal', name: 'Approver', approver: true });
  assert.deepEqual(field(items, 'principalId'), { kind: 'principal', name: 'Requester', approver: false });
  assert.deepEqual(field(items, 'name'), { kind: 'text', text: written });
  assert.deepEqual(field(items, 'fields'), { kind: 'group', rows: [
    { field: 'owner', value: { kind: 'identifier', name: 'Approver', id: approver.id, approver: true }, literal: true },
    { field: 'note', value: { kind: 'text', text: written }, literal: true },
    { field: 'ids', value: { kind: 'list', items: [{ kind: 'text', text: requester.id }] }, literal: true },
  ] });
});

test('競合を防ぐための版番号は隠し、処理に渡すデータの同名の値は表示する', async () => {
  const items = await rows({ id: requester.id, version: 3, fields: { version: 2, revision: 4 } });
  assert.deepEqual(items.map(row => row.field), ['id', 'fields']);
  assert.deepEqual(field(items, 'fields'), { kind: 'group', rows: [
    { field: 'version', value: { kind: 'text', text: '2' }, literal: true },
    { field: 'revision', value: { kind: 'text', text: '4' }, literal: true },
  ] });
});

test('SSH公開鍵は形式と指紋で示し、鍵として読めない文字列はそのまま表示する', async () => {
  const name = Buffer.from('ssh-ed25519'), key = randomBytes(32);
  const blob = Buffer.concat([Buffer.from([0, 0, 0, name.length]), name, Buffer.from([0, 0, 0, key.length]), key]);
  assert.deepEqual(field(await rows({ publicKey: 'ssh-ed25519 ' + blob.toString('base64') + ' laptop' }), 'publicKey'),
    { kind: 'key', algorithm: 'ED25519', comment: 'laptop',
      fingerprint: 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '') });
  assert.deepEqual(field(await rows({ publicKey: 'ssh-ed25519 A' }), 'publicKey'), { kind: 'text', text: 'ssh-ed25519 A' });
});

test('SSH鍵でログインするアカウントの記録はその操作の結果として示し、同じ形の値を別の操作が返したときはそのまま扱う', () => {
  const authorization = { id: randomUUID(), hostId: randomUUID(), keyId: randomUUID(), account: 'deploy',
    key: { name: 'Laptop', fingerprint: 'SHA256:abc' }, host: { name: 'Staging', address: 'staging.example.test', port: 22 } };
  assert.equal(knownResult('ssh.access.grant', authorization), true);
  assert.equal(knownResult('ssh.host.create', authorization), false);
  assert.equal(knownResult('resource.update', { ...authorization, rows: [1, 2] }), false);
  assert.equal(knownResult('ssh.access.grant', { account: 'deploy' }), false);
});
