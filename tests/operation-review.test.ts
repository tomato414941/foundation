import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { reviewer } from '../web/app/operation-review.js';

const approver = { id: randomUUID(), name: 'Approver' }, requester = { id: randomUUID(), name: 'Requester' };
const rows = reviewer({ approver, requester, principals: [], inspect: false, signal: new AbortController().signal });
const field = (items: Awaited<ReturnType<typeof rows>>, name: string) => items.find(row => row.field === name)?.value;

test('参照するIDの位置だけを名前に置き換え、名前や引数に書かれたUUIDはそのまま表示する', async () => {
  const written = randomUUID();
  const items = await rows({ ownerId: '$approver', principalId: requester.id, name: written,
    arguments: { owner: '$approver', note: written, ids: [requester.id] } });
  assert.deepEqual(field(items, 'ownerId'), { kind: 'principal', name: 'Approver', approver: true });
  assert.deepEqual(field(items, 'principalId'), { kind: 'principal', name: 'Requester', approver: false });
  assert.deepEqual(field(items, 'name'), { kind: 'text', text: written });
  assert.deepEqual(field(items, 'arguments'), { kind: 'group', rows: [
    { field: 'owner', value: { kind: 'identifier', name: 'Approver', id: approver.id, approver: true }, literal: true },
    { field: 'note', value: { kind: 'text', text: written }, literal: true },
    { field: 'ids', value: { kind: 'list', items: [{ kind: 'text', text: requester.id }] }, literal: true },
  ] });
});

test('競合を防ぐための版番号は隠し、処理に渡すデータの同名の値は表示する', async () => {
  const items = await rows({ id: requester.id, version: 3, arguments: { version: 2, revision: 4 } });
  assert.deepEqual(items.map(row => row.field), ['id', 'arguments']);
  assert.deepEqual(field(items, 'arguments'), { kind: 'group', rows: [
    { field: 'version', value: { kind: 'text', text: '2' }, literal: true },
    { field: 'revision', value: { kind: 'text', text: '4' }, literal: true },
  ] });
});

test('SSH公開鍵は形式と指紋で示し、鍵として読めない文字列はそのまま表示する', async () => {
  const name = Buffer.from('ssh-ed25519'), key = randomBytes(32);
  const blob = Buffer.concat([Buffer.from([0, 0, 0, name.length]), name, Buffer.from([0, 0, 0, key.length]), key]);
  const items = await rows({ hostKeys: ['ssh-ed25519 ' + blob.toString('base64') + ' server', 'ssh-ed25519 A'] });
  assert.deepEqual(field(items, 'hostKeys'), { kind: 'list', items: [
    { kind: 'key', algorithm: 'ED25519', comment: 'server',
      fingerprint: 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '') },
    { kind: 'text', text: 'ssh-ed25519 A' },
  ] });
});

test('コマンドはシェルで展開せず、渡す引数を1つずつそのまま示す', async () => {
  const command = ['printf', '%s\n', '$HOME', '`date`', 'two words'];
  assert.deepEqual(field(await rows({ command }), 'command'), { kind: 'command', parts: command });
});
