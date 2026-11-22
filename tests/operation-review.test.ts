import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { reviewer } from '../web/app/operation-review.js';

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
