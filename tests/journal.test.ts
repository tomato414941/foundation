import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileJournal } from '../runtime/journal.js';
import { bindKeys, newIdentityKeys } from '../shared/authority.js';

test('未送信のトークン更新の記録を再起動後に見つけ、送信済みの記録も再送確認のために保持する', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-journal-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const keys = await newIdentityKeys(), binding = bindKeys(crypto.randomUUID(), keys);
  const journal = new FileJournal(directory, 'https://foundation.test', binding, keys);
  const first = 'refresh_' + crypto.randomUUID(), second = 'refresh_' + crypto.randomUUID();
  await journal.write(first, { delivered: false, receipt: 'first result' });
  await journal.write(second, { delivered: false, receipt: 'second result' });
  await journal.write(first, { delivered: true, receipt: 'first result' });
  const restarted = new FileJournal(directory, 'https://foundation.test', binding, keys);
  assert.deepEqual(await restarted.pending('refresh_'), [second]);
  assert.deepEqual(await restarted.read(first), { delivered: true, receipt: 'first result' });
  assert.deepEqual(await restarted.read(second), { delivered: false, receipt: 'second result' });
});
