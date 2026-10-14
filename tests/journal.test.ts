import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { journalLock } from '../runtime/lock.js';
import { FileJournal } from '../runtime/journal.js';
import { bindKeys, newIdentityKeys } from '../shared/authority.js';

test('未送信の実行記録を再起動後に見つけ、送信済みの結果も再送確認のために保持する', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-journal-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const keys = await newIdentityKeys(), binding = bindKeys(crypto.randomUUID(), keys);
  const journal = new FileJournal(directory, 'https://foundation.test', binding, keys);
  const first = 'run_' + crypto.randomUUID(), second = 'run_' + crypto.randomUUID();
  await journal.write(first, { delivered: false, receipt: 'first result' });
  await journal.write(second, { delivered: false, receipt: 'second result' });
  await journal.write(first, { delivered: true, receipt: 'first result' });
  const restarted = new FileJournal(directory, 'https://foundation.test', binding, keys);
  assert.deepEqual(await restarted.pending('run_'), [second]);
  assert.deepEqual(await restarted.read(first), { delivered: true, receipt: 'first result' });
  assert.deepEqual(await restarted.read(second), { delivered: false, receipt: 'second result' });
});

test('実行先の同時起動を制限し、終了や異常停止の後に再起動する', { skip: process.platform !== 'linux' }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-lock-'));
  try {
    const path = join(directory, 'process.lock'), release = await journalLock(path);
    await assert.rejects(journalLock(path), /already running/);
    await release();
    const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e',
      "import { journalLock } from './runtime/lock.ts';const release=await journalLock(process.argv[1]);process.stdout.write('ready');setInterval(()=>{},1000);", path],
    { stdio: ['ignore', 'pipe', 'pipe'] });
    try {
      await once(child.stdout, 'data');
      await assert.rejects(journalLock(path), /already running/);
    } finally { const closed = once(child, 'close'); child.kill('SIGKILL'); await closed; }
    const resumed = await journalLock(path);
    await assert.rejects(journalLock(path), /already running/);
    await resumed();
  } finally { await rm(directory, { recursive: true, force: true }); }
});
