import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { journalLock } from '../runtime/lock.js';

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
