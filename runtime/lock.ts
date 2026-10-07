import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { open, rm } from 'node:fs/promises';

// A kernel lock is released on a crash; the file itself must stay in place so
// concurrent starters always contend for the same inode.
export async function journalLock(path: string): Promise<() => Promise<void>> {
  if (process.platform !== 'linux') {
    const file = await open(path, 'wx', 0o600).catch(() => {
      throw new Error('This executor is locked. Check that its previous process has stopped before removing ' + path + '.');
    });
    await file.writeFile(JSON.stringify({ pid: process.pid }));
    return async () => { await file.close(); await rm(path, { force: true }); };
  }
  const file = await open(path, constants.O_CREAT | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    // fd 3 and file share an open file description. Linux retains the lock
    // after the helper exits until this process closes its own descriptor.
    const child = spawn('flock', ['--nonblock', '--conflict-exit-code', '73', '3'],
      { stdio: ['ignore', 'ignore', 'ignore', file.fd] });
    await new Promise<void>((resolve, reject) => {
      child.once('error', () => reject(new Error('Install util-linux (flock) to run an executor on this host.')));
      child.once('close', code => code === 0 ? resolve() : reject(new Error(code === 73
        ? 'This executor is already running.' : 'The executor lock could not be acquired.')));
    });
  } catch (error) { await file.close(); throw error; }
  return () => file.close();
}
