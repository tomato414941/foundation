import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { OpenSSH, shellQuote } from '../server/ssh-client.js';
import { SSHProcess } from '../server/ssh-process.js';
import { ProcessView } from '../shared/process.js';
import type { ProcessRequest } from '../shared/process.js';

import { sshFixture } from './ssh-support.js';

test('SSHで同じOSとファイルを操作し、接続をまたいでコマンドの結果と停止を扱う', async t => {
  const { directory, ssh, keys, destination, ids, runtime, execute } = await sshFixture(t);
  const process = (input: Partial<ProcessRequest> & Pick<ProcessRequest, 'command'>) => {
    const id = randomUUID(); ids.push(id);
    return ProcessView.parse({ id, environmentId: destination.id, ownerId: randomUUID(), actorId: randomUUID(),
      workingDirectory: directory, timeoutSeconds: 10, ...input, state: 'queued', result: null, error: null,
      createdAt: new Date().toISOString(), startedAt: null, finishedAt: null });
  };
  const finished = async (id: string) => {
    for (let attempt = 0; attempt < 100; attempt++) {
      const result = await runtime.inspect(destination, id);
      if (result.state !== 'running') return result;
      await delay(50);
    }
    throw new Error('The command did not finish.');
  };

  await t.test('引数・環境変数・標準入力をそのまま渡し、SSHとファイルを共有する', async () => {
    const value = "日本語 '$HOME' $(touch should-not-exist)\nsecond line";
    const task = process({ command: ['/bin/sh', '-c', 'printf "%s" "$VALUE"; cat; printf error >&2; printf shared > shared.txt'],
      environment: { VALUE: value }, stdin: '\ninput' });
    await runtime.start(destination, task);
    const result = await finished(task.id);
    assert.equal(result.state, 'succeeded');
    assert.equal(result.result.stdout, value + '\ninput');
    assert.equal(result.result.stderr, 'error');
    assert.equal((await ssh.run(destination, 'cat ' + shellQuote(join(directory, 'shared.txt')))).stdout, 'shared');
    assert.equal((await ssh.run(destination, 'test -e ' + shellQuote(join(directory, 'should-not-exist')))).code, 1);
  });
  await t.test('同じIDの再送を同じ処理として扱い、新しい接続から完了結果を取得する', async () => {
    const task = process({ command: ['/bin/sh', '-c', 'printf x >> once.txt; sleep 1; printf complete'] });
    await runtime.start(destination, task);
    await runtime.start(destination, task);
    assert.equal((await finished(task.id)).result.stdout, 'complete');
    assert.equal(await readFile(join(directory, 'once.txt'), 'utf8'), 'x');
    const resumed = new SSHProcess(new OpenSSH(), join(directory, 'processes'));
    assert.equal((await resumed.inspect(destination, task.id)).state, 'succeeded');
  });
  await t.test('実行中の処理を停止し、制限時間を超えた処理を終了する', async () => {
    const cancelled = process({ command: ['sleep', '30'], timeoutSeconds: 30 });
    await runtime.start(destination, cancelled);
    assert.equal((await runtime.inspect(destination, cancelled.id)).state, 'running');
    await runtime.cancel(destination, cancelled.id);
    assert.notEqual((await finished(cancelled.id)).state, 'running');
    const timed = process({ command: ['sleep', '30'], timeoutSeconds: 1 });
    await runtime.start(destination, timed);
    const result = await finished(timed.id);
    assert.equal(result.state, 'failed');
    assert.equal(result.result.timedOut, true);
  });
  await t.test('取得する出力を上限内に収め、出力が続く処理の途中経過を読む', async () => {
    const task = process({ command: ['/bin/sh', '-c', 'head -c 1100000 /dev/zero | tr "\\000" x; sleep 1'] });
    await runtime.start(destination, task);
    const result = await finished(task.id);
    assert.equal(result.result.stdout.length, 1_000_000);
    assert.equal(result.result.truncated, true);
  });
  await t.test('コマンドが起動したバックグラウンド処理を終了後も動かす', async () => {
    const task = process({ command: ['/bin/sh', '-c', 'sleep 30 & echo $!'], timeoutSeconds: 1 });
    await runtime.start(destination, task);
    const result = await finished(task.id), pid = Number(result.result.stdout.trim());
    assert.equal(result.state, 'succeeded');
    assert.ok(Number.isSafeInteger(pid) && pid > 0);
    await delay(1200);
    assert.equal((await ssh.run(destination, 'kill -0 ' + pid)).code, 0);
  });
  await t.test('SFTPで置いたファイルをAPI用のコマンドから読む', async () => {
    const key = join(directory, 'sftp-key'), known = join(directory, 'known-hosts'), batch = join(directory, 'sftp-batch');
    await writeFile(key, keys.privateKey, { mode: 0o600 });
    await writeFile(known, `[${destination.host}]:${destination.port} ${keys.hostPublicKey}\n`);
    await writeFile(join(directory, 'upload.txt'), 'SFTP shared content');
    await writeFile(batch, `put ${directory}/upload.txt ${directory}/uploaded.txt\n`);
    await execute('sftp', ['-F', '/dev/null', '-b', batch, '-i', key, '-P', String(destination.port),
      '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + known,
      destination.username + '@' + destination.host]);
    const task = process({ command: ['cat', 'uploaded.txt'] });
    await runtime.start(destination, task);
    assert.equal((await finished(task.id)).result.stdout, 'SFTP shared content');
  });
  await t.test('登録されたホスト鍵と認証鍵を持つ接続を受け付ける', async () => {
    const other = await ssh.keys();
    await assert.rejects(ssh.run({ ...destination, hostKey: other.hostPublicKey }, 'true'));
    await assert.rejects(ssh.run({ ...destination, privateKey: other.privateKey }, 'true'));
    assert.equal((await ssh.run(destination, 'true')).code, 0);
  });
});
