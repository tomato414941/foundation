import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { homedir, userInfo } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { SSHServer } from '../runtime/ssh.js';
import { CommandProcess } from '../runtime/command.js';
import { SSHHeartbeat } from '../shared/ssh.js';
import type { z } from 'zod';

const execute = promisify(execFile);
async function unusedPort() {
  const server = createServer();
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const port = address.port;
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

test('通常のSSHとSFTPで作業ファイルを扱い、鍵の変更と再起動後もホスト鍵を検証して接続する', async t => {
  const directory = await mkdtemp(join(homedir(), '.foundation-ssh-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const first = join(directory, 'first'), second = join(directory, 'second');
  for (const path of [first, second]) await execute('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', path]);
  const firstPublic = (await readFile(first + '.pub', 'utf8')).trim(), secondPublic = (await readFile(second + '.pub', 'utf8')).trim();
  const port = await unusedPort(), workspace = join(directory, 'workspace'), knownHosts = join(directory, 'known_hosts');
  let configuration = { authorizedKeys: [firstPublic], port, revision: 1 };
  let reported: z.infer<typeof SSHHeartbeat> | undefined;
  let reachable = true;
  const options = { directory: join(directory, 'ssh'), workspace, port, username: userInfo().username,
    listenAddress: '127.0.0.1', sessionCommand: '/bin/sh ' + resolve('deploy/environment/ssh-session.sh') };
  const heartbeat = async (value: z.infer<typeof SSHHeartbeat>) => {
    if (!reachable) throw new Error('Foundation is unavailable.');
    reported = value;
    return { configuration };
  };
  let server = new SSHServer(options, heartbeat);
  t.after(() => server.stop());
  await server.start();
  assert.ok(reported);
  assert.equal(reported.appliedRevision, 1);
  const hostKey = reported.hostKey;
  await writeFile(knownHosts, '[127.0.0.1]:' + port + ' ' + hostKey + '\n', { mode: 0o600 });
  const authentication = (key: string) => ['-F', '/dev/null', '-i', key, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + knownHosts, '-o', 'GlobalKnownHostsFile=/dev/null',
    '-o', 'ConnectTimeout=5', '-o', 'LogLevel=ERROR'];
  const target = userInfo().username + '@127.0.0.1';
  const ssh = (key: string, command: string, args: string[] = []) => execute('ssh',
    [...authentication(key), '-p', String(port), ...args, target, command], { timeout: 10_000 });
  const written = await ssh(first, "printf 'shared workspace' > result.txt; pwd; cat result.txt");
  assert.equal(written.stdout, workspace + '\nshared workspace');
  assert.equal(await readFile(join(workspace, 'result.txt'), 'utf8'), 'shared workspace');
  const commands = new CommandProcess({ isolation: 'container', workspace,
    image: process.env.TEST_COMMAND_IMAGE ?? 'node@sha256:d8e448a56fc63242f70026718378bd4b00f8c82e78d20eefb199224a4d8e33d8' });
  const result = await commands.execute({ command: ['node', '-e',
    "const fs=require('fs');process.stdout.write(fs.readFileSync('result.txt'));fs.writeFileSync('api.txt','from the command API')"],
    workingDirectory: '/workspace', timeoutSeconds: 20, environment: {}, files: {} }, new AbortController().signal);
  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, 'shared workspace');
  assert.equal((await ssh(first, 'cat api.txt')).stdout, 'from the command API');
  const terminal = await ssh(first, "test -t 0 && printf 'terminal works'", ['-tt']);
  assert.equal(terminal.stdout, 'terminal works');
  const upload = join(directory, 'upload.txt'), downloaded = join(directory, 'download.txt'), batch = join(directory, 'sftp.batch');
  await writeFile(upload, 'SFTP round trip');
  await writeFile(batch, 'put ' + upload + ' uploaded.txt\nget result.txt ' + downloaded + '\n');
  await execute('sftp', [...authentication(first), '-P', String(port), '-b', batch, target], { timeout: 10_000 });
  assert.equal(await readFile(join(workspace, 'uploaded.txt'), 'utf8'), 'SFTP round trip');
  assert.equal(await readFile(downloaded, 'utf8'), 'shared workspace');
  const session = spawn('ssh', [...authentication(first), '-p', String(port), target, 'cat > /dev/null'], { stdio: ['pipe', 'ignore', 'ignore'] });
  t.after(() => { session.kill(); });
  for (let attempt = 0; attempt < 100 && await server.activeSessions() === 0; attempt++) await delay(20);
  await server.sync();
  assert.equal(reported.activeSessions, 1);
  session.stdin!.end();
  for (let attempt = 0; attempt < 100 && await server.activeSessions() !== 0; attempt++) await delay(20);
  assert.equal(await server.activeSessions(), 0);
  configuration = { ...configuration, authorizedKeys: [secondPublic], revision: 2 };
  await server.sync();
  await server.sync();
  assert.equal(reported.appliedRevision, 2);
  await assert.rejects(ssh(first, 'true'), error => error instanceof Error && /Permission denied/.test(error.message));
  assert.equal((await ssh(second, 'cat result.txt')).stdout, 'shared workspace');
  reachable = false;
  await assert.rejects(server.sync());
  assert.equal((await ssh(second, 'cat uploaded.txt')).stdout, 'SFTP round trip');
  reachable = true;
  await server.stop();
  server = new SSHServer(options, heartbeat);
  await server.start();
  assert.equal(reported.hostKey, hostKey);
  assert.equal((await ssh(second, 'cat result.txt')).stdout, 'shared workspace');
  configuration = { ...configuration, authorizedKeys: [], revision: 3 };
  await server.sync();
  await assert.rejects(ssh(second, 'true'), error => error instanceof Error && /Permission denied/.test(error.message));
});
