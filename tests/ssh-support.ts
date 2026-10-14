import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { homedir, userInfo } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { OpenSSH } from '../server/ssh-client.js';
import { SSHProcess } from '../server/ssh-process.js';

const execute = promisify(execFile);

export async function sshFixture(t: TestContext) {
  const directory = await mkdtemp(join(homedir(), '.foundation-ssh-process-'));
  const ssh = new OpenSSH(), keys = await ssh.keys(), username = userInfo().username;
  const socket = createServer();
  await new Promise<void>(resolve => socket.listen(0, '127.0.0.1', resolve));
  const address = socket.address();
  assert.ok(address && typeof address !== 'string');
  const port = address.port;
  await new Promise<void>((resolve, reject) => socket.close(error => error ? reject(error) : resolve()));
  await writeFile(join(directory, 'host'), keys.hostPrivateKey, { mode: 0o600 });
  await writeFile(join(directory, 'authorized_keys'), keys.publicKey + '\n', { mode: 0o600 });
  const config = join(directory, 'sshd_config');
  await writeFile(config, [
    'Port ' + port, 'ListenAddress 127.0.0.1', 'HostKey ' + join(directory, 'host'),
    'AuthorizedKeysFile ' + join(directory, 'authorized_keys'), 'AllowUsers ' + username,
    'PidFile ' + join(directory, 'sshd.pid'), 'UsePAM no', 'StrictModes yes',
    'PasswordAuthentication no', 'KbdInteractiveAuthentication no', 'PubkeyAuthentication yes',
    'Subsystem sftp /usr/lib/openssh/sftp-server', '',
  ].join('\n'));
  const daemon = spawn('/usr/sbin/sshd', ['-D', '-e', '-f', config], { stdio: ['ignore', 'ignore', 'pipe'] });
  let errors = '';
  daemon.stderr.on('data', chunk => { errors += String(chunk); });
  const destination = { id: randomUUID(), host: '127.0.0.1', port, username,
    privateKey: keys.privateKey, hostKey: keys.hostPublicKey };
  const ids: string[] = [];
  t.after(async () => {
    for (const id of ids) await execute('sudo', ['-n', 'systemctl', 'stop', 'foundation-process-' + id + '.service']).catch(() => {});
    for (const id of ids) await execute('sudo', ['-n', 'systemctl', 'reset-failed', 'foundation-process-' + id + '.service']).catch(() => {});
    daemon.kill();
    await execute('sudo', ['-n', 'rm', '-rf', '--', join(directory, 'processes')]);
    await rm(directory, { recursive: true, force: true });
  });
  for (let attempt = 0; ; attempt++) {
    try { assert.equal((await ssh.run(destination, 'printf ready')).stdout, 'ready'); break; }
    catch (error) { if (attempt >= 20 || daemon.exitCode !== null) throw new Error(errors, { cause: error }); await delay(50); }
  }
  const runtime = new SSHProcess(ssh, join(directory, 'processes'));
  return { directory, ssh, keys, destination, ids, runtime, execute };
}
