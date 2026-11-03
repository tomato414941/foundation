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

// An sshd of its own on a free local port, letting in the current user with a key made for it, whose keys are read
// from a file in its directory instead of the user's own.
export async function sshServer(t: TestContext, cleanup: () => Promise<void> = async () => {}) {
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
  t.after(async () => {
    await cleanup();
    daemon.kill();
    await rm(directory, { recursive: true, force: true });
  });
  for (let attempt = 0; ; attempt++) {
    try { assert.equal((await ssh.run(destination, 'printf ready')).stdout, 'ready'); break; }
    catch (error) { if (attempt >= 20 || daemon.exitCode !== null) throw new Error(errors, { cause: error }); await delay(50); }
  }
  return { directory, ssh, keys, destination, port, username, authorizedKeys: join(directory, 'authorized_keys') };
}

export async function sshFixture(t: TestContext) {
  const ids: string[] = [];
  const server = await sshServer(t, async () => {
    for (const id of ids) await execute('sudo', ['-n', 'systemctl', 'stop', 'foundation-process-' + id + '.service']).catch(() => {});
    for (const id of ids) await execute('sudo', ['-n', 'systemctl', 'reset-failed', 'foundation-process-' + id + '.service']).catch(() => {});
    await execute('sudo', ['-n', 'rm', '-rf', '--', join(server.directory, 'processes')]);
  }), { directory, ssh, destination } = server;
  const runtime = new SSHProcess(ssh, join(directory, 'processes'));
  return { directory, ssh, keys: server.keys, destination, ids, runtime, execute };
}
