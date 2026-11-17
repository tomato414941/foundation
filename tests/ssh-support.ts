import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { homedir, userInfo } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';

const execute = promisify(execFile);

// An sshd of its own on a free local port, letting in the current user with a key made for it, whose keys are read
// from a file in its directory instead of the user's own.
export async function sshServer(t: TestContext) {
  const directory = await mkdtemp(join(homedir(), '.foundation-ssh-server-'));
  let daemon: ReturnType<typeof spawn> | undefined;
  t.after(async () => {
    daemon?.kill();
    await rm(directory, { recursive: true, force: true });
  });
  for (const name of ['identity', 'host']) await execute('ssh-keygen',
    ['-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', join(directory, name)], { timeout: 10_000 });
  const read = (name: string) => readFile(join(directory, name), 'utf8');
  const keys = { privateKey: await read('identity'), publicKey: (await read('identity.pub')).trim(),
    hostPrivateKey: await read('host'), hostPublicKey: (await read('host.pub')).trim() };
  const username = userInfo().username;
  const socket = createServer();
  await new Promise<void>(resolve => socket.listen(0, '127.0.0.1', resolve));
  const address = socket.address();
  assert.ok(address && typeof address !== 'string');
  const port = address.port;
  await new Promise<void>((resolve, reject) => socket.close(error => error ? reject(error) : resolve()));
  await writeFile(join(directory, 'authorized_keys'), keys.publicKey + '\n', { mode: 0o600 });
  await writeFile(join(directory, 'known_hosts'), '[127.0.0.1]:' + port + ' ' + keys.hostPublicKey + '\n', { mode: 0o600 });
  const config = join(directory, 'sshd_config');
  await writeFile(config, [
    'Port ' + port, 'ListenAddress 127.0.0.1', 'HostKey ' + join(directory, 'host'),
    'AuthorizedKeysFile ' + join(directory, 'authorized_keys'), 'AllowUsers ' + username,
    'PidFile ' + join(directory, 'sshd.pid'), 'UsePAM no', 'StrictModes yes',
    'PasswordAuthentication no', 'KbdInteractiveAuthentication no', 'PubkeyAuthentication yes',
    'Subsystem sftp /usr/lib/openssh/sftp-server', '',
  ].join('\n'));
  const started = spawn('/usr/sbin/sshd', ['-D', '-e', '-f', config], { stdio: ['ignore', 'ignore', 'pipe'] });
  daemon = started;
  let errors = '';
  started.stderr.on('data', chunk => { errors += String(chunk); });
  const ready = () => execute('ssh', ['-F', '/dev/null', '-T', '-i', join(directory, 'identity'), '-p', String(port),
    ...['BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none', 'StrictHostKeyChecking=yes',
      'UserKnownHostsFile=' + join(directory, 'known_hosts'), 'GlobalKnownHostsFile=/dev/null', 'ConnectTimeout=8',
      'LogLevel=ERROR'].flatMap(value => ['-o', value]), '--', username + '@127.0.0.1', 'printf ready'], { timeout: 25_000 });
  for (let attempt = 0; ; attempt++) {
    try { assert.equal((await ready()).stdout, 'ready'); break; }
    catch (error) { if (attempt >= 20 || started.exitCode !== null) throw new Error(errors, { cause: error }); await delay(50); }
  }
  return { directory, keys, port, username, authorizedKeys: join(directory, 'authorized_keys') };
}
