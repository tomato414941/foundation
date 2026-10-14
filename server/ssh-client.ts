import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isIP } from 'node:net';
import { promisify } from 'node:util';
import { z } from 'zod';
import { SSHPublicKey } from '../shared/ssh.js';
import { fail } from './errors.js';

const execute = promisify(execFile);
export const SSHKeys = z.object({
  privateKey: z.string(), publicKey: SSHPublicKey,
  hostPrivateKey: z.string(), hostPublicKey: SSHPublicKey,
}).strict();
export type SSHKeyPair = z.infer<typeof SSHKeys>;
export interface SSHDestination {
  id: string; host: string; port: number; username: string; privateKey: string; hostKey: string;
}
export interface SSHResponse { code: number; stdout: string; stderr: string; }
export interface SSHClient {
  keys(): Promise<SSHKeyPair>;
  run(destination: SSHDestination, command: string, input?: string): Promise<SSHResponse>;
}
export const shellQuote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";

export class OpenSSH implements SSHClient {
  async keys(): Promise<SSHKeyPair> {
    const directory = await mkdtemp(join(tmpdir(), 'foundation-ssh-'));
    try {
      for (const name of ['identity', 'host']) await execute('ssh-keygen',
        ['-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', join(directory, name)], { timeout: 10_000 });
      const [privateKey, publicKey, hostPrivateKey, hostPublicKey] = await Promise.all(
        ['identity', 'identity.pub', 'host', 'host.pub'].map(name => readFile(join(directory, name), 'utf8')));
      return SSHKeys.parse({ privateKey, publicKey, hostPrivateKey, hostPublicKey });
    } finally { await rm(directory, { recursive: true, force: true }); }
  }

  async run(destination: SSHDestination, command: string, input = ''): Promise<SSHResponse> {
    if (!isIP(destination.host) || !/^[a-zA-Z0-9_-]+$/.test(destination.id) ||
      !/^[a-z_][a-z0-9_-]*$/.test(destination.username) ||
      !Number.isInteger(destination.port) || destination.port < 1 || destination.port > 65535)
      fail(502, 'ssh_unavailable', 'The execution environment has no valid SSH address.');
    const directory = await mkdtemp(join(tmpdir(), 'foundation-ssh-'));
    try {
      const identity = join(directory, 'identity'), hosts = join(directory, 'known_hosts');
      await writeFile(identity, destination.privateKey, { mode: 0o600 });
      await writeFile(hosts, destination.id + ' ' + SSHPublicKey.parse(destination.hostKey) + '\n', { mode: 0o600 });
      const options = ['BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none',
        'StrictHostKeyChecking=yes', 'UserKnownHostsFile=' + hosts, 'GlobalKnownHostsFile=/dev/null',
        'HostKeyAlias=' + destination.id, 'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no',
        'ConnectTimeout=8', 'ConnectionAttempts=1', 'ServerAliveInterval=5', 'ServerAliveCountMax=2',
        'ClearAllForwardings=yes', 'PermitLocalCommand=no', 'LogLevel=ERROR'];
      return await new Promise<SSHResponse>((resolve, reject) => {
        const child = execFile('ssh', ['-F', '/dev/null', '-T', '-i', identity, '-p', String(destination.port),
          ...options.flatMap(value => ['-o', value]), '--', destination.username + '@' + destination.host, command],
        { timeout: 25_000, killSignal: 'SIGKILL', maxBuffer: 8_000_000, encoding: 'utf8' }, (error, stdout, stderr) => {
          if (error && (typeof error.code !== 'number' || error.code === 255 || error.killed)) {
            reject(new Error('The execution environment could not be reached over SSH.'));
          } else resolve({ code: error ? Number(error.code) : 0, stdout, stderr });
        });
        child.stdin?.on('error', () => {});
        child.stdin?.end(input);
      });
    } finally { await rm(directory, { recursive: true, force: true }); }
  }
}
