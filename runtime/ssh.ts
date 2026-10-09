import { spawn, execFile } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { chmod, lstat, mkdir, readFile, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { createConnection } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { childEnvironment } from './command.js';
import { SSHPublicKey, SSHWorkerState } from '../shared/ssh.js';
import type { SSHHeartbeat } from '../shared/ssh.js';
import type { z } from 'zod';

const execute = promisify(execFile);
type Heartbeat = (value: z.infer<typeof SSHHeartbeat>) => Promise<z.infer<typeof SSHWorkerState>>;
const quote = (value: string) => '"' + value.replaceAll('\\', '\\\\').replaceAll('"', '\\"') + '"';

export class SSHServer {
  private child: ChildProcess | null = null;
  private hostKey = '';
  private appliedRevision = 0;
  private pending: Promise<void> | null = null;
  private timer: NodeJS.Timeout | undefined;
  private closing = false;
  readonly sessions: string;
  constructor(readonly options: { directory: string; workspace: string; port: number;
    username?: string; listenAddress?: string; sessionCommand?: string; workspaceLink?: string }, readonly heartbeat: Heartbeat) {
    if (!Number.isInteger(options.port) || options.port < 1024 || options.port > 65535) throw new Error('Use an allocated SSH port.');
    for (const value of Object.values(options)) if (typeof value === 'string' && /[\r\n\0]/.test(value))
      throw new Error('Use SSH paths and addresses without control characters.');
    this.sessions = join(options.directory, 'sessions');
  }
  async start() {
    await mkdir(this.options.directory, { recursive: true, mode: 0o700 });
    await mkdir(this.sessions, { recursive: true, mode: 0o700 });
    await mkdir(this.options.workspace, { recursive: true, mode: 0o700 });
    if (this.options.workspaceLink) {
      try {
        await lstat(this.options.workspaceLink);
        if (await realpath(this.options.workspaceLink) !== await realpath(this.options.workspace))
          throw new Error('The SSH workspace points to another environment.');
      }
      catch (error) {
        if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error;
        await symlink(this.options.workspace, this.options.workspaceLink);
      }
    }
    const key = join(this.options.directory, 'host_ed25519');
    try { await lstat(key); }
    catch (error) {
      if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error;
      await execute('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'foundation-environment', '-f', key],
        { env: childEnvironment(), timeout: 10_000 });
    }
    await chmod(key, 0o600);
    this.hostKey = SSHPublicKey.parse((await execute('ssh-keygen', ['-y', '-f', key],
      { env: childEnvironment(), timeout: 10_000 })).stdout);
    const file = join(this.options.directory, 'sshd_config');
    const config = [
      'Port ' + this.options.port,
      ...(this.options.listenAddress ? ['ListenAddress ' + this.options.listenAddress] : []),
      'HostKey ' + quote(key),
      'PidFile ' + quote(join(this.options.directory, 'sshd.pid')),
      'AuthorizedKeysFile ' + quote(join(this.options.directory, 'authorized_keys')),
      'AllowUsers ' + (this.options.username ?? 'root'),
      'PubkeyAuthentication yes', 'AuthenticationMethods publickey',
      'PasswordAuthentication no', 'KbdInteractiveAuthentication no', 'PermitEmptyPasswords no',
      'PermitRootLogin prohibit-password', 'UsePAM no', 'StrictModes yes', 'PrintMotd no',
      'Subsystem sftp /usr/lib/openssh/sftp-server',
      'ForceCommand ' + (this.options.sessionCommand ?? '/usr/local/bin/foundation-ssh-session'),
      'SetEnv ' + quote('FOUNDATION_SSH_SESSIONS=' + this.sessions) + ' ' +
        quote('FOUNDATION_SSH_WORKSPACE=' + (this.options.workspaceLink ?? this.options.workspace)),
      'ClientAliveInterval 30', 'ClientAliveCountMax 3', 'LoginGraceTime 30',
    ].join('\n') + '\n';
    await writeFile(file, config, { mode: 0o600 });
    await this.sync();
    await execute('/usr/sbin/sshd', ['-t', '-f', file], { env: childEnvironment(), timeout: 10_000 });
    const child = spawn('/usr/sbin/sshd', ['-D', '-e', '-f', file],
      { env: childEnvironment(), detached: true, stdio: 'ignore' });
    this.child = child;
    let failure: Error | null = null;
    child.once('error', error => { failure = error; });
    try {
      for (let attempt = 0; ; attempt++) {
        if (failure || child.exitCode !== null || child.signalCode !== null || attempt >= 100)
          throw failure ?? new Error('The SSH server could not start.');
        if (await this.listening()) break;
        await delay(50);
      }
      await this.sync();
      this.timer = setInterval(() => {
        if (!this.pending && !this.closing) {
          this.pending = this.sync().catch(() => {
            process.stderr.write(JSON.stringify({ event: 'ssh_settings_pending' }) + '\n');
          }).finally(() => { this.pending = null; });
        }
      }, 10_000);
      this.timer.unref();
    } catch (error) { await this.stop(); throw error; }
  }
  ensureRunning() {
    if (!this.child?.pid || this.child.exitCode !== null || this.child.signalCode !== null)
      throw new Error('The SSH server has stopped.');
  }
  private listening() {
    return new Promise<boolean>(resolve => {
      const socket = createConnection({ host: this.options.listenAddress === '::1' ? '::1' : '127.0.0.1', port: this.options.port });
      socket.setTimeout(500);
      socket.once('connect', () => { socket.destroy(); resolve(true); });
      socket.once('error', () => { socket.destroy(); resolve(false); });
      socket.once('timeout', () => { socket.destroy(); resolve(false); });
    });
  }
  async activeSessions() {
    let count = 0;
    for (const name of await readdir(this.sessions)) {
      if (!/^[1-9][0-9]*$/.test(name)) continue;
      const file = join(this.sessions, name);
      try {
        const [saved, current] = await Promise.all([readFile(file, 'utf8'), readFile('/proc/' + name + '/stat', 'utf8')]);
        const start = (value: string) => value.slice(value.lastIndexOf(')') + 2).trim().split(/\s+/)[19];
        if (!start(saved) || start(saved) !== start(current)) throw new Error('The SSH session has ended.');
        count++;
      } catch { await rm(file, { force: true }); }
    }
    return Math.min(count, 1024);
  }
  async sync() {
    const { configuration } = SSHWorkerState.parse(await this.heartbeat({ hostKey: this.hostKey,
      appliedRevision: this.child?.pid && this.child.exitCode === null && this.child.signalCode === null
        ? this.appliedRevision : 0, activeSessions: await this.activeSessions() }));
    if (!configuration || configuration.port !== this.options.port) throw new Error('The SSH settings belong to another listener.');
    if (this.appliedRevision !== configuration.revision) {
      const temporary = join(this.options.directory, 'authorized_keys.' + crypto.randomUUID());
      await writeFile(temporary, configuration.authorizedKeys.join('\n') + '\n', { mode: 0o600, flag: 'wx' });
      await rename(temporary, join(this.options.directory, 'authorized_keys'));
      this.appliedRevision = configuration.revision;
    }
  }
  async stop() {
    this.closing = true;
    clearInterval(this.timer);
    await this.pending;
    const child = this.child; this.child = null;
    if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
    await new Promise<void>(resolve => {
      child.once('close', () => resolve());
      try { process.kill(-child.pid!, 'SIGTERM'); } catch { resolve(); }
      const timer = setTimeout(() => { try { process.kill(-child.pid!, 'SIGKILL'); } catch {} resolve(); }, 2000);
      timer.unref();
      child.once('close', () => clearTimeout(timer));
    });
  }
}
