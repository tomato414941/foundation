import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
export interface RunnerJob {
  command: string[];
  stdin?: string;
  timeoutSeconds: number;
  environment: Record<string, string>;
  files: Record<string, string>;
  workingDirectory?: string;
}
export interface CommandResult {
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
}

export interface CommandExecutor {
  execute(job: RunnerJob, signal: AbortSignal): Promise<CommandResult>;
}
export function childEnvironment(input: Record<string, string> = {}) {
  const inherited = Object.fromEntries(['PATH', 'LANG', 'LC_ALL', 'TZ', 'TERM', 'HOME', 'TMPDIR',
    'SYSTEMROOT', 'COMSPEC', 'PATHEXT'].flatMap(name => process.env[name] ? [[name, process.env[name]!]] : []));
  return { ...inherited, ...input };
}

export class CommandProcess implements CommandExecutor {
  constructor(readonly options: { isolation: 'process' | 'container'; image?: string; cwd?: string; workspace?: string }) {
    if (options.isolation === 'container' && !/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(options.image ?? ''))
      throw new Error('Choose a container image pinned to its SHA-256 digest.');
  }
  async execute(job: RunnerJob, signal: AbortSignal): Promise<CommandResult> {
    signal.throwIfAborted();
    const directory = await mkdtemp(join(tmpdir(), 'foundation-job-'));
    const files = join(directory, 'files');
    const name = 'foundation-' + crypto.randomUUID();
    const container = this.options.isolation === 'container';
    const output: CommandResult = { exitCode: null, signal: null, stdout: '', stderr: '', timedOut: false, truncated: false };
    let interrupted = false;
    try {
      await mkdir(files, { mode: 0o700 });
      const values = { ...job.environment };
      for (const [key, value] of Object.entries(job.files)) {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new Error('Use valid file variable names.');
        await writeFile(join(files, key), Buffer.from(value, 'base64'), { mode: 0o600, flag: 'wx' });
        values[key] = container ? '/run/foundation/' + key : join(files, key);
      }
      let command = job.command;
      if (container) {
        if (Object.entries(values).some(([key, value]) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || value.includes('\0')))
          throw new Error('Use valid environment variable names and values without null bytes.');
        // Env files are line-oriented; Docker accepts multiline values as individual arguments.
        const multiline = Object.entries(values).filter(([, value]) => /[\r\n]/.test(value));
        const envFile = join(directory, 'environment');
        await writeFile(envFile, Object.entries(values).filter(([, value]) => !/[\r\n]/.test(value))
          .map(([key, value]) => key + '=' + value).join('\n'),
          { mode: 0o600, flag: 'wx' });
        if (this.options.workspace) await mkdir(this.options.workspace, { recursive: true, mode: 0o700 });
        command = ['docker', 'run', '--rm', '--name', name, '--init', '--read-only', '--cap-drop=ALL',
          '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=512m', '--cpus=1',
          '--network=bridge', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
          '--user=' + String(process.getuid?.() ?? 65534) + ':' + String(process.getgid?.() ?? 65534),
          '--mount=type=bind,source=' + files + ',target=/run/foundation,readonly',
          '--env-file', envFile,
          ...multiline.flatMap(([key, value]) => ['--env', key + '=' + value]),
          ...(this.options.workspace ? ['--mount=type=bind,source=' + this.options.workspace + ',target=/workspace'] : []),
          ...(job.workingDirectory ? ['--workdir', job.workingDirectory] : []),
          '--entrypoint=' + job.command[0]!, '-i', this.options.image!, ...job.command.slice(1)];
      }
      await new Promise<void>(resolve => {
        const child = spawn(command[0]!, command.slice(1), {
          env: childEnvironment(container ? {} : values), cwd: container ? this.options.cwd : job.workingDirectory ?? this.options.cwd,
          detached: process.platform !== 'win32', stdio: ['pipe', 'pipe', 'pipe'],
        });
        const decoders = { stdout: new StringDecoder('utf8'), stderr: new StringDecoder('utf8') };
        let size = 0, settled = false;
        const collect = (field: 'stdout' | 'stderr', bytes: Buffer) => {
          const remaining = Math.max(0, 1_000_000 - size);
          if (bytes.length > remaining) output.truncated = true;
          const accepted = bytes.subarray(0, remaining);
          size += accepted.length;
          output[field] += decoders[field].write(accepted);
        };
        child.stdout.on('data', (bytes: Buffer) => collect('stdout', bytes));
        child.stderr.on('data', (bytes: Buffer) => collect('stderr', bytes));
        child.stdin.on('error', () => {});
        child.stdin.end(job.stdin ?? '');
        const kill = () => {
          interrupted = true;
          try {
            if (child.pid && process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL');
            else child.kill('SIGKILL');
          } catch { /* The process may have already exited. */ }
        };
        const timer = setTimeout(() => { output.timedOut = true; kill(); }, job.timeoutSeconds * 1000);
        timer.unref();
        const finish = () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          signal.removeEventListener('abort', kill);
          output.stdout += decoders.stdout.end();
          output.stderr += decoders.stderr.end();
          resolve();
        };
        signal.addEventListener('abort', kill, { once: true });
        if (signal.aborted) kill();
        child.once('error', () => { output.exitCode = 127; output.stderr = 'The command could not be started.'; finish(); });
        child.once('close', (code, exitSignal) => { output.exitCode = code; output.signal = exitSignal; finish(); });
      });
      return output;
    } finally {
      if (container && interrupted) await new Promise<void>(resolve => {
        const cleanup = spawn('docker', ['rm', '-f', name], { env: childEnvironment(), stdio: 'ignore' });
        cleanup.once('close', () => resolve());
        cleanup.once('error', () => resolve());
        setTimeout(() => { cleanup.kill('SIGKILL'); resolve(); }, 10_000).unref();
      });
      await rm(directory, { recursive: true, force: true });
    }
  }
}
