import { constants } from 'node:os';
import { z } from 'zod';
import { ProcessResult } from '../shared/process.js';
import type { ProcessInfo } from '../shared/process.js';
import type { SSHClient, SSHDestination } from './ssh-client.js';
import { shellQuote as quote } from './ssh-client.js';

export interface RemoteProcess {
  state: 'running' | 'succeeded' | 'failed' | 'uncertain';
  result: z.infer<typeof ProcessResult>;
}

// Transient OS services retain command status when an SSH connection or the API server restarts.
export class SSHProcess {
  constructor(readonly ssh: SSHClient, readonly directory = '/var/lib/foundation/processes') {}
  private location(id: string) {
    z.uuid().parse(id);
    return { directory: this.directory + '/' + id, unit: 'foundation-process-' + id + '.service' };
  }
  async start(destination: SSHDestination, process: ProcessInfo) {
    const { directory, unit } = this.location(process.id);
    const command = 'exec env -- ' + Object.entries(process.environment).map(([name, value]) => quote(name + '=' + value)).join(' ') +
      ' ' + process.command.map(quote).join(' ') + '\n';
    const file = (name: string, content: string) =>
      'printf %s ' + quote(Buffer.from(content).toString('base64')) + ' | base64 --decode > ' + quote(directory + '/' + name);
    const script = [
      'set -eu', 'umask 077',
      'install -d -m 0711 ' + quote(this.directory),
      'if ! mkdir -m 0700 ' + quote(directory) + '; then exit 0; fi',
      file('command.sh', command), file('stdin', process.stdin),
      'chown -R ' + quote(destination.username) + ' ' + quote(directory),
      'cat /proc/sys/kernel/random/boot_id > ' + quote(directory + '/boot'),
      ['systemd-run', '--quiet', '--unit=' + unit, '--service-type=exec', '--remain-after-exit',
        '--property=User=' + destination.username,
        '--property=WorkingDirectory=' + process.workingDirectory.replaceAll('%', '%%'),
        '--property=RuntimeMaxSec=' + process.timeoutSeconds,
        '--property=TimeoutStopSec=5s', '--property=KillMode=control-group', '--property=UMask=0077',
        '--property=StandardInput=file:' + directory + '/stdin',
        '--property=StandardOutput=append:' + directory + '/stdout',
        '--property=StandardError=append:' + directory + '/stderr',
        '--', '/bin/sh', directory + '/command.sh'].map(quote).join(' '),
    ].join('\n');
    const result = await this.ssh.run(destination, 'sudo -n /bin/sh -s', script);
    if (result.code) throw new Error('The command could not be started on the execution environment.');
  }
  async inspect(destination: SSHDestination, id: string): Promise<RemoteProcess> {
    const { directory, unit } = this.location(id);
    const script = [
      'set -eu',
      'systemctl show --property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus ' + quote(unit) + ' || true',
      "printf '%s\\n' OUTPUT",
      ...['stdout', 'stderr'].flatMap(name => [
        'if test -f ' + quote(directory + '/' + name) + '; then',
        'wc -c < ' + quote(directory + '/' + name),
        'head -c 1000001 ' + quote(directory + '/' + name) + ' | base64 --wrap=0',
        "printf '\\n'", 'else', "printf '0\\n\\n'", 'fi',
      ]),
    ].join('\n');
    const response = await this.ssh.run(destination, 'sudo -n /bin/sh -s', script);
    if (response.code) throw new Error('The command status could not be read from the execution environment.');
    const [status, output] = response.stdout.split('\nOUTPUT\n');
    if (output === undefined) throw new Error('The execution environment returned an invalid command status.');
    const fields = Object.fromEntries(status!.split('\n').filter(Boolean).map(line => {
      const index = line.indexOf('='); return [line.slice(0, index), line.slice(index + 1)];
    }));
    const [stdoutSize, stdout, stderrSize, stderr] = output.split('\n');
    const running = fields.LoadState === 'loaded' &&
      (fields.ActiveState === 'activating' || fields.ActiveState === 'deactivating' || fields.SubState === 'running');
    const finished = fields.LoadState === 'loaded' && !running &&
      ['exited', 'failed', 'dead'].includes(fields.SubState ?? '');
    const code = Number(fields.ExecMainCode), exit = Number(fields.ExecMainStatus);
    const signal = code === 2 || code === 3
      ? Object.entries(constants.signals).find(([, value]) => value === exit)?.[0] ?? 'SIGUNKNOWN' : null;
    const result = ProcessResult.parse({
      exitCode: finished && code === 1 ? exit : null, signal: finished ? signal : null,
      stdout: Buffer.from(stdout ?? '', 'base64').subarray(0, 1_000_000).toString('utf8'),
      stderr: Buffer.from(stderr ?? '', 'base64').subarray(0, 1_000_000).toString('utf8'),
      timedOut: fields.Result === 'timeout', truncated: Number(stdoutSize) > 1_000_000 || Number(stderrSize) > 1_000_000,
    });
    return { state: running ? 'running' : !finished ? 'uncertain'
      : result.exitCode === 0 && fields.Result === 'success' ? 'succeeded' : 'failed', result };
  }
  async cancel(destination: SSHDestination, id: string) {
    const { unit } = this.location(id);
    const result = await this.ssh.run(destination, 'sudo -n systemctl stop ' + quote(unit));
    if (result.code) throw new Error('The command could not be stopped on the execution environment.');
  }
}
