import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import type { EnvironmentOptions } from '../shared/contracts.js';
import type { Configuration } from './config.js';
import { DomainError, fail } from './errors.js';

export interface RunnerJob {
  command: string[];
  stdin?: string;
  timeoutSeconds: number;
  environment: Record<string, string>;
  files: Record<string, string>;
}
export interface CommandResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
}
export interface Runner {
  readonly enabled: boolean;
  start(
    id: string,
    options: EnvironmentOptions,
    environment: Record<string, string>,
    created: (machineId: string) => Promise<void>,
  ): Promise<string>;
  execute(machineId: string, job: RunnerJob, signal: AbortSignal): Promise<CommandResult>;
  stop(machineId: string): Promise<void>;
  find(id: string): Promise<string | null>;
}
const sizes = {
  small: { cpu_kind: 'shared', cpus: 1, memory_mb: 512 },
  medium: { cpu_kind: 'shared', cpus: 2, memory_mb: 1024 },
  large: { cpu_kind: 'shared', cpus: 4, memory_mb: 2048 },
};
export class FlyRunner implements Runner {
  readonly enabled: boolean;
  constructor(readonly config: Configuration) {
    this.enabled = Boolean(config.FLY_API_TOKEN && config.FLY_APP && config.FLY_IMAGE);
  }
  private async call(
    method: string,
    path: string,
    body?: unknown,
    timeout = 30_000,
  ): Promise<Record<string, unknown> | Array<Record<string, unknown>>> {
    if (!this.enabled) fail(503, 'environments_unavailable', 'Environments are not configured.');
    try {
      const response = await fetch(
        'https://api.machines.dev/v1/apps/' + encodeURIComponent(this.config.FLY_APP) + path,
        {
          method,
          headers: {
            authorization: 'Bearer ' + this.config.FLY_API_TOKEN,
            ...(body === undefined ? {} : { 'content-type': 'application/json' }),
          },
          redirect: 'error',
          signal: AbortSignal.timeout(timeout),
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        },
      );
      if (response.status === 404)
        throw new DomainError(404, 'machine_missing', 'The environment is no longer running.');
      if (!response.ok)
        fail(502, 'runner_unavailable', 'The environment provider could not complete the operation.');
      const text = await response.text();
      if (text.length > 4_000_000) fail(502, 'runner_response', 'The environment returned too much output.');
      return text ? JSON.parse(text) : {};
    } catch (error) {
      if (error instanceof DomainError) throw error;
      fail(502, 'runner_unavailable', 'The environment provider could not be reached.');
    }
  }
  async find(id: string) {
    const rows = await this.call('GET', '/machines');
    if (!Array.isArray(rows))
      fail(502, 'runner_response', 'The environment provider returned an invalid response.');
    return (rows.find((row) => row.name === 'foundation-' + id)?.id as string | undefined) ?? null;
  }
  async start(
    id: string,
    options: EnvironmentOptions,
    environment: Record<string, string>,
    created: (machineId: string) => Promise<void>,
  ) {
    const image = options.image ?? this.config.FLY_IMAGE;
    if (image.startsWith('registry.fly.io/') && image !== this.config.FLY_IMAGE)
      fail(400, 'image_unavailable', 'Choose a public image or the Foundation image.');
    let machineId = await this.find(id);
    if (!machineId) {
      try {
        const machine = await this.call('POST', '/machines', {
          name: 'foundation-' + id,
          region: this.config.FLY_REGION,
          config: {
            image,
            init: { exec: ['sleep', 'infinity'] },
            env: { HOME: '/root', ...environment },
            guest: sizes[options.size],
            auto_destroy: true,
            restart: { policy: 'no' },
            metadata: { foundation_environment: id },
          },
        });
        if (Array.isArray(machine) || typeof machine.id !== 'string')
          fail(502, 'runner_response', 'The environment provider returned an invalid response.');
        machineId = machine.id;
      } catch (error) {
        machineId = await this.find(id);
        if (!machineId) throw error;
      }
    }
    await created(machineId);
    await this.call(
      'GET',
      '/machines/' + encodeURIComponent(machineId) + '/wait?state=started&timeout=60',
      undefined,
      70_000,
    );
    const probe = await this.exec(machineId, ['node', '--version']);
    if (probe.exit_code !== 0 || !/^v(2[4-9]|[3-9][0-9])\./.test(String(probe.stdout)))
      fail(400, 'runtime_required', 'Use an image containing Node.js 24 or later.');
    return machineId;
  }
  private async exec(machineId: string, command: string[]): Promise<Record<string, unknown>> {
    const result = await this.call(
      'POST',
      '/machines/' + encodeURIComponent(machineId) + '/exec',
      { command, timeout: 20 },
      undefined,
    );
    if (Array.isArray(result)) fail(502, 'runner_response', 'The environment returned an invalid response.');
    return result;
  }
  private async put(machineId: string, path: string, data: Uint8Array) {
    for (let offset = 0; offset === 0 || offset < data.length; offset += 16384) {
      const script =
        "const fs=require('node:fs');fs.mkdirSync(require('node:path').dirname(process.argv[1]),{recursive:true,mode:448});fs.writeFileSync(process.argv[1],Buffer.from(process.argv[2],'base64'),{flag:process.argv[3],mode:384});";
      const result = await this.exec(machineId, [
        'node',
        '-e',
        script,
        path,
        Buffer.from(data.subarray(offset, offset + 16384)).toString('base64'),
        offset === 0 ? 'w' : 'a',
      ]);
      if (result.exit_code !== 0) fail(502, 'runner_write', 'The environment could not receive its inputs.');
    }
  }
  async execute(machineId: string, job: RunnerJob, signal: AbortSignal): Promise<CommandResult> {
    const directory = '/tmp/foundation-' + randomUUID();
    const extension = import.meta.url.endsWith('.ts') ? 'ts' : 'js',
      agent = await readFile(new URL('./runner-agent.' + extension, import.meta.url));
    try {
      await this.put(machineId, directory + '/agent.' + (extension === 'ts' ? 'mts' : 'mjs'), agent);
      await this.put(machineId, directory + '/input.json', Buffer.from(JSON.stringify(job)));
      signal.throwIfAborted();
      const start = await this.exec(machineId, [
        'node',
        '-e',
        "const c=require('node:child_process').spawn('node',[process.argv[1],process.argv[2]],{detached:true,stdio:'ignore'});c.unref();",
        directory + '/agent.' + (extension === 'ts' ? 'mts' : 'mjs'),
        directory,
      ]);
      if (start.exit_code !== 0) fail(502, 'runner_start', 'The command could not be started.');
      const deadline = Date.now() + (job.timeoutSeconds + 30) * 1000;
      while (Date.now() < deadline) {
        signal.throwIfAborted();
        const result = await this.exec(machineId, [
          'node',
          '-e',
          "const fs=require('node:fs');const p=process.argv[1]+'/result.json';if(fs.existsSync(p))process.stdout.write(fs.readFileSync(p));else process.exitCode=2;",
          directory,
        ]);
        if (result.exit_code === 0) {
          const value = JSON.parse(String(result.stdout)) as CommandResult;
          if (
            typeof value.stdout !== 'string' ||
            typeof value.stderr !== 'string' ||
            typeof value.timedOut !== 'boolean'
          )
            fail(502, 'runner_response', 'The command returned an invalid result.');
          return value;
        }
        await delay(1000, undefined, { signal });
      }
      throw new DomainError(504, 'command_timeout', 'The command did not finish before its time limit.');
    } catch (error) {
      if (signal.aborted || (error instanceof DomainError && error.code === 'command_timeout'))
        await this.stop(machineId);
      throw error;
    } finally {
      if (!signal.aborted)
        await this.exec(machineId, [
          'node',
          '-e',
          "require('node:fs').rmSync(process.argv[1],{recursive:true,force:true});",
          directory,
        ]).catch(() => {});
    }
  }
  async stop(machineId: string) {
    try {
      await this.call('DELETE', '/machines/' + encodeURIComponent(machineId) + '?force=true');
    } catch (error) {
      if (!(error instanceof DomainError && error.code === 'machine_missing')) throw error;
    }
  }
}
