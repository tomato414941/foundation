import { spawn } from 'node:child_process';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { z } from 'zod';
import type { Client } from './client.js';
import type { InjectionInput } from '../../shared/contracts.js';
import { Injection } from '../../shared/session.js';
import { decode, open } from '../../shared/encryption.js';

export function secretVariants(values: string[]) {
  return [
    ...new Set(
      values
        .filter(Boolean)
        .flatMap((value) => [
          value,
          encodeURIComponent(value),
          JSON.stringify(value).slice(1, -1),
          Buffer.from(value).toString('base64'),
          Buffer.from(value).toString('base64url'),
        ]),
    ),
  ].sort((a, b) => b.length - a.length);
}
export class Redactor {
  private pending = '';
  private decoder = new StringDecoder('utf8');
  private max: number;
  constructor(
    readonly secrets: string[],
    readonly output: (value: string) => void,
  ) {
    this.max = Math.max(1, ...secrets.map((value) => value.length));
  }
  write(chunk: Buffer) {
    this.pending += this.decoder.write(chunk);
    this.flush(false);
  }
  end() {
    this.pending += this.decoder.end();
    this.flush(true);
  }
  private flush(final: boolean) {
    const limit = final ? this.pending.length : Math.max(0, this.pending.length - this.max + 1);
    let position = 0,
      result = '';
    while (position < limit) {
      const match = this.secrets.find((secret) => this.pending.startsWith(secret, position));
      if (match) {
        result += '[redacted]';
        position += match.length;
      } else {
        result += this.pending[position];
        position++;
      }
    }
    this.pending = this.pending.slice(position);
    if (result) this.output(result);
  }
}
const Payload = z
  .object({
    environment: z.record(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/), z.string()),
    files: z.record(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/), z.string()),
  })
  .strict();
export async function execute(client: Client, inputs: InjectionInput[], command: string[]) {
  if (!command.length) throw new Error('Put the command after --.');
  const session = await client.session();
  if (!session.principal) throw new Error('The machine identity is no longer valid.');
  const injection = await client.json('/api/inputs', { method: 'POST', body: { inputs } }, Injection);
  const payload = Payload.parse(
    JSON.parse(
      decode(
        await open(injection.sealed, client.identity.privateKey, session.principal.id, injection.context),
      ),
    ),
  );
  const directory = await mkdtemp(join(tmpdir(), 'foundation-'));
  await chmod(directory, 0o700);
  try {
    const environment = { ...process.env, ...payload.environment };
    const sensitive = [
      ...Object.values(payload.environment),
      process.env.FOUNDATION_TOKEN ?? '',
      process.env.FOUNDATION_PRIVATE_KEY ?? '',
    ];
    for (const [name, value] of Object.entries(payload.files)) {
      const bytes = Buffer.from(value, 'base64');
      const path = join(directory, name);
      await writeFile(path, bytes, { mode: 0o600, flag: 'wx' });
      environment[name] = path;
      sensitive.push(bytes.toString('utf8'), value, bytes.toString('base64url'));
    }
    return await new Promise<number>((resolve, reject) => {
      const child = spawn(command[0]!, command.slice(1), {
        env: environment,
        stdio: ['inherit', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
      });
      const variants = secretVariants(sensitive),
        out = new Redactor(variants, (value) => process.stdout.write(value)),
        err = new Redactor(variants, (value) => process.stderr.write(value));
      child.stdout.on('data', (chunk: Buffer) => out.write(chunk));
      child.stderr.on('data', (chunk: Buffer) => err.write(chunk));
      const forward = (signal: NodeJS.Signals) => {
        if (!child.pid) return;
        try {
          if (process.platform === 'win32') child.kill(signal);
          else process.kill(-child.pid, signal);
        } catch {}
      };
      const interrupt = () => forward('SIGINT'),
        terminate = () => forward('SIGTERM');
      process.on('SIGINT', interrupt);
      process.on('SIGTERM', terminate);
      child.once('error', () =>
        reject(new Error('The command could not be started. Check the executable and arguments.')),
      );
      child.once('close', (code, signal) => {
        process.off('SIGINT', interrupt);
        process.off('SIGTERM', terminate);
        out.end();
        err.end();
        resolve(code ?? (signal === 'SIGINT' ? 130 : signal === 'SIGTERM' ? 143 : 1));
      });
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
