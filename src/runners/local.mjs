import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

// What a runner promises, whatever it runs on. Foundation keeps everything else - who may use a machine, how long it
// lives, what it costs - so a runner only has to do these:
//   start({ id, size, env })            -> { machine, home }   make one machine; env is set for every command, and a
//                                       value beginning with ~/ names a path under the machine's home
//   exec(machine, { command, stdin, timeoutMs }) -> { exitCode, stdout, stderr, timedOut }   run one command
//   put(machine, path, content, mode)   write one file (path relative to home)
//   remove(machine, path)               remove one file
//   stop(machine)                       stop the machine and throw it away
//
// This one runs each machine as a directory on this host. It isolates nothing and is for tests and development only.
const OUTPUT_MAX = 1024 * 1024;

export class LocalRunner {
  constructor() { this.name = 'local'; this.machines = new Map(); }
  async start({ id, env = {} }) {
    const home = await mkdtemp(join(tmpdir(), 'foundation-env-'));
    const machine = id + ':' + randomUUID();
    const placed = Object.fromEntries(Object.entries(env).map(([name, value]) => [name, String(value).startsWith('~/') ? join(home, String(value).slice(2)) : String(value)]));
    this.machines.set(machine, { home, env: placed, running: new Set() });
    return { machine, home };
  }
  at(machine) {
    const found = this.machines.get(machine);
    if (!found) throw Object.assign(new Error('machine is gone'), { gone: true });
    return found;
  }
  within(home, path) {
    const target = resolve(home, path);
    if (!target.startsWith(home + '/')) throw new Error('outside the machine');
    return target;
  }
  exec(machine, { command, stdin = null, timeoutMs }) {
    const { home, env, running } = this.at(machine);
    return new Promise(done => {
      const child = spawn(command[0], command.slice(1), { cwd: home, env: { PATH: process.env.PATH, HOME: home, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
      running.add(child);
      const out = [], err = [];
      let outLength = 0, errLength = 0, timedOut = false;
      child.stdout.on('data', chunk => { if (outLength < OUTPUT_MAX) { out.push(chunk); outLength += chunk.length; } });
      child.stderr.on('data', chunk => { if (errLength < OUTPUT_MAX) { err.push(chunk); errLength += chunk.length; } });
      const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeoutMs);
      const finish = code => { clearTimeout(timer); running.delete(child); done({ exitCode: code, stdout: Buffer.concat(out).subarray(0, OUTPUT_MAX), stderr: Buffer.concat(err).subarray(0, OUTPUT_MAX), timedOut }); };
      child.on('error', error => { err.push(Buffer.from(String(error.message))); finish(127); });
      child.on('close', code => finish(code ?? 137));
      child.stdin.end(stdin ?? undefined);
    });
  }
  async put(machine, path, content, mode = 0o600) {
    const { home } = this.at(machine), target = this.within(home, path);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(target, content, { mode });
  }
  async remove(machine, path) {
    const { home } = this.at(machine);
    await rm(this.within(home, path), { force: true });
  }
  async stop(machine) {
    const found = this.machines.get(machine);
    if (!found) return;
    this.machines.delete(machine);
    for (const child of found.running) child.kill('SIGKILL');
    await rm(found.home, { recursive: true, force: true });
  }
}
