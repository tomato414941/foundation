import { fail, HttpError } from '../errors.mjs';

// Machines lent on Fly Machines: each one a Firecracker micro-VM, made for one environment and destroyed with it. The
// runner keeps to the contract in local.mjs; everything else (who may use it, how long it lives, what it costs) is
// Foundation's. It should run in a Fly organization of its own, so a machine cannot reach any other app's private
// network, with a token that reaches only that organization's one app.
//
// The machine does nothing by itself: whatever its image would run, it sleeps until commands are run in it, and stops
// being paid for when destroyed.
const API = 'https://api.machines.dev/v1';
const GUESTS = {
  small: { cpu_kind: 'shared', cpus: 1, memory_mb: 512 },
  medium: { cpu_kind: 'shared', cpus: 2, memory_mb: 1024 },
  large: { cpu_kind: 'shared', cpus: 4, memory_mb: 2048 },
};
const HOME = '/root', REGISTRY = 'registry.fly.io/';
// Fly's exec carries its command as arguments, each bounded by the machine's kernel; a file goes in by pieces.
const PIECE = 64 * 1024;

export class FlyRunner {
  constructor({ token, app, image, region = 'nrt', fetcher = fetch }) {
    if (!token || !app || !image) throw new Error('FlyRunner needs a token, an app and an image');
    Object.assign(this, { name: 'fly', token, app, image, region, fetcher });
  }
  async call(method, path, body, { timeoutMs = 30_000 } = {}) {
    let response;
    try {
      response = await this.fetcher(API + '/apps/' + encodeURIComponent(this.app) + path, { method, redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
        headers: { authorization: 'Bearer ' + this.token, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    } catch { fail(502, 'runner_unavailable', 'エンバイロメントを用意できませんでした。時間をおいて再度お試しください。'); }
    const creating = method === 'POST' && path === '/machines';
    if (response.status === 404 && !creating) throw Object.assign(new Error('machine is gone'), { gone: true });
    if (!response.ok) {
      const error = new HttpError(502, 'runner_unavailable', 'エンバイロメントを用意できませんでした。時間をおいて再度お試しください。');
      // Explicit request rejection is different from a timeout/5xx: the provider did not accept creation.
      if (creating && [400, 401, 402, 403, 404, 422, 429].includes(response.status)) error.notCreated = true;
      throw error;
    }
    const text = await response.text();
    let data; try { data = text ? JSON.parse(text) : {}; } catch { data = {}; }
    return data;
  }
  // Fly's registry holds the organization's images, not the public's: of it, only this runner's own image is lent.
  reserved(image) { return image.startsWith(REGISTRY); }
  async start({ id, image = this.image, size = 'small', env = {}, onCreated = () => {} }) {
    const placed = Object.fromEntries(Object.entries(env).map(([name, value]) => [name, String(value).startsWith('~/') ? HOME + '/' + String(value).slice(2) : String(value)]));
    const made = await this.call('POST', '/machines', {
      name: 'env-' + id, region: this.region,
      config: { image, init: { exec: ['sleep', 'infinity'] }, env: { HOME, ...placed }, guest: GUESTS[size] ?? GUESTS.small, auto_destroy: true, restart: { policy: 'no' },
        metadata: { foundation_environment: id } },
    });
    if (typeof made.id !== 'string') fail(502, 'runner_unavailable', 'エンバイロメントを用意できませんでした。');
    onCreated(made.id);
    await this.call('GET', '/machines/' + made.id + '/wait?state=started&timeout=60', undefined, { timeoutMs: 70_000 });
    return { machine: made.id, home: HOME };
  }
  // One call to Fly's exec. It carries no standard input and gives up after about a minute, so what a command needs
  // of either is arranged inside the machine instead (see exec).
  async once(machine, command, timeoutMs) {
    const seconds = Math.max(1, Math.min(55, Math.ceil(timeoutMs / 1000)));
    const done = await this.call('POST', '/machines/' + machine + '/exec', { command, timeout: seconds }, { timeoutMs: seconds * 1000 + 15_000 });
    return { exitCode: typeof done.exit_code === 'number' ? done.exit_code : null, stdout: Buffer.from(done.stdout ?? '', 'utf8'), stderr: Buffer.from(done.stderr ?? '', 'utf8') };
  }
  // A command runs in the background inside the machine, its input fed from a file and its output and exit code
  // written to files; short calls look in on it until it ends or its time is up. So a command may take as long as
  // the environment allows and still be answered, and its input and output are the bytes it read and wrote.
  // What is handed to the command goes in as files of the run: a variable's value in env, a file under files/ with its
  // path in the variable. All of it goes with the run when its output is collected.
  async exec(machine, { command, stdin = null, env = {}, files = [], timeoutMs }) {
    const run = '.foundation/run/' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    if (stdin !== null) await this.put(machine, run + '/stdin', stdin);
    const lines = [...Object.entries(env).map(([name, value]) => name + ' ' + Buffer.from(value).toString('base64')), ...files.map(file => file.env + ' @' + file.filename)];
    for (const file of files) await this.put(machine, run + '/files/' + file.filename, file.content);
    if (lines.length) await this.put(machine, run + '/env', lines.join('\n') + '\n');
    const started = await this.once(machine, ['sh', '-c',
      'dir="$HOME/$1"; shift; mkdir -p "$dir"; [ -f "$dir/stdin" ] || : > "$dir/stdin"; [ -f "$dir/env" ] || : > "$dir/env"; ' +
      '(while read -r name value; do case "$value" in @*) export "$name=$dir/files/${value#@}";; *) export "$name=$(printf %s "$value" | base64 -d)";; esac; done < "$dir/env"; ' +
      'cd "$HOME" && setsid "$@" < "$dir/stdin" > "$dir/stdout" 2> "$dir/stderr"; echo $? > "$dir/code.tmp"; mv "$dir/code.tmp" "$dir/code") > /dev/null 2>&1 & ' +
      'echo $! > "$dir/pid"', 'start', run, ...command], 20_000);
    if (started.exitCode !== 0) return { exitCode: 127, stdout: Buffer.alloc(0), stderr: started.stderr, timedOut: false };
    const deadline = Date.now() + timeoutMs;
    let wait = 300;
    for (;;) {
      const looked = await this.once(machine, ['sh', '-c', 'cat "$HOME/$1/code" 2>/dev/null', 'look', run], 20_000);
      if (looked.exitCode === 0) break;
      if (Date.now() >= deadline) {
        await this.once(machine, ['sh', '-c', 'kill -9 -- -"$(cat "$HOME/$1/pid")" 2>/dev/null; true', 'kill', run], 20_000).catch(() => {});
        const { stdout, stderr } = await this.collect(machine, run);
        return { exitCode: null, stdout, stderr, timedOut: true };
      }
      await new Promise(resolve => setTimeout(resolve, wait));
      wait = Math.min(2000, wait * 2);
    }
    const { stdout, stderr, code } = await this.collect(machine, run);
    return { exitCode: code, stdout, stderr, timedOut: false };
  }
  // The output as bytes, whatever they are, and the exit code, in one call; then the run's files go.
  async collect(machine, run) {
    const read = await this.once(machine, ['sh', '-c',
      'cd "$HOME/$1" || exit 1; for part in stdout stderr code; do head -c 1048576 "$part" 2>/dev/null | base64 -w0; echo; done; cd "$HOME"; rm -rf "$HOME/$1"', 'collect', run], 30_000);
    const [stdout = '', stderr = '', code = ''] = read.stdout.toString().split('\n').map(part => Buffer.from(part.trim(), 'base64'));
    const parsed = Number.parseInt(code.toString().trim(), 10);
    return { stdout: Buffer.from(stdout), stderr: Buffer.from(stderr), code: Number.isFinite(parsed) ? parsed : null };
  }
  // Files are written from inside, so nothing but the machine's own shell touches its disk.
  async put(machine, path, content, mode = 0o600) {
    const bytes = Buffer.from(content);
    for (let at = 0; at === 0 || at < bytes.length; at += PIECE) {
      const encoded = bytes.subarray(at, at + PIECE).toString('base64');
      const done = await this.once(machine, ['sh', '-c',
        'umask 077; target="$HOME/$1"; mkdir -p "$(dirname "$target")" && if [ "$4" = 0 ]; then printf %s "$2" | base64 -d > "$target"; else printf %s "$2" | base64 -d >> "$target"; fi && chmod "$3" "$target"',
        'put', path, encoded, mode.toString(8), String(at)], 20_000);
      if (done.exitCode !== 0) fail(502, 'runner_unavailable', 'ファイルを置けませんでした。');
    }
  }
  async remove(machine, path) {
    await this.once(machine, ['sh', '-c', 'rm -f "$HOME/$1"', 'remove', path], 20_000);
  }
  async stop(machine) {
    try {
      await this.call('DELETE', '/machines/' + machine + '?force=true');
      const remaining = await this.call('GET', '/machines/' + machine);
      if (remaining.state !== 'destroyed') fail(502, 'runner_unavailable', 'エンバイロメントの削除を確認できませんでした。');
    }
    catch (error) { if (!error?.gone) throw error; }
  }
}
