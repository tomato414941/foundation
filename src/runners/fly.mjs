import { fail } from '../errors.mjs';

// Machines lent on Fly Machines: each one a Firecracker micro-VM, made for one environment and destroyed with it. The
// runner keeps to the contract in local.mjs; everything else (who may use it, how long it lives, what it costs) is
// Foundation's. It should run in a Fly organization of its own, so a machine cannot reach any other app's private
// network, with a token that reaches only that organization's one app.
//
// The machine does nothing by itself: it sleeps until commands are run in it, and stops being paid for when destroyed.
const API = 'https://api.machines.dev/v1';
const GUESTS = {
  small: { cpu_kind: 'shared', cpus: 1, memory_mb: 512 },
  medium: { cpu_kind: 'shared', cpus: 2, memory_mb: 1024 },
  large: { cpu_kind: 'shared', cpus: 4, memory_mb: 2048 },
};
const HOME = '/root';

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
    } catch { fail(502, 'runner_unavailable', '実行環境を用意できませんでした。時間をおいて再度お試しください。'); }
    const text = await response.text();
    let data; try { data = text ? JSON.parse(text) : {}; } catch { data = {}; }
    if (response.status === 404) throw Object.assign(new Error('machine is gone'), { gone: true });
    if (!response.ok) fail(502, 'runner_unavailable', '実行環境を用意できませんでした。時間をおいて再度お試しください。');
    return data;
  }
  async start({ id, size = 'small', env = {} }) {
    const placed = Object.fromEntries(Object.entries(env).map(([name, value]) => [name, String(value).startsWith('~/') ? HOME + '/' + String(value).slice(2) : String(value)]));
    const made = await this.call('POST', '/machines', {
      name: 'env-' + id, region: this.region,
      config: { image: this.image, env: { HOME, ...placed }, guest: GUESTS[size] ?? GUESTS.small, auto_destroy: true, restart: { policy: 'no' },
        metadata: { foundation_environment: id } },
    });
    if (typeof made.id !== 'string') fail(502, 'runner_unavailable', '実行環境を用意できませんでした。');
    await this.call('GET', '/machines/' + made.id + '/wait?state=started&timeout=60', undefined, { timeoutMs: 70_000 });
    return { machine: made.id, home: HOME };
  }
  async exec(machine, { command, stdin = null, timeoutMs }) {
    const seconds = Math.max(1, Math.ceil(timeoutMs / 1000));
    try {
      const done = await this.call('POST', '/machines/' + machine + '/exec', { command, timeout: seconds, ...(stdin === null ? {} : { stdin }) }, { timeoutMs: timeoutMs + 15_000 });
      return { exitCode: typeof done.exit_code === 'number' ? done.exit_code : null, stdout: Buffer.from(done.stdout ?? '', 'utf8'), stderr: Buffer.from(done.stderr ?? '', 'utf8'), timedOut: false };
    } catch (error) {
      if (error?.name === 'TimeoutError' || error?.code === 'runner_unavailable') return { exitCode: null, stdout: Buffer.alloc(0), stderr: Buffer.from('The command did not finish in time.'), timedOut: true };
      throw error;
    }
  }
  // Files are written from inside, so nothing but the machine's own shell touches its disk.
  async put(machine, path, content, mode = 0o600) {
    const encoded = Buffer.from(content).toString('base64');
    const done = await this.exec(machine, { timeoutMs: 20_000, command: ['sh', '-c',
      'umask 077; target="$HOME/$1"; mkdir -p "$(dirname "$target")" && printf %s "$2" | base64 -d > "$target" && chmod "$3" "$target"', 'put', path, encoded, mode.toString(8)] });
    if (done.exitCode !== 0) fail(502, 'runner_unavailable', 'ファイルを置けませんでした。');
  }
  async remove(machine, path) {
    await this.exec(machine, { timeoutMs: 20_000, command: ['sh', '-c', 'rm -f "$HOME/$1"', 'remove', path] });
  }
  async stop(machine) {
    try { await this.call('DELETE', '/machines/' + machine + '?force=true'); }
    catch (error) { if (!error?.gone) throw error; }
  }
}
