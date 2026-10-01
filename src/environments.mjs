import { randomUUID } from 'node:crypto';
import { fail } from './errors.mjs';
import { redact } from './fetch.mjs';
import { resourceName } from './resources.mjs';

// A machine lent to a holder: a shell, files and the network. It is a resource, not a principal, and by itself it can
// reach nothing of Foundation's. The holder may give it an identity: a principal it acts as inside, the way a cloud
// machine is given a role. Only a principal the giver may act as can be given; the machine then holds a key for it
// that dies with the machine.
//
// The machine is lent; the computing it uses is spent. What each principal spends is counted against a monthly limit
// its owner may set, so whoever pays for many principals can bound each of them.
export const SIZES = { small: 1, medium: 2, large: 4 };
export const KEY_PATH = '.foundation/key';
const COMMAND_PARTS = 200, COMMAND_LENGTH = 100_000, STDIN_MAX = 1024 * 1024, KEPT_OUTPUT = 256 * 1024, STOPPED_KEPT = 3600_000;
const COLUMNS = 'r.id,r.holder_id,r.kind,r.name,r.created_at,r.updated_at,e.size,e.lifetime,e.idle_seconds,e.max_seconds,e.identity,e.runner,e.machine,e.status,e.started_at,e.last_active_at,e.expires_at';
const FROM = 'FROM resources r JOIN environments e ON e.resource_id=r.id';
const month = (at = Date.now()) => new Date(at).toISOString().slice(0, 7);
const iso = value => value === null || value === undefined ? null : new Date(value).toISOString();

export class Environments {
  // limits: freeSeconds (what anyone may compute each month), monthlySeconds (the default for one that pays, and the
  // most it may be allowed), concurrent, maxSeconds, idleSeconds. payments: who pays, and what they computed is charged.
  constructor({ store, resources, principals, payments, runner = null, origin = '', limits = {} }) {
    Object.assign(this, { store, db: store.db, resources, principals, payments, runner, origin });
    // The free part is also bounded for all who do not pay together - what they compute in a month and how many
    // machines they run at once - so what costs Foundation without anyone paying cannot grow past it.
    this.limits = { freeSeconds: 36_000, freePoolSeconds: 360_000, freeConcurrent: 3, monthlySeconds: 360_000, concurrent: 3, maxSeconds: 3600, idleSeconds: 600, ...limits };
    // Values handed into a machine, kept only in memory, to take out of what its commands print.
    this.revealed = new Map();
    this.pending = new Map();
  }
  get enabled() { return Boolean(this.runner); }
  check() { if (!this.enabled) fail(503, 'environments_unavailable', '環境は現在使えません。'); }

  get(id) { return typeof id === 'string' ? this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.id=?`).get(id) : undefined; }
  at(id) {
    const row = this.get(id);
    if (!row) fail(404, 'not_found', '見つかりません。');
    return row;
  }
  list(holderId) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.holder_id=? ORDER BY r.created_at,r.id`).all(holderId); }
  view(row) {
    return { ...this.resources.view(row), size: row.size, lifetime: { end: row.lifetime, idle_seconds: row.idle_seconds, max_seconds: row.max_seconds },
      identity: row.identity, status: row.status, started_at: iso(row.started_at), last_active_at: iso(row.last_active_at), expires_at: iso(row.expires_at) };
  }

  // Computing: what a principal spent this month, counting machines still running, and the most it may spend.
  ceiling(principalId) { return this.payments.paying(principalId) ? this.limits.monthlySeconds : this.limits.freeSeconds; }
  limitOf(principalId) {
    const set = this.db.prepare('SELECT monthly_seconds FROM compute_limits WHERE principal_id=?').get(principalId)?.monthly_seconds;
    return Math.min(set ?? Infinity, this.ceiling(principalId));
  }
  usage(principalId, now = Date.now()) {
    const spent = this.db.prepare('SELECT seconds FROM compute_usage WHERE principal_id=? AND month=?').get(principalId, month(now))?.seconds ?? 0;
    const running = this.db.prepare(`SELECT e.size,e.started_at ${FROM} WHERE r.holder_id=? AND e.status<>'stopped'`).all(principalId)
      .reduce((total, row) => total + Math.ceil((now - row.started_at) / 1000) * SIZES[row.size], 0);
    return { month: month(now), used_seconds: spent + running, limit_seconds: this.limitOf(principalId) };
  }
  // An owner bounds what a principal it owns may spend, up to Foundation's own default.
  setLimit(principalId, seconds) {
    if (!Number.isInteger(seconds) || seconds < 0 || seconds > this.limits.monthlySeconds) fail(400, 'invalid_limit', `上限は0〜${this.limits.monthlySeconds}秒で指定してください。`);
    this.db.prepare('INSERT OR REPLACE INTO compute_limits (principal_id,monthly_seconds) VALUES (?,?)').run(principalId, seconds);
    return this.usage(principalId);
  }
  spend(row, until) {
    const seconds = Math.ceil((until - row.started_at) / 1000) * SIZES[row.size];
    this.db.prepare('INSERT INTO compute_usage (principal_id,month,seconds) VALUES (?,?,?) ON CONFLICT(principal_id,month) DO UPDATE SET seconds=seconds+excluded.seconds')
      .run(row.holder_id, month(until), seconds);
    this.payments.computed(row.holder_id, seconds, until);
  }
  // What all who do not pay have computed this month, and how many machines they are running now.
  freeUsage(now = Date.now()) {
    const payers = new Set(this.payments.payers()), free = id => !payers.has(id);
    const spent = this.db.prepare('SELECT principal_id, seconds FROM compute_usage WHERE month=?').all(month(now)).filter(row => free(row.principal_id)).reduce((total, row) => total + row.seconds, 0);
    const running = this.db.prepare(`SELECT r.holder_id, e.size, e.started_at ${FROM} WHERE e.status<>'stopped'`).all().filter(row => free(row.holder_id));
    return { seconds: spent + running.reduce((total, row) => total + Math.ceil((now - row.started_at) / 1000) * SIZES[row.size], 0), machines: running.length };
  }
  within(holderId) {
    if (!this.payments.paying(holderId)) {
      const shared = this.freeUsage();
      if (shared.seconds >= this.limits.freePoolSeconds || shared.machines >= this.limits.freeConcurrent) fail(402, 'payment_required', '今月の無料枠はすべて使われました。支払い方法を登録すると、続けて使えます。');
    }
    const { used_seconds, limit_seconds } = this.usage(holderId);
    if (used_seconds >= limit_seconds && !this.payments.paying(holderId) && limit_seconds === this.limits.freeSeconds) fail(402, 'payment_required', '無料枠の上限に達しました。続けて使うには支払い方法を登録してください。');
    if (used_seconds >= limit_seconds) fail(429, 'compute_limit', '今月の計算時間の上限に達しました。');
  }

  // Opening one. The identity is checked by the caller: it must be one the opener may act as.
  async open(holderId, input = {}, origin = this.origin) {
    this.check();
    const size = input.size ?? 'small';
    if (!Object.hasOwn(SIZES, size)) fail(400, 'invalid_size', 'size は small / medium / large のいずれかです。');
    const lifetime = input.lifetime ?? {}, end = lifetime.end ?? 'idle';
    if (!['exit', 'idle'].includes(end)) fail(400, 'invalid_lifetime', 'lifetime.end は exit か idle です。');
    const idle = lifetime.idle_seconds ?? this.limits.idleSeconds, max = lifetime.max_seconds ?? this.limits.maxSeconds;
    if (!Number.isInteger(idle) || idle < 30 || idle > this.limits.maxSeconds) fail(400, 'invalid_lifetime', `idle_seconds は30〜${this.limits.maxSeconds}秒です。`);
    if (!Number.isInteger(max) || max < 30 || max > this.limits.maxSeconds) fail(400, 'invalid_lifetime', `max_seconds は30〜${this.limits.maxSeconds}秒です。`);
    const name = input.name === undefined ? '環境' : resourceName(input.name);
    const id = randomUUID(), now = Date.now();
    this.store.transaction(() => {
      if (this.db.prepare(`SELECT count(*) n ${FROM} WHERE r.holder_id=? AND e.status<>'stopped'`).get(holderId).n >= this.limits.concurrent) fail(429, 'environment_limit', `同時に開ける環境は${this.limits.concurrent}つまでです。`);
      this.within(holderId);
      this.resources.insert(id, holderId, 'environment', name);
      this.db.prepare("INSERT INTO environments (resource_id,size,lifetime,idle_seconds,max_seconds,identity,runner,status,started_at,last_active_at,expires_at) VALUES (?,?,?,?,?,NULL,?,'starting',?,?,?)")
        .run(id, size, end, idle, max, this.runner.name, now, now, now + max * 1000);
    });
    try {
      const started = await this.runner.start({ id, size, env: { FOUNDATION_URL: origin, FOUNDATION_RUNTIME_KEY_FILE: '~/' + KEY_PATH } });
      this.db.prepare("UPDATE environments SET machine=?,status='ready' WHERE resource_id=?").run(started.machine, id);
      if (input.identity) await this.attach(this.get(id), input.identity);
    } catch (error) {
      await this.remove(this.get(id)).catch(() => {});
      throw error;
    }
    return this.get(id);
  }

  // Giving it an identity: a key for that principal, placed inside, living no longer than the machine.
  async attach(row, principalId) {
    this.usable(row);
    this.principals.at(principalId);
    this.principals.revokeEnvironmentKeys(row.id);
    const key = this.principals.issueKey(principalId, { expiresAt: row.expires_at, environmentId: row.id });
    this.reveal(row.id, [key.token]);
    try { await this.runner.put(row.machine, KEY_PATH, key.token + '\n', 0o600); }
    catch (error) { this.principals.revokeEnvironmentKeys(row.id); throw error; }
    this.db.prepare('UPDATE environments SET identity=? WHERE resource_id=?').run(principalId, row.id);
    return this.get(row.id);
  }
  async detach(row) {
    this.principals.revokeEnvironmentKeys(row.id);
    this.db.prepare('UPDATE environments SET identity=NULL WHERE resource_id=?').run(row.id);
    if (row.status !== 'stopped') await this.runner.remove(row.machine, KEY_PATH).catch(() => {});
    return this.get(row.id);
  }
  usable(row) {
    if (row.status === 'stopped' || !row.machine) fail(409, 'environment_stopped', 'この環境は止まっています。新しく開いてください。');
  }
  // What a command handed into a machine, to be taken out of what it prints.
  reveal(id, values) {
    const kept = this.revealed.get(id) ?? new Set();
    for (const value of values) if (typeof value === 'string' && value.length >= 4) kept.add(value);
    this.revealed.set(id, kept);
  }

  // Running one command. It is answered when done; the caller may stop waiting and ask again by its id.
  run(row, byId, input = {}) {
    this.usable(row);
    const command = input.command;
    if (!Array.isArray(command) || !command.length || command.length > COMMAND_PARTS || command.some(part => typeof part !== 'string' || part.length > COMMAND_LENGTH) || !command[0])
      fail(400, 'invalid_command', 'command は文字列の配列で指定してください。');
    if (input.stdin !== undefined && input.stdin !== null && (typeof input.stdin !== 'string' || Buffer.byteLength(input.stdin) > STDIN_MAX)) fail(400, 'invalid_stdin', 'stdin は1MBまでの文字列です。');
    const remaining = Math.floor((row.expires_at - Date.now()) / 1000);
    const timeout = input.timeout_seconds ?? Math.min(300, remaining);
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > remaining) fail(400, 'invalid_timeout', `timeout_seconds は1〜${Math.max(1, remaining)}秒です。`);
    if (row.status === 'busy') fail(409, 'environment_busy', '前のコマンドが終わるまで待ってください。');
    this.within(row.holder_id);
    const id = randomUUID(), now = Date.now();
    this.store.transaction(() => {
      this.db.prepare("UPDATE environments SET status='busy',last_active_at=? WHERE resource_id=?").run(now, row.id);
      this.db.prepare("INSERT INTO environment_commands (id,environment_id,by_id,command,status,started_at) VALUES (?,?,?,?,'running',?)").run(id, row.id, byId, JSON.stringify(command), now);
    });
    const done = this.runner.exec(row.machine, { command, stdin: input.stdin ?? null, timeoutMs: timeout * 1000 })
      .then(result => this.finish(row.id, id, result), error => this.finish(row.id, id, { exitCode: null, stdout: Buffer.alloc(0), stderr: Buffer.from(String(error.message || 'failed')), failed: true }));
    this.pending.set(id, done);
    done.finally(() => this.pending.delete(id));
    return { id, done };
  }
  finish(environmentId, commandId, { exitCode, stdout, stderr, timedOut = false, failed = false }) {
    const values = [...(this.revealed.get(environmentId) ?? [])];
    const clean = buffer => redact(buffer, values).subarray(0, KEPT_OUTPUT).toString('utf8');
    const now = Date.now(), current = this.get(environmentId);
    this.db.prepare('UPDATE environment_commands SET status=?,exit_code=?,stdout=?,stderr=?,ended_at=? WHERE id=?')
      .run(failed ? 'failed' : timedOut ? 'timed_out' : 'done', exitCode, clean(stdout), clean(stderr), now, commandId);
    if (current && current.status === 'busy') this.db.prepare("UPDATE environments SET status='ready',last_active_at=? WHERE resource_id=?").run(now, environmentId);
    if (current && current.lifetime === 'exit') return this.stop(this.get(environmentId)).then(() => this.command(environmentId, commandId));
    return this.command(environmentId, commandId);
  }
  command(environmentId, commandId) {
    const row = this.db.prepare('SELECT * FROM environment_commands WHERE id=? AND environment_id=?').get(commandId, environmentId);
    if (!row) fail(404, 'not_found', '見つかりません。');
    return { id: row.id, environment_id: row.environment_id, command: JSON.parse(row.command), status: row.status, exit_code: row.exit_code,
      stdout: row.stdout, stderr: row.stderr, started_at: iso(row.started_at), ended_at: iso(row.ended_at) };
  }
  // Waits for a command up to a while; what is not done by then is answered as running.
  async answer(environmentId, commandId, waitMs) {
    const done = this.pending.get(commandId);
    if (done) await Promise.race([done.catch(() => {}), new Promise(resolve => setTimeout(resolve, waitMs).unref?.())]);
    return this.command(environmentId, commandId);
  }

  // Stopping: the machine is thrown away, its keys die, and what it used is spent. The record of it stays a while so
  // results can still be read, then goes.
  async stop(row) {
    if (!row || row.status === 'stopped') return row;
    const now = Date.now();
    this.store.transaction(() => {
      this.principals.revokeEnvironmentKeys(row.id);
      this.spend(row, now);
      this.db.prepare("UPDATE environments SET status='stopped',expires_at=? WHERE resource_id=?").run(now + STOPPED_KEPT, row.id);
    });
    this.revealed.delete(row.id);
    if (row.machine) await this.runner?.stop(row.machine).catch(() => {});
    return this.get(row.id);
  }
  async remove(row) {
    if (!row) return;
    await this.stop(row);
    this.resources.remove(row);
  }
  async removeAll(holderId) { for (const row of this.list(holderId)) await this.remove(row); }
  // Machines past their time, idle too long, or stopped long enough ago.
  async sweep(now = Date.now()) {
    const rows = this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE e.expires_at<=? OR (e.status='ready' AND e.lifetime='idle' AND e.last_active_at+e.idle_seconds*1000<=?)`).all(now, now);
    for (const row of rows) {
      if (row.status === 'stopped') this.resources.remove(row);
      else await this.stop(row);
    }
  }
}
