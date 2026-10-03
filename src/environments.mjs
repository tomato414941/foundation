import { randomUUID } from 'node:crypto';
import { fail } from './errors.mjs';
import { redact } from './fetch.mjs';
import { resourceName } from './resources.mjs';

// A machine lent to a owner: a shell, files and the network. It is a resource, not a principal, and by itself it can
// reach nothing of Foundation's. The owner may give it an identity: a principal it acts as inside, the way a cloud
// machine is given a role. Only a principal the giver may act as can be given; the machine then holds a key for it
// that dies with the machine.
//
// What it is made from is the opener's to choose, as with any cloud machine: an image, or Foundation's general one,
// which holds common tools and nothing of Foundation's. What a command needs of Foundation is handed to that command.
//
// The machine is lent; the computing it uses is spent. What each principal spends is counted against a monthly limit
// its owner may set, so whoever pays for many principals can bound each of them.
export const SIZES = { small: 1, medium: 2, large: 4 };
export const KEY_PATH = '.foundation/key';
const COMMAND_PARTS = 200, COMMAND_LENGTH = 100_000, STDIN_MAX = 1024 * 1024, KEPT_OUTPUT = 256 * 1024, STOPPED_KEPT = 3600_000;
// The lease outlasts a runner stop call; crashed attempts become due again without an in-memory queue.
const STOP_LEASE = 120_000, STOP_RETRY = 5000, STOP_RETRY_MAX = 300_000;
const COLUMNS = 'r.id,r.owner_id,r.kind,r.name,r.created_at,r.updated_at,e.image,e.size,e.lifetime,e.idle_seconds,e.max_seconds,e.identity,e.runner,e.machine,e.status,e.started_at,e.last_active_at,e.expires_at,e.stop_attempts,e.stop_retry_at,e.remove_requested';
const FROM = 'FROM resources r JOIN environments e ON e.resource_id=r.id';
const month = (at = Date.now()) => new Date(at).toISOString().slice(0, 7);
// An OCI image reference: [registry/]repository[:tag][@digest], at most 255 characters.
const IMAGE = /^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?\/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$/;
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
    this.stopping = new Map();
    this.opening = new Set();
  }
  get enabled() { return Boolean(this.runner); }
  check() { if (!this.enabled) fail(503, 'environments_unavailable', 'エンバイロメントは現在使えません。'); }

  get(id) { return typeof id === 'string' ? this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.id=?`).get(id) : undefined; }
  at(id) {
    const row = this.get(id);
    if (!row) fail(404, 'not_found', '見つかりません。');
    return row;
  }
  list(ownerId) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.owner_id=? ORDER BY r.created_at,r.id`).all(ownerId); }
  view(row) {
    return { ...this.resources.view(row), image: row.image, size: row.size, lifetime: { end: row.lifetime, idle_seconds: row.idle_seconds, max_seconds: row.max_seconds },
      identity: row.identity, status: row.status, started_at: iso(row.started_at), last_active_at: iso(row.last_active_at), expires_at: iso(row.expires_at) };
  }

  // Computing: what a principal spent this month, counting machines still running, and the most it may spend.
  ceiling(principalId) { return this.payments.paying(principalId) ? this.limits.monthlySeconds : this.limits.freeSeconds; }
  limitOf(principalId) {
    const set = this.db.prepare('SELECT monthly_seconds FROM compute_limits WHERE principal_id=?').get(principalId)?.monthly_seconds;
    return Math.min(set ?? Infinity, this.ceiling(principalId));
  }
  // What is spent is counted for the payer, over everyone it pays for; the limit is the principal's own, under the
  // payer's ceiling.
  usage(principalId, now = Date.now()) {
    const payer = this.payments.payerOf(principalId), family = payer === null ? [principalId] : this.payments.family(payer), marks = family.map(() => '?').join(',');
    const spent = this.db.prepare(`SELECT COALESCE(SUM(seconds),0) AS seconds FROM compute_usage WHERE month=? AND principal_id IN (${marks})`).get(month(now), ...family).seconds;
    const running = this.db.prepare(`SELECT e.size,e.started_at ${FROM} WHERE e.status<>'stopped' AND r.owner_id IN (${marks})`).all(...family)
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
      .run(row.owner_id, month(until), seconds);
    this.payments.computed(row.owner_id, seconds, until);
  }
  // What all who do not pay have computed this month, and how many machines they are running now.
  freeUsage(now = Date.now()) {
    const payers = new Set(this.payments.payers()), free = id => !payers.has(this.payments.payerOf(id));
    const spent = this.db.prepare('SELECT principal_id, seconds FROM compute_usage WHERE month=?').all(month(now)).filter(row => free(row.principal_id)).reduce((total, row) => total + row.seconds, 0);
    const running = this.db.prepare(`SELECT r.owner_id, e.size, e.started_at ${FROM} WHERE e.status<>'stopped'`).all().filter(row => free(row.owner_id));
    return { seconds: spent + running.reduce((total, row) => total + Math.ceil((now - row.started_at) / 1000) * SIZES[row.size], 0), machines: running.length };
  }
  within(ownerId) {
    this.payments.needsPayer(ownerId, 'エンバイロメントを使う');
    if (!this.payments.paying(ownerId)) {
      const shared = this.freeUsage();
      if (shared.seconds >= this.limits.freePoolSeconds || shared.machines >= this.limits.freeConcurrent) fail(402, 'payment_required', '今月の無料枠はすべて使われました。支払い方法を登録すると、続けて使えます。');
    }
    const { used_seconds, limit_seconds } = this.usage(ownerId);
    if (used_seconds >= limit_seconds && !this.payments.paying(ownerId) && limit_seconds === this.limits.freeSeconds) fail(402, 'payment_required', '無料枠の上限に達しました。続けて使うには支払い方法を登録してください。');
    if (used_seconds >= limit_seconds) fail(429, 'compute_limit', '今月の計算時間の上限に達しました。');
  }

  // An image named by the opener. The runner's own registry holds what only Foundation may use, so of it only the
  // general image may be named.
  image(value) {
    if (value === undefined || value === null) return this.runner.image ?? null;
    if (typeof value !== 'string' || value.length > 255 || !IMAGE.test(value)) fail(400, 'invalid_image', 'image はイメージの参照（例: python:3.12-slim）で指定してください。');
    if (value !== this.runner.image && this.runner.reserved?.(value)) fail(400, 'invalid_image', 'このイメージは使えません。');
    return value;
  }

  // Opening one. The identity is checked by the caller: it must be one the opener may act as.
  async open(ownerId, input = {}, origin = this.origin) {
    this.check();
    const image = this.image(input.image);
    const size = input.size ?? 'small';
    if (!Object.hasOwn(SIZES, size)) fail(400, 'invalid_size', 'size は small / medium / large のいずれかです。');
    const lifetime = input.lifetime ?? {}, end = lifetime.end ?? 'idle';
    if (!['exit', 'idle'].includes(end)) fail(400, 'invalid_lifetime', 'lifetime.end は exit か idle です。');
    const idle = lifetime.idle_seconds ?? this.limits.idleSeconds, max = lifetime.max_seconds ?? this.limits.maxSeconds;
    if (!Number.isInteger(idle) || idle < 30 || idle > this.limits.maxSeconds) fail(400, 'invalid_lifetime', `idle_seconds は30〜${this.limits.maxSeconds}秒です。`);
    if (!Number.isInteger(max) || max < 30 || max > this.limits.maxSeconds) fail(400, 'invalid_lifetime', `max_seconds は30〜${this.limits.maxSeconds}秒です。`);
    const name = input.name === undefined ? 'エンバイロメント' : resourceName(input.name);
    const id = randomUUID(), now = Date.now();
    this.store.transaction(() => {
      this.principals.at(ownerId);
      if (this.db.prepare(`SELECT count(*) n ${FROM} WHERE r.owner_id=? AND e.status<>'stopped'`).get(ownerId).n >= this.limits.concurrent) fail(429, 'environment_limit', `同時に開けるエンバイロメントは${this.limits.concurrent}つまでです。`);
      this.within(ownerId);
      this.resources.insert(id, ownerId, 'environment', name);
      this.db.prepare("INSERT INTO environments (resource_id,image,size,lifetime,idle_seconds,max_seconds,identity,runner,status,started_at,last_active_at,expires_at) VALUES (?,?,?,?,?,?,NULL,?,'starting',?,?,?)")
        .run(id, image, size, end, idle, max, this.runner.name, now, now, now + max * 1000);
    });
    this.opening.add(id);
    try {
      const started = await this.runner.start({ id, image, size, env: { FOUNDATION_URL: origin, FOUNDATION_RUNTIME_KEY_FILE: '~/' + KEY_PATH },
        onCreated: machine => this.db.prepare('UPDATE environments SET machine=? WHERE resource_id=?').run(machine, id) });
      this.db.prepare("UPDATE environments SET machine=?,status=CASE WHEN status='starting' THEN 'ready' ELSE status END WHERE resource_id=?").run(started.machine, id);
      this.opening.delete(id);
      this.usable(this.get(id));
      if (input.identity) await this.attach(this.get(id), input.identity);
    } catch (error) {
      this.opening.delete(id);
      if (error?.notCreated) this.store.transaction(() => {
        const row = this.get(id);
        if (row && !row.machine) { this.principals.revokeEnvironmentKeys(id); this.resources.remove(row); }
      });
      await this.remove(this.get(id)).catch(() => {});
      throw error;
    }
    return this.get(id);
  }

  // Giving it an identity: a key for that principal, placed inside, living no longer than the machine.
  async attach(row, principalId) {
    const key = this.store.transaction(() => {
      row = this.usable(row);
      this.principals.at(principalId);
      this.principals.revokeEnvironmentKeys(row.id);
      return this.principals.issueKey(principalId, { expiresAt: row.expires_at, environmentId: row.id });
    });
    this.reveal(row.id, [key.token]);
    try { await this.runner.put(row.machine, KEY_PATH, key.token + '\n', 0o600); }
    catch (error) { this.principals.revokeEnvironmentKeys(row.id); throw error; }
    // A stop may have revoked the key while the runner was writing it; never restore that identity afterward.
    this.usable(this.get(row.id));
    const changed = this.db.prepare("UPDATE environments SET identity=? WHERE resource_id=? AND status IN ('ready','busy')").run(principalId, row.id);
    if (!changed.changes) this.usable(this.get(row.id));
    return this.get(row.id);
  }
  async detach(row) {
    this.principals.revokeEnvironmentKeys(row.id);
    this.db.prepare('UPDATE environments SET identity=NULL WHERE resource_id=?').run(row.id);
    const id = row.id;
    row = this.get(id);
    if (row?.machine && ['ready', 'busy'].includes(row.status)) await this.runner?.remove(row.machine, KEY_PATH).catch(() => {});
    return this.get(id);
  }
  usable(row) {
    row = row && this.get(row.id);
    if (!row || !['ready', 'busy'].includes(row.status) || !row.machine) fail(409, 'environment_stopped', 'このエンバイロメントは利用できません。新しく開いてください。');
    return row;
  }
  // What a command handed into a machine, to be taken out of what it prints.
  reveal(id, values) {
    const kept = this.revealed.get(id) ?? new Set();
    for (const value of values) if (typeof value === 'string' && value.length >= 4) kept.add(value);
    this.revealed.set(id, kept);
  }

  // Running one command. It is answered when done; the caller may stop waiting and ask again by its id. handed is what
  // was obtained for it (as POST /v1/injections answers): variables, and files whose paths are variables.
  run(row, byId, input = {}, handed = null) {
    row = this.usable(row);
    const command = input.command;
    if (!Array.isArray(command) || !command.length || command.length > COMMAND_PARTS || command.some(part => typeof part !== 'string' || part.length > COMMAND_LENGTH) || !command[0])
      fail(400, 'invalid_command', 'command は文字列の配列で指定してください。');
    if (input.stdin !== undefined && input.stdin !== null && (typeof input.stdin !== 'string' || Buffer.byteLength(input.stdin) > STDIN_MAX)) fail(400, 'invalid_stdin', 'stdin は1MBまでの文字列です。');
    const remaining = Math.floor((row.expires_at - Date.now()) / 1000);
    const timeout = input.timeout_seconds ?? Math.min(300, remaining);
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > remaining) fail(400, 'invalid_timeout', `timeout_seconds は1〜${Math.max(1, remaining)}秒です。`);
    this.within(row.owner_id);
    const id = randomUUID(), now = Date.now();
    this.store.transaction(() => {
      row = this.usable(row);
      if (row.status === 'busy') fail(409, 'environment_busy', '前のコマンドが終わるまで待ってください。');
      this.db.prepare("UPDATE environments SET status='busy',last_active_at=? WHERE resource_id=?").run(now, row.id);
      this.db.prepare("INSERT INTO environment_commands (id,environment_id,by_id,command,status,started_at) VALUES (?,?,?,?,'running',?)").run(id, row.id, byId, JSON.stringify(command), now);
    });
    const env = handed?.environment ?? {}, files = (handed?.files ?? []).map(file => ({ env: file.env, filename: file.filename, content: Buffer.from(file.content, 'base64') }));
    this.reveal(row.id, [...Object.values(env), ...files.map(file => file.content.toString('utf8'))]);
    const done = this.runner.exec(row.machine, { command, stdin: input.stdin ?? null, env, files, timeoutMs: timeout * 1000 })
      .then(result => this.finish(row.id, id, result), error => this.finish(row.id, id, { exitCode: null, stdout: Buffer.alloc(0), stderr: Buffer.from(String(error.message || 'failed')), failed: true }));
    this.pending.set(id, done);
    done.then(() => this.pending.delete(id), () => this.pending.delete(id));
    return { id, done };
  }
  finish(environmentId, commandId, { exitCode, stdout, stderr, timedOut = false, failed = false }) {
    const values = [...(this.revealed.get(environmentId) ?? [])];
    const clean = buffer => redact(buffer, values).subarray(0, KEPT_OUTPUT).toString('utf8');
    const now = Date.now(), current = this.get(environmentId);
    this.db.prepare('UPDATE environment_commands SET status=?,exit_code=?,stdout=?,stderr=?,ended_at=? WHERE id=?')
      .run(failed ? 'failed' : timedOut ? 'timed_out' : 'done', exitCode, clean(stdout), clean(stderr), now, commandId);
    if (!current || current.status === 'stopped') this.revealed.delete(environmentId);
    if (!current) return null;
    if (current.status === 'busy') this.db.prepare("UPDATE environments SET status='ready',last_active_at=? WHERE resource_id=? AND status='busy'").run(now, environmentId);
    if (current.lifetime === 'exit') return this.stop(current).then(() => this.get(environmentId) ? this.command(environmentId, commandId) : null);
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

  // A stop first closes access and becomes durable. Only the runner's confirmation settles the computing and
  // starts retention. Failures stay stopping, with a bounded retry delay; a lease recovers interrupted attempts.
  async stop(row, { remove = false, now = Date.now() } = {}) {
    if (!row) return;
    row = this.store.transaction(() => {
      const current = this.get(row.id);
      if (!current) return;
      if (remove) this.db.prepare('UPDATE environments SET remove_requested=1 WHERE resource_id=?').run(current.id);
      if (!['stopping', 'stopped'].includes(current.status)) {
        this.principals.revokeEnvironmentKeys(current.id);
        this.db.prepare("UPDATE environments SET status='stopping',identity=NULL,stop_retry_at=? WHERE resource_id=?").run(now, current.id);
      }
      return this.get(current.id);
    });
    if (!row || row.status === 'stopped') return row;
    if (this.stopping.has(row.id)) return this.stopping.get(row.id);
    // start() may still return a machine. Keep the stop intent so it cannot make the environment ready again.
    if (!row.machine && this.opening.has(row.id)) return row;
    const claimed = this.store.transaction(() => {
      const current = this.get(row.id);
      if (!current || current.status !== 'stopping' || current.stop_retry_at > now) return;
      this.db.prepare('UPDATE environments SET stop_attempts=stop_attempts+1,stop_retry_at=? WHERE resource_id=?').run(now + STOP_LEASE, row.id);
      return this.get(row.id);
    });
    if (!claimed) return this.get(row.id);
    const done = this.tryStop(claimed, now);
    this.stopping.set(row.id, done);
    try { return await done; }
    finally { this.stopping.delete(row.id); }
  }
  async tryStop(row, attemptedAt) {
    try {
      // No ID can mean the process died before creation answered, not that no machine was allocated.
      // Retain that uncertain record rather than lose a late creation response or falsely settle its usage.
      if (!row.machine) throw new Error('machine creation is unconfirmed');
      if (!this.runner || this.runner.name !== row.runner) throw new Error('runner unavailable');
      await this.runner.stop(row.machine);
    } catch (error) {
      if (!error?.gone) {
        const delay = Math.min(STOP_RETRY_MAX, STOP_RETRY * 2 ** Math.min(row.stop_attempts - 1, 10));
        this.db.prepare("UPDATE environments SET stop_retry_at=? WHERE resource_id=? AND status='stopping' AND stop_attempts=?")
          .run(Math.max(Date.now(), attemptedAt) + delay, row.id, row.stop_attempts);
        return this.get(row.id);
      }
    }
    return this.store.transaction(() => {
      const current = this.get(row.id);
      // Another process may have taken over an expired lease. Only its current attempt may settle the account.
      if (!current || current.status !== 'stopping' || current.stop_attempts !== row.stop_attempts) return current;
      const now = Math.max(Date.now(), attemptedAt);
      this.spend(current, now);
      this.db.prepare("UPDATE environments SET status='stopped',expires_at=?,stop_retry_at=NULL WHERE resource_id=?").run(now + STOPPED_KEPT, row.id);
      // Keep redaction values until an already-running command has collected its final output.
      if (!this.db.prepare("SELECT 1 FROM environment_commands WHERE environment_id=? AND status='running'").get(row.id)) this.revealed.delete(row.id);
      const stopped = this.get(row.id);
      if (stopped.remove_requested) this.resources.remove(stopped);
      return stopped;
    });
  }
  async remove(row) {
    const stopped = await this.stop(row, { remove: true });
    if (!stopped) return;
    if (stopped.status !== 'stopped') fail(503, 'environment_stopping', 'エンバイロメントの停止を確認できていません。停止と削除は自動で再試行されます。');
    this.resources.remove(stopped);
  }
  async removeAll(ownerId) {
    // Request every stop even if one provider call fails; retain the owner until all machines are gone.
    const results = await Promise.allSettled(this.list(ownerId).map(row => this.remove(row)));
    const failed = results.find(result => result.status === 'rejected');
    if (failed) throw failed.reason;
  }
  // Called in the owner-deletion transaction: a concurrent open during provider cleanup must not be cascaded away.
  assertRemoved(ownerId) {
    if (this.list(ownerId).length) fail(409, 'environments_changed', '新しいエンバイロメントが開かれています。もう一度削除してください。');
  }
  // Machines past their time, idle too long, due for a stop retry, or stopped long enough ago.
  async sweep(now = Date.now()) {
    const rows = this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE
      (e.status='stopping' AND e.stop_retry_at<=?) OR
      (e.status<>'stopping' AND (e.expires_at<=? OR (e.status='ready' AND e.lifetime='idle' AND e.last_active_at+e.idle_seconds*1000<=?)))`).all(now, now, now);
    for (const row of rows) {
      if (row.status === 'stopped') this.resources.remove(row);
      else await this.stop(row, { now });
    }
  }
}
