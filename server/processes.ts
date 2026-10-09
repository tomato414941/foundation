import { randomUUID } from 'node:crypto';
import type { Actor } from './authorization.js';
import type { Resources } from './resources.js';
import type { Delegation } from './delegation.js';
import { iso } from './database.js';
import type { Queryable } from './database.js';
import { fail, required } from './errors.js';
import { canonical } from '../shared/authority.js';
import { Operations } from '../shared/custody.js';
import { ProcessView } from '../shared/process.js';
import type { Completion, ProcessInfo, ProcessRequest } from '../shared/process.js';

interface ProcessRow {
  id: string; owner_id: string; actor_id: string; executor_id: string; environment_id: string;
  actor: Actor; request: ProcessRequest & { workingDirectory: string }; state: ProcessInfo['state'];
  result: ProcessInfo['result']; error: string | null;
  phase: 'queued' | 'claimed' | 'dispatched' | 'settled'; cancel_requested: boolean;
  lease_token: string | null; created_at: Date; started_at: Date | null; finished_at: Date | null;
}

export class Processes {
  constructor(readonly resources: Resources, readonly delegation: Delegation) {}

  private view(row: ProcessRow): ProcessInfo {
    return ProcessView.parse({ ...row.request, id: row.id, ownerId: row.owner_id, actorId: row.actor_id,
      environmentId: row.environment_id, state: row.state, result: row.result, error: row.error,
      createdAt: iso(row.created_at), startedAt: row.started_at ? iso(row.started_at) : null,
      finishedAt: row.finished_at ? iso(row.finished_at) : null });
  }
  private async row(id: string) {
    return required(await this.resources.db.one<ProcessRow>('SELECT * FROM environment_processes WHERE id=$1', [id]));
  }
  async register(actor: Actor, id: string, input: { workingDirectory: string }) {
    const environment = await this.delegation.requireExecutor(actor, id);
    if (!environment.registration.manifest.capabilities.includes(Operations.command))
      fail(409, 'commands_unavailable', 'This environment cannot run commands.');
    await this.resources.db.pool.query(
      "UPDATE resources SET data=jsonb_set(data,'{processes}',$2::jsonb),version=version+1,updated_at=now() WHERE id=$1 AND data->'processes' IS DISTINCT FROM $2::jsonb",
      [id, JSON.stringify(input)]);
    return input;
  }
  private async validate(actor: Actor, environmentId: string, connection: Queryable = this.resources.db.pool) {
    const resource = await this.resources.get(environmentId, connection);
    if (resource.kind !== 'environment') fail(400, 'wrong_kind', 'Choose an execution environment.');
    await this.resources.authorization.requireResource(actor, resource, 'execute', connection);
    if (resource.data.state !== 'running' || resource.data.deletion)
      fail(409, 'environment_stopped', 'Choose a running execution environment.');
    const environment = await this.delegation.environment(environmentId, connection);
    if (environment.stopped_at) fail(409, 'environment_stopped', 'Choose a running execution environment.');
    if (!resource.data.processes || !environment.registration.manifest.capabilities.includes(Operations.command))
      fail(409, 'commands_unavailable', 'This environment has not enabled process execution.');
    if (!environment.heartbeat_at || Date.now() - environment.heartbeat_at.getTime() > 90_000)
      if (!await this.resources.db.one(
        "SELECT 1 FROM execution_tasks WHERE environment_id=$1 AND state='running' AND lease_until>now() LIMIT 1",
        [environmentId], connection))
        fail(503, 'environment_unavailable', 'The execution environment is not responding.');
    return { resource, environment };
  }
  async create(actor: Actor, environmentId: string, input: ProcessRequest & { id?: string }) {
    const { id = randomUUID(), ...request } = input;
    return this.resources.db.transaction(async connection => {
      await connection.query('SELECT id FROM resources WHERE id=$1 FOR UPDATE', [environmentId]);
      const previous = await this.resources.db.one<ProcessRow>('SELECT * FROM environment_processes WHERE id=$1', [id], connection);
      if (previous) {
        await this.resources.authorization.active(actor, connection);
        if (previous.actor_id !== actor.id || previous.environment_id !== environmentId ||
          canonical(previous.request) !== canonical({ ...request,
            workingDirectory: request.workingDirectory ?? previous.request.workingDirectory }))
          fail(409, 'process_conflict', 'Use a new process ID for a different command.');
        return this.view(previous);
      }
      const { resource, environment } = await this.validate(actor, environmentId, connection);
      const workingDirectory = request.workingDirectory ?? (resource.data.processes as { workingDirectory: string }).workingDirectory;
      const active = await this.resources.db.one<{ count: string }>(
        "SELECT count(*) FROM environment_processes WHERE environment_id=$1 AND state IN ('queued','running')", [environmentId], connection);
      if (Number(active?.count) >= 20) fail(429, 'process_limit', 'Wait for an existing process to finish.');
      const row = await this.resources.db.one<ProcessRow>(
        `INSERT INTO environment_processes(id,owner_id,actor_id,executor_id,environment_id,state,actor,request)
         VALUES($1,$2,$3,$4,$5,'queued',$6,$7) ON CONFLICT(id) DO NOTHING RETURNING *`,
        [id, resource.owner_id, actor.id, environment.executor_id, environmentId,
          JSON.stringify(actor), JSON.stringify({ ...request, workingDirectory })], connection);
      if (!row) fail(409, 'process_conflict', 'Use a new process ID for a different command.');
      await this.resources.audit.record(resource.owner_id, actor.id, 'process.create', id, { environmentId }, connection);
      return this.view(row);
    });
  }
  async get(actor: Actor, id: string) {
    const row = await this.row(id);
    if (row.actor_id === actor.id) await this.resources.authorization.active(actor);
    else await this.resources.authorization.requirePrincipal(actor, row.owner_id, 'read');
    return this.view(row);
  }
  async list(actor: Actor, environmentId: string, limit = 100, after?: string) {
    const resource = await this.resources.get(environmentId);
    await this.resources.authorization.requireResource(actor, resource, 'read');
    const all = await this.resources.authorization.can(actor, { type: 'principal', id: resource.owner_id }, 'read');
    const rows = await this.resources.db.all<ProcessRow>(
      `SELECT * FROM environment_processes WHERE environment_id=$1 AND ($2::boolean OR actor_id=$3)
       AND ($4::uuid IS NULL OR id>$4) ORDER BY id LIMIT $5`, [environmentId, all, actor.id, after ?? null, limit + 1]);
    return { items: rows.slice(0, limit).map(row => this.view(row)), next: rows.length > limit ? rows[limit - 1]!.id : null };
  }
  async claim(actor: Actor, environmentId: string) {
    await this.delegation.heartbeat(actor, environmentId);
    const lease = randomUUID();
    const row = await this.resources.db.one<ProcessRow>(
      `UPDATE environment_processes SET state='running',phase='claimed',lease_token=$2,lease_until=now()+interval '60 seconds'
       WHERE id=(SELECT id FROM environment_processes WHERE environment_id=$1 AND state='queued'
         ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *`, [environmentId, lease]);
    if (!row) return null;
    try { await this.validate(row.actor, environmentId); }
    catch {
      await this.resources.db.pool.query(
        `UPDATE environment_processes SET state='failed',phase='settled',error='authorization_changed',finished_at=now(),lease_until=NULL
         WHERE id=$1 AND lease_token=$2 AND phase='claimed' AND state='running' AND cancel_requested=false`, [row.id, lease]);
      return null;
    }
    return { lease, process: this.view(row) };
  }
  async dispatch(actor: Actor, id: string, lease: string) {
    const row = await this.row(id);
    await this.delegation.requireExecutor(actor, row.environment_id);
    await this.validate(row.actor, row.environment_id);
    const updated = await this.resources.db.one(
      `UPDATE environment_processes SET phase='dispatched',started_at=now() WHERE id=$1 AND lease_token=$2
       AND phase='claimed' AND state='running' AND cancel_requested=false AND lease_until>now() RETURNING id`, [id, lease]);
    if (!updated) fail(409, 'lease_lost', 'This process can no longer be started with that lease.');
    await this.resources.db.pool.query(
      "UPDATE resources SET data=jsonb_set(data,'{lastActiveAt}',to_jsonb($2::text)) WHERE id=$1",
      [row.environment_id, new Date().toISOString()]);
    return { ok: true as const };
  }
  async renew(actor: Actor, id: string, lease: string) {
    const row = await this.row(id);
    await this.delegation.heartbeat(actor, row.environment_id);
    try { await this.validate(row.actor, row.environment_id); }
    catch { return { active: false }; }
    const updated = await this.resources.db.one(
      `UPDATE environment_processes SET lease_until=now()+interval '60 seconds' WHERE id=$1 AND lease_token=$2
       AND state='running' AND cancel_requested=false AND lease_until>now() RETURNING id`, [id, lease]);
    if (updated) await this.resources.db.pool.query(
      "UPDATE resources SET data=jsonb_set(data,'{lastActiveAt}',to_jsonb($2::text)) WHERE id=$1",
      [row.environment_id, new Date().toISOString()]);
    return { active: Boolean(updated) };
  }
  async finish(actor: Actor, id: string, lease: string, completion: Completion) {
    const row = await this.row(id);
    await this.resources.authorization.active(actor);
    if (row.executor_id !== actor.id) fail(403, 'forbidden', 'Only the selected environment can complete this process.');
    if (row.phase === 'settled') {
      if (row.state !== 'cancelled' && canonical({ state: row.state, result: row.result, error: row.error }) !== canonical(completion))
        fail(409, 'process_settled', 'This process already has a final result.');
      return this.view(row);
    }
    if (completion.state === 'succeeded' && (row.phase !== 'dispatched' || completion.result?.exitCode !== 0 ||
      completion.result.signal || completion.result.timedOut))
      fail(400, 'invalid_result', 'A successful process must have completed with exit code zero.');
    const updated = await this.resources.db.one<ProcessRow>(
      `UPDATE environment_processes SET state=$3,phase='settled',result=$4,error=$5,finished_at=now(),lease_until=NULL
       WHERE id=$1 AND lease_token=$2 AND state IN ('running','uncertain') RETURNING *`,
      [id, lease, completion.state, completion.result ? JSON.stringify(completion.result) : null, completion.error]);
    if (!updated) fail(409, 'lease_lost', 'This process cannot accept a result from that lease.');
    await this.resources.db.pool.query(
      "UPDATE resources SET data=jsonb_set(data,'{lastActiveAt}',to_jsonb($2::text)) WHERE id=$1",
      [row.environment_id, new Date().toISOString()]);
    return this.view(updated);
  }
  async cancel(actor: Actor, id: string) {
    const row = await this.row(id);
    if (row.actor_id === actor.id) await this.resources.authorization.active(actor);
    else await this.resources.authorization.requirePrincipal(actor, row.owner_id, 'execute');
    await this.resources.db.pool.query(
      `UPDATE environment_processes SET cancel_requested=true,
       state=CASE WHEN phase='dispatched' THEN 'uncertain' ELSE 'cancelled' END,
       phase=CASE WHEN phase='dispatched' THEN phase ELSE 'settled' END,
       error=CASE WHEN phase='dispatched' THEN 'cancellation_pending' ELSE NULL END,
       finished_at=CASE WHEN phase='dispatched' THEN NULL ELSE now() END,lease_until=NULL
       WHERE id=$1 AND state IN ('queued','running')`, [id]);
    return this.get(actor, id);
  }
  async recover() {
    await this.resources.db.pool.query(
      `UPDATE environment_processes SET state=CASE WHEN phase='dispatched' THEN 'uncertain' ELSE 'queued' END,
       error=CASE WHEN phase='dispatched' THEN 'execution_interrupted' ELSE NULL END,
       phase=CASE WHEN phase='dispatched' THEN phase ELSE 'queued' END,
       finished_at=CASE WHEN phase='dispatched' THEN now() ELSE NULL END,lease_until=NULL
       WHERE state='running' AND lease_until<now()`);
  }
}
