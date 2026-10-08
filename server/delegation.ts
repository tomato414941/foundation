import { randomUUID } from 'node:crypto';
import type { Actor } from './authorization.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Bindings } from './bindings.js';
import type { Custody } from './custody.js';
import type { Queryable } from './database.js';
import { iso } from './database.js';
import { canonical, hash } from '../shared/authority.js';
import { matchesPin, operationName, verifyRun } from '../shared/custody.js';
import type { CustodyContent, ExecutionIntent, SealedRun } from '../shared/custody.js';
import { Task, authorizeEnvironment, verifyEnvironment, verifyReceipt } from '../shared/execution.js';
import type { RegisteredEnvironment, SignedReceipt, TaskView } from '../shared/execution.js';
import { fail, required } from './errors.js';

interface EnvironmentRow {
  resource_id: string;
  executor_id: string;
  registration: RegisteredEnvironment;
  heartbeat_at: Date | null;
  stopped_at: Date | null;
}
interface TaskRow {
  id: string;
  owner_id: string;
  actor_id: string;
  environment_id: string;
  kind: TaskView['kind'];
  state: TaskView['state'];
  actor: Actor;
  request: SealedRun;
  receipt: SignedReceipt | null;
  error: string | null;
  phase: 'queued' | 'claimed' | 'dispatched' | 'settled';
  cancel_requested: boolean;
  lease_token: string | null;
  lease_until: Date | null;
  created_at: Date;
  started_at: Date | null;
  finished_at: Date | null;
}
export interface ClaimedTask {
  lease: string;
  request: SealedRun;
  sources: CustodyContent[];
}

export class Delegation {
  checkApproval?: (actor: Actor, intent: ExecutionIntent) => Promise<void>;
  constructor(
    readonly resources: Resources, readonly bindings: Bindings,
    readonly custody: Custody, readonly origin: string,
  ) {}

  async environment(id: string, connection: Queryable = this.resources.db.pool) {
    return required(await this.resources.db.one<EnvironmentRow>(
      'SELECT * FROM executor_environments WHERE resource_id=$1', [id], connection,
    ));
  }

  async register(actor: Actor, input: RegisteredEnvironment) {
    await this.resources.authorization.active(actor);
    const environment = await verifyEnvironment(input), { manifest } = environment;
    if (manifest.origin !== this.origin || manifest.executor.principalId !== actor.id)
      fail(403, 'forbidden', 'Register an execution environment using its own identity.');
    // Operator attribution is a principal, not an unverified provider label.
    if (manifest.operatorId !== actor.id)
      fail(400, 'invalid_operator', 'Use the registering identity as the execution operator.');
    await this.bindings.requireCurrent(manifest.executor);
    return this.resources.db.transaction(async connection => {
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [manifest.ownerId]);
      const old = await this.resources.db.one<EnvironmentRow>(
        'SELECT * FROM executor_environments WHERE resource_id=$1 FOR UPDATE', [manifest.id], connection,
      );
      const reserved = await this.resources.db.one<ResourceRow>(
        'SELECT r.* FROM resources r JOIN environment_jobs j ON j.resource_id=r.id WHERE r.id=$1 FOR UPDATE OF r',
        [manifest.id], connection,
      );
      if (reserved && (reserved.owner_id !== manifest.ownerId || reserved.data.executorId !== actor.id ||
        !['starting', 'running'].includes(String(reserved.data.state)) || manifest.driver !== 'managed' ||
        manifest.isolation !== 'container' || manifest.commandImage !== reserved.data.image))
        fail(403, 'forbidden', 'Use the identity and isolation reserved for this environment.');
      if (old) {
        if (old.executor_id !== actor.id || old.registration.manifest.ownerId !== manifest.ownerId)
          fail(403, 'forbidden', 'This execution environment belongs to another identity.');
        if (old.stopped_at) fail(409, 'environment_stopped', 'Create a new environment after this one has been stopped.');
        if (canonical(old.registration) === canonical(environment)) return this.resources.get(manifest.id, connection);
        if (manifest.revision !== old.registration.manifest.revision + 1)
          fail(409, 'changed', 'Use the next environment revision.');
      } else {
        if (!reserved && !(await this.resources.authorization.canCreate(actor, manifest.ownerId, 'environment', connection)))
          fail(403, 'forbidden', 'You cannot open an environment for this principal.');
        if (manifest.revision !== 1) fail(400, 'invalid_revision', 'Start the environment at revision one.');
      }
      const now = new Date().toISOString();
      const previous = old || reserved ? await this.resources.get(manifest.id, connection) : null;
      const { awsPrincipal: _awsPrincipal, ...metadata } = previous?.data ?? {};
      const data = {
        ...metadata,
        driver: manifest.driver, executorId: actor.id, operatorId: manifest.operatorId,
        capabilities: manifest.capabilities.map(operationName), isolation: manifest.isolation,
        manifestDigest: await hash(manifest),
        ...(manifest.awsPrincipal ? { awsPrincipal: manifest.awsPrincipal } : {}),
        size: metadata.size ?? 'small', lifetime: metadata.lifetime ?? { idleSeconds: 86400, maxSeconds: 86400 },
        state: 'running', startedAt: metadata.startedAt ?? now, stoppedAt: null, lastActiveAt: now, error: null,
      };
      const row = previous
        ? await this.resources.update(previous, { name: manifest.name, data }, connection)
        : await this.resources.insert(manifest.ownerId, 'environment', manifest.name, data, { id: manifest.id }, connection);
      await connection.query(
        `INSERT INTO executor_environments(resource_id,executor_id,registration,heartbeat_at) VALUES($1,$2,$3,now())
         ON CONFLICT(resource_id) DO UPDATE SET registration=EXCLUDED.registration,heartbeat_at=now()`,
        [manifest.id, actor.id, JSON.stringify(environment)],
      );
      await this.resources.audit.record(manifest.ownerId, actor.id, 'environment.register', manifest.id,
        { executorId: actor.id, revision: manifest.revision }, connection);
      return row;
    });
  }

  async heartbeat(actor: Actor, id: string) {
    const environment = await this.requireExecutor(actor, id);
    await this.resources.db.pool.query('UPDATE executor_environments SET heartbeat_at=now() WHERE resource_id=$1', [id]);
    return { registration: environment.registration };
  }

  private async requireExecutor(actor: Actor, id: string) {
    await this.resources.authorization.active(actor);
    const environment = await this.environment(id);
    if (environment.executor_id !== actor.id) fail(403, 'forbidden', 'Use the identity registered for this environment.');
    if (environment.stopped_at) fail(409, 'environment_stopped', 'This execution environment has been stopped.');
    await this.bindings.requireCurrent(environment.registration.manifest.executor);
    return environment;
  }

  private view(row: TaskRow): TaskView {
    return Task.parse({
      id: row.id, ownerId: row.owner_id, actorId: row.actor_id, environmentId: row.environment_id,
      kind: row.kind, state: row.state, intent: row.request.intent, requestSignature: row.request.signature,
      receipt: row.receipt, error: row.error,
      createdAt: iso(row.created_at), startedAt: row.started_at ? iso(row.started_at) : null,
      finishedAt: row.finished_at ? iso(row.finished_at) : null,
    });
  }

  private async validate(actor: Actor, request: SealedRun) {
    const run = await verifyRun(request), { intent } = run;
    if (intent.origin !== this.origin || intent.actor.principalId !== actor.id)
      fail(403, 'forbidden', 'Sign execution requests with your own identity.');
    await this.bindings.requireCurrent(intent.actor);
    if (intent.approval) {
      if (!this.checkApproval) fail(503, 'approval_unavailable', 'The approval request cannot be checked.');
      await this.checkApproval(actor, intent);
    }
    await this.resources.authorization.requirePrincipal(actor, intent.ownerId, 'execute');
    const environment = await this.environment(intent.environmentId);
    if (environment.stopped_at) fail(409, 'environment_stopped', 'Choose an active execution environment.');
    await this.bindings.requireCurrent(intent.executor);
    await authorizeEnvironment(environment.registration, intent);
    await this.resources.authorization.requireResource(actor, await this.resources.get(intent.environmentId), 'execute');
    const sources: CustodyContent[] = [];
    for (const pin of intent.sources) {
      const row = await this.resources.get(pin.id);
      await this.resources.authorization.requireResource(actor, row, 'use');
      const content = await this.custody.get(pin.id);
      if (!await matchesPin(content, pin))
        fail(409, 'changed', 'An input changed. Review it before submitting another execution.');
      sources.push(content);
    }
    if (sources.reduce((bytes, content) => bytes + JSON.stringify(content).length, 0) > 16_000_000)
      fail(413, 'input_limit', 'Use at most 16 MB of encrypted inputs in one execution.');
    return { run, sources };
  }

  async submit(actor: Actor, request: SealedRun) {
    const { run } = await this.validate(actor, request), { intent } = run;
    const runActor: Actor = { id: actor.id,
      ...(actor.credentialId ? { credentialId: actor.credentialId } : {}),
      ...(actor.sessionId ? { sessionId: actor.sessionId } : {}),
    };
    return this.resources.db.transaction(async connection => {
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [intent.ownerId]);
      const previous = await this.resources.db.one<TaskRow>('SELECT * FROM execution_tasks WHERE id=$1', [intent.id], connection);
      if (previous) {
        if (canonical(previous.request) !== canonical(run))
          fail(409, 'run_conflict', 'Use a new run ID for a different execution request.');
        return this.view(previous);
      }
      const active = await this.resources.db.one<{ count: string }>(
        "SELECT count(*) FROM execution_tasks WHERE owner_id=$1 AND state IN ('queued','running')", [intent.ownerId], connection,
      );
      if (Number(active?.count) >= 20) fail(429, 'run_limit', 'Wait for an existing run to finish.');
      const row = required(await this.resources.db.one<TaskRow>(
        `INSERT INTO execution_tasks(id,owner_id,actor_id,environment_id,kind,state,actor,request)
         VALUES($1,$2,$3,$4,$5,'queued',$6,$7) RETURNING *`,
        [intent.id, intent.ownerId, actor.id, intent.environmentId, operationName(intent.operation), JSON.stringify(runActor), JSON.stringify(run)], connection,
      ));
      await this.resources.audit.record(intent.ownerId, actor.id, 'run.create', intent.id,
        { environmentId: intent.environmentId, kind: operationName(intent.operation) }, connection);
      return this.view(row);
    });
  }

  async get(actor: Actor, id: string) {
    const row = required(await this.resources.db.one<TaskRow>('SELECT * FROM execution_tasks WHERE id=$1', [id]));
    if (actor.id === row.actor_id) await this.resources.authorization.active(actor);
    else await this.resources.authorization.requirePrincipal(actor, row.owner_id, 'read');
    return this.view(row);
  }

  async list(actor: Actor, ownerId: string, limit = 100, after?: string) {
    await this.resources.authorization.requirePrincipal(actor, ownerId, 'read');
    const rows = await this.resources.db.all<TaskRow>(
      'SELECT * FROM execution_tasks WHERE owner_id=$1 AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT $3',
      [ownerId, after ?? null, limit + 1],
    );
    return { items: rows.slice(0, limit).map(row => this.view(row)), next: rows.length > limit ? rows[limit - 1]!.id : null };
  }

  async claim(actor: Actor, environmentId: string): Promise<ClaimedTask | null> {
    await this.heartbeat(actor, environmentId);
    const lease = randomUUID();
    const row = await this.resources.db.one<TaskRow>(
      `UPDATE execution_tasks SET state='running',phase='claimed',started_at=coalesce(started_at,now()),
         lease_token=$2,lease_until=now()+interval '60 seconds'
       WHERE id=(SELECT id FROM execution_tasks WHERE environment_id=$1 AND state='queued'
         ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *`, [environmentId, lease],
    );
    if (!row) return null;
    try {
      const { sources } = await this.validate(row.actor, row.request);
      return { lease, request: row.request, sources };
    } catch {
      await this.resources.db.pool.query(
        `UPDATE execution_tasks SET state='failed',phase='settled',error='authorization_changed',finished_at=now(),lease_until=NULL
         WHERE id=$1 AND lease_token=$2 AND phase='claimed'`, [row.id, lease],
      );
      return null;
    }
  }

  async renew(actor: Actor, id: string, lease: string) {
    const row = required(await this.resources.db.one<TaskRow>('SELECT * FROM execution_tasks WHERE id=$1', [id]));
    await this.requireExecutor(actor, row.environment_id);
    const updated = await this.resources.db.one(
      `UPDATE execution_tasks SET lease_until=now()+interval '60 seconds' WHERE id=$1 AND lease_token=$2
       AND state='running' AND cancel_requested=false AND lease_until>now() RETURNING id`, [id, lease],
    );
    return { active: Boolean(updated) };
  }

  async dispatch(actor: Actor, id: string, lease: string) {
    const row = required(await this.resources.db.one<TaskRow>('SELECT * FROM execution_tasks WHERE id=$1', [id]));
    await this.requireExecutor(actor, row.environment_id);
    await this.validate(row.actor, row.request);
    const updated = await this.resources.db.one(
      `UPDATE execution_tasks SET phase='dispatched' WHERE id=$1 AND lease_token=$2 AND state='running'
       AND phase='claimed' AND cancel_requested=false AND lease_until>now() RETURNING id`, [id, lease],
    );
    if (!updated) fail(409, 'lease_lost', 'The execution lease is no longer valid.');
    await this.resources.db.pool.query(
      "UPDATE resources SET data=jsonb_set(data,'{lastActiveAt}',to_jsonb($2::text)) WHERE id=$1",
      [row.environment_id, new Date().toISOString()],
    );
    return { ok: true as const };
  }

  async finish(actor: Actor, lease: string, receipt: SignedReceipt) {
    const row = required(await this.resources.db.one<TaskRow>('SELECT * FROM execution_tasks WHERE id=$1', [receipt.id]));
    // A stopped executor may still reconcile a result it durably recorded before stopping.
    await this.resources.authorization.active(actor);
    if (row.request.intent.executor.principalId !== actor.id)
      fail(403, 'forbidden', 'Only the selected executor can complete this run.');
    await verifyReceipt(receipt, row.request.intent);
    if (row.receipt) {
      if (canonical(row.receipt) !== canonical(receipt)) fail(409, 'run_settled', 'This run already has a final result.');
      return this.view(row);
    }
    if (receipt.state === 'succeeded' && row.phase !== 'dispatched')
      fail(409, 'run_not_dispatched', 'Start the authorized operation before reporting its success.');
    const updated = await this.resources.db.one<TaskRow>(
      `UPDATE execution_tasks SET state=$3,phase='settled',receipt=$4,error=NULL,finished_at=now(),lease_until=NULL
       WHERE id=$1 AND lease_token=$2 AND state IN ('running','uncertain') RETURNING *`,
      [row.id, lease, receipt.state, JSON.stringify(receipt)],
    );
    if (!updated) fail(409, 'lease_lost', 'This run can no longer accept a result from that execution lease.');
    return this.view(updated);
  }

  async cancel(actor: Actor, id: string) {
    const row = required(await this.resources.db.one<TaskRow>('SELECT * FROM execution_tasks WHERE id=$1', [id]));
    await this.resources.authorization.requirePrincipal(actor, row.owner_id, 'execute');
    await this.resources.db.pool.query(
      `UPDATE execution_tasks SET cancel_requested=true,
         state=CASE WHEN phase='dispatched' THEN 'uncertain' ELSE 'cancelled' END,
         error=CASE WHEN phase='dispatched' THEN 'cancellation_pending' ELSE NULL END,
         finished_at=now(),lease_until=NULL WHERE id=$1 AND state IN ('queued','running')`, [id],
    );
    return this.get(actor, id);
  }

  async stop(actor: Actor, environmentId: string, connection: Queryable = this.resources.db.pool): Promise<void> {
    if (connection === this.resources.db.pool)
      return this.resources.db.transaction(transaction => this.stop(actor, environmentId, transaction));
    const resource = await this.resources.get(environmentId, connection);
    await this.resources.authorization.requireResource(actor, resource, 'delete', connection);
    await connection.query('UPDATE executor_environments SET stopped_at=now() WHERE resource_id=$1', [environmentId]);
    await connection.query(
      `UPDATE resources SET data=data||jsonb_build_object('state','stopped','stoppedAt',$2::text),version=version+1 WHERE id=$1`,
      [environmentId, new Date().toISOString()],
    );
    await connection.query(
      `UPDATE execution_tasks SET cancel_requested=true,
         state=CASE WHEN phase='dispatched' THEN 'uncertain' ELSE 'cancelled' END,
         error=CASE WHEN phase='dispatched' THEN 'environment_stopped' ELSE NULL END,
         finished_at=now(),lease_until=NULL WHERE environment_id=$1 AND state IN ('queued','running')`, [environmentId],
    );
  }

  async recover() {
    await this.resources.db.pool.query(
      `UPDATE execution_tasks SET state=CASE WHEN phase='dispatched' THEN 'uncertain' ELSE 'queued' END,
       error=CASE WHEN phase='dispatched' THEN 'execution_interrupted' ELSE NULL END,
       phase=CASE WHEN phase='dispatched' THEN phase ELSE 'queued' END,
       finished_at=CASE WHEN phase='dispatched' THEN now() ELSE NULL END,lease_until=NULL
       WHERE state='running' AND lease_until<now()`,
    );
    await this.resources.db.pool.query(
      `UPDATE execution_tasks SET state='failed',phase='settled',error='intent_expired',finished_at=now()
       WHERE state='queued' AND (request->'intent'->>'expiresAt')::timestamptz<=now()`,
    );
  }
}
