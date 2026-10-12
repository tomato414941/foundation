import { randomInt, randomUUID } from 'node:crypto';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor, Authorization } from './authorization.js';
import { principal } from './authorization.js';
import type { Principals } from './principals.js';
import { digest } from './vault.js';
import { atPointer, setPointer } from '../shared/values.js';
import { Id, Json, Operation } from '../shared/contracts.js';
import type { RequestedOperation } from '../shared/contracts.js';
import type { Proposed } from './relations.js';
import type { z } from 'zod';
import { ExecutionInput } from '../shared/executions.js';
import type { Vault } from './vault.js';
import { fail, failure, required } from './errors.js';
import { AgreementNeeded } from './relations.js';
import type { Audit } from './audit.js';
import type { DefinitionRegistry } from './definitions.js';
import { OperationFailed } from './definitions.js';
import { hash } from '../shared/authority.js';
import { Execution } from '../shared/executions.js';
import type { DefinitionCall, ExecutionView, OperationWaiting } from '../shared/executions.js';
import type { JsonValue } from '../shared/contracts.js';
import { deliverExecution } from './request-delivery.js';
import type { TaskView } from '../shared/runtime-protocol.js';
import type { InvocationView } from '../shared/function-api.js';

interface Snapshot {
  actor: Actor;
  creatorActor: Actor;
  agreementIndex: number | null;
  responders: string[];
  submissionDigest: string | null;
  operations: RequestedOperation[];
  index: number;
  results: Array<JsonValue | null>;
  proofs: Array<string | null>;
  inFlight: number | null;
  continuation: OperationWaiting['continuation'];
  preparations?: Array<{ index: number; digest: string }>;
  runtime?: { kind: 'run' | 'function'; id: string };
}
interface ExecutionRow {
  id: string; actor_id: string; creator_id: string; owner_id: string | null; responder_id: string | null; message: string;
  proposal: Proposed | null; code_hash: string | null; attempts: number;
  response: 'none' | 'pending' | 'accepted' | 'declined' | 'cancelled' | 'expired';
  state: ExecutionView['state']; wait: ExecutionView['wait'];
  snapshot: string; revision: number; lease_token: string | null; lease_until: Date | null; expires_at: Date; created_at: Date;
}
// One persisted execution mechanism serves direct calls and calls awaiting a person's response.
export class Executions {
  runtime!: {
    get(actor: Actor, reference: NonNullable<Snapshot['runtime']>): Promise<TaskView | InvocationView>;
    cancel(actor: Actor, reference: NonNullable<Snapshot['runtime']>): Promise<TaskView | InvocationView>;
  };
  constructor(readonly db: Database, readonly vault: Vault, readonly authorization: Authorization,
    readonly definitions: DefinitionRegistry, readonly audit: Audit, readonly principals: Principals, readonly origin: string) {}
  private async row(id: string) {
    return required(await this.db.one<ExecutionRow>('SELECT * FROM executions WHERE id=$1', [id]));
  }
  private read(row: ExecutionRow) { return this.vault.decrypt<Snapshot>(row.snapshot, 'operation-execution:' + row.id); }
  private authority(actor: Actor) {
    const authority = { ...actor };
    // A login authenticates a call; the saved execution retains the identity, credential, and consent.
    delete authority.sessionId;
    return authority;
  }
  private operationActor(snapshot: Snapshot): Actor {
    const actor = { ...snapshot.actor, approvalIndex: snapshot.index };
    if (actor.agreedBy && snapshot.agreementIndex !== snapshot.index) {
      delete actor.agreedBy;
      delete actor.approvalId;
    }
    return actor;
  }
  async canRespond(actor: Actor | null, row: ExecutionRow) {
    if (!actor) return false;
    await this.authorization.active(actor);
    if (actor.requestId) return !!await this.db.one('SELECT 1 FROM requests WHERE id=$1 AND execution_id=$2 AND to_id=$3',
      [actor.requestId, row.id, actor.id]);
    if (row.response === 'accepted' && actor.id === row.actor_id) return true;
    if (row.responder_id) return this.authorization.holds(actor.id, principal(row.responder_id), 'stands');
    return row.code_hash ? actor.id !== row.creator_id : actor.id === row.actor_id;
  }
  private async proposal(proposed: Proposed | null) {
    if (!proposed) return null;
    const named = async (id: string) => {
      const found = await this.db.one<{ name: string }>('SELECT name FROM principals WHERE id=$1 UNION ALL SELECT name FROM resources WHERE id=$1', [id]);
      return { id, name: found?.name ?? id };
    };
    return proposed.kind === 'line'
      ? { kind: proposed.kind, subject: await named(proposed.subjectId), relation: proposed.relation, object: await named(proposed.objectId) }
      : { kind: proposed.kind, item: await named(proposed.itemId), to: await named(proposed.to) };
  }
  private async view(row: ExecutionRow, snapshot: Snapshot, actor: Actor | null = { id: snapshot.actor.id }): Promise<ExecutionView> {
    const [creator, canRespond, proposal] = await Promise.all([this.principals.get(row.creator_id),
      this.canRespond(actor, row), this.proposal(row.proposal)]);
    const deliveries = await this.db.all<{ id: string }>('SELECT id FROM requests WHERE execution_id=$1 ORDER BY created_at', [row.id]);
    const runtime = await this.db.all<{ id: string; index: number }>(`SELECT id,(request->'intent'->'operationContext'->>'index')::integer AS index
      FROM execution_tasks WHERE request->'intent'->'operationContext'->>'id'=$1 ORDER BY created_at`, [row.id]);
    const currentResult = snapshot.results[snapshot.index];
    const error = currentResult && typeof currentResult === 'object' && !Array.isArray(currentResult) && 'error' in currentResult ? currentResult.error : null;
    return Execution.parse({ id: row.id, actorId: row.actor_id, ownerId: row.owner_id ?? row.creator_id,
      requests: deliveries.map(item => item.id), creator: { id: creator.id, name: creator.name },
      steps: snapshot.operations.map((operation, index) => {
        const result = snapshot.results[index];
        const runs: ExecutionView['steps'][number]['runs'] = runtime.filter(run => run.index === index).map(run => ({ kind: 'run' as const, id: run.id }));
        if (snapshot.runtime && index === 0) runs.push(snapshot.runtime);
        if (!snapshot.runtime && operation.name === 'function.invoke' && result && typeof result === 'object' && !Array.isArray(result) && typeof result.id === 'string')
          runs.push({ kind: 'function', id: result.id });
        return { index, name: operation.name, state: index < snapshot.index ? 'succeeded' : index === snapshot.index ? row.state : 'waiting', runs };
      }),
      approval: row.wait === 'approval' ? { requestId: deliveries.at(-1)?.id ?? null, proposal } : null,
      canContinue: canRespond && ['waiting', 'running', 'failed'].includes(row.state),
      error,
      canCancel: !!actor && !actor.requestId && !['succeeded', 'cancelled'].includes(row.state) && [row.creator_id, row.actor_id].includes(actor.id),
      url: this.origin + '/executions/' + row.id,
      operations: snapshot.operations.map(operation => ({ ...operation, title: this.definitions.describe(operation),
        execution: this.definitions.get(operation.name).execution, configure: [...this.definitions.get(operation.name).configure] })),
      index: snapshot.index, state: row.state, wait: row.wait,
      waiting: (row.wait === 'input' || row.wait === 'execution' && !!snapshot.continuation) && canRespond && (actor?.id === row.actor_id || actor?.requestId)
        ? { index: snapshot.index, invocation: { name: snapshot.operations[snapshot.index]!.name, input: snapshot.operations[snapshot.index]!.input },
          continuation: snapshot.continuation, ...(this.operationActor(snapshot).approvalId ? { approval: { id: snapshot.actor.approvalId!, index: snapshot.index } } : {}) } : null,
      results: snapshot.results.map((result, index) => snapshot.operations[index]?.name === 'function.invoke' && result &&
        typeof result === 'object' && !Array.isArray(result) && 'result' in result ? result.result : result),
      createdAt: iso(row.created_at), expiresAt: iso(row.expires_at) });
  }
  private async expire(row: ExecutionRow) {
    if (row.expires_at.getTime() > Date.now() || !['waiting', 'running', 'failed'].includes(row.state)) return row;
    if (row.state === 'failed' && (await this.read(row)).runtime) return row;
    await this.db.transaction(async connection => {
      await this.revoke(row.id, connection);
      await connection.query("UPDATE executions SET response='expired' WHERE id=$1", [row.id]);
      await connection.query("UPDATE requests SET state='expired',answered_at=now() WHERE execution_id=$1 AND state='pending'", [row.id]);
    });
    return this.row(row.id);
  }
  async expireAll() {
    const rows = await this.db.all<ExecutionRow>("SELECT * FROM executions WHERE expires_at<=now() AND state IN ('waiting','running','failed')");
    for (const row of rows) await this.expire(row);
  }
  async recoverAll() {
    const rows = await this.db.all<ExecutionRow>("SELECT * FROM executions WHERE state IN ('running','uncertain') AND (lease_until IS NULL OR lease_until<now()) ORDER BY created_at");
    const errors: unknown[] = [];
    for (const row of rows) {
      try { await this.recover(await this.expire(row)); }
      catch (error) { errors.push(error); }
    }
    if (errors.length) throw new AggregateError(errors, 'Operation recovery failed.');
  }
  async peek(id: string) {
    const row = await this.db.one<ExecutionRow>('SELECT * FROM executions WHERE id=$1', [id]);
    if (!row) return null;
    const current = await this.recover(await this.expire(row));
    return this.view(current, await this.read(current));
  }
  async get(actor: Actor | null, id: string, resume = true) {
    const row = await this.expire(await this.row(id));
    const snapshot = await this.read(row);
    if (actor) await this.authorization.active(actor);
    if (actor?.requestId && !await this.db.one('SELECT 1 FROM requests WHERE id=$1 AND execution_id=$2', [actor.requestId, id]))
      fail(403, 'forbidden', 'This link can open only its own execution.');
    const publicJoin = row.code_hash && !row.responder_id;
    if (!publicJoin && (!actor ||
      actor.id !== row.creator_id && actor.id !== row.actor_id && !snapshot.responders.includes(actor.id) && !(await this.canRespond(actor, row)) &&
      !(row.owner_id && !actor.requestId && await this.authorization.holds(actor.id, principal(row.owner_id), 'read'))))
      fail(403, 'forbidden', 'This operation belongs to another principal.');
    const current = resume ? await this.recover(row) : row;
    return this.view(current, await this.read(current), actor);
  }
  async list(actor: Actor, limit = 100, after?: string, ownerId?: string) {
    await this.authorization.active(actor);
    if (actor.requestId) fail(403, 'forbidden', 'This link can open only its own operation.');
    const represented = await this.authorization.find(actor.id, 'principal', 'stands');
    if (ownerId) await this.authorization.requirePrincipal(actor, ownerId, 'read');
    const rows = await this.db.all<{ id: string }>(`SELECT id FROM executions
      WHERE (($5::uuid IS NULL AND (creator_id=$1 OR actor_id=$1 OR responder_id=ANY($2::uuid[]))) OR owner_id=$5)
      AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4`,
      [actor.id, represented, after ?? null, limit + 1, ownerId ?? null]);
    return { items: await Promise.all(rows.slice(0, limit).map(row => this.get(actor, row.id))), next: rows.length > limit ? rows[limit - 1]!.id : null };
  }
  async recordRuntime(kind: 'run' | 'function', job: TaskView | InvocationView) {
    if ('intent' in job && job.intent.operationContext) {
      const context = job.intent.operationContext;
      try {
        await this.locked(context.id, async () => {
          const row = await this.row(context.id), snapshot = await this.read(row);
          if (row.state === 'waiting' && row.wait === 'input' && snapshot.index === context.index && snapshot.continuation)
            await this.save(row, snapshot, 'running', 'execution');
        });
      } catch (error) {
        if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'execution_busy') throw error;
      }
      return;
    }
    if (await this.db.one('SELECT 1 FROM executions WHERE id=$1', [job.id])) return;
    const call = 'functionId' in job ? { name: 'function.invoke', input: { functionId: job.functionId, ownerId: job.ownerId } }
      : { name: 'run.execute', input: { ownerId: job.ownerId, environmentId: job.environmentId, operation: { kind: job.kind } } };
    const actor = { id: job.actorId }, state = job.state === 'queued' ? 'running' : job.state;
    const snapshot: Snapshot = { actor, creatorActor: actor, agreementIndex: null, responders: [], submissionDigest: null,
      operations: [Operation.parse(call)], index: state === 'succeeded' ? 1 : 0,
      results: [Json.parse('intent' in job ? { kind: 'run', id: job.id } : job)], proofs: [null], inFlight: null, continuation: null,
      runtime: { kind, id: job.id } };
    await this.db.pool.query(`INSERT INTO executions(id,actor_id,creator_id,owner_id,state,wait,snapshot,expires_at,created_at)
      VALUES($1,$2,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO NOTHING`, [job.id, job.actorId, job.ownerId, state,
      state === 'running' ? 'execution' : null, await this.vault.encrypt(snapshot, 'operation-execution:' + job.id),
      'intent' in job ? job.intent.expiresAt : new Date(Date.now() + 86_400_000), job.createdAt]);
  }
  async importRuntimeHistory() {
    if (await this.db.one("SELECT 1 FROM schema_migrations WHERE name='unified-execution-history'")) return;
    const jobs = await this.db.all<{ id: string; actor_id: string }>(`SELECT id,actor_id FROM execution_tasks
      WHERE request->'intent'->'operationContext' IS NULL AND NOT EXISTS(SELECT 1 FROM executions e WHERE e.id=execution_tasks.id)`);
    for (const job of jobs) await this.recordRuntime('run', await this.runtime.get({ id: job.actor_id }, { kind: 'run', id: job.id }));
    const functions = await this.db.all<{ id: string; actor_id: string }>(`SELECT id,actor_id FROM function_invocations f
      WHERE NOT EXISTS(SELECT 1 FROM executions e WHERE e.id=f.id)`);
    const roots = await this.db.all<{ id: string; snapshot: string }>('SELECT id,snapshot FROM executions');
    const included = new Set<string>();
    for (const row of roots) {
      const snapshot = await this.vault.decrypt<Snapshot>(row.snapshot, 'operation-execution:' + row.id);
      for (const operation of snapshot.operations)
        if (operation.name === 'function.invoke' && typeof operation.input.id === 'string') included.add(operation.input.id);
      for (const result of snapshot.results)
        if (result && typeof result === 'object' && !Array.isArray(result) && typeof result.id === 'string') included.add(result.id);
      const owner = snapshot.operations.map(operation => operation.input.ownerId).find(value => Id.safeParse(value).success);
      if (owner) await this.db.pool.query('UPDATE executions SET owner_id=$2 WHERE id=$1 AND owner_id IS NULL AND EXISTS(SELECT 1 FROM principals WHERE id=$2)', [row.id, owner]);
    }
    for (const job of functions) {
      if (!included.has(job.id)) await this.recordRuntime('function', await this.runtime.get({ id: job.actor_id }, { kind: 'function', id: job.id }));
    }
    await this.db.pool.query('UPDATE executions SET owner_id=creator_id WHERE owner_id IS NULL');
    await this.db.pool.query("INSERT INTO schema_migrations(name) VALUES('unified-execution-history') ON CONFLICT DO NOTHING");
  }
  async plan(id: string, actor: Actor, operations: DefinitionCall[], expiresAt: Date, results?: Array<JsonValue | null>,
    response?: { responderId?: string; message: string; code?: string; pending?: boolean; deliver?: boolean }, submissionDigest: string | null = null) {
    const index = results ? results.findIndex(result => result === null || (typeof result === 'object' && !Array.isArray(result) &&
      ('error' in result || 'pending' in result))) : 0;
    const snapshot: Snapshot = { actor: this.authority(actor), creatorActor: this.authority(actor), agreementIndex: null, responders: [], submissionDigest, operations: operations.map(operation => Operation.parse(operation)),
      index: index < 0 ? operations.length : index, results: results ?? operations.map(() => null),
      proofs: operations.map(() => null), inFlight: null, continuation: null };
    await this.db.pool.query(
      `INSERT INTO executions(id,actor_id,creator_id,responder_id,message,code_hash,response,state,wait,snapshot,expires_at)
       VALUES($1,$2,$2,$3,$4,$5,$6,'waiting','approval',$7,$8) ON CONFLICT(id) DO NOTHING`,
      [id, actor.id, response?.responderId ?? null, response?.message ?? '', response?.code ? digest(response.code) : null,
        response && response.pending !== false ? 'pending' : 'none', await this.vault.encrypt(snapshot, 'operation-execution:' + id), expiresAt]);
    if (submissionDigest) {
      const saved = await this.row(id);
      if (saved.creator_id !== actor.id || (await this.read(saved)).submissionDigest !== submissionDigest)
        fail(409, 'execution_conflict', 'Use a new execution ID for different operations.');
    }
    if (response && response.pending !== false && response.deliver !== false && (response.responderId || response.code))
      await deliverExecution(this.db.pool, { executionId: id, fromId: actor.id, toId: response.responderId ?? null,
        message: response.message, purpose: 'input', expiresAt });
    const owner = operations.map(operation => operation.input.ownerId).find(value => Id.safeParse(value).success);
    await this.db.pool.query('UPDATE executions SET owner_id=COALESCE(owner_id,(SELECT id FROM principals WHERE id=$2),creator_id) WHERE id=$1', [id, owner ?? actor.id]);
  }
  private bootstrap(actorId: string, operations: RequestedOperation[]) {
    const operation = operations[0], body = operation?.input;
    return operations.length === 1 && operation?.name === 'relation.draw' &&
      (body?.subjectId === actorId || body?.subjectId === '$requester') && body.relation === 'agent' &&
      body.objectId === '$approver' && Object.keys(body).length === 3 && operation.inputs.length === 0;
  }
  async create(actor: Actor, input: z.infer<typeof ExecutionInput>, invitation = false) {
    if (actor.requestId) fail(403, 'forbidden', 'Sign in to prepare a new operation.');
    await this.authorization.active(actor);
    const submissionDigest = await hash({ operations: input.operations, responderId: input.responderId ?? null,
      message: input.message, expiresInMinutes: input.expiresInMinutes, invitation });
    if (input.id && await this.db.one('SELECT 1 FROM executions WHERE id=$1', [input.id])) {
      const saved = await this.row(input.id);
      if (saved.creator_id !== actor.id || (await this.read(saved)).submissionDigest !== submissionDigest)
        fail(409, 'execution_conflict', 'Use a new execution ID for different operations.');
      return this.get(actor, input.id);
    }
    for (const operation of input.operations) {
      const definition = this.definitions.get(operation.name);
      for (const field of operation.inputs) {
        if (field.secret && !definition.secret(field.pointer)) fail(400, 'encrypted_input_required', 'Choose an operation that encrypts this input.');
        try { if (atPointer(operation.input, field.pointer) === undefined) throw new Error(); }
        catch { fail(400, 'invalid_pointer', 'Place each requested field in the operation input.'); }
      }
      if (definition.execution === 'keyholder' && ['value', 'clientSecret'].some(key => operation.input[key] !== undefined && operation.input[key] !== ''))
        fail(400, 'encrypted_input_required', 'Supply private material directly with your encryption keys.');
      if (definition.review) operation.input = await definition.review(actor, operation.input);
    }
    if (input.responderId) await this.principals.get(input.responderId);
    if (invitation && (input.responderId || !this.bootstrap(actor.id, input.operations))) fail(400, 'recipient_required', 'Choose who should handle this operation.');
    const requiresResponse = !!input.responderId || invitation || input.operations.some(operation => operation.inputs.some(field => !field.secret));
    if (!requiresResponse) return this.start(actor, input.operations, { id: input.id, expiresAt: new Date(Date.now() + input.expiresInMinutes * 60_000), message: input.message, submissionDigest });
    const pending = await this.db.one<{ count: string }>("SELECT count(*) FROM executions WHERE creator_id=$1 AND state IN ('waiting','running') AND response='pending' AND expires_at>now()", [actor.id]);
    if (Number(pending?.count) >= 20) fail(429, 'request_limit', 'Wait for an existing operation to finish.');
    const alphabet = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
    const code = invitation ? Array.from({ length: 8 }, () => alphabet[randomInt(alphabet.length)]).join('') : undefined;
    const id = input.id ?? randomUUID();
    await this.plan(id, actor, input.operations, new Date(Date.now() + input.expiresInMinutes * 60_000), undefined,
      { responderId: input.responderId ?? (invitation ? undefined : actor.id), message: input.message, code,
        deliver: !!input.responderId || invitation }, submissionDigest);
    return { ...await this.get(actor, id), ...(code ? { code } : {}) };
  }
  async deliver(actor: Actor, id: string, to: string, message: string, expiresInMinutes: number) {
    await this.principals.get(to);
    return this.locked(id, async () => {
      const row = await this.row(id), snapshot = await this.read(row);
      await this.authorization.active(actor);
      if (actor.requestId || row.creator_id !== actor.id || row.state !== 'waiting' || row.wait !== 'input' || snapshot.continuation)
        fail(409, 'execution_changed', 'Send a request for an execution awaiting input.');
      const expiresAt = new Date(Math.min(row.expires_at.getTime(), Date.now() + expiresInMinutes * 60_000));
      if (expiresAt.getTime() <= Date.now()) fail(409, 'execution_expired', 'This execution has expired.');
      return this.db.transaction(async connection => {
        await connection.query("UPDATE executions SET responder_id=$2,message=$3,response='pending',state='waiting',wait='approval',expires_at=$4,revision=revision+1 WHERE id=$1",
          [id, to, message, expiresAt]);
        return deliverExecution(connection, { executionId: id, fromId: actor.id, toId: to, message, purpose: 'input', expiresAt });
      });
    });
  }
  private substitute(value: JsonValue, responder: string, creator: string): JsonValue {
    if (value === '$approver') return responder;
    if (value === '$requester') return creator;
    if (Array.isArray(value)) return value.map(child => this.substitute(child, responder, creator));
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, this.substitute(child, responder, creator)]));
    return value;
  }
  async respond(actor: Actor, id: string, values: Array<Record<string, JsonValue>> = [], code?: string,
    configuration: Array<Record<string, JsonValue>> = []) {
    const row = await this.expire(await this.row(id)), previous = await this.read(row);
    if (!(await this.canRespond(actor, row))) fail(403, 'forbidden', 'This operation is addressed to another principal.');
    if (row.response !== 'pending') fail(409, 'execution_changed', 'This operation is already being handled.');
    if (row.code_hash) {
      const attempted = await this.db.one('UPDATE executions SET attempts=attempts+1 WHERE id=$1 AND attempts<5 RETURNING attempts', [id]);
      if (!attempted || digest((code ?? '').replaceAll('-', '').toUpperCase()) !== row.code_hash) fail(400, 'invalid_code', 'Enter the code shown by the requesting device.');
    }
    const effectiveId = actor.requestId ? required(row.responder_id) : actor.id;
    const effectiveActor: Actor = row.proposal ? { ...previous.creatorActor, agreedBy: effectiveId, approvalId: id }
      : { id: effectiveId, ...(actor.credentialId ? { credentialId: actor.credentialId } : {}), approvalId: id };
    const filled = await Promise.all(previous.operations.map(async (operation, index) => {
      if (index < previous.index) return operation;
      const current = structuredClone(operation), supplied = values[index] ?? {};
      if (Object.keys(supplied).some(pointer => !operation.inputs.some(field => field.pointer === pointer && !field.secret)))
        fail(400, 'unexpected_input', 'Only provide the fields this operation asks for.');
      for (const field of operation.inputs.filter(field => !field.secret)) {
        if (supplied[field.pointer] === undefined) fail(400, 'missing_input', 'Complete the requested fields.');
        try { setPointer(current.input, field.pointer, supplied[field.pointer]!); }
        catch { fail(400, 'invalid_pointer', 'The requested input target was not found.'); }
      }
      if (row.proposal && (Object.keys(supplied).length || Object.keys(configuration[index] ?? {}).length))
        fail(400, 'operation_changed', 'Approve the change exactly as it was proposed.');
      if (!row.proposal) current.input = this.substitute(current.input, effectiveId, row.creator_id) as Record<string, JsonValue>;
      const configured = Object.keys(configuration[index] ?? {}).length ? this.definitions.configure(current, configuration[index]!) : current;
      const prepared = await this.definitions.prepareFor(row.proposal ? previous.creatorActor : actor, configured);
      return { ...current, ...prepared.invocation };
    }));
    await this.db.transaction(async connection => {
      await this.authorization.active(actor, connection);
      await this.authorize(effectiveActor, id, filled, connection);
      if (row.code_hash) {
        await connection.query('SELECT pg_advisory_xact_lock(736023743)');
        const device = await this.principals.get(row.creator_id, connection);
        if (device.owner_id || await this.authorization.holds(row.creator_id, principal(effectiveId), 'stands', connection))
          fail(409, 'already_owned', 'This device has already been taken on.');
        await connection.query('UPDATE principals SET owner_id=$2 WHERE id=$1', [row.creator_id, effectiveId]);
        await connection.query('UPDATE executions SET responder_id=$2,code_hash=NULL WHERE id=$1', [id, effectiveId]);
      }
    });
    try { await this.start(effectiveActor, filled, { id, expiresAt: row.expires_at }); }
    catch (error) { if (!(error && typeof error === 'object' && 'code' in error && error.code === 'execution_busy')) throw error; }
    await this.audit.record(row.creator_id, effectiveId, 'operation.respond', id, {});
    return this.get(actor, id);
  }
  async authorize(actor: Actor, id: string, operations: DefinitionCall[], connection: Queryable) {
    const row = required(await this.db.one<ExecutionRow>('SELECT * FROM executions WHERE id=$1 FOR UPDATE', [id], connection));
    const previous = await this.read(row);
    if (row.expires_at.getTime() <= Date.now()) fail(409, 'execution_expired', 'This operation has expired.');
    if (previous.inFlight !== null || row.state === 'uncertain')
      fail(409, 'execution_uncertain', 'Check the result before starting this operation again.');
    if ((row.state !== 'waiting' || row.wait !== 'approval') && row.state !== 'failed')
      fail(409, 'execution_changed', 'This operation is already being handled.');
    if (row.lease_until && row.lease_until.getTime() > Date.now()) fail(409, 'execution_busy', 'This operation is in progress.');
    const snapshot: Snapshot = { ...previous, actor: this.authority(actor), continuation: null,
      agreementIndex: row.proposal ? previous.index : null,
      responders: [...new Set([...previous.responders, actor.agreedBy ?? actor.id])],
      operations: operations.map((operation, index) => index < previous.index ? previous.operations[index]! : { ...previous.operations[index]!, ...operation }) };
    await connection.query("UPDATE executions SET actor_id=$2,snapshot=$3,state='running',wait=NULL,response='accepted',revision=revision+1 WHERE id=$1",
      [id, actor.id, await this.vault.encrypt(snapshot, 'operation-execution:' + id)]);
    await connection.query("UPDATE requests SET state='accepted',answered_at=now(),to_id=COALESCE(to_id,$2) WHERE execution_id=$1 AND state='pending'",
      [id, actor.agreedBy ?? actor.id]);
  }
  async revoke(id: string, connection: Queryable) {
    const row = await this.db.one<ExecutionRow>('SELECT * FROM executions WHERE id=$1 FOR UPDATE', [id], connection);
    await connection.query(
      `UPDATE execution_tasks SET cancel_requested=true,
       state=CASE WHEN phase='dispatched' THEN 'uncertain' ELSE 'cancelled' END,
       error=CASE WHEN phase='dispatched' THEN 'approval_cancelled' ELSE NULL END,
       finished_at=now(),lease_until=NULL
       WHERE (request->'intent'->'approval'->>'id'=$1 OR request->'intent'->'operationContext'->>'id'=$1) AND state IN ('queued','running')`, [id]);
    if (!row || ['succeeded', 'cancelled'].includes(row.state)) return;
    const snapshot = await this.read(row);
    if (snapshot.runtime) {
      const job = await this.runtime.cancel(snapshot.actor, snapshot.runtime);
      await connection.query('UPDATE executions SET state=$2,wait=NULL,revision=revision+1 WHERE id=$1',
        [id, job.state === 'succeeded' ? 'succeeded' : job.state === 'running' ? 'running' : job.state === 'uncertain' ? 'uncertain' : 'cancelled']);
      return;
    }
    const current = snapshot.operations[snapshot.index], result = snapshot.results[snapshot.index];
    const cancelled = current && result && row.wait === 'execution'
      ? await this.definitions.get(current.name).cancel?.({ id: snapshot.actor.id }, result) : null;
    const unknown = cancelled && typeof cancelled === 'object' && 'state' in cancelled && cancelled.state === 'uncertain' ||
      row.state === 'uncertain' || snapshot.inFlight !== null || await this.db.one(
      "SELECT 1 FROM execution_tasks WHERE (request->'intent'->'approval'->>'id'=$1 OR request->'intent'->'operationContext'->>'id'=$1) AND state='uncertain' LIMIT 1", [id], connection);
    if (current) snapshot.results[snapshot.index] = cancelled ? Json.parse(cancelled) : { state: unknown ? 'uncertain' : 'cancelled' };
    await connection.query('UPDATE executions SET state=$2,wait=NULL,snapshot=$3,revision=revision+1 WHERE id=$1',
      [id, unknown ? 'uncertain' : 'cancelled', await this.vault.encrypt(snapshot, 'operation-execution:' + id)]);
  }
  async cancel(actor: Actor, id: string, decline = false) {
    const item = await this.get(actor, id, false);
    if (decline ? !item.canContinue : !item.canCancel) fail(403, 'forbidden', 'You cannot cancel this execution.');
    await this.db.transaction(async connection => {
      await this.revoke(id, connection);
      await connection.query("UPDATE executions SET response=$2 WHERE id=$1 AND state IN ('cancelled','uncertain')",
        [id, decline ? 'declined' : 'cancelled']);
      await connection.query("UPDATE requests SET state=$2,answered_at=now() WHERE execution_id=$1 AND state='pending'",
        [id, decline ? 'declined' : 'cancelled']);
    });
    return this.get(actor, id);
  }
  private async locked<T>(id: string, action: () => Promise<T>) {
    const lease = randomUUID();
    const claimed = await this.db.pool.query(
      "UPDATE executions SET lease_token=$2,lease_until=now()+interval '90 seconds' WHERE id=$1 AND (lease_until IS NULL OR lease_until<now())", [id, lease]);
    if (!claimed.rowCount) fail(409, 'execution_busy', 'This operation is already being continued.');
    const renewal = setInterval(() => {
      void this.db.pool.query("UPDATE executions SET lease_until=now()+interval '90 seconds' WHERE id=$1 AND lease_token=$2", [id, lease]).catch(() => {});
    }, 15_000);
    renewal.unref();
    try {
      return await action();
    } finally {
      clearInterval(renewal);
      await this.db.pool.query('UPDATE executions SET lease_token=NULL,lease_until=NULL WHERE id=$1 AND lease_token=$2', [id, lease]);
    }
  }
  private async recover(row: ExecutionRow) {
    if (!['running', 'uncertain'].includes(row.state) || (row.lease_until && row.lease_until.getTime() > Date.now())) return row;
    const initial = await this.read(row);
    if (row.state === 'uncertain' && !initial.runtime && !this.definitions.get(initial.operations[initial.index]!.name).observe) return row;
    try {
      return await this.locked(row.id, async () => {
        const current = await this.row(row.id), saved = await this.read(current);
        if (saved.runtime) {
          const job = await this.runtime.get(saved.actor, saved.runtime);
          saved.results[0] = Json.parse('intent' in job ? { kind: 'run', id: job.id } : job);
          saved.index = job.state === 'succeeded' ? 1 : 0;
          await this.save(current, saved, job.state === 'queued' ? 'running' : job.state,
            ['queued', 'running'].includes(job.state) ? 'execution' : null);
        } else if (current.state === 'uncertain') {
          const definition = this.definitions.get(saved.operations[saved.index]!.name);
          const observed = await definition.observe!({ id: saved.actor.id }, required(saved.results[saved.index]));
          saved.results[saved.index] = observed.result;
          if (observed.state !== 'pending') {
            if (observed.state === 'succeeded') saved.index++;
            await this.save(current, saved, observed.state === 'succeeded' && saved.index < saved.operations.length ? 'running' : observed.state);
            if (observed.state === 'succeeded' && saved.index < saved.operations.length) await this.resume(current, saved);
          }
        } else if (current.state === 'running' && saved.inFlight !== null) {
          saved.results[saved.inFlight] = { error: { code: 'execution_uncertain', message: 'Check the result before starting this operation again.' } };
          await this.save(current, saved, 'uncertain');
        } else if (current.state === 'running') await this.resume(current, saved);
        return current;
      });
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'execution_busy') return this.row(row.id);
      throw error;
    }
  }
  private async save(row: ExecutionRow, snapshot: Snapshot, state: ExecutionRow['state'], wait: ExecutionRow['wait'] = null, connection?: Queryable) {
    const encrypted = await this.vault.encrypt(snapshot, 'operation-execution:' + row.id);
    const owner = snapshot.operations.map(operation => operation.input.ownerId).find(value => Id.safeParse(value).success);
    const persist = async (connection: Queryable) => {
      const updated = await connection.query(
        'UPDATE executions SET snapshot=$2,state=$3,wait=$4,revision=revision+1,actor_id=$7 WHERE id=$1 AND revision=$5 AND lease_token=$6 AND lease_until>now()',
        [row.id, encrypted, state, wait, row.revision, row.lease_token, snapshot.actor.id]);
      if (!updated.rowCount) fail(409, 'execution_changed', 'Reload this operation before continuing.');
      await connection.query('UPDATE executions SET responder_id=$2,proposal=$3,response=$4 WHERE id=$1',
        [row.id, row.responder_id, row.proposal ? JSON.stringify(row.proposal) : null, row.response]);
      if (owner) {
        const saved = await connection.query<{ owner_id: string }>('UPDATE executions SET owner_id=COALESCE((SELECT id FROM principals WHERE id=$2),owner_id,creator_id) WHERE id=$1 RETURNING owner_id', [row.id, owner]);
        row.owner_id = saved.rows[0]!.owner_id;
      }
    };
    if (connection) await persist(connection); else await this.db.transaction(persist);
    row.revision++; row.state = state; row.wait = wait; row.actor_id = snapshot.actor.id; row.snapshot = encrypted;
  }

  async start(actor: Actor, operations: DefinitionCall[], options: { id?: string; expiresAt?: Date; results?: Array<JsonValue | null>; message?: string; submissionDigest?: string } = {}) {
    const id = options.id ?? randomUUID();
    await this.plan(id, actor, operations, options.expiresAt ?? new Date(Date.now() + 86_400_000), options.results,
      options.message ? { message: options.message, pending: false } : undefined, options.submissionDigest);
    return this.locked(id, async () => {
      const row = await this.row(id), previous = await this.read(row);
      if (previous.runtime) fail(409, 'execution_changed', 'Follow the recorded execution to its result.');
      if (row.state === 'succeeded') return this.view(row, previous);
      if (row.state === 'cancelled') fail(409, 'cancelled', 'This operation was cancelled.');
      if (previous.inFlight !== null && row.state !== 'uncertain') await this.save(row, previous, 'uncertain');
      if (row.state === 'uncertain')
        fail(409, 'execution_uncertain', 'Check the last operation before starting it again.');
      if (row.state === 'waiting' && row.wait === 'input') return this.view(row, previous);
      let prepared: DefinitionCall[];
      try {
        prepared = await Promise.all(operations.map(async (operation, index) => index < previous.index ? previous.operations[index]!
          : { ...previous.operations[index]!, ...(await this.definitions.prepareFor(actor, operation)).invocation }));
      } catch (error) {
        const fault = failure(error);
        previous.actor = this.authority(actor);
        previous.results[previous.index] = { error: { code: fault.code, message: fault.message } };
        await this.save(row, previous, 'failed'); throw fault;
      }
      const snapshot: Snapshot = { ...previous, actor: this.authority(actor), operations: prepared.map(operation => Operation.parse(operation)), continuation: null };
      await this.save(row, snapshot, 'running');
      return this.resume(row, snapshot);
    });
  }
  async retry(actor: Actor, id: string) {
    const item = await this.get(actor, id, false), row = await this.row(id), snapshot = await this.read(row);
    if (actor.requestId || actor.id !== row.actor_id || !item.canContinue || row.state !== 'failed')
      fail(409, 'execution_changed', 'Continue a failed execution with the identity handling it.');
    return this.start(snapshot.actor, snapshot.operations, { id, expiresAt: row.expires_at });
  }
  private async active(row: ExecutionRow, snapshot: Snapshot) {
    if (row.expires_at.getTime() <= Date.now()) fail(409, 'execution_expired', 'This operation has expired.');
    await this.authorization.active(snapshot.actor);
  }
  private async resume(row: ExecutionRow, snapshot: Snapshot): Promise<ExecutionView> {
    for (; snapshot.index < snapshot.operations.length; snapshot.index++) {
      try { await this.active(row, snapshot); }
      catch (error) {
        const fault = failure(error);
        snapshot.results[snapshot.index] = { error: { code: fault.code, message: fault.message } };
        await this.save(row, snapshot, 'failed'); throw fault;
      }
      const operation = snapshot.operations[snapshot.index]!, definition = this.definitions.get(operation.name);
      if (definition.execution === 'keyholder') {
        if (snapshot.continuation) {
          const task = await this.db.one<{ id: string; state: string; resource_id: string | null }>(`SELECT t.id,t.state,c.resource_id
            FROM execution_tasks t LEFT JOIN resource_custody c ON c.content->>'creationRunId'=t.id::text
            WHERE t.request->'intent'->'operationContext'->>'id'=$1 AND t.request->'intent'->'operationContext'->>'index'=$2
            ORDER BY t.created_at DESC LIMIT 1`, [row.id, String(snapshot.index)]);
          if (task && ['queued', 'running'].includes(task.state)) {
            await this.save(row, snapshot, 'running', 'execution');
            return this.view(row, snapshot);
          }
          if (task && (snapshot.continuation.kind === 'run' || task.resource_id)) {
            try { return await this.finishInput(row, snapshot, task.resource_id ? { runId: task.id, resourceId: task.resource_id } : { runId: task.id }); }
            catch (error) { if (error instanceof OperationFailed) return this.view(row, snapshot); throw error; }
          }
        }
        snapshot.results[snapshot.index] = { pending: true };
        await this.save(row, snapshot, 'waiting', 'input');
        return this.view(row, snapshot);
      }
      if (row.wait === 'execution' && definition.observe) {
        const observed = await definition.observe(snapshot.actor, required(snapshot.results[snapshot.index]));
        snapshot.results[snapshot.index] = observed.result;
        if (observed.state === 'pending') {
          await this.save(row, snapshot, 'running', 'execution');
          return this.view(row, snapshot);
        }
        if (observed.state !== 'succeeded') {
          await this.save(row, snapshot, observed.state);
          return this.view(row, snapshot);
        }
        snapshot.index++;
        await this.save(row, snapshot, snapshot.index === snapshot.operations.length ? 'succeeded' : 'running');
        return this.resume(row, snapshot);
      }
      snapshot.inFlight = snapshot.index;
      await this.save(row, snapshot, 'running');
      try {
        snapshot.results[snapshot.index] = await this.definitions.execute(this.operationActor(snapshot), operation);
      } catch (error) {
        snapshot.inFlight = null;
        if (error instanceof AgreementNeeded && !this.operationActor(snapshot).approvalId) {
          row.responder_id = error.to; row.proposal = error.proposed; row.response = 'pending';
          snapshot.actor = this.authority(snapshot.creatorActor); snapshot.agreementIndex = null;
          await this.save(row, snapshot, 'waiting', 'approval');
          await deliverExecution(this.db.pool, { executionId: row.id, fromId: row.creator_id, toId: row.responder_id,
            message: row.message, purpose: 'approval', expiresAt: row.expires_at });
          return this.view(row, snapshot);
        }
        const fault = failure(error);
        snapshot.results[snapshot.index] = { error: { code: fault.code, message: fault.message } };
        await this.save(row, snapshot, 'failed'); throw fault;
      }
      snapshot.inFlight = null;
      if (definition.observe) {
        await this.save(row, snapshot, 'running', 'execution');
        return this.resume(row, snapshot);
      }
      const next = { ...snapshot, index: snapshot.index + 1 };
      await this.save(row, next, next.index === snapshot.operations.length ? 'succeeded' : 'running');
    }
    await this.save(row, snapshot, 'succeeded');
    return this.view(row, snapshot);
  }
  async input(actor: Actor, id: string) {
    const row = await this.recover(await this.row(id)), snapshot = await this.read(row);
    if (actor.requestId || row.actor_id !== actor.id) fail(403, 'forbidden', 'Sign in with the identity handling this operation.');
    await this.authorization.active(actor);
    await this.active(row, snapshot);
    if (row.state === 'uncertain') fail(409, 'execution_uncertain', 'Check the result before starting this operation again.');
    if (!(row.state === 'waiting' && row.wait === 'input' || row.state === 'running' && row.wait === 'execution' && snapshot.continuation))
      fail(409, 'execution_changed', 'This execution is no longer awaiting input.');
    return { row, snapshot, plan: required((await this.view(row, snapshot, actor)).waiting) };
  }
  async track(actor: Actor, id: string, index: number, continuation: NonNullable<OperationWaiting['continuation']>) {
    return this.locked(id, async () => {
      const { row, snapshot, plan } = await this.input(actor, id);
      if ((plan.invocation.name !== 'connection.connect' || continuation.kind !== 'connection') &&
        (!['run.execute', 'connection.revoke'].includes(plan.invocation.name) || continuation.kind !== 'run'))
        fail(400, 'invalid_continuation', 'Continue the operation that is awaiting input.');
      if (plan.index !== index || (snapshot.continuation && JSON.stringify(snapshot.continuation) !== JSON.stringify(continuation)))
        fail(409, 'execution_changed', 'Continue the operation already in progress.');
      snapshot.continuation = continuation;
      await this.save(row, snapshot, 'waiting', 'input');
      return this.view(row, snapshot);
    });
  }
  async configure(actor: Actor, id: string, index: number, values: Record<string, JsonValue>) {
    return this.locked(id, async () => {
      const { row, snapshot, plan } = await this.input(actor, id);
      if (plan.index !== index || snapshot.continuation) fail(409, 'execution_changed', 'Continue the operation already in progress.');
      const prepared = await this.definitions.prepareFor(actor, this.definitions.configure(plan.invocation, values));
      snapshot.operations[index] = { ...snapshot.operations[index]!, ...prepared.invocation };
      await this.save(row, snapshot, 'waiting', 'input');
      return this.view(row, snapshot);
    });
  }
  async prepareInput(actor: Actor, id: string, index: number, proof: JsonValue) {
    return this.locked(id, async () => {
      const saved = await this.row(id), previous = await this.read(saved), proofDigest = await hash(proof);
      await this.authorization.active(actor);
      if (saved.actor_id !== actor.id || actor.requestId) fail(403, 'forbidden', 'Use the identity handling this execution.');
      if (previous.preparations?.some(item => item.index === index && item.digest === proofDigest))
        return this.view(saved, previous, actor);
      const { row, snapshot, plan } = await this.input(actor, id);
      if (plan.index !== index || snapshot.continuation) fail(409, 'execution_changed', 'Continue the execution already in progress.');
      const definition = this.definitions.get(plan.invocation.name), prepare = required(definition.prepareInput);
      await this.db.transaction(async connection => {
        const input = await prepare(this.operationActor(snapshot), plan.invocation.input, proof, connection);
        snapshot.operations[index] = { ...snapshot.operations[index]!, ...this.definitions.prepare({ name: plan.invocation.name, input }).invocation };
        snapshot.preparations = [...snapshot.preparations ?? [], { index, digest: proofDigest }];
        await this.save(row, snapshot, 'waiting', 'input', connection);
      });
      return this.view(row, snapshot, actor);
    });
  }
  async complete(actor: Actor, id: string, index: number, proof: JsonValue) {
    return this.locked(id, async () => {
      const row = await this.row(id), snapshot = await this.read(row), proofDigest = await hash(proof);
      if (row.actor_id !== actor.id || actor.requestId) fail(403, 'forbidden', 'Use the identity handling this operation.');
      if (index < snapshot.index && snapshot.proofs[index] === proofDigest) return this.view(row, snapshot);
      await this.active(row, snapshot);
      if (!(row.state === 'waiting' && row.wait === 'input' || row.state === 'running' && row.wait === 'execution' && snapshot.continuation) || index !== snapshot.index)
        fail(409, 'execution_changed', 'This operation is no longer awaiting that input.');
      return this.finishInput(row, snapshot, proof);
    });
  }
  private async finishInput(row: ExecutionRow, snapshot: Snapshot, proof: JsonValue) {
      const id = row.id, index = snapshot.index, proofDigest = await hash(proof);
      const operation = snapshot.operations[index]!, definition = this.definitions.get(operation.name);
      const complete = required(definition.complete, 'This operation does not accept client completion.');
      snapshot.inFlight = index;
      await this.save(row, snapshot, 'running');
      try {
        snapshot.results[index] = await complete(this.operationActor(snapshot), operation.input, proof, { id, index });
      } catch (error) {
        snapshot.inFlight = null;
        if (error instanceof OperationFailed) {
          snapshot.results[index] = { error: { code: error.code, message: error.message }, result: error.result };
          snapshot.continuation = null;
          await this.save(row, snapshot, error.uncertain ? 'uncertain' : 'failed'); throw error;
        }
        await this.save(row, snapshot, 'waiting', 'input'); throw error;
      }
      snapshot.inFlight = null; snapshot.proofs[index] = proofDigest;
      snapshot.index++; snapshot.continuation = null;
      await this.save(row, snapshot, 'running');
      return this.resume(row, snapshot);
  }
}
