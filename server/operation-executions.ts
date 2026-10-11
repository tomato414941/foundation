import { randomInt, randomUUID } from 'node:crypto';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor, Authorization } from './authorization.js';
import { principal } from './authorization.js';
import type { Principals } from './principals.js';
import { digest } from './vault.js';
import { atPointer, setPointer } from '../shared/values.js';
import { Json, Operation } from '../shared/contracts.js';
import type { RequestedOperation } from '../shared/contracts.js';
import type { Proposed } from './relations.js';
import type { z } from 'zod';
import { ExecutionInput } from '../shared/operations.js';
import type { Vault } from './vault.js';
import { fail, failure, required } from './errors.js';
import { AgreementNeeded } from './relations.js';
import type { Audit } from './audit.js';
import type { OperationRegistry } from './operations.js';
import { OperationFailed } from './operations.js';
import { hash } from '../shared/authority.js';
import { OperationExecution } from '../shared/operations.js';
import type { OperationInvocation, OperationExecutionView, OperationWaiting } from '../shared/operations.js';
import type { JsonValue } from '../shared/contracts.js';

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
}
interface ExecutionRow {
  id: string; actor_id: string; creator_id: string; responder_id: string | null; message: string;
  proposal: Proposed | null; code_hash: string | null; attempts: number; response: OperationExecutionView['response'];
  state: OperationExecutionView['state']; wait: OperationExecutionView['wait'];
  snapshot: string; revision: number; lease_token: string | null; lease_until: Date | null; expires_at: Date; created_at: Date;
}
// One persisted execution mechanism serves direct calls and calls awaiting a person's response.
export class OperationExecutions {
  constructor(readonly db: Database, readonly vault: Vault, readonly authorization: Authorization,
    readonly operations: OperationRegistry, readonly audit: Audit, readonly principals: Principals, readonly origin: string) {}
  private async row(id: string) {
    return required(await this.db.one<ExecutionRow>('SELECT * FROM operation_executions WHERE id=$1', [id]));
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
    if (actor.requestId) return actor.requestId === row.id && actor.id === row.responder_id;
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
  private async view(row: ExecutionRow, snapshot: Snapshot, actor: Actor | null = { id: snapshot.actor.id }): Promise<OperationExecutionView> {
    const [creator, responder, canRespond, proposal] = await Promise.all([this.principals.get(row.creator_id),
      row.responder_id ? this.principals.get(row.responder_id) : null, this.canRespond(actor, row), this.proposal(row.proposal)]);
    return OperationExecution.parse({ id: row.id, actorId: row.actor_id, creator: { id: creator.id, name: creator.name },
      responder: responder ? { id: responder.id, name: responder.name } : null, message: row.message, proposal,
      response: row.response, canRespond, canCancel: !!actor && !actor.requestId && [row.creator_id, row.actor_id].includes(actor.id),
      url: this.origin + '/operations/' + row.id,
      operations: snapshot.operations.map(operation => ({ ...operation, title: this.operations.describe(operation),
        execution: this.operations.get(operation.name).execution, configure: [...this.operations.get(operation.name).configure] })),
      index: snapshot.index, state: row.state, wait: row.wait,
      waiting: row.wait === 'input' && canRespond && (actor?.id === row.actor_id || actor?.requestId === row.id)
        ? { index: snapshot.index, invocation: { name: snapshot.operations[snapshot.index]!.name, input: snapshot.operations[snapshot.index]!.input },
          continuation: snapshot.continuation, ...(this.operationActor(snapshot).approvalId ? { approval: { id: snapshot.actor.approvalId!, index: snapshot.index } } : {}) } : null,
      results: snapshot.results, createdAt: iso(row.created_at), expiresAt: iso(row.expires_at) });
  }
  private async expire(row: ExecutionRow) {
    if (row.expires_at.getTime() > Date.now() || !['waiting', 'running', 'failed'].includes(row.state)) return row;
    await this.db.transaction(async connection => {
      await this.revoke(row.id, connection);
      await connection.query("UPDATE operation_executions SET response='expired' WHERE id=$1", [row.id]);
    });
    return this.row(row.id);
  }
  async expireAll() {
    const rows = await this.db.all<ExecutionRow>("SELECT * FROM operation_executions WHERE expires_at<=now() AND state IN ('waiting','running','failed')");
    for (const row of rows) await this.expire(row);
  }
  async peek(id: string) {
    const row = await this.db.one<ExecutionRow>('SELECT * FROM operation_executions WHERE id=$1', [id]);
    if (!row) return null;
    const current = await this.recover(await this.expire(row));
    return this.view(current, await this.read(current));
  }
  async get(actor: Actor | null, id: string, resume = true) {
    const row = await this.expire(await this.row(id));
    const snapshot = await this.read(row);
    if (actor) await this.authorization.active(actor);
    if (actor?.requestId && actor.requestId !== id) fail(403, 'forbidden', 'This link can open only its own operation.');
    const publicJoin = row.code_hash && !row.responder_id;
    if (!publicJoin && (!actor || actor.requestId && actor.requestId !== id ||
      actor.id !== row.creator_id && actor.id !== row.actor_id && !snapshot.responders.includes(actor.id) && !(await this.canRespond(actor, row))))
      fail(403, 'forbidden', 'This operation belongs to another principal.');
    const current = resume ? await this.recover(row) : row;
    return this.view(current, await this.read(current), actor);
  }
  async list(actor: Actor, limit = 100, after?: string) {
    await this.authorization.active(actor);
    if (actor.requestId) fail(403, 'forbidden', 'This link can open only its own operation.');
    const represented = await this.authorization.find(actor.id, 'principal', 'stands');
    const rows = await this.db.all<{ id: string }>(`SELECT id FROM operation_executions
      WHERE (creator_id=$1 OR actor_id=$1 OR responder_id=ANY($2::uuid[])) AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4`,
      [actor.id, represented, after ?? null, limit + 1]);
    return { items: await Promise.all(rows.slice(0, limit).map(row => this.get(actor, row.id))), next: rows.length > limit ? rows[limit - 1]!.id : null };
  }
  async plan(id: string, actor: Actor, operations: OperationInvocation[], expiresAt: Date, results?: Array<JsonValue | null>,
    response?: { responderId?: string; message: string; code?: string; pending?: boolean }, submissionDigest: string | null = null) {
    const index = results ? results.findIndex(result => result === null || (typeof result === 'object' && !Array.isArray(result) &&
      ('error' in result || 'pending' in result))) : 0;
    const snapshot: Snapshot = { actor: this.authority(actor), creatorActor: this.authority(actor), agreementIndex: null, responders: [], submissionDigest, operations: operations.map(operation => Operation.parse(operation)),
      index: index < 0 ? operations.length : index, results: results ?? operations.map(() => null),
      proofs: operations.map(() => null), inFlight: null, continuation: null };
    await this.db.pool.query(
      `INSERT INTO operation_executions(id,actor_id,creator_id,responder_id,message,code_hash,response,state,wait,snapshot,expires_at)
       VALUES($1,$2,$2,$3,$4,$5,$6,'waiting','approval',$7,$8) ON CONFLICT(id) DO NOTHING`,
      [id, actor.id, response?.responderId ?? null, response?.message ?? '', response?.code ? digest(response.code) : null,
        response && response.pending !== false ? 'pending' : 'none', await this.vault.encrypt(snapshot, 'operation-execution:' + id), expiresAt]);
    if (submissionDigest) {
      const saved = await this.row(id);
      if (saved.creator_id !== actor.id || (await this.read(saved)).submissionDigest !== submissionDigest)
        fail(409, 'execution_conflict', 'Use a new execution ID for different operations.');
    }
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
    if (input.id && await this.db.one('SELECT 1 FROM operation_executions WHERE id=$1', [input.id])) {
      const saved = await this.row(input.id);
      if (saved.creator_id !== actor.id || (await this.read(saved)).submissionDigest !== submissionDigest)
        fail(409, 'execution_conflict', 'Use a new execution ID for different operations.');
      return this.get(actor, input.id);
    }
    for (const operation of input.operations) {
      const definition = this.operations.get(operation.name);
      for (const field of operation.inputs) {
        if (field.secret && !definition.secret(field.pointer)) fail(400, 'encrypted_input_required', 'Choose an operation that encrypts this input.');
        try { if (atPointer(operation.input, field.pointer) === undefined) throw new Error(); }
        catch { fail(400, 'invalid_pointer', 'Place each requested field in the operation input.'); }
      }
      if (definition.execution === 'keyholder' && (['value', 'clientSecret'].some(key => operation.input[key] !== undefined && operation.input[key] !== '') ||
        operation.input.fields && Object.values(operation.input.fields as Record<string, JsonValue>).some(value => value !== '')))
        fail(400, 'encrypted_input_required', 'Supply private material directly with your encryption keys.');
      if (definition.review) operation.input = await definition.review(actor, operation.input);
    }
    if (input.responderId) await this.principals.get(input.responderId);
    if (invitation && (input.responderId || !this.bootstrap(actor.id, input.operations))) fail(400, 'recipient_required', 'Choose who should handle this operation.');
    const requiresResponse = !!input.responderId || invitation || input.operations.some(operation => operation.inputs.some(field => !field.secret));
    if (!requiresResponse) return this.start(actor, input.operations, { id: input.id, expiresAt: new Date(Date.now() + input.expiresInMinutes * 60_000), message: input.message, submissionDigest });
    const pending = await this.db.one<{ count: string }>("SELECT count(*) FROM operation_executions WHERE creator_id=$1 AND state IN ('waiting','running') AND response='pending' AND expires_at>now()", [actor.id]);
    if (Number(pending?.count) >= 20) fail(429, 'request_limit', 'Wait for an existing operation to finish.');
    const alphabet = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
    const code = invitation ? Array.from({ length: 8 }, () => alphabet[randomInt(alphabet.length)]).join('') : undefined;
    const id = input.id ?? randomUUID();
    await this.plan(id, actor, input.operations, new Date(Date.now() + input.expiresInMinutes * 60_000), undefined,
      { responderId: input.responderId ?? (invitation ? undefined : actor.id), message: input.message, code }, submissionDigest);
    return { ...await this.get(actor, id), ...(code ? { code } : {}) };
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
      const attempted = await this.db.one('UPDATE operation_executions SET attempts=attempts+1 WHERE id=$1 AND attempts<5 RETURNING attempts', [id]);
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
      const configured = Object.keys(configuration[index] ?? {}).length ? this.operations.configure(current, configuration[index]!) : current;
      const prepared = await this.operations.prepareFor(row.proposal ? previous.creatorActor : actor, configured);
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
        await connection.query('UPDATE operation_executions SET responder_id=$2,code_hash=NULL WHERE id=$1', [id, effectiveId]);
      }
    });
    try { await this.start(effectiveActor, filled, { id, expiresAt: row.expires_at }); }
    catch (error) { if (!(error && typeof error === 'object' && 'code' in error && error.code === 'execution_busy')) throw error; }
    await this.audit.record(row.creator_id, effectiveId, 'operation.respond', id, {});
    return this.get(actor, id);
  }
  async authorize(actor: Actor, id: string, operations: OperationInvocation[], connection: Queryable) {
    const row = required(await this.db.one<ExecutionRow>('SELECT * FROM operation_executions WHERE id=$1 FOR UPDATE', [id], connection));
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
    await connection.query("UPDATE operation_executions SET actor_id=$2,snapshot=$3,state='running',wait=NULL,response='accepted',revision=revision+1 WHERE id=$1",
      [id, actor.id, await this.vault.encrypt(snapshot, 'operation-execution:' + id)]);
  }
  async revoke(id: string, connection: Queryable) {
    const row = await this.db.one<ExecutionRow>('SELECT * FROM operation_executions WHERE id=$1 FOR UPDATE', [id], connection);
    await connection.query(
      `UPDATE execution_tasks SET cancel_requested=true,
       state=CASE WHEN phase='dispatched' THEN 'uncertain' ELSE 'cancelled' END,
       error=CASE WHEN phase='dispatched' THEN 'approval_cancelled' ELSE NULL END,
       finished_at=now(),lease_until=NULL
       WHERE (request->'intent'->'approval'->>'id'=$1 OR request->'intent'->'operationContext'->>'id'=$1) AND state IN ('queued','running')`, [id]);
    if (!row || ['succeeded', 'cancelled'].includes(row.state)) return;
    const snapshot = await this.read(row);
    const current = snapshot.operations[snapshot.index], result = snapshot.results[snapshot.index];
    const cancelled = current && result && row.wait === 'execution'
      ? await this.operations.get(current.name).cancel?.({ id: snapshot.actor.id }, result) : null;
    const unknown = cancelled && typeof cancelled === 'object' && 'state' in cancelled && cancelled.state === 'uncertain' ||
      row.state === 'uncertain' || snapshot.inFlight !== null || await this.db.one(
      "SELECT 1 FROM execution_tasks WHERE (request->'intent'->'approval'->>'id'=$1 OR request->'intent'->'operationContext'->>'id'=$1) AND state='uncertain' LIMIT 1", [id], connection);
    if (current) snapshot.results[snapshot.index] = cancelled ? Json.parse(cancelled) : { state: unknown ? 'uncertain' : 'cancelled' };
    await connection.query('UPDATE operation_executions SET state=$2,wait=NULL,snapshot=$3,revision=revision+1 WHERE id=$1',
      [id, unknown ? 'uncertain' : 'cancelled', await this.vault.encrypt(snapshot, 'operation-execution:' + id)]);
  }
  async cancel(actor: Actor, id: string, decline = false) {
    const item = await this.get(actor, id, false);
    if (decline ? !item.canRespond : !item.canCancel) fail(403, 'forbidden', 'You cannot cancel this operation.');
    await this.db.transaction(async connection => {
      await this.revoke(id, connection);
      await connection.query("UPDATE operation_executions SET response=$2 WHERE id=$1 AND state IN ('cancelled','uncertain')",
        [id, decline ? 'declined' : 'cancelled']);
    });
    return this.get(actor, id);
  }
  private async locked<T>(id: string, action: () => Promise<T>) {
    const lease = randomUUID();
    const claimed = await this.db.pool.query(
      "UPDATE operation_executions SET lease_token=$2,lease_until=now()+interval '90 seconds' WHERE id=$1 AND (lease_until IS NULL OR lease_until<now())", [id, lease]);
    if (!claimed.rowCount) fail(409, 'execution_busy', 'This operation is already being continued.');
    const renewal = setInterval(() => {
      void this.db.pool.query("UPDATE operation_executions SET lease_until=now()+interval '90 seconds' WHERE id=$1 AND lease_token=$2", [id, lease]).catch(() => {});
    }, 15_000);
    renewal.unref();
    try {
      return await action();
    } finally {
      clearInterval(renewal);
      await this.db.pool.query('UPDATE operation_executions SET lease_token=NULL,lease_until=NULL WHERE id=$1 AND lease_token=$2', [id, lease]);
    }
  }
  private async recover(row: ExecutionRow) {
    if (row.state !== 'running' || (row.lease_until && row.lease_until.getTime() > Date.now())) return row;
    try {
      return await this.locked(row.id, async () => {
        const current = await this.row(row.id), saved = await this.read(current);
        if (current.state === 'running' && saved.inFlight !== null) {
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
  private async save(row: ExecutionRow, snapshot: Snapshot, state: ExecutionRow['state'], wait: ExecutionRow['wait'] = null) {
    const encrypted = await this.vault.encrypt(snapshot, 'operation-execution:' + row.id);
    await this.db.transaction(async connection => {
      const updated = await connection.query(
        'UPDATE operation_executions SET snapshot=$2,state=$3,wait=$4,revision=revision+1,actor_id=$7 WHERE id=$1 AND revision=$5 AND lease_token=$6 AND lease_until>now()',
        [row.id, encrypted, state, wait, row.revision, row.lease_token, snapshot.actor.id]);
      if (!updated.rowCount) fail(409, 'execution_changed', 'Reload this operation before continuing.');
      if (snapshot.actor.approvalId && state === 'failed') row.response = 'pending';
      await connection.query('UPDATE operation_executions SET responder_id=$2,proposal=$3,response=$4 WHERE id=$1',
        [row.id, row.responder_id, row.proposal ? JSON.stringify(row.proposal) : null, row.response]);
    });
    row.revision++; row.state = state; row.wait = wait; row.actor_id = snapshot.actor.id; row.snapshot = encrypted;
  }

  async start(actor: Actor, operations: OperationInvocation[], options: { id?: string; expiresAt?: Date; results?: Array<JsonValue | null>; message?: string; submissionDigest?: string } = {}) {
    const id = options.id ?? randomUUID();
    await this.plan(id, actor, operations, options.expiresAt ?? new Date(Date.now() + 86_400_000), options.results,
      options.message ? { message: options.message, pending: false } : undefined, options.submissionDigest);
    return this.locked(id, async () => {
      const row = await this.row(id), previous = await this.read(row);
      if (row.state === 'succeeded') return this.view(row, previous);
      if (row.state === 'cancelled') fail(409, 'cancelled', 'This operation was cancelled.');
      if (previous.inFlight !== null && row.state !== 'uncertain') await this.save(row, previous, 'uncertain');
      if (row.state === 'uncertain')
        fail(409, 'execution_uncertain', 'Check the last operation before starting it again.');
      if (row.state === 'waiting' && row.wait === 'input') return this.view(row, previous);
      let prepared: OperationInvocation[];
      try {
        prepared = await Promise.all(operations.map(async (operation, index) => index < previous.index ? previous.operations[index]!
          : { ...previous.operations[index]!, ...(await this.operations.prepareFor(actor, operation)).invocation }));
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
  private async active(row: ExecutionRow, snapshot: Snapshot) {
    if (row.expires_at.getTime() <= Date.now()) fail(409, 'execution_expired', 'This operation has expired.');
    await this.authorization.active(snapshot.actor);
  }
  private async resume(row: ExecutionRow, snapshot: Snapshot): Promise<OperationExecutionView> {
    for (; snapshot.index < snapshot.operations.length; snapshot.index++) {
      try { await this.active(row, snapshot); }
      catch (error) {
        const fault = failure(error);
        snapshot.results[snapshot.index] = { error: { code: fault.code, message: fault.message } };
        await this.save(row, snapshot, 'failed'); throw fault;
      }
      const operation = snapshot.operations[snapshot.index]!, definition = this.operations.get(operation.name);
      if (definition.execution === 'keyholder') {
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
        snapshot.results[snapshot.index] = await this.operations.execute(this.operationActor(snapshot), operation);
      } catch (error) {
        snapshot.inFlight = null;
        if (error instanceof AgreementNeeded && !this.operationActor(snapshot).approvalId) {
          row.responder_id = error.to; row.proposal = error.proposed; row.response = 'pending';
          snapshot.actor = this.authority(snapshot.creatorActor); snapshot.agreementIndex = null;
          await this.save(row, snapshot, 'waiting', 'approval');
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
    if (row.state !== 'waiting' || row.wait !== 'input') fail(409, 'execution_changed', 'This operation is no longer awaiting input.');
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
      snapshot.operations[index] = { ...snapshot.operations[index]!, ...this.operations.prepare(this.operations.configure(plan.invocation, values)).invocation };
      await this.save(row, snapshot, 'waiting', 'input');
      return this.view(row, snapshot);
    });
  }
  async complete(actor: Actor, id: string, index: number, proof: JsonValue) {
    return this.locked(id, async () => {
      const row = await this.row(id), snapshot = await this.read(row), proofDigest = await hash(proof);
      if (row.actor_id !== actor.id || actor.requestId) fail(403, 'forbidden', 'Use the identity handling this operation.');
      if (index < snapshot.index && snapshot.proofs[index] === proofDigest) return this.view(row, snapshot);
      await this.active(row, snapshot);
      if (row.state !== 'waiting' || row.wait !== 'input' || index !== snapshot.index)
        fail(409, 'execution_changed', 'This operation is no longer awaiting that input.');
      const operation = snapshot.operations[index]!, definition = this.operations.get(operation.name);
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
    });
  }
}
