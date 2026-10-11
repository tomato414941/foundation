import { randomUUID } from 'node:crypto';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor, Authorization } from './authorization.js';
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
  operations: OperationInvocation[];
  index: number;
  results: Array<JsonValue | null>;
  proofs: Array<string | null>;
  inFlight: number | null;
  continuation: OperationWaiting['continuation'];
}
interface ExecutionRow {
  id: string; actor_id: string; state: OperationExecutionView['state']; wait: OperationExecutionView['wait'];
  snapshot: string; revision: number; lease_token: string | null; lease_until: Date | null; expires_at: Date; created_at: Date;
}
// One persisted execution mechanism serves direct calls and calls awaiting a person's response.
export class OperationExecutions {
  consent: ((actor: Actor, id: string, operation: OperationInvocation, error: AgreementNeeded) => Promise<void>) | null = null;
  constructor(readonly db: Database, readonly vault: Vault, readonly authorization: Authorization,
    readonly operations: OperationRegistry, readonly audit: Audit) {}
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
  private view(row: ExecutionRow, snapshot: Snapshot): OperationExecutionView {
    return OperationExecution.parse({ id: row.id, actorId: row.actor_id, index: snapshot.index, state: row.state, wait: row.wait,
      waiting: row.wait === 'input' ? { index: snapshot.index, invocation: snapshot.operations[snapshot.index],
        continuation: snapshot.continuation, ...(snapshot.actor.approvalId ? { approval: { id: snapshot.actor.approvalId, index: snapshot.index } } : {}) } : null,
      results: snapshot.results, createdAt: iso(row.created_at), expiresAt: iso(row.expires_at) });
  }
  async peek(id: string) {
    const row = await this.db.one<ExecutionRow>('SELECT * FROM operation_executions WHERE id=$1', [id]);
    if (!row) return null;
    const current = await this.recover(row);
    return this.view(current, await this.read(current));
  }
  async get(actor: Actor, id: string, resume = true) {
    await this.authorization.active(actor);
    const row = await this.row(id);
    if (row.actor_id !== actor.id || actor.requestId) fail(403, 'forbidden', 'Use the identity that is handling this operation.');
    const current = resume ? await this.recover(row) : row;
    return this.view(current, await this.read(current));
  }
  async plan(id: string, actor: Actor, operations: OperationInvocation[], expiresAt: Date, results?: Array<JsonValue | null>) {
    const index = results ? results.findIndex(result => result === null || (typeof result === 'object' && !Array.isArray(result) &&
      ('error' in result || 'pending' in result))) : 0;
    const snapshot: Snapshot = { actor: this.authority(actor), operations, index: index < 0 ? operations.length : index, results: results ?? operations.map(() => null),
      proofs: operations.map(() => null), inFlight: null, continuation: null };
    await this.db.pool.query(
      "INSERT INTO operation_executions(id,actor_id,state,wait,snapshot,expires_at) VALUES($1,$2,'waiting','approval',$3,$4) ON CONFLICT(id) DO NOTHING",
      [id, actor.id, await this.vault.encrypt(snapshot, 'operation-execution:' + id), expiresAt]);
  }
  async authorize(actor: Actor, id: string, operations: OperationInvocation[], connection: Queryable) {
    const row = required(await this.db.one<ExecutionRow>('SELECT * FROM operation_executions WHERE id=$1 FOR UPDATE', [id], connection));
    const previous = await this.read(row);
    if (previous.inFlight !== null || row.state === 'uncertain')
      fail(409, 'execution_uncertain', 'Check the result before starting this operation again.');
    if ((row.state !== 'waiting' || row.wait !== 'approval') && row.state !== 'failed')
      fail(409, 'request_answered', 'This operation is already being handled.');
    if (row.lease_until && row.lease_until.getTime() > Date.now()) fail(409, 'execution_busy', 'This operation is in progress.');
    const snapshot: Snapshot = { ...previous, actor: this.authority(actor), continuation: null,
      operations: operations.map((operation, index) => index < previous.index ? previous.operations[index]! : operation) };
    await connection.query("UPDATE operation_executions SET actor_id=$2,snapshot=$3,state='running',wait=NULL,revision=revision+1 WHERE id=$1",
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
    const unknown = row.state === 'uncertain' || snapshot.inFlight !== null || await this.db.one(
      "SELECT 1 FROM execution_tasks WHERE (request->'intent'->'approval'->>'id'=$1 OR request->'intent'->'operationContext'->>'id'=$1) AND state='uncertain' LIMIT 1", [id], connection);
    await connection.query('UPDATE operation_executions SET state=$2,wait=NULL,revision=revision+1 WHERE id=$1', [id, unknown ? 'uncertain' : 'cancelled']);
  }
  async cancel(actor: Actor, id: string) {
    await this.get(actor, id, false);
    await this.db.transaction(connection => this.revoke(id, connection));
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
      if (snapshot.actor.approvalId) {
        const approved = await connection.query<{ from_id: string }>(
          `UPDATE approval_requests SET results=$2,
            state=CASE WHEN $3='succeeded' THEN 'approved' WHEN $3='failed' THEN 'pending' ELSE state END,
            finished_at=CASE WHEN $3='succeeded' THEN now() ELSE finished_at END
            WHERE id=$1 AND state='running' AND expires_at>now() RETURNING from_id`,
          [snapshot.actor.approvalId, JSON.stringify(snapshot.results), state]);
        if (state === 'succeeded' && approved.rows[0]) await this.audit.record(approved.rows[0].from_id,
          snapshot.actor.agreedBy ?? snapshot.actor.id, 'request.approve', snapshot.actor.approvalId, {}, connection);
      }
    });
    row.revision++; row.state = state; row.wait = wait; row.actor_id = snapshot.actor.id;
  }

  async start(actor: Actor, operations: OperationInvocation[], options: { id?: string; expiresAt?: Date; results?: Array<JsonValue | null> } = {}) {
    const id = options.id ?? randomUUID();
    await this.plan(id, actor, operations, options.expiresAt ?? new Date(Date.now() + 86_400_000), options.results);
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
          : (await this.operations.prepareFor(actor, operation)).invocation));
      } catch (error) {
        const fault = failure(error);
        previous.actor = this.authority(actor);
        previous.results[previous.index] = { error: { code: fault.code, message: fault.message } };
        await this.save(row, previous, 'failed'); throw fault;
      }
      const snapshot: Snapshot = { ...previous, actor: this.authority(actor), operations: prepared, continuation: null };
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
      snapshot.inFlight = snapshot.index;
      await this.save(row, snapshot, 'running');
      try {
        snapshot.results[snapshot.index] = await this.operations.execute(
          { ...snapshot.actor, approvalIndex: snapshot.index }, operation);
      } catch (error) {
        snapshot.inFlight = null;
        if (error instanceof AgreementNeeded && !snapshot.actor.approvalId && this.consent) {
          await this.consent(snapshot.actor, row.id, operation, error);
          await this.save(row, snapshot, 'waiting', 'approval');
          return this.view(row, snapshot);
        }
        const fault = failure(error);
        snapshot.results[snapshot.index] = { error: { code: fault.code, message: fault.message } };
        await this.save(row, snapshot, 'failed'); throw fault;
      }
      snapshot.inFlight = null;
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
    if (row.state !== 'waiting' || row.wait !== 'input') fail(409, 'request_answered', 'This operation is no longer awaiting input.');
    return { row, snapshot, plan: required(this.view(row, snapshot).waiting) };
  }
  async track(actor: Actor, id: string, index: number, continuation: NonNullable<OperationWaiting['continuation']>) {
    return this.locked(id, async () => {
      const { row, snapshot, plan } = await this.input(actor, id);
      if ((plan.invocation.name !== 'connection.connect' || continuation.kind !== 'connection') &&
        (plan.invocation.name !== 'run.execute' || continuation.kind !== 'run'))
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
      snapshot.operations[index] = this.operations.prepare(this.operations.configure(plan.invocation, values)).invocation;
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
        fail(409, 'request_answered', 'This operation is no longer awaiting that input.');
      const operation = snapshot.operations[index]!, definition = this.operations.get(operation.name);
      const complete = required(definition.complete, 'This operation does not accept client completion.');
      snapshot.inFlight = index;
      await this.save(row, snapshot, 'running');
      try {
        snapshot.results[index] = await complete({ ...snapshot.actor, approvalIndex: index }, operation.input, proof, { id, index });
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
