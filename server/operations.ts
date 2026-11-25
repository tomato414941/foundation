import { randomUUID } from 'node:crypto';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor, Authorization } from './authorization.js';
import { principal } from './authorization.js';
import type { Principals } from './principals.js';
import type { Vault } from './vault.js';
import type { DefinitionRegistry } from './definitions.js';
import { OperationFailed } from './definitions.js';
import { AgreementNeeded } from './relations.js';
import type { Requests } from './requests.js';
import { fail, failure, required } from './errors.js';
import { Id } from '../shared/contracts.js';
import type { JsonValue } from '../shared/contracts.js';
import { hash } from '../shared/digest.js';
import { OperationInput, OperationView, serviceStep } from '../shared/operations.js';
import type { OperationCall, OperationContinuation, OperationRecordView, RequestRecordView } from '../shared/operations.js';
import type { z } from 'zod';

type State = OperationRecordView['state'];
// What an operation holds that names its actor's sign-in or the content it was given: kept encrypted.
interface Snapshot {
  actor: Actor;
  input: Record<string, JsonValue>;
  result: JsonValue | null;
  proof: string | null;
  continuation: OperationContinuation | null;
  inFlight: boolean;
  submission: string | null;
}
interface OperationRow {
  id: string; request_id: string | null; owner_id: string | null; actor_id: string; name: string;
  state: State; record: string; revision: number; lease_token: string | null; lease_until: Date | null;
  expires_at: Date | null; created_at: Date; updated_at: Date;
}

// An operation changes something in Foundation. Its actor makes it at once; one that seals what it saves is made by the
// actor's device, which sends what it sealed, or first waits on the service it connects to. An operation that needs
// another principal's agreement becomes a request to it, and the requested operation is made once that principal approves.
export class Operations {
  constructor(readonly db: Database, readonly vault: Vault, readonly authorization: Authorization,
    readonly definitions: DefinitionRegistry, readonly principals: Principals, readonly origin: string,
    readonly requests: () => Requests) {}

  private read(row: OperationRow) { return this.vault.decrypt<Snapshot>(row.record, 'operation:' + row.id); }
  private async row(id: string, connection: Queryable = this.db.pool) {
    return required(await this.db.one<OperationRow>('SELECT * FROM operations WHERE id=$1', [Id.parse(id)], connection));
  }
  // A sign-in authenticates a call; the operation keeps the identity, credential, consent and approval it is made with.
  authority(actor: Actor) {
    const { sessionId: _sessionId, ...authority } = actor;
    return authority;
  }
  // The operation's actor as it is signed in now, keeping the approval and agreement the operation is made under.
  private signedIn(saved: Actor, current: Actor): Actor {
    const { credentialId: _credentialId, ...kept } = saved;
    return this.authority({ ...kept, ...(current.credentialId ? { credentialId: current.credentialId } : {}) });
  }
  private owner(input: Record<string, JsonValue>) {
    const value = input.ownerId;
    return typeof value === 'string' && Id.safeParse(value).success ? value : null;
  }
  async view(row: OperationRow, snapshot: Snapshot, viewer: Actor | null): Promise<OperationRecordView> {
    const definition = this.definitions.get(row.name), actor = await this.principals.named(row.actor_id);
    const result = snapshot.result;
    const fault = result && typeof result === 'object' && !Array.isArray(result) && 'error' in result ? result.error : null;
    const error = fault && typeof fault === 'object' && !Array.isArray(fault) && typeof fault.code === 'string' && typeof fault.message === 'string'
      ? { code: fault.code, message: fault.message } : null;
    const acts = !!viewer && await this.acts(viewer, row);
    return OperationView.parse({ id: row.id, name: row.name, title: this.definitions.describe({ name: row.name, input: snapshot.input }),
      input: snapshot.input, keyholder: definition.keyholder, configure: [...definition.configure],
      ownerId: row.owner_id, actor: { id: actor.id, name: actor.name },
      requestId: row.request_id,
      state: row.state, result: error ? null : result !== null && definition.resultView ? definition.resultView(result) : result, error,
      continuation: snapshot.continuation,
      canPerform: acts && (['stopped', 'failed'].includes(row.state) || row.state === 'in_progress' && !!snapshot.continuation),
      canCancel: acts && (row.state === 'stopped' || row.state === 'in_progress' && !!snapshot.continuation),
      url: this.origin + '/operations/' + row.id, createdAt: iso(row.created_at), updatedAt: iso(row.updated_at),
      expiresAt: row.expires_at ? iso(row.expires_at) : null });
  }
  // Who goes on with an operation: the principal it is made by, signed in as itself.
  private async acts(actor: Actor, row: OperationRow) {
    return actor.id === row.actor_id;
  }
  private async visible(actor: Actor, row: OperationRow) {
    if (await this.acts(actor, row)) return true;
    if (row.owner_id && await this.authorization.holds(actor.id, principal(row.owner_id), 'read')) return true;
    if (row.request_id && await this.db.one('SELECT 1 FROM requests WHERE id=$1 AND (from_id=$2 OR to_id=$2 OR answered_by=$2)',
      [row.request_id, actor.id])) return true;
    return !!await this.db.one('SELECT 1 FROM principals WHERE id=$1 AND retired_at IS NOT NULL AND merged_into=$2', [row.actor_id, actor.id]);
  }
  async get(actor: Actor, id: string) {
    await this.authorization.active(actor);
    const row = await this.recover(await this.row(id));
    if (!(await this.visible(actor, row))) fail(403, 'forbidden', 'This operation belongs to another principal.');
    return this.view(row, await this.read(row), actor);
  }
  // Operations made by the actor or changing what it uses, the latest first.
  async list(actor: Actor, options: { limit?: number; after?: string; ownerId?: string; requestId?: string } = {}) {
    await this.authorization.active(actor);
    const limit = options.limit ?? 100, represented = await this.authorization.find(actor.id, 'principal', 'stands');
    if (options.ownerId) await this.authorization.requirePrincipal(actor, options.ownerId, 'read');
    const rows = await this.db.all<OperationRow>(`SELECT o.* FROM operations o LEFT JOIN principals p ON p.id=o.actor_id
      WHERE ($4::uuid IS NULL AND (o.actor_id=$1 OR o.owner_id=ANY($2::uuid[]) OR p.merged_into=$1) OR o.owner_id=$4)
      AND ($5::uuid IS NULL OR o.request_id=$5)
      AND ($3::uuid IS NULL OR (o.created_at,o.id)<(SELECT created_at,id FROM operations WHERE id=$3))
      ORDER BY o.created_at DESC,o.id DESC LIMIT $6`,
    [actor.id, represented, options.after ?? null, options.ownerId ?? null, options.requestId ?? null, limit + 1]);
    const items = await Promise.all(rows.slice(0, limit).map(async row => {
      const current = await this.recover(row);
      return this.view(current, await this.read(current), actor);
    }));
    return { items, next: rows.length > limit ? rows[limit - 1]!.id : null };
  }
  async plan(connection: Queryable, requestId: string, operation: OperationCall, actor: Actor) {
    const id = randomUUID(), snapshot: Snapshot = { actor: this.authority(actor), input: operation.input,
      result: null, proof: null, continuation: null, inFlight: false, submission: null };
    await connection.query(`INSERT INTO operations(id,request_id,owner_id,actor_id,name,state,record)
      VALUES($1,$2,(SELECT id FROM principals WHERE id=$3),$4,$5,'stopped',$6)`,
    [id, requestId, this.owner(operation.input) ?? actor.id, actor.id, operation.name, await this.vault.encrypt(snapshot, 'operation:' + id)]);
    return id;
  }
  // A server operation can start as soon as its approval is committed. A keyholder continues on its device.
  async runApproved(id: string, name: string) {
    if (!this.definitions.has(name) || this.definitions.get(name).keyholder) return;
    try {
      await this.locked(id, async () => {
        const current = await this.row(id);
        if (current.state === 'stopped') await this.make(current, await this.read(current));
      });
    } catch { /* The operation records its own failure; a busy operation is already claimed. */ }
  }

  async perform(actor: Actor, body: z.input<typeof OperationInput>): Promise<OperationRecordView | RequestRecordView> {
    await this.authorization.active(actor);
    const call = OperationInput.parse(body), id = call.id ?? randomUUID();
    const submission = await hash({ name: call.name, input: call.input, proof: call.proof === undefined ? null : await hash(call.proof),
      continuation: call.continuation ?? null });
    const existing = await this.db.one<OperationRow>('SELECT * FROM operations WHERE id=$1', [id]);
    if (existing) {
      if (existing.actor_id !== actor.id || (await this.read(existing)).submission !== submission)
        fail(409, 'operation_conflict', 'Use a new operation ID for a different operation.');
      return this.view(existing, await this.read(existing), actor);
    }
    const { definition, invocation } = await this.definitions.prepareFor(actor, { name: call.name, input: call.input });
    if (definition.keyholder) {
      if (call.proof === undefined && !call.continuation)
        fail(400, 'proof_required', 'Seal what this operation saves on your device and send it with the operation.');
      if (call.continuation && definition.continuation !== call.continuation.kind)
        fail(400, 'invalid_continuation', 'This operation does not wait on a service.');
    } else if (call.proof !== undefined || call.continuation) fail(400, 'invalid_input', 'This operation is made by the server.');
    const snapshot: Snapshot = { actor: this.authority(actor), input: invocation.input, result: null, proof: null,
      continuation: call.continuation ?? null, inFlight: false, submission };
    await this.db.pool.query(`INSERT INTO operations(id,owner_id,actor_id,name,state,record,expires_at)
      VALUES($1,(SELECT id FROM principals WHERE id=$2),$3,$4,'in_progress',$5,$6) ON CONFLICT(id) DO NOTHING`,
    [id, this.owner(invocation.input) ?? actor.id, actor.id, call.name, await this.vault.encrypt(snapshot, 'operation:' + id),
      call.continuation ? new Date(Date.now() + serviceStep) : null]);
    const row = await this.row(id);
    if (row.actor_id !== actor.id || (await this.read(row)).submission !== submission)
      fail(409, 'operation_conflict', 'Use a new operation ID for a different operation.');
    if (call.continuation) return this.view(row, snapshot, actor);
    return this.locked(id, async () => this.make(await this.row(id), await this.read(await this.row(id)), call.proof));
  }
  // Makes a stopped or failed operation, or finishes one that waited on its service with what the device sealed.
  async continue(actor: Actor, id: string, proof?: JsonValue): Promise<OperationRecordView | RequestRecordView> {
    await this.authorization.active(actor);
    const row = await this.recover(await this.row(id));
    if (!(await this.acts(actor, row))) fail(403, 'forbidden', 'Make this operation as the principal it belongs to.');
    const snapshot = await this.read(row);
    if (row.state === 'succeeded' && proof !== undefined && snapshot.proof === await hash(proof)) return this.view(row, snapshot, actor);
    if (row.state === 'uncertain') fail(409, 'operation_uncertain', 'Check the result before making this operation again.');
    if (!(['stopped', 'failed'].includes(row.state) || row.state === 'in_progress' && snapshot.continuation))
      fail(409, 'operation_changed', 'This operation is not waiting to be made.');
    const definition = this.definitions.get(row.name);
    if (definition.keyholder && proof === undefined)
      fail(400, 'proof_required', 'Seal what this operation saves on your device and send it with the operation.');
    if (!definition.keyholder && proof !== undefined) fail(400, 'invalid_input', 'This operation is made by the server.');
    return this.locked(id, async () => {
      const current = await this.row(id), saved = await this.read(current);
      if (current.state !== row.state) fail(409, 'operation_changed', 'Reload this operation before continuing.');
      saved.actor = this.signedIn(saved.actor, actor);
      return this.make(current, saved, proof);
    });
  }
  // Fills what a request left for its approver to choose in an operation that is not made yet.
  async configure(actor: Actor, id: string, values: Record<string, JsonValue>) {
    return this.locked(id, async () => {
      const row = await this.row(id), snapshot = await this.read(row);
      await this.authorization.active(actor);
      if (!(await this.acts(actor, row))) fail(403, 'forbidden', 'Change this operation as the principal it belongs to.');
      if (row.state !== 'stopped') fail(409, 'operation_changed', 'Change an operation before it is made.');
      const prepared = await this.definitions.prepareFor(snapshot.actor, this.definitions.configure({ name: row.name, input: snapshot.input }, values));
      snapshot.input = prepared.invocation.input;
      await this.save(row, snapshot, 'stopped');
      return this.view(row, snapshot, actor);
    });
  }
  // Records the service step a device waits on for an operation it makes.
  async track(actor: Actor, id: string, continuation: OperationContinuation) {
    return this.locked(id, async () => {
      const row = await this.row(id), snapshot = await this.read(row);
      await this.authorization.active(actor);
      if (!(await this.acts(actor, row))) fail(403, 'forbidden', 'Make this operation as the principal it belongs to.');
      if (this.definitions.get(row.name).continuation !== continuation.kind) fail(400, 'invalid_continuation', 'This operation does not wait on a service.');
      if (!(row.state === 'stopped' || row.state === 'in_progress' && snapshot.continuation?.id === continuation.id))
        fail(409, 'operation_changed', 'Continue the operation already in progress.');
      snapshot.continuation = continuation;
      row.expires_at = new Date(Date.now() + serviceStep);
      await this.save(row, snapshot, 'in_progress');
      return this.view(row, snapshot, actor);
    });
  }
  // Stops an operation that is not made yet, or that waits on its service.
  async cancel(actor: Actor, id: string) {
    const row = await this.recover(await this.row(id));
    await this.authorization.active(actor);
    if (!(await this.acts(actor, row))) fail(403, 'forbidden', 'Stop this operation as the principal it belongs to.');
    await this.locked(id, async () => {
      const current = await this.row(id), snapshot = await this.read(current);
      if (!(current.state === 'stopped' || current.state === 'in_progress' && snapshot.continuation))
        fail(409, 'operation_changed', 'This operation is not waiting to be made.');
      snapshot.continuation = null;
      await this.save(current, snapshot, 'cancelled');
    });
    return this.get(actor, id);
  }
  // The operation a device waits on its service for, as that device's actor sees it.
  async waiting(actor: Actor, id: string) {
    const row = await this.row(id), snapshot = await this.read(row);
    if (row.actor_id !== actor.id) fail(403, 'forbidden', 'Sign in with the identity making this operation.');
    if (row.state !== 'in_progress' || !snapshot.continuation || (row.expires_at && row.expires_at.getTime() <= Date.now()))
      fail(409, 'operation_changed', 'This operation is no longer waiting on its service.');
    return { row, snapshot };
  }

  private async make(row: OperationRow, snapshot: Snapshot, proof?: JsonValue): Promise<OperationRecordView | RequestRecordView> {
    const definition = this.definitions.get(row.name), invocation = { name: row.name, input: snapshot.input };
    snapshot.inFlight = true;
    await this.save(row, snapshot, 'in_progress');
    try {
      await this.authorization.active(snapshot.actor);
      snapshot.result = definition.keyholder
        ? await required(definition.complete, 'This operation is made by the server.')(snapshot.actor, snapshot.input, proof ?? null)
        : await this.definitions.execute(snapshot.actor, invocation);
    } catch (error) {
      snapshot.inFlight = false;
      if (error instanceof AgreementNeeded && !snapshot.actor.approvalId && !row.request_id) {
        // The other side is asked: the change waits for its agreement as a request, and is made once it agrees.
        const request = await this.requests().propose(snapshot.actor, error.to, error.proposed, invocation);
        await this.db.pool.query('DELETE FROM operations WHERE id=$1', [row.id]);
        return request;
      }
      if (error instanceof OperationFailed) {
        snapshot.result = { error: { code: error.code, message: error.message }, result: error.result };
        snapshot.continuation = null;
        await this.save(row, snapshot, error.uncertain ? 'uncertain' : 'failed'); throw error;
      }
      const fault = failure(error);
      snapshot.result = { error: { code: fault.code, message: fault.message } };
      // A device that waits on its service may send its result again.
      await this.save(row, snapshot, snapshot.continuation ? 'in_progress' : 'failed'); throw fault;
    }
    snapshot.inFlight = false; snapshot.continuation = null;
    snapshot.proof = proof === undefined ? null : await hash(proof);
    await this.save(row, snapshot, 'succeeded');
    return this.view(row, snapshot, snapshot.actor);
  }
  private async save(row: OperationRow, snapshot: Snapshot, state: State, connection?: Queryable) {
    const record = await this.vault.encrypt(snapshot, 'operation:' + row.id);
    const updated = await (connection ?? this.db.pool).query(
      `UPDATE operations SET record=$2,state=$3,expires_at=$4,revision=revision+1,updated_at=now()
       WHERE id=$1 AND revision=$5 AND lease_token=$6 AND lease_until>now()`,
      [row.id, record, state, state === 'in_progress' && snapshot.continuation ? row.expires_at : null, row.revision, row.lease_token]);
    if (!updated.rowCount) fail(409, 'operation_changed', 'Reload this operation before continuing.');
    row.revision++; row.state = state; row.record = record;
  }
  private async locked<T>(id: string, action: () => Promise<T>) {
    const lease = randomUUID();
    const claimed = await this.db.pool.query(
      "UPDATE operations SET lease_token=$2,lease_until=now()+interval '90 seconds' WHERE id=$1 AND (lease_until IS NULL OR lease_until<now())",
      [id, lease]);
    if (!claimed.rowCount) fail(409, 'operation_busy', 'This operation is already being made.');
    const renewal = setInterval(() => {
      void this.db.pool.query("UPDATE operations SET lease_until=now()+interval '90 seconds' WHERE id=$1 AND lease_token=$2", [id, lease]).catch(() => {});
    }, 15_000);
    renewal.unref();
    try { return await action(); }
    finally {
      clearInterval(renewal);
      await this.db.pool.query('UPDATE operations SET lease_token=NULL,lease_until=NULL WHERE id=$1 AND lease_token=$2', [id, lease]);
    }
  }
  // An operation left being made when its server stopped may or may not have taken effect.
  private async recover(row: OperationRow) {
    if (row.state !== 'in_progress' || (row.lease_until && row.lease_until.getTime() > Date.now())) return row;
    const snapshot = await this.read(row);
    if (!snapshot.inFlight) return row;
    try {
      await this.locked(row.id, async () => {
        const current = await this.row(row.id), saved = await this.read(current);
        if (current.state !== 'in_progress' || !saved.inFlight) return;
        saved.inFlight = false; saved.continuation = null;
        saved.result = { error: { code: 'operation_uncertain', message: 'Check the result before making this operation again.' } };
        await this.save(current, saved, 'uncertain');
      });
    } catch (error) {
      if (!(error && typeof error === 'object' && 'code' in error && error.code === 'operation_busy')) throw error;
    }
    return this.row(row.id);
  }
  // Pick up an approval committed just before its server stopped.
  async runApprovedPending() {
    const rows = await this.db.all<{ id: string; name: string }>(
      "SELECT id,name FROM operations WHERE state='stopped' AND request_id IS NOT NULL AND (lease_until IS NULL OR lease_until<now())");
    for (const row of rows) await this.runApproved(row.id, row.name);
  }
  async recoverAll() {
    const rows = await this.db.all<OperationRow>(
      "SELECT * FROM operations WHERE state='in_progress' AND (lease_until IS NULL OR lease_until<now()) ORDER BY created_at");
    for (const row of rows) await this.recover(row);
  }
  // A device that never finished what its service waited on leaves the operation stopped by time.
  async expireAll() {
    await this.db.pool.query(
      "UPDATE operations SET state='cancelled',expires_at=NULL,updated_at=now(),revision=revision+1 WHERE state='in_progress' AND expires_at<=now() AND (lease_until IS NULL OR lease_until<now())");
  }
}
