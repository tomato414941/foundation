import { randomInt, randomUUID } from 'node:crypto';
import type { z } from 'zod';
import type { Database } from './database.js';
import { iso } from './database.js';
import type { Authorization, Actor } from './authorization.js';
import { principal } from './authorization.js';
import type { Principals } from './principals.js';
import type { Authentication } from './authentication.js';
import type { Audit } from './audit.js';
import { Vault, digest, token } from './vault.js';
import { ApprovalRequest, ConnectionRequest } from '../shared/contracts.js';
import type {
  RequestedOperation,
  RequestInput,
  ApprovalView,
  JsonValue,
  Settings,
} from '../shared/contracts.js';
import { setPointer, atPointer } from '../shared/values.js';
import type { Proposed } from './relations.js';
import { fail, required } from './errors.js';
import type { OperationRegistry } from './operations.js';
import type { OperationExecutions } from './operation-executions.js';

interface RequestRow {
  id: string;
  from_id: string;
  to_id: string | null;
  message: string;
  operations: string;
  results: Array<JsonValue | null>;
  state: ApprovalView['state'];
  code_hash: string | null;
  attempts: number;
  expires_at: Date;
  created_at: Date;
  private_input: string | null;
  continue_url: string | null;
  proposal: Proposed | null;
  credential_id: string | null;
}
interface ResponseContext {
  actor: Actor;
  operations: RequestedOperation[];
}
export class Requests {
  constructor(
    readonly db: Database,
    readonly authorization: Authorization,
    readonly principals: Principals,
    readonly authentication: Authentication,
    readonly audit: Audit,
    readonly vault: Vault,
    readonly origin: string,
    readonly operations: OperationRegistry,
    readonly executions: OperationExecutions,
  ) {}
  private async row(id: string): Promise<RequestRow> {
    await this.db.pool.query(
      "UPDATE approval_requests SET state='expired',private_input=NULL,continue_url=NULL,finished_at=now() WHERE id=$1 AND expires_at<=now() AND state IN ('pending','running')",
      [id],
    );
    return required(await this.db.one<RequestRow>('SELECT * FROM approval_requests WHERE id=$1', [id]));
  }
  private async canRespond(actor: Actor | null, row: RequestRow) {
    if (!actor) return false;
    await this.authorization.active(actor);
    if (actor.requestId) return actor.requestId === row.id && actor.id === row.to_id;
    if (row.to_id) return this.authorization.holds(actor.id, principal(row.to_id), 'stands');
    return Boolean(row.code_hash) && actor.id !== row.from_id;
  }
  private async view(actor: Actor | null, row: RequestRow, code?: string): Promise<ApprovalView> {
    const from = await this.principals.get(row.from_id),
      to = row.to_id ? await this.principals.get(row.to_id) : null;
    const settings = await this.db.one<{ settings: z.infer<typeof Settings> }>(
      'SELECT settings FROM integration_settings WHERE principal_id=$1',
      [from.id],
    );
    const returnUrl = settings?.settings.returnUrl ? new URL(settings.settings.returnUrl) : null;
    if (returnUrl) {
      returnUrl.searchParams.set('requestId', row.id);
      returnUrl.searchParams.set('state', row.state);
    }
    return ApprovalRequest.parse({
      id: row.id,
      from: { id: from.id, name: from.name },
      to: to ? { id: to.id, name: to.name } : null,
      message: row.message,
      proposal: row.proposal && (await this.proposal(row.proposal)),
      // The operation definition supplies the same description to every entry point.
      operations: (await this.vault.decrypt<RequestedOperation[]>(row.operations, 'request-operations:' + row.id)).map(
        (operation) => {
          const invocation = this.operations.resolve(operation);
          return { ...operation, title: this.operations.describe(operation), invocation,
            execution: this.operations.get(invocation.name).execution };
        },
      ),
      results: row.results,
      state: row.state,
      createdAt: iso(row.created_at),
      expiresAt: iso(row.expires_at),
      url: this.origin + '/requests/' + row.id,
      ...(code ? { code } : {}),
      continueUrl: row.continue_url,
      returnUrl: returnUrl?.href ?? null,
      refreshUrl: settings?.settings.refreshUrl ?? null,
      canRespond: await this.canRespond(actor, row),
      waiting: row.state === 'running' && await this.canRespond(actor, row) ? (await this.executions.peek(row.id))?.waiting ?? null : null,
    });
  }
  // A proposed change as the one asked reads it: who and what, by name.
  private async proposal(proposed: Proposed) {
    const named = async (id: string) => {
      const found = await this.db.one<{ name: string }>(
        'SELECT name FROM principals WHERE id=$1 UNION ALL SELECT name FROM resources WHERE id=$1',
        [id],
      );
      return { id, name: found?.name ?? id };
    };
    return proposed.kind === 'line'
      ? { kind: proposed.kind, subject: await named(proposed.subjectId), relation: proposed.relation, object: await named(proposed.objectId) }
      : { kind: proposed.kind, item: await named(proposed.itemId), to: await named(proposed.to) };
  }
  async get(actor: Actor | null, id: string) {
    let row = await this.row(id);
    const publicJoin = row.code_hash && row.to_id === null;
    if (!publicJoin && (!actor || (actor.id !== row.from_id && !(await this.canRespond(actor, row)))))
      fail(403, 'forbidden', 'This request is addressed to another principal.');
    if (row.state === 'running') {
      if (!await this.executions.peek(id) && row.private_input && actor && !actor.requestId && await this.canRespond(actor, row))
        await this.operationPlan(actor, id);
      row = await this.row(id);
    }
    return this.view(actor, row);
  }
  async list(actor: Actor, limit = 100, after?: string) {
    if (actor.requestId) fail(403, 'forbidden', 'This link can open only its own request.');
    const ids = await this.authorization.find(actor.id, 'principal', 'stands');
    const rows = await this.db.all<RequestRow>(
      'SELECT * FROM approval_requests WHERE (from_id=$1 OR to_id=ANY($2::uuid[])) AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4',
      [actor.id, ids, after ?? null, limit + 1],
    );
    return {
      items: await Promise.all(rows.slice(0, limit).map((row) => this.get(actor, row.id))),
      next: rows.length > limit ? rows[limit - 1]!.id : null,
    };
  }
  private bootstrap(actorId: string, operations: RequestedOperation[]) {
    const operation = operations[0] ? this.operations.resolve(operations[0]) : null;
    const body = operation?.input;
    return (
      operations.length === 1 &&
      operation?.name === 'relation.draw' &&
      Boolean(
        body &&
          typeof body === 'object' &&
          !Array.isArray(body) &&
          (body.subjectId === actorId || body.subjectId === '$requester') &&
          body.relation === 'agent' &&
          body.objectId === '$approver' &&
          Object.keys(body).length === 3,
      ) &&
      operations[0]!.inputs.length === 0
    );
  }
  async create(actor: Actor, input: z.infer<typeof RequestInput>) {
    if (actor.requestId) fail(403, 'forbidden', 'Sign in to create a new request.');
    for (const operation of input.operations) {
      const invocation = this.operations.resolve(operation), definition = this.operations.get(invocation.name);
      for (const field of operation.inputs)
        if (field.secret && !definition.secret(field.pointer))
          fail(400, 'encrypted_input_required', 'Choose an operation that handles this input with your encryption keys.');
      if (definition.execution === 'keyholder') {
        for (const key of ['value', 'clientSecret'])
          if (invocation.input[key] !== undefined && invocation.input[key] !== '')
            fail(400, 'encrypted_input_required', 'Enter private material when responding to the request.');
        if (invocation.input.fields &&
          Object.values(invocation.input.fields as Record<string, JsonValue>).some(value => value !== ''))
          fail(400, 'encrypted_input_required', 'Enter service credentials when responding to the request.');
      }
      for (const field of operation.inputs)
        try {
          if (atPointer(operation.body, field.pointer) === undefined)
            fail(400, 'invalid_pointer', 'Place each requested field in the operation body.');
        } catch {
          fail(400, 'invalid_pointer', 'Place each requested field in the operation body.');
        }
    }
    const to = input.to ?? (await this.principals.get(actor.id)).owner_id;
    if (to) await this.principals.get(to);
    if (!to && !this.bootstrap(actor.id, input.operations))
      fail(400, 'recipient_required', 'Choose who should answer this request.');
    await this.limit(actor.id);
    const alphabet = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
    const code = to
      ? undefined
      : Array.from({ length: 8 }, () => alphabet[randomInt(alphabet.length)]).join('');
    const id = randomUUID(),
      row = required(
        await this.db.one<RequestRow>(
          "INSERT INTO approval_requests(id,from_id,to_id,message,operations,results,state,code_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,'pending',$7,$8) RETURNING *",
          [
            id,
            actor.id,
            to,
            input.message,
            await this.vault.encrypt(input.operations, 'request-operations:' + id),
            JSON.stringify(input.operations.map(() => null)),
            code ? digest(code) : null,
            new Date(Date.now() + input.expiresInMinutes * 60_000),
          ],
        ),
      );
    await this.executions.plan(id, actor, input.operations.map(operation => this.operations.resolve(operation)), row.expires_at);
    return this.view(actor, row, code);
  }
  private async limit(actorId: string) {
    const pending = await this.db.one<{ count: string }>(
      "SELECT count(*) FROM approval_requests WHERE from_id=$1 AND state IN ('pending','running') AND expires_at>now()",
      [actorId],
    );
    if (Number(pending?.count) >= 20) fail(429, 'request_limit', 'Wait for an existing request to finish.');
  }
  // A change its requester has made its own side of, sent to the side it waits on for a day. Once that side agrees, the
  // requester makes it as it asked, with the key it asked with: the one who agrees gives only its own side.
  async propose(actor: Actor, to: string, proposed: Proposed, operation: RequestedOperation, executionId?: string) {
    if (actor.requestId || actor.approvalId) fail(403, 'forbidden', 'You do not have permission to perform this action.');
    await this.limit(actor.id);
    const id = executionId ?? randomUUID(),
      row = required(
        await this.db.one<RequestRow>(
          `INSERT INTO approval_requests(id,from_id,to_id,message,operations,results,state,expires_at,proposal,credential_id)
          VALUES($1,$2,$3,'',$4,'[null]','pending',now()+interval '1 day',$5,$6) RETURNING *`,
          [
            id,
            actor.id,
            to,
            await this.vault.encrypt([operation], 'request-operations:' + id),
            JSON.stringify(proposed),
            actor.credentialId ?? null,
          ],
        ),
      );
    return this.view(actor, row);
  }
  private substitute(value: JsonValue, actorId: string, fromId: string): JsonValue {
    if (value === '$approver') return actorId;
    if (value === '$requester') return fromId;
    if (Array.isArray(value)) return value.map((child) => this.substitute(child, actorId, fromId));
    if (value && typeof value === 'object')
      return Object.fromEntries(
        Object.entries(value).map(([key, child]) => [key, this.substitute(child, actorId, fromId)]),
      );
    return value;
  }
  async approve(
    actor: Actor,
    id: string,
    values: Array<Record<string, JsonValue>>,
    code?: string,
    configuration: Array<Record<string, JsonValue>> = [],
  ) {
    let row = await this.row(id);
    if (!(await this.canRespond(actor, row)))
      fail(403, 'forbidden', 'This request is addressed to another principal.');
    if (row.state !== 'pending') fail(409, 'request_answered', 'This request is already being handled.');
    if (row.code_hash) {
      const attempted = await this.db.one<{ attempts: number }>(
        'UPDATE approval_requests SET attempts=attempts+1 WHERE id=$1 AND attempts<5 RETURNING attempts',
        [id],
      );
      if (!attempted || digest((code ?? '').replaceAll('-', '').toUpperCase()) !== row.code_hash)
        fail(400, 'invalid_code', 'Enter the code shown by the requesting device.');
    }
    const operations = await this.vault.decrypt<RequestedOperation[]>(
      row.operations,
      'request-operations:' + id,
    );
    const effectiveId = actor.requestId ? required(row.to_id) : actor.id;
    const completed = (await this.executions.peek(id))?.index ?? 0;
    const filled = operations.map((operation, index) => {
      const current = structuredClone(operation),
        supplied = values[index] ?? {};
      if (index < completed) return current;
      if (
        Object.keys(supplied).some((pointer) => !operation.inputs.some((input) => input.pointer === pointer && !input.secret))
      )
        fail(400, 'unexpected_input', 'Only provide the fields this request asks for.');
      for (const field of operation.inputs.filter(input => !input.secret)) {
        const value = supplied[field.pointer];
        if (value === undefined) fail(400, 'missing_input', 'Complete the requested fields.');
        try {
          setPointer(current.body, field.pointer, value);
        } catch {
          fail(400, 'invalid_pointer', 'The requested input target was not found.');
        }
      }
      // A proposed change is made exactly as it was proposed.
      if (row.proposal) return current;
      current.path = current.path
        .replaceAll('{approver}', effectiveId)
        .replaceAll('{requester}', row.from_id);
      if (current.body !== undefined) current.body = this.substitute(current.body, effectiveId, row.from_id);
      return Object.keys(configuration[index] ?? {}).length ? this.operations.configure(current, configuration[index]!) : current;
    });
    const prepared = await Promise.all(filled.map(async (operation, index) => index < completed
      ? { invocation: this.operations.resolve(operation) } : this.operations.prepareFor(actor, this.operations.resolve(operation, true))));
    const effectiveActor: Actor = row.proposal
      ? {
          id: row.from_id,
          ...(row.credential_id ? { credentialId: row.credential_id } : {}),
          agreedBy: effectiveId,
          approvalId: id,
        }
      : {
          id: effectiveId,
          ...(actor.sessionId ? { sessionId: actor.sessionId } : {}),
          ...(actor.credentialId ? { credentialId: actor.credentialId } : {}),
          approvalId: id,
        };
    const invocations = prepared.map(value => value.invocation);
    await this.executions.plan(id, effectiveActor, invocations, row.expires_at, row.results);
    await this.db.transaction(async (connection) => {
      await this.executions.authorize(effectiveActor, id, invocations, connection);
      const claimed = await connection.query(
        "UPDATE approval_requests SET state='running',private_input=NULL,continue_url=NULL WHERE id=$1 AND state='pending' AND expires_at>now()",
        [id],
      );
      if (!claimed.rowCount) fail(409, 'request_answered', 'This request is already being handled.');
      if (row.code_hash) {
        await connection.query('SELECT pg_advisory_xact_lock(736023743)');
        const device = await this.principals.get(row.from_id, connection);
        if (device.owner_id || (await this.authorization.holds(row.from_id, principal(effectiveId), 'stands', connection)))
          fail(409, 'already_owned', 'This device has already been taken on.');
        await connection.query('UPDATE principals SET owner_id=$2 WHERE id=$1', [row.from_id, effectiveId]);
        await connection.query('UPDATE approval_requests SET to_id=$2,code_hash=NULL WHERE id=$1', [
          id,
          effectiveId,
        ]);
      }
    });
    try { await this.executions.start(effectiveActor, invocations, { id, expiresAt: row.expires_at }); }
    catch (error) {
      if (!(error && typeof error === 'object' && 'code' in error && error.code === 'execution_busy')) throw error;
    }
    return this.get(actor, id);
  }
  async operationPlan(actor: Actor, id: string) {
    const row = await this.row(id);
    if (actor.requestId || !await this.canRespond(actor, row) || row.state !== 'running')
      fail(409, 'request_answered', 'Sign in with your keys to continue this request.');
    // Existing running requests are adopted by the common execution engine when first resumed.
    if (!await this.executions.peek(id) && row.private_input) {
      const context = await this.vault.decrypt<ResponseContext>(row.private_input, 'request-input:' + id);
      await this.executions.start(context.actor, context.operations.map(operation => this.operations.resolve(operation)),
        { id, expiresAt: row.expires_at, results: row.results });
    }
    const { plan } = await this.executions.input(actor, id);
    return { id, ...plan };
  }
  async connectionPlan(actor: Actor, id: string) {
    const plan = await this.operationPlan(actor, id);
    if (plan.invocation.name !== 'connection.connect') fail(403, 'forbidden', 'Continue the connection approved by this identity.');
    const { ownerId, methodId, connectionId, environmentId, name } = plan.invocation.input;
    return { id, index: plan.index, input: ConnectionRequest.parse({ ownerId, methodId, connectionId, environmentId, name }) };
  }
  async decline(actor: Actor, id: string) {
    const row = await this.row(id);
    if (!(await this.canRespond(actor, row)))
      fail(403, 'forbidden', 'This request is addressed to another principal.');
    await this.db.transaction(async connection => {
      await connection.query('SELECT id FROM operation_executions WHERE id=$1 FOR UPDATE', [id]);
      const changed = await connection.query(
        "UPDATE approval_requests SET state='declined',finished_at=now(),private_input=NULL,continue_url=NULL WHERE id=$1 AND state IN ('pending','running')", [id]);
      if (changed.rowCount) await this.executions.revoke(id, connection);
    });
    return this.get(actor, id);
  }
  async cancel(actor: Actor, id: string) {
    const row = await this.row(id);
    if (actor.requestId || actor.id !== row.from_id)
      fail(403, 'forbidden', 'Only the requester can cancel this request.');
    await this.db.transaction(async connection => {
      await connection.query('SELECT id FROM operation_executions WHERE id=$1 FOR UPDATE', [id]);
      const changed = await connection.query(
        "UPDATE approval_requests SET state='cancelled',finished_at=now(),private_input=NULL,continue_url=NULL WHERE id=$1 AND state IN ('pending','running')", [id]);
      if (changed.rowCount) await this.executions.revoke(id, connection);
    });
    return this.get(actor, id);
  }
  async link(actor: Actor, id: string) {
    const row = await this.row(id);
    if (actor.requestId || !row.to_id || !(await this.canRespond(actor, row)))
      fail(403, 'forbidden', 'Only the recipient can issue a request link.');
    const secret = token();
    await this.db.pool.query(
      'INSERT INTO request_links(token_hash,request_id,principal_id,expires_at) VALUES($1,$2,$3,$4)',
      [digest(secret), id, row.to_id, row.expires_at],
    );
    return { url: this.origin + '/requests/' + id + '#token=' + secret, expiresAt: iso(row.expires_at) };
  }
  async redeem(id: string, secret: string) {
    const row = await this.db.one<{ principal_id: string }>(
      'DELETE FROM request_links WHERE token_hash=$1 AND request_id=$2 AND expires_at>now() RETURNING principal_id',
      [digest(secret), id],
    );
    if (!row) fail(400, 'invalid_link', 'This link has expired or was already used.');
    const request = await this.row(id);
    if (!['pending', 'running'].includes(request.state))
      fail(409, 'request_answered', 'This request has already been answered.');
    return this.authentication.session(row.principal_id, undefined, this.db.pool, id);
  }
}
