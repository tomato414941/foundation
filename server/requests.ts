import { randomInt, randomUUID } from 'node:crypto';
import type { z } from 'zod';
import type { Database } from './database.js';
import { iso } from './database.js';
import type { Authorization, Actor } from './authorization.js';
import type { Principals } from './principals.js';
import type { Authentication } from './authentication.js';
import type { Integrations } from './integrations.js';
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
import { fail, failure, required } from './errors.js';

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
}
interface ResponseContext {
  actor: Actor;
  operations: RequestedOperation[];
  browser: string;
  index: number;
}
export interface OperationDispatcher {
  allows(operation: RequestedOperation): boolean;
  execute(actor: Actor, operation: RequestedOperation, browser: string): Promise<JsonValue>;
}
export class Requests {
  dispatcher: OperationDispatcher | null = null;
  constructor(
    readonly db: Database,
    readonly authorization: Authorization,
    readonly principals: Principals,
    readonly authentication: Authentication,
    readonly integrations: Integrations,
    readonly audit: Audit,
    readonly vault: Vault,
    readonly origin: string,
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
    if (row.to_id) return this.authorization.stands(actor.id, row.to_id);
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
      operations: await this.vault.decrypt<RequestedOperation[]>(
        row.operations,
        'request-operations:' + row.id,
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
    });
  }
  async get(actor: Actor | null, id: string) {
    const row = await this.row(id);
    const publicJoin = row.code_hash && row.to_id === null;
    if (!publicJoin && (!actor || (actor.id !== row.from_id && !(await this.canRespond(actor, row)))))
      fail(403, 'forbidden', 'This request is addressed to another principal.');
    return this.view(actor, row);
  }
  async list(actor: Actor, limit = 100, after?: string) {
    if (actor.requestId) fail(403, 'forbidden', 'This link can open only its own request.');
    const ids = await this.authorization.standsAs(actor.id);
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
    const body = operations[0]?.body;
    return (
      operations.length === 1 &&
      operations[0]?.method === 'POST' &&
      operations[0].path === '/api/relations' &&
      Boolean(
        body &&
          typeof body === 'object' &&
          !Array.isArray(body) &&
          (body.subjectId === actorId || body.subjectId === '$requester') &&
          body.relation === 'agent' &&
          body.principalId === '$approver' &&
          Object.keys(body).length === 3,
      ) &&
      operations[0].inputs.length === 0
    );
  }
  async create(actor: Actor, input: z.infer<typeof RequestInput>) {
    if (actor.requestId) fail(403, 'forbidden', 'Sign in to create a new request.');
    for (const operation of input.operations) {
      if (operation.method === 'CONNECT') {
        ConnectionRequest.parse(operation.body);
        if (operation.path !== '/api/connections' || operation.inputs.length)
          fail(400, 'invalid_operation', 'Request a connection method, then enter its secrets in the encrypted connection form.');
      } else if (operation.inputs.some(field => field.secret))
        fail(400, 'encrypted_input_required', 'Use a CONNECT request to enter service secrets on a selected executor.');
      else if (!this.dispatcher?.allows(operation))
        fail(400, 'operation_unavailable', 'This operation cannot be requested for approval.');
      for (const field of operation.inputs)
        try {
          if (atPointer(operation.body, field.pointer) === undefined)
            fail(400, 'invalid_pointer', 'Place each requested field in the operation body.');
        } catch {
          fail(400, 'invalid_pointer', 'Place each requested field in the operation body.');
        }
    }
    const owner = await this.db.one<{ subject_id: string }>(
      "SELECT subject_id FROM relations WHERE principal_id=$1 AND relation='owner' ORDER BY created_at,id LIMIT 1",
      [actor.id],
    );
    const to = input.to ?? owner?.subject_id ?? null;
    if (to) await this.principals.get(to);
    if (!to && !this.bootstrap(actor.id, input.operations))
      fail(400, 'recipient_required', 'Choose who should answer this request.');
    const pending = await this.db.one<{ count: string }>(
      "SELECT count(*) FROM approval_requests WHERE from_id=$1 AND state IN ('pending','running') AND expires_at>now()",
      [actor.id],
    );
    if (Number(pending?.count) >= 20) fail(429, 'request_limit', 'Wait for an existing request to finish.');
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
    if (to) await this.integrations.enqueue(to, { type: 'request.created', requestId: id, from: actor.id });
    return this.view(actor, row, code);
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
    browser: string,
    values: Array<Record<string, JsonValue>>,
    code?: string,
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
    const filled = operations.map((operation, index) => {
      const current = structuredClone(operation),
        supplied = values[index] ?? {};
      const previous = row.results[index];
      if (
        previous &&
        typeof previous === 'object' &&
        !Array.isArray(previous) &&
        !Object.hasOwn(previous, 'error') &&
        !Object.hasOwn(previous, 'pending')
      )
        return current;
      if (
        Object.keys(supplied).some((pointer) => !operation.inputs.some((input) => input.pointer === pointer))
      )
        fail(400, 'unexpected_input', 'Only provide the fields this request asks for.');
      for (const field of operation.inputs) {
        const value = supplied[field.pointer];
        if (value === undefined) fail(400, 'missing_input', 'Complete the requested fields.');
        try {
          setPointer(current.body, field.pointer, value);
        } catch {
          fail(400, 'invalid_pointer', 'The requested input target was not found.');
        }
      }
      current.path = current.path
        .replaceAll('{approver}', effectiveId)
        .replaceAll('{requester}', row.from_id);
      if (current.body !== undefined) current.body = this.substitute(current.body, effectiveId, row.from_id);
      return current;
    });
    const effectiveActor: Actor = {
      id: effectiveId,
      ...(actor.sessionId ? { sessionId: actor.sessionId } : {}),
      ...(actor.credentialId ? { credentialId: actor.credentialId } : {}),
      approvalId: id,
    };
    const responseContext: ResponseContext = { actor: effectiveActor, operations: filled, browser, index: 0 };
    await this.db.transaction(async (connection) => {
      const claimed = await connection.query(
        "UPDATE approval_requests SET state='running',private_input=$2,continue_url=NULL WHERE id=$1 AND state='pending' AND expires_at>now()",
        [id, await this.vault.encrypt(responseContext, 'request-input:' + id)],
      );
      if (!claimed.rowCount) fail(409, 'request_answered', 'This request is already being handled.');
      if (row.code_hash) {
        await connection.query('SELECT pg_advisory_xact_lock(736023743)');
        const owner = await this.db.one(
          "SELECT 1 FROM relations WHERE principal_id=$1 AND relation='owner'",
          [row.from_id],
          connection,
        );
        if (owner || (await this.authorization.stands(row.from_id, effectiveId, connection)))
          fail(409, 'already_owned', 'This device has already been taken on.');
        await connection.query(
          "INSERT INTO relations(id,subject_id,principal_id,relation) VALUES($1,$2,$3,'owner')",
          [randomUUID(), effectiveId, row.from_id],
        );
        await connection.query('UPDATE approval_requests SET to_id=$2,code_hash=NULL WHERE id=$1', [
          id,
          effectiveId,
        ]);
      }
    });
    await this.resume(id);
    return this.get(actor, id);
  }
  private async resume(id: string) {
    let row = await this.row(id);
    if (row.state !== 'running' || !row.private_input) return;
    const context = await this.vault.decrypt<ResponseContext>(row.private_input, 'request-input:' + id);
    for (let index = context.index; index < context.operations.length; index++) {
      const previous = row.results[index];
      if (
        previous &&
        typeof previous === 'object' &&
        !Array.isArray(previous) &&
        !Object.hasOwn(previous, 'error') &&
        !Object.hasOwn(previous, 'pending')
      )
        continue;
      try {
        await this.authorization.active(context.actor);
        const operation = context.operations[index]!;
        if (operation.method === 'CONNECT') {
          const input = ConnectionRequest.parse(operation.body);
          const query = new URLSearchParams({ method: input.methodId, approval: id,
            ...(input.connectionId ? { connection: input.connectionId } : {}),
            ...(input.environmentId ? { environment: input.environmentId } : {}) });
          const results = [...row.results]; results[index] = { pending: true };
          await this.db.pool.query(
            "UPDATE approval_requests SET results=$2,continue_url=$3,private_input=$4 WHERE id=$1 AND state='running'",
            [id, JSON.stringify(results), this.origin + '/p/' + input.ownerId + '/services/new?' + query,
              await this.vault.encrypt({ ...context, index }, 'request-input:' + id)]);
          return;
        }
        const result = await required(this.dispatcher).execute(
          { ...context.actor, approvalIndex: index }, operation, context.browser);
        row.results[index] = result;
        await this.db.pool.query(
          "UPDATE approval_requests SET results=$2,private_input=$3 WHERE id=$1 AND state='running'",
          [
            id,
            JSON.stringify(row.results),
            await this.vault.encrypt({ ...context, index: index + 1 }, 'request-input:' + id),
          ],
        );
      } catch (error) {
        const fault = failure(error);
        row.results[index] = { error: { code: fault.code, message: fault.message } };
        await this.db.pool.query(
          "UPDATE approval_requests SET state='pending',results=$2,private_input=NULL,continue_url=NULL WHERE id=$1 AND state='running'",
          [id, JSON.stringify(row.results)],
        );
        throw fault;
      }
    }
    await this.db.pool.query(
      "UPDATE approval_requests SET state='approved',finished_at=now(),private_input=NULL,continue_url=NULL WHERE id=$1 AND state='running'",
      [id],
    );
    await this.integrations.enqueue(row.from_id, { type: 'request.approved', requestId: id });
    await this.audit.record(row.from_id, context.actor.id, 'request.approve', id);
  }
  async completed(actor: Actor, result: JsonValue) {
    if (!actor.approvalId || actor.approvalIndex === undefined) return;
    const row = await this.row(actor.approvalId);
    if (row.state !== 'running' || !row.private_input)
      fail(409, 'request_answered', 'This request is no longer awaiting a connection.');
    const context = await this.vault.decrypt<ResponseContext>(row.private_input, 'request-input:' + row.id);
    if (context.actor.id !== actor.id || context.index !== actor.approvalIndex)
      fail(403, 'forbidden', 'This connection belongs to a different request.');
    row.results[actor.approvalIndex] = result;
    const updated = await this.db.pool.query(
      "UPDATE approval_requests SET results=$2,continue_url=NULL,private_input=$3 WHERE id=$1 AND state='running' AND expires_at>now()",
      [
        row.id,
        JSON.stringify(row.results),
        await this.vault.encrypt({ ...context, index: context.index + 1 }, 'request-input:' + row.id),
      ],
    );
    if (!updated.rowCount) fail(409, 'request_answered', 'This request is no longer active.');
    await this.resume(row.id);
  }
  async connectionPlan(actor: Actor, id: string) {
    const row = await this.row(id);
    if (actor.requestId || !await this.canRespond(actor, row) || row.state !== 'running' || !row.private_input)
      fail(409, 'request_answered', 'Sign in with your keys to continue this pending connection request.');
    const context = await this.vault.decrypt<ResponseContext>(row.private_input, 'request-input:' + id);
    if (context.actor.id !== actor.id || context.operations[context.index]?.method !== 'CONNECT')
      fail(403, 'forbidden', 'Continue the connection approved by this identity.');
    return { id, index: context.index, input: ConnectionRequest.parse(context.operations[context.index]!.body) };
  }
  private async stopExecutions(id: string) {
    await this.db.pool.query(
      `UPDATE execution_tasks SET cancel_requested=true,
       state=CASE WHEN phase='dispatched' THEN 'uncertain' ELSE 'cancelled' END,
       error=CASE WHEN phase='dispatched' THEN 'approval_cancelled' ELSE NULL END,
       finished_at=now(),lease_until=NULL
       WHERE request->'intent'->'approval'->>'id'=$1 AND state IN ('queued','running')`, [id]);
  }
  async decline(actor: Actor, id: string) {
    const row = await this.row(id);
    if (!(await this.canRespond(actor, row)))
      fail(403, 'forbidden', 'This request is addressed to another principal.');
    await this.db.pool.query(
      "UPDATE approval_requests SET state='declined',finished_at=now(),private_input=NULL,continue_url=NULL WHERE id=$1 AND state IN ('pending','running')",
      [id],
    );
    await this.stopExecutions(id);
    await this.integrations.enqueue(row.from_id, { type: 'request.declined', requestId: id });
    return this.get(actor, id);
  }
  async cancel(actor: Actor, id: string) {
    const row = await this.row(id);
    if (actor.requestId || actor.id !== row.from_id)
      fail(403, 'forbidden', 'Only the requester can cancel this request.');
    await this.db.pool.query(
      "UPDATE approval_requests SET state='cancelled',finished_at=now(),private_input=NULL,continue_url=NULL WHERE id=$1 AND state IN ('pending','running')",
      [id],
    );
    await this.stopExecutions(id);
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
