import { randomInt, randomUUID } from 'node:crypto';
import type { z } from 'zod';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor, Authorization } from './authorization.js';
import { principal } from './authorization.js';
import type { Authentication } from './authentication.js';
import type { Principals } from './principals.js';
import type { Proposed } from './relations.js';
import type { Vault } from './vault.js';
import { digest, token } from './vault.js';
import type { Audit } from './audit.js';
import type { DefinitionRegistry } from './definitions.js';
import type { Operations } from './operations.js';
import { fail, required } from './errors.js';
import { atPointer, setPointer } from '../shared/values.js';
import { Id, Operation } from '../shared/contracts.js';
import type { JsonValue, RequestedOperation, Settings } from '../shared/contracts.js';
import { hash } from '../shared/authority.js';
import { RequestCreate, RequestView } from '../shared/operations.js';
import type { OperationCall, OperationRecordView, RequestRecordView } from '../shared/operations.js';

type State = RequestRecordView['state'];
// Who asked, with the sign-in and consent it asked with, and the operations it asked for: kept encrypted.
interface Snapshot {
  creatorActor: Actor;
  operations: RequestedOperation[];
  submission: string | null;
}
interface RequestRow {
  id: string; from_id: string; to_id: string | null; owner_id: string | null; message: string; record: string;
  proposal: Proposed | null; code_hash: string | null; attempts: number; state: State; expires_at: Date;
  created_at: Date; answered_at: Date | null; answered_by: string | null;
}

// A request asks the principal it is sent to, or whoever enters its code, to make operations. It waits until that
// principal approves it, giving what it asks for, or declines it, until its requester withdraws it, or until it expires.
export class Requests {
  constructor(readonly db: Database, readonly vault: Vault, readonly authorization: Authorization,
    readonly authentication: Authentication, readonly definitions: DefinitionRegistry, readonly principals: Principals,
    readonly audit: Audit, readonly origin: string, readonly operations: Operations) {}

  private read(row: RequestRow) { return this.vault.decrypt<Snapshot>(row.record, 'request:' + row.id); }
  private async row(id: string, connection: Queryable = this.db.pool) {
    return required(await this.db.one<RequestRow>('SELECT * FROM requests WHERE id=$1', [Id.parse(id)], connection));
  }
  // Whether the actor may approve or decline the request: through its link, as the principal it is sent to, or, for a
  // request that a code opens, as anyone but its requester.
  async canAnswer(actor: Actor | null, row: RequestRow) {
    if (!actor || row.state !== 'pending') return false;
    await this.authorization.active(actor);
    if (actor.requestId) return actor.requestId === row.id && row.to_id === actor.id;
    if (row.to_id) return this.authorization.holds(actor.id, principal(row.to_id), 'stands');
    return !!row.code_hash && actor.id !== row.from_id;
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
  private async view(row: RequestRow, actor: Actor | null, code?: string): Promise<RequestRecordView> {
    const snapshot = await this.read(row);
    const [from, to, settings, performed] = await Promise.all([this.principals.named(row.from_id),
      row.to_id ? this.principals.named(row.to_id) : null,
      this.db.one<{ settings: z.infer<typeof Settings> }>('SELECT settings FROM integration_settings WHERE principal_id=$1', [row.from_id]),
      this.db.all<{ id: string; position: number; state: OperationRecordView['state'] }>(
        'SELECT id,position,state FROM operations WHERE request_id=$1 ORDER BY position', [row.id])]);
    const returnUrl = settings?.settings.returnUrl ? new URL(settings.settings.returnUrl) : null;
    if (returnUrl) { returnUrl.searchParams.set('requestId', row.id); returnUrl.searchParams.set('state', row.state); }
    return RequestView.parse({ id: row.id, from: { id: from.id, name: from.name }, to: to ? { id: to.id, name: to.name } : null,
      message: row.message, operations: snapshot.operations.map(operation => {
        const definition = this.definitions.get(operation.name);
        return { ...operation, title: this.definitions.describe(operation), keyholder: definition.keyholder,
          configure: [...definition.configure] };
      }), proposal: await this.proposal(row.proposal), state: row.state, createdAt: iso(row.created_at), expiresAt: iso(row.expires_at),
      answeredAt: row.answered_at ? iso(row.answered_at) : null,
      performed, url: this.origin + '/requests/' + row.id,
      ...(code ? { code } : {}), returnUrl: returnUrl?.href ?? null, refreshUrl: settings?.settings.refreshUrl ?? null,
      canAnswer: await this.canAnswer(actor, row),
      canWithdraw: !!actor && !actor.requestId && row.state === 'pending' && actor.id === row.from_id });
  }
  private async expire(row: RequestRow) {
    if (row.state !== 'pending' || row.expires_at.getTime() > Date.now()) return row;
    await this.db.pool.query("UPDATE requests SET state='expired',answered_at=now() WHERE id=$1 AND state='pending'", [row.id]);
    return this.row(row.id);
  }
  async expireAll() {
    await this.db.pool.query("UPDATE requests SET state='expired',answered_at=now() WHERE state='pending' AND expires_at<=now()");
  }
  async get(actor: Actor | null, id: string) {
    if (actor?.requestId && actor.requestId !== id) fail(403, 'forbidden', 'This link can open only its own request.');
    const row = await this.expire(await this.row(id));
    if (actor) await this.authorization.active(actor);
    const open = row.code_hash && !row.to_id && row.state === 'pending';
    if (!open && (!actor || actor.id !== row.from_id && actor.id !== row.answered_by && !(await this.canAnswer(actor, row)) &&
      !(row.to_id && !actor.requestId && await this.authorization.holds(actor.id, principal(row.to_id), 'stands')) &&
      !(row.owner_id && !actor.requestId && await this.authorization.holds(actor.id, principal(row.owner_id), 'read')) &&
      !(!actor.requestId && await this.db.one('SELECT 1 FROM principals WHERE id=$1 AND retired_at IS NOT NULL AND merged_into=$2', [row.from_id, actor.id]))))
      fail(403, 'forbidden', 'This request belongs to other principals.');
    return this.view(row, actor);
  }
  // Requests the actor sent or that were sent to principals it acts as, the latest first.
  async list(actor: Actor, limit = 100, after?: string) {
    await this.authorization.active(actor);
    if (actor.requestId) fail(403, 'forbidden', 'This link can open only its own request.');
    const ids = await this.authorization.find(actor.id, 'principal', 'stands');
    const rows = await this.db.all<RequestRow>(`SELECT r.* FROM requests r LEFT JOIN principals p ON p.id=r.from_id
      WHERE (r.from_id=$1 OR r.to_id=ANY($2::uuid[]) OR r.answered_by=$1 OR p.merged_into=$1)
      AND ($3::uuid IS NULL OR (r.created_at,r.id)<(SELECT created_at,id FROM requests WHERE id=$3))
      ORDER BY r.created_at DESC,r.id DESC LIMIT $4`, [actor.id, ids, after ?? null, limit + 1]);
    const items = await Promise.all(rows.slice(0, limit).map(async row => this.view(await this.expire(row), actor)));
    return { items, next: rows.length > limit ? rows[limit - 1]!.id : null };
  }
  // A device not yet taken on asks to be: one line making it a delegate of whoever approves.
  private bootstrap(actorId: string, operations: RequestedOperation[]) {
    const operation = operations[0], body = operation?.input;
    return operations.length === 1 && operation?.name === 'relation.draw' &&
      (body?.subjectId === actorId || body?.subjectId === '$requester') && body.relation === 'delegate' &&
      body.objectId === '$approver' && Object.keys(body).length === 3 && operation.inputs.length === 0;
  }
  async create(actor: Actor, body: z.input<typeof RequestCreate>) {
    if (actor.requestId) fail(403, 'forbidden', 'Sign in to send a request.');
    await this.authorization.active(actor);
    const input = RequestCreate.parse(body), creator = await this.principals.get(actor.id);
    const to = input.to ?? creator.owner_id ?? undefined, invitation = !to;
    const submission = await hash({ operations: input.operations, to: to ?? null, message: input.message,
      expiresInMinutes: input.expiresInMinutes, invitation });
    if (input.id && await this.db.one('SELECT 1 FROM requests WHERE id=$1', [input.id])) {
      const saved = await this.row(input.id);
      if (saved.from_id !== actor.id || (await this.read(saved)).submission !== submission)
        fail(409, 'request_conflict', 'Use a new request ID for a different request.');
      return this.view(saved, actor);
    }
    const operations = await Promise.all(input.operations.map(async requested => {
      const operation = Operation.parse(requested), definition = this.definitions.get(operation.name);
      for (const field of operation.inputs) {
        if (field.secret && !definition.secret(field.pointer)) fail(400, 'encrypted_input_required', 'Choose an operation that encrypts this input.');
        try { if (atPointer(operation.input, field.pointer) === undefined) throw new Error(); }
        catch { fail(400, 'invalid_pointer', 'Place each requested field in the operation input.'); }
      }
      if (definition.keyholder && ['value', 'clientSecret'].some(key => operation.input[key] !== undefined && operation.input[key] !== ''))
        fail(400, 'encrypted_input_required', 'Supply private material directly with your encryption keys.');
      if (definition.review) operation.input = await definition.review(actor, operation.input);
      return operation;
    }));
    if (to) await this.principals.get(to);
    if (invitation && !this.bootstrap(actor.id, operations)) fail(400, 'recipient_required', 'Choose who should handle this request.');
    const pending = await this.db.one<{ count: string }>("SELECT count(*) FROM requests WHERE from_id=$1 AND state='pending' AND expires_at>now()", [actor.id]);
    if (Number(pending?.count) >= 20) fail(429, 'request_limit', 'Wait for an earlier request to be answered.');
    const alphabet = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
    const code = invitation ? Array.from({ length: 8 }, () => alphabet[randomInt(alphabet.length)]).join('') : undefined;
    const id = input.id ?? randomUUID(), expiresAt = new Date(Date.now() + input.expiresInMinutes * 60_000);
    await this.insert({ id, from: actor, to: to ?? null, message: input.message, operations, proposal: null,
      code: code ?? null, expiresAt, submission });
    return this.view(await this.row(id), actor, code);
  }
  // A change the actor made its own side of, sent to the principal whose agreement it needs.
  async propose(creatorActor: Actor, to: string, proposed: Proposed, operation: OperationCall) {
    const id = randomUUID(), expiresAt = new Date(Date.now() + 86_400_000);
    await this.insert({ id, from: creatorActor, to, message: '', operations: [Operation.parse({ ...operation, inputs: [] })],
      proposal: proposed, code: null, expiresAt, submission: null });
    return this.view(await this.row(id), creatorActor);
  }
  private async insert(input: { id: string; from: Actor; to: string | null; message: string; operations: RequestedOperation[];
    proposal: Proposed | null; code: string | null; expiresAt: Date; submission: string | null }) {
    const snapshot: Snapshot = { creatorActor: this.operations.authority(input.from), operations: input.operations, submission: input.submission };
    const owner = input.operations.map(operation => operation.input.ownerId).find(value => Id.safeParse(value).success);
    await this.db.pool.query(`INSERT INTO requests(id,from_id,to_id,owner_id,message,record,proposal,code_hash,state,expires_at)
      VALUES($1,$2,$3,(SELECT id FROM principals WHERE id=$4),$5,$6,$7,$8,'pending',$9)`,
    [input.id, input.from.id, input.to, typeof owner === 'string' ? owner : input.to ?? input.from.id, input.message,
      await this.vault.encrypt(snapshot, 'request:' + input.id), input.proposal ? JSON.stringify(input.proposal) : null,
      input.code ? digest(input.code) : null, input.expiresAt]);
  }
  private substitute(value: JsonValue, approver: string, requester: string): JsonValue {
    if (value === '$approver') return approver;
    if (value === '$requester') return requester;
    if (Array.isArray(value)) return value.map(child => this.substitute(child, approver, requester));
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, this.substitute(child, approver, requester)]));
    return value;
  }
  // Approving fills in what the request asks the approver for, and makes its operations in order.
  async approve(actor: Actor, id: string, values: Array<Record<string, JsonValue>> = [], code?: string,
    configuration: Array<Record<string, JsonValue>> = []) {
    const row = await this.expire(await this.row(id)), snapshot = await this.read(row);
    if (row.state !== 'pending') fail(409, 'request_answered', 'This request has already been answered.');
    if (!(await this.canAnswer(actor, row))) fail(403, 'forbidden', 'This request is sent to another principal.');
    if (row.code_hash) {
      const attempted = await this.db.one('UPDATE requests SET attempts=attempts+1 WHERE id=$1 AND attempts<5 RETURNING attempts', [id]);
      if (!attempted || digest((code ?? '').replaceAll('-', '').toUpperCase()) !== row.code_hash) fail(400, 'invalid_code', 'Enter the code shown by the requesting device.');
    }
    const approverId = actor.requestId ? required(row.to_id) : actor.id;
    // A change the requester made its side of is made as the requester, with the approver's agreement.
    const approver: Actor = row.proposal ? { ...snapshot.creatorActor, agreedBy: approverId, approvalId: id }
      : { id: approverId, ...(actor.credentialId ? { credentialId: actor.credentialId } : {}), approvalId: id };
    const filled = await Promise.all(snapshot.operations.map(async (operation, position) => {
      const current = structuredClone(operation), supplied = values[position] ?? {};
      if (Object.keys(supplied).some(pointer => !operation.inputs.some(field => field.pointer === pointer && !field.secret)))
        fail(400, 'unexpected_input', 'Only provide the fields this request asks for.');
      for (const field of operation.inputs.filter(field => !field.secret)) {
        if (supplied[field.pointer] === undefined) fail(400, 'missing_input', 'Complete the requested fields.');
        try { setPointer(current.input, field.pointer, supplied[field.pointer]!); }
        catch { fail(400, 'invalid_pointer', 'The requested input target was not found.'); }
      }
      if (row.proposal && (Object.keys(supplied).length || Object.keys(configuration[position] ?? {}).length))
        fail(400, 'operation_changed', 'Approve the change exactly as it was proposed.');
      if (!row.proposal) current.input = this.substitute(current.input, approverId, row.from_id) as Record<string, JsonValue>;
      const configured = Object.keys(configuration[position] ?? {}).length ? this.definitions.configure(current, configuration[position]!) : current;
      return (await this.definitions.prepareFor(row.proposal ? snapshot.creatorActor : actor, configured)).invocation;
    }));
    await this.db.transaction(async connection => {
      await this.authorization.active(actor, connection);
      // A change made as its requester needs the requester's sign-in still to hold.
      if (row.proposal) await this.authorization.active(snapshot.creatorActor, connection);
      const locked = required(await this.db.one<RequestRow>('SELECT * FROM requests WHERE id=$1 FOR UPDATE', [id], connection));
      if (locked.state !== 'pending' || locked.expires_at.getTime() <= Date.now())
        fail(409, 'request_answered', 'This request has already been answered.');
      if (row.code_hash) {
        await connection.query('SELECT pg_advisory_xact_lock(736023743)');
        const device = await this.principals.get(row.from_id, connection);
        if (device.owner_id || await this.authorization.holds(row.from_id, principal(approverId), 'stands', connection))
          fail(409, 'already_owned', 'This device has already been taken on.');
        await connection.query('UPDATE principals SET owner_id=$2 WHERE id=$1', [row.from_id, approverId]);
      }
      await connection.query("UPDATE requests SET state='approved',answered_at=now(),answered_by=$2,to_id=COALESCE(to_id,$2),code_hash=NULL WHERE id=$1",
        [id, approverId]);
      await this.operations.plan(connection, id, filled,
        filled.map((_operation, position) => ({ ...approver, approvalIndex: position })));
    });
    await this.audit.record(row.from_id, approverId, 'request.approve', id, {});
    await this.operations.advance(id);
    return this.get(actor, id);
  }
  async decline(actor: Actor, id: string) {
    const row = await this.expire(await this.row(id));
    if (row.state !== 'pending') fail(409, 'request_answered', 'This request has already been answered.');
    if (!(await this.canAnswer(actor, row))) fail(403, 'forbidden', 'This request is sent to another principal.');
    await this.db.pool.query("UPDATE requests SET state='declined',answered_at=now(),answered_by=$2 WHERE id=$1 AND state='pending'",
      [id, actor.id]);
    return this.get(actor, id);
  }
  async withdraw(actor: Actor, id: string) {
    const row = await this.expire(await this.row(id));
    await this.authorization.active(actor);
    if (actor.requestId || actor.id !== row.from_id) fail(403, 'forbidden', 'Only its requester can withdraw a request.');
    if (row.state !== 'pending') fail(409, 'request_answered', 'This request has already been answered.');
    await this.db.pool.query("UPDATE requests SET state='withdrawn',answered_at=now() WHERE id=$1 AND state='pending'", [id]);
    return this.get(actor, id);
  }
  async link(actor: Actor, id: string) {
    const item = await this.get(actor, id);
    if (actor.requestId || !item.to || !item.canAnswer) fail(403, 'forbidden', 'Only the recipient can issue a request link.');
    const secret = token();
    await this.db.pool.query('INSERT INTO request_links(token_hash,request_id,principal_id,expires_at) VALUES($1,$2,$3,$4)',
      [digest(secret), id, item.to.id, item.expiresAt]);
    return { url: item.url + '#token=' + secret, expiresAt: item.expiresAt };
  }
  async redeem(id: string, secret: string) {
    const row = await this.db.one<{ principal_id: string }>('DELETE FROM request_links WHERE token_hash=$1 AND request_id=$2 AND expires_at>now() RETURNING principal_id', [digest(secret), id]);
    if (!row) fail(400, 'invalid_link', 'This link has expired or was already used.');
    const item = await this.get({ id: row.principal_id }, id);
    if (item.state !== 'pending') fail(409, 'request_answered', 'This request has already been answered.');
    return this.authentication.session(row.principal_id, undefined, this.db.pool, id);
  }
}
