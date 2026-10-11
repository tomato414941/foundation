import type { z } from 'zod';
import type { Database } from './database.js';
import type { Actor, Authorization } from './authorization.js';
import type { Authentication } from './authentication.js';
import { digest, token } from './vault.js';
import { ApprovalRequest } from '../shared/contracts.js';
import type { RequestInput, JsonValue, Settings } from '../shared/contracts.js';
import type { OperationExecutions } from './operation-executions.js';
import { ExecutionInput, executionRequestState } from '../shared/operations.js';
import { fail } from './errors.js';

// A request delivers an execution. Inputs, consent, progress, and results belong to that execution.
export class Requests {
  constructor(readonly db: Database, readonly authorization: Authorization, readonly authentication: Authentication,
    readonly origin: string, readonly executions: OperationExecutions) {}
  async get(actor: Actor | null, id: string, code?: string) {
    const item = await this.executions.get(actor, id);
    const settings = await this.db.one<{ settings: z.infer<typeof Settings> }>('SELECT settings FROM integration_settings WHERE principal_id=$1', [item.creator.id]);
    const state = executionRequestState(item);
    const returnUrl = settings?.settings.returnUrl ? new URL(settings.settings.returnUrl) : null;
    if (returnUrl) { returnUrl.searchParams.set('requestId', id); returnUrl.searchParams.set('state', state); }
    return ApprovalRequest.parse({ id, from: item.creator, to: item.responder, message: item.message, proposal: item.proposal,
      operations: item.operations, results: item.results, state, createdAt: item.createdAt, expiresAt: item.expiresAt,
      url: this.origin + '/requests/' + id, ...(code ? { code } : {}), returnUrl: returnUrl?.href ?? null,
      refreshUrl: settings?.settings.refreshUrl ?? null, canRespond: item.canRespond, canCancel: item.canCancel,
      executionState: item.state, waiting: item.waiting });
  }
  async list(actor: Actor, limit = 100, after?: string) {
    if (actor.requestId) fail(403, 'forbidden', 'This link can open only its own request.');
    const ids = await this.authorization.find(actor.id, 'principal', 'stands');
    const rows = await this.db.all<{ id: string }>(
      `SELECT id FROM operation_executions WHERE (responder_id IS NOT NULL OR code_hash IS NOT NULL)
       AND (creator_id=$1 OR responder_id=ANY($2::uuid[])) AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4`, [actor.id, ids, after ?? null, limit + 1]);
    return { items: await Promise.all(rows.slice(0, limit).map(row => this.get(actor, row.id))), next: rows.length > limit ? rows[limit - 1]!.id : null };
  }
  async create(actor: Actor, input: z.infer<typeof RequestInput>) {
    const creator = await this.executions.principals.get(actor.id);
    const responderId = input.to ?? creator.owner_id ?? undefined;
    const execution = await this.executions.create(actor, ExecutionInput.parse({ operations: input.operations, responderId,
      message: input.message, expiresInMinutes: input.expiresInMinutes }), !responderId);
    await this.db.pool.query('INSERT INTO approval_requests(id) VALUES($1)', [execution.id]);
    return this.get(actor, execution.id, execution.code);
  }
  async approve(actor: Actor, id: string, values: Array<Record<string, JsonValue>>, code?: string, configuration: Array<Record<string, JsonValue>> = []) {
    await this.executions.respond(actor, id, values, code, configuration);
    return this.get(actor, id);
  }
  async decline(actor: Actor, id: string) { await this.executions.cancel(actor, id, true); return this.get(actor, id); }
  async cancel(actor: Actor, id: string) { await this.executions.cancel(actor, id); return this.get(actor, id); }
  async link(actor: Actor, id: string) {
    const item = await this.executions.get(actor, id);
    if (actor.requestId || !item.responder || !item.canRespond) fail(403, 'forbidden', 'Only the recipient can issue a request link.');
    const secret = token();
    await this.db.transaction(async connection => {
      await connection.query('INSERT INTO approval_requests(id) VALUES($1) ON CONFLICT(id) DO NOTHING', [id]);
      await connection.query('INSERT INTO request_links(token_hash,request_id,principal_id,expires_at) VALUES($1,$2,$3,$4)',
        [digest(secret), id, item.responder!.id, item.expiresAt]);
    });
    return { url: this.origin + '/requests/' + id + '#token=' + secret, expiresAt: item.expiresAt };
  }
  async redeem(id: string, secret: string) {
    const row = await this.db.one<{ principal_id: string }>('DELETE FROM request_links WHERE token_hash=$1 AND request_id=$2 AND expires_at>now() RETURNING principal_id', [digest(secret), id]);
    if (!row) fail(400, 'invalid_link', 'This link has expired or was already used.');
    const item = await this.executions.get({ id: row.principal_id }, id);
    if (!['waiting', 'running', 'failed'].includes(item.state)) fail(409, 'request_answered', 'This operation has already finished.');
    return this.authentication.session(row.principal_id, undefined, this.db.pool, id);
  }
}
