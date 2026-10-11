import type { z } from 'zod';
import type { Database } from './database.js';
import { iso } from './database.js';
import type { Actor, Authorization } from './authorization.js';
import type { Authentication } from './authentication.js';
import { digest, token } from './vault.js';
import { ApprovalRequest } from '../shared/contracts.js';
import type { RequestInput, JsonValue, Settings } from '../shared/contracts.js';
import type { Executions } from './executions.js';
import { ExecutionInput } from '../shared/executions.js';
import { fail, required } from './errors.js';

interface RequestRow {
  id: string; execution_id: string; from_id: string; to_id: string | null; message: string;
  purpose: 'input' | 'approval'; state: z.infer<typeof ApprovalRequest>['state']; expires_at: Date; created_at: Date;
}

export class Requests {
  constructor(readonly db: Database, readonly authorization: Authorization, readonly authentication: Authentication,
    readonly origin: string, readonly executions: Executions) {}
  private async row(id: string) { return required(await this.db.one<RequestRow>('SELECT * FROM requests WHERE id=$1', [id])); }
  async get(actor: Actor | null, id: string, code?: string) {
    if (actor?.requestId && actor.requestId !== id) fail(403, 'forbidden', 'This link can open only its own request.');
    let row = await this.row(id);
    const execution = await this.executions.get(actor, row.execution_id);
    row = await this.row(id);
    const [from, to, settings] = await Promise.all([this.executions.principals.get(row.from_id),
      row.to_id ? this.executions.principals.get(row.to_id) : null,
      this.db.one<{ settings: z.infer<typeof Settings> }>('SELECT settings FROM integration_settings WHERE principal_id=$1', [row.from_id])]);
    const returnUrl = settings?.settings.returnUrl ? new URL(settings.settings.returnUrl) : null;
    if (returnUrl) { returnUrl.searchParams.set('requestId', id); returnUrl.searchParams.set('state', row.state); }
    return ApprovalRequest.parse({ id, executionId: row.execution_id, from: { id: from.id, name: from.name },
      to: to ? { id: to.id, name: to.name } : null, message: row.message, purpose: row.purpose, state: row.state,
      createdAt: iso(row.created_at), expiresAt: iso(row.expires_at), url: this.origin + '/requests/' + id,
      ...(code ? { code } : {}), returnUrl: returnUrl?.href ?? null, refreshUrl: settings?.settings.refreshUrl ?? null,
      canRespond: row.state === 'pending' && execution.canContinue, canCancel: execution.canCancel && row.state === 'pending' });
  }
  async list(actor: Actor, limit = 100, after?: string) {
    if (actor.requestId) fail(403, 'forbidden', 'This link can open only its own request.');
    const ids = await this.authorization.find(actor.id, 'principal', 'stands');
    const rows = await this.db.all<{ id: string }>(`SELECT id FROM requests WHERE
      (from_id=$1 OR to_id=ANY($2::uuid[])) AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4`, [actor.id, ids, after ?? null, limit + 1]);
    return { items: await Promise.all(rows.slice(0, limit).map(row => this.get(actor, row.id))), next: rows.length > limit ? rows[limit - 1]!.id : null };
  }
  async create(actor: Actor, input: z.infer<typeof RequestInput>) {
    const creator = await this.executions.principals.get(actor.id);
    const responderId = input.to ?? creator.owner_id ?? undefined;
    if (input.executionId) {
      if (!responderId) fail(400, 'recipient_required', 'Choose who should provide input or consent.');
      const id = await this.executions.deliver(actor, input.executionId, responderId, input.message, input.expiresInMinutes);
      return this.get(actor, id);
    }
    const execution = await this.executions.create(actor, ExecutionInput.parse({ operations: input.operations, responderId,
      message: input.message, expiresInMinutes: input.expiresInMinutes }), !responderId);
    const row = required(await this.db.one<{ id: string }>("SELECT id FROM requests WHERE execution_id=$1 AND state='pending'", [execution.id]));
    return this.get(actor, row.id, execution.code);
  }
  async approve(actor: Actor, id: string, values: Array<Record<string, JsonValue>>, code?: string, configuration: Array<Record<string, JsonValue>> = []) {
    const row = await this.row(id);
    if (row.state !== 'pending') fail(409, 'request_answered', 'This request has already been answered.');
    await this.executions.respond(actor, row.execution_id, values, code, configuration);
    return this.get(actor, id);
  }
  async decline(actor: Actor, id: string) {
    const row = await this.row(id);
    if (row.state !== 'pending') fail(409, 'request_answered', 'This request has already been answered.');
    await this.executions.cancel(actor, row.execution_id, true);
    return this.get(actor, id);
  }
  async cancel(actor: Actor, id: string) {
    const row = await this.row(id);
    if (row.state !== 'pending') fail(409, 'request_answered', 'This request has already been answered.');
    await this.executions.cancel(actor, row.execution_id);
    return this.get(actor, id);
  }
  async link(actor: Actor, id: string) {
    const item = await this.get(actor, id);
    if (actor.requestId || !item.to || !item.canRespond) fail(403, 'forbidden', 'Only the recipient can issue a request link.');
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
