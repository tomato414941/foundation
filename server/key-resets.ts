import { randomUUID } from 'node:crypto';
import { decodeProtectedHeader } from 'jose';
import type { z } from 'zod';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor, Authorization } from './authorization.js';
import type { Audit } from './audit.js';
import { WrappedKey } from '../shared/contracts.js';
import { verifyBinding } from '../shared/authority.js';
import { bindFirst } from './bindings.js';
import type { Confirmations } from './confirmations.js';
import type { PublicEncryptionKey } from '../shared/contracts.js';
import type { KeyResetCompletion } from '../shared/session.js';
import { fail, required } from './errors.js';

// Whoever lost every copy of the private key makes new keys. Nothing tells them from whoever took over their email, so
// the request waits a week, and meanwhile anyone signed in as the principal, as on a device that still holds the
// private key, can cancel it. Once ready, it can be completed for a month.
const waiting = 7 * 86_400_000, lasting = 30 * 86_400_000;

export class KeyResets {
  constructor(readonly db: Database, readonly authorization: Authorization, readonly audit: Audit,
    readonly confirmations: Confirmations) {}
  async get(principalId: string, connection: Queryable = this.db.pool) {
    const row = await this.db.one<{ created_at: Date; data: { readyAt: string } }>(
      "SELECT created_at,data FROM challenges WHERE kind='key-reset' AND principal_id=$1 AND expires_at>now()",
      [principalId], connection);
    return row ? { requestedAt: iso(row.created_at), readyAt: iso(row.data.readyAt) } : null;
  }
  async request(actor: Actor, principalId: string) {
    await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials');
    if (actor.id !== principalId) fail(403, 'forbidden', 'Sign in as this principal to make its keys again.');
    return this.db.transaction(async connection => {
      const principal = required(await this.db.one<{ public_key: PublicEncryptionKey | null }>(
        'SELECT public_key FROM principals WHERE id=$1 FOR UPDATE', [principalId], connection));
      if (!principal.public_key) fail(409, 'key_missing', 'Register a passkey to make the keys.');
      const pending = await this.get(principalId, connection);
      if (pending) return pending;
      const readyAt = new Date(Date.now() + waiting);
      await connection.query("DELETE FROM challenges WHERE kind='key-reset' AND principal_id=$1", [principalId]);
      await connection.query(
        "INSERT INTO challenges(id,kind,principal_id,data,expires_at) VALUES($1,'key-reset',$2,$3,$4)",
        [randomUUID(), principalId, JSON.stringify({ readyAt: readyAt.toISOString() }), new Date(readyAt.getTime() + lasting)]);
      await this.audit.record(principalId, actor.id, 'principal.requestKeyReset', principalId, {}, connection);
      return required(await this.get(principalId, connection));
    });
  }
  async cancel(actor: Actor, principalId: string) {
    await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials');
    const removed = await this.db.pool.query("DELETE FROM challenges WHERE kind='key-reset' AND principal_id=$1", [principalId]);
    if (removed.rowCount) await this.audit.record(principalId, actor.id, 'principal.cancelKeyReset', principalId);
  }
  // Replaces the keys once the request is ready, with the private key wrapped for the passkey that confirms it. The
  // keys that passkeys and API keys held before no longer belong to the principal, and what only they opened is
  // entered again with the new keys, which are bound as an identity's first keys.
  async complete(actor: Actor, principalId: string, input: z.infer<typeof KeyResetCompletion>) {
    await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials');
    const binding = await verifyBinding(input.binding);
    if (actor.id !== principalId || binding.principalId !== principalId || decodeProtectedHeader(input.wrappedKey).sub !== principalId)
      fail(403, 'forbidden', 'Make new keys for this principal while signed in as it.');
    await this.db.transaction(async connection => {
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [principalId]);
      const ready = await this.db.one(
        `DELETE FROM challenges WHERE kind='key-reset' AND principal_id=$1 AND expires_at>now()
         AND (data->>'readyAt')::timestamptz<=now() RETURNING id`, [principalId], connection);
      if (!ready) fail(409, 'key_reset_waiting', 'Wait until the request to make new keys is ready.');
      await this.confirmations.consume(connection, actor, { action: 'keyReset.complete', principalId,
        binding: input.binding, wrappedKey: WrappedKey.parse(input.wrappedKey), credentialId: input.credentialId });
      await connection.query('UPDATE principal_key_bindings SET retired_at=now() WHERE principal_id=$1 AND retired_at IS NULL', [principalId]);
      await connection.query('UPDATE principals SET public_key=NULL WHERE id=$1', [principalId]);
      await bindFirst(connection, this.db, this.audit, actor.id, input.binding);
      await connection.query('UPDATE credentials SET private_wrap=CASE WHEN id=$2 THEN $3 END WHERE principal_id=$1',
        [principalId, input.credentialId, WrappedKey.parse(input.wrappedKey)]);
      await this.audit.record(principalId, actor.id, 'principal.resetKeys', principalId, {}, connection);
    });
  }
}
