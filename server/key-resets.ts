import { randomUUID } from 'node:crypto';
import { decodeProtectedHeader, importJWK } from 'jose';
import type { z } from 'zod';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor, Authorization } from './authorization.js';
import type { Audit } from './audit.js';
import { PublicKey, WrappedKey } from '../shared/contracts.js';
import type { PublicEncryptionKey } from '../shared/contracts.js';
import type { KeyResetCompletion } from '../shared/session.js';
import { fail, required } from './errors.js';

// Whoever lost every copy of the private key makes new keys. Nothing tells them from whoever took over their email, so
// the request waits a week, and meanwhile anyone signed in as the principal, as on a device that still holds the
// private key, can cancel it. Once ready, it can be completed for a month.
const waiting = 7 * 86_400_000, lasting = 30 * 86_400_000;

export class KeyResets {
  constructor(readonly db: Database, readonly authorization: Authorization, readonly audit: Audit) {}
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
  // Replaces the keys once the request is ready, with the private key wrapped for the passkey this session signed in
  // with. The one that passkeys and API keys held before no longer belongs to the principal, and what only it opened is
  // entered again with the new keys; the principal's new signing key is published as for one that had none.
  async complete(actor: Actor, principalId: string, input: z.infer<typeof KeyResetCompletion>) {
    await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials');
    if (actor.id !== principalId || decodeProtectedHeader(input.wrappedKey).sub !== principalId)
      fail(403, 'forbidden', 'Sign in as this principal with the passkey that holds its new keys.');
    await importJWK(PublicKey.parse(input.publicKey), 'ECDH-ES+A256KW');
    await this.db.transaction(async connection => {
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [principalId]);
      if (!await this.db.one("SELECT 1 FROM credentials WHERE id=$1 AND principal_id=$2 AND kind='passkey'",
        [actor.credentialId ?? null, principalId], connection))
        fail(403, 'forbidden', 'Sign in as this principal with the passkey that holds its new keys.');
      const ready = await this.db.one(
        `DELETE FROM challenges WHERE kind='key-reset' AND principal_id=$1 AND expires_at>now()
         AND (data->>'readyAt')::timestamptz<=now() RETURNING id`, [principalId], connection);
      if (!ready) fail(409, 'key_reset_waiting', 'Wait until the request to make new keys is ready.');
      await connection.query('UPDATE principal_key_bindings SET retired_at=now() WHERE principal_id=$1 AND retired_at IS NULL', [principalId]);
      await connection.query('UPDATE principals SET public_key=$2 WHERE id=$1', [principalId, JSON.stringify(PublicKey.parse(input.publicKey))]);
      await connection.query('UPDATE credentials SET private_wrap=CASE WHEN id=$2 THEN $3 END WHERE principal_id=$1',
        [principalId, actor.credentialId, WrappedKey.parse(input.wrappedKey)]);
      await this.audit.record(principalId, actor.id, 'principal.resetKeys', principalId, {}, connection);
    });
  }
}
