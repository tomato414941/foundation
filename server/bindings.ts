import type { z } from 'zod';
import type { Actor, Authorization } from './authorization.js';
import type { Database, Queryable } from './database.js';
import type { Audit } from './audit.js';
import { SignedBinding, canonical, verifyBinding } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import type { PublicEncryptionKey } from '../shared/contracts.js';
import { samePublicKey } from './encryption-validation.js';
import type { Confirmations } from './confirmations.js';
import { fail, required } from './errors.js';

export class Bindings {
  constructor(readonly db: Database, readonly authorization: Authorization, readonly audit: Audit,
    readonly confirmations: Confirmations) {}

  async current(principalId: string, connection: Queryable = this.db.pool) {
    const row = await this.db.one<{ binding: BoundKeys; signature: string }>(
      'SELECT binding,signature FROM principal_key_bindings WHERE principal_id=$1 AND retired_at IS NULL',
      [principalId], connection,
    );
    if (!row) fail(409, 'key_binding_required', 'Register encryption and signing keys for this identity.');
    const value = SignedBinding.parse(row);
    await verifyBinding(value);
    return value;
  }

  async requireCurrent(binding: BoundKeys, connection: Queryable = this.db.pool) {
    // A transactional writer keeps its verified keys current until its references have been stored.
    if (connection !== this.db.pool)
      await connection.query('SELECT id FROM principal_key_bindings WHERE principal_id=$1 AND retired_at IS NULL FOR SHARE',
        [binding.principalId]);
    const current = await this.current(binding.principalId, connection);
    if (canonical(current.binding) !== canonical(binding))
      fail(409, 'key_binding_changed', 'This identity changed its keys. Review the new keys before continuing.');
    return current;
  }

  async replacement(principalId: string, bindingId: string) {
    const row = await this.db.one<{
      previous: z.infer<typeof SignedBinding>; replacement: z.infer<typeof SignedBinding>; previous_signature: string;
    }>("SELECT previous,replacement,previous_signature FROM key_rotations WHERE principal_id=$1 AND state='committed' " +
      "AND previous#>>'{binding,id}'=$2 LIMIT 1", [principalId, bindingId]);
    return { replacement: row
      ? { previous: row.previous, replacement: row.replacement, previousSignature: row.previous_signature } : null };
  }

  // Publishes the first keys of an identity, or confirms the same ones again. Making them takes a confirmation, since
  // whoever binds them signs for the identity afterwards: an identity with an encryption key and nothing else confirms
  // by opening a secret sealed for that key, so that its token alone does not bind someone else's signing key.
  async publish(actor: Actor, input: z.infer<typeof SignedBinding>) {
    const signed = SignedBinding.parse(input);
    const binding = await verifyBinding(signed);
    await this.authorization.requirePrincipal(actor, binding.principalId, 'manage_credentials');
    return this.db.transaction(async connection => {
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [binding.principalId]);
      await this.authorization.requirePrincipal(actor, binding.principalId, 'manage_credentials', connection);
      const previous = await this.db.one<{ binding: BoundKeys; signature: string }>(
        'SELECT binding,signature FROM principal_key_bindings WHERE principal_id=$1 AND retired_at IS NULL',
        [binding.principalId], connection,
      );
      if (previous) {
        if (canonical(previous.binding) === canonical(binding)) return SignedBinding.parse(previous);
        fail(409, 'key_binding_changed', 'Replace the keys of this identity with a key rotation.');
      }
      await this.confirmations.consume(connection, actor, { action: 'keys.bind', principalId: binding.principalId, binding: signed });
      await bindFirst(connection, this.db, this.audit, actor.id, signed);
      return signed;
    });
  }
}

// Records the first keys of an identity, with its encryption key, in the transaction that makes it so. The keys
// must keep an encryption key the identity already has.
export async function bindFirst(connection: Queryable, db: Database, audit: Audit, actorId: string,
  input: z.infer<typeof SignedBinding>) {
  const signed = SignedBinding.parse(input), binding = await verifyBinding(signed);
  if (binding.generation !== 1 || binding.previous !== null)
    fail(400, 'invalid_key_binding', 'Start this identity with its first key binding.');
  const principal = required(await db.one<{ public_key: PublicEncryptionKey | null }>(
    'SELECT public_key FROM principals WHERE id=$1 FOR UPDATE', [binding.principalId], connection));
  if (await db.one('SELECT 1 FROM principal_key_bindings WHERE principal_id=$1 AND retired_at IS NULL', [binding.principalId], connection))
    fail(409, 'key_binding_changed', 'Replace the keys of this identity with a key rotation.');
  if (principal.public_key && !samePublicKey(principal.public_key, binding.encryption))
    fail(409, 'rekey_required', 'Use the existing encryption key when registering its signing key.');
  await connection.query('INSERT INTO principal_key_bindings(id,principal_id,binding,signature) VALUES($1,$2,$3,$4)',
    [binding.id, binding.principalId, JSON.stringify(binding), signed.signature]);
  await connection.query('UPDATE principals SET public_key=$2 WHERE id=$1', [binding.principalId, JSON.stringify(binding.encryption)]);
  await audit.record(binding.principalId, actorId, 'principal.bindKeys', binding.id, { generation: binding.generation }, connection);
  return binding;
}
