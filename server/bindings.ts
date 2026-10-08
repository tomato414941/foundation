import type { z } from 'zod';
import type { Actor, Authorization } from './authorization.js';
import type { Database, Queryable } from './database.js';
import type { Audit } from './audit.js';
import { SignedBinding, canonical, hash, verify, verifyBinding } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import type { PublicEncryptionKey } from '../shared/contracts.js';
import { samePublicKey } from './encryption-validation.js';
import { fail, required } from './errors.js';

export class Bindings {
  constructor(readonly db: Database, readonly authorization: Authorization, readonly audit: Audit) {}

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
    const current = await this.current(binding.principalId, connection);
    if (canonical(current.binding) !== canonical(binding))
      fail(409, 'key_binding_changed', 'This identity changed its keys. Review the new keys before continuing.');
    return current;
  }

  async publish(actor: Actor, input: z.infer<typeof SignedBinding>, previousSignature?: string) {
    const signed = SignedBinding.parse(input);
    const binding = await verifyBinding(signed);
    await this.authorization.requirePrincipal(actor, binding.principalId, 'credentials');
    return this.db.transaction(async connection => {
      const principal = required(await this.db.one<{ public_key: PublicEncryptionKey | null }>(
        'SELECT public_key FROM principals WHERE id=$1 FOR UPDATE', [binding.principalId], connection,
      ));
      const previous = await this.db.one<{ binding: BoundKeys; signature: string }>(
        'SELECT binding,signature FROM principal_key_bindings WHERE principal_id=$1 AND retired_at IS NULL',
        [binding.principalId], connection,
      );
      if (previous) {
        if (canonical(previous.binding) === canonical(binding)) return SignedBinding.parse(previous);
        if (!previousSignature || binding.generation !== previous.binding.generation + 1 ||
          binding.previous !== await hash(previous.binding))
          fail(409, 'key_binding_changed', 'Authorize replacement keys with the current signing key.');
        await verify(binding, previousSignature, previous.binding.signing, 'key-replacement');
        const inUse = await this.db.one(
          `SELECT 1 FROM resource_custody WHERE jsonb_path_exists(content,
            '$.policy.**.id ? (@ == $binding)', jsonb_build_object('binding',$1::text))
           UNION ALL SELECT 1 FROM executor_environments WHERE registration->'manifest'->'executor'->>'id'=$1 LIMIT 1`,
          [previous.binding.id], connection,
        );
        if (inUse) fail(409, 'rekey_required', 'Re-encrypt shared content and update execution environments before replacing these keys.');
        await connection.query('UPDATE principal_key_bindings SET retired_at=now() WHERE id=$1', [previous.binding.id]);
      } else if (binding.generation !== 1 || binding.previous !== null) {
        fail(400, 'invalid_key_binding', 'Start this identity with its first key binding.');
      } else if (principal.public_key && !samePublicKey(principal.public_key, binding.encryption)) {
        fail(409, 'rekey_required', 'Use the existing encryption key when registering its signing key.');
      }
      await connection.query(
        'INSERT INTO principal_key_bindings(id,principal_id,binding,signature) VALUES($1,$2,$3,$4)',
        [binding.id, binding.principalId, JSON.stringify(binding), signed.signature],
      );
      await connection.query('UPDATE principals SET public_key=$2 WHERE id=$1',
        [binding.principalId, JSON.stringify(binding.encryption)]);
      await this.audit.record(binding.principalId, actor.id, 'principal.bindKeys', binding.id,
        { generation: binding.generation }, connection);
      return signed;
    });
  }
}
