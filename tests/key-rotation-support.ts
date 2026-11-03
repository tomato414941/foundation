import { randomUUID } from 'node:crypto';
import type { Actor } from '../server/authorization.js';
import type { Database } from '../server/database.js';
import type { Bindings } from '../server/bindings.js';
import { bindFirst } from '../server/bindings.js';
import type { KeyRotations } from '../server/key-rotations.js';
import { bindKeys, hash, newIdentityKeys, sign, signBinding } from '../shared/authority.js';
import type { BoundKeys, IdentityKeys } from '../shared/authority.js';
import { sealHandoff } from '../shared/key-rotations.js';

interface Holder { actor: Actor; binding: BoundKeys; keys: IdentityKeys }

// What a client sends to start replacing the holder's keys with new ones.
export async function rotationStart(holder: Holder) {
  const keys = await newIdentityKeys();
  const binding = { ...bindKeys(holder.actor.id, keys), generation: holder.binding.generation + 1,
    previous: await hash(holder.binding) };
  return { keys, binding, input: { id: randomUUID(), replacement: await signBinding(binding, keys),
    previousSignature: await sign(binding, holder.keys.signing, 'key-replacement'),
    handoff: await sealHandoff(holder.binding, binding, keys) } };
}

// Rotates the keys of a holder that has nothing encrypted yet.
export async function rotateKeys(rotations: KeyRotations, holder: Holder) {
  const { keys, binding, input } = await rotationStart(holder);
  await rotations.start(holder.actor, holder.actor.id, input);
  await rotations.commit(holder.actor, holder.actor.id, input.id);
  return { keys, binding };
}

// Replaces the keys without a signed history, as a key reset does once its waiting period has passed.
export async function resetKeys(db: Database, bindings: Bindings, holder: Holder) {
  const keys = await newIdentityKeys(), binding = bindKeys(holder.actor.id, keys);
  await db.pool.query('UPDATE principal_key_bindings SET retired_at=now() WHERE principal_id=$1 AND retired_at IS NULL',
    [holder.actor.id]);
  await db.pool.query('UPDATE principals SET public_key=$2 WHERE id=$1', [holder.actor.id, JSON.stringify(binding.encryption)]);
  const signed = await signBinding(binding, keys);
  await db.transaction(connection => bindFirst(connection, db, bindings.audit, holder.actor.id, signed));
  return { keys, binding };
}
