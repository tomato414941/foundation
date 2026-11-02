import { z } from 'zod';
import { Id, Name, Sealed, Time } from './contracts.js';
import {
  Fingerprint, KeyReplacement, PrivateKeys, Signature, SignedBinding, canonical, hash, publicPart, sign, signBinding, thumbprint,
  verifiesReplacement,
} from './authority.js';
import type { BoundKeys, IdentityKeys, KeyMaterial } from './authority.js';
import { bindKeys, newIdentityKeys } from './authority.js';
import { decode, encode, open, seal } from './encryption.js';
import { AccessPolicy, ProtectedContent, protect, reveal, verifyContent } from './custody.js';
import type { CustodyContent, CustodyPolicy } from './custody.js';
import { SignedEnvironment, signEnvironment } from './runtime-protocol.js';
import { FunctionSettingsApproval, approveFunctionSettings } from './function-api.js';
import { openKeyring, signKeyring } from './keyring.js';
import type { JsonApi } from './client.js';
import type { JWK } from 'jose';

export const RotationKind = z.enum(['content', 'result', 'environment', 'keyring', 'functionSettings']);
export const RotationStart = z.object({
  id: Id, replacement: SignedBinding, previousSignature: Signature, handoff: Sealed,
}).strict();
export const RotationHandoff = z.object({ replacement: KeyReplacement, handoff: Sealed }).strict();
export const RotationPayload = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('content'), content: ProtectedContent }).strict(),
  z.object({ kind: z.literal('result'), content: ProtectedContent }).strict(),
  z.object({ kind: z.literal('environment'), registration: SignedEnvironment }).strict(),
  z.object({ kind: z.literal('keyring'), signature: Signature }).strict(),
  z.object({ kind: z.literal('functionSettings'), approval: FunctionSettingsApproval }).strict(),
]);
export type PreparedRotationPayload = z.infer<typeof RotationPayload>;
export const RotationPreparation = z.object({
  sourceDigest: Fingerprint, payload: RotationPayload, signature: Signature,
}).strict();
export const RotationEndorsement = z.object({ sourceDigest: Fingerprint, payload: RotationPayload }).strict();
export const RotationSource = z.record(z.string(), z.unknown());
export const RotationItem = z.object({
  kind: RotationKind, id: Id, name: Name.nullable(), sourceDigest: Fingerprint,
  state: z.enum(['pending', 'prepared', 'stale']),
  // The principals that must sign the item when the rotating principal cannot: it only reads or runs the item.
  signers: z.array(Id).nullable(), source: RotationSource.nullable(),
});
export const RotationRequest = z.object({
  rotation: z.object({ id: Id, principalId: Id, previous: SignedBinding, replacement: SignedBinding,
    previousSignature: Signature }).strict(),
  kind: RotationKind, id: Id, name: Name, sourceDigest: Fingerprint, source: RotationSource,
}).strict();
export const RotationBlocker = z.object({ kind: z.string(), id: Id, reason: z.string() });
export const RotationView = z.object({
  id: Id, principalId: Id, state: z.enum(['preparing', 'committed', 'cancelled']),
  previous: SignedBinding, replacement: SignedBinding, previousSignature: Signature, handoff: Sealed,
  createdAt: Time, finishedAt: Time.nullable(),
  total: z.number().int().nonnegative(), prepared: z.number().int().nonnegative(),
  blockers: z.array(RotationBlocker), items: z.array(RotationItem), next: z.string().nullable(),
});

// A rotation changes key bindings, never the principals, permissions, destinations or expiry dates.
export function rotationPolicy(policy: CustodyPolicy, previous: BoundKeys, replacement: BoundKeys): CustodyPolicy {
  const replace = (binding: BoundKeys) => {
    if (binding.id !== previous.id) return binding;
    if (canonical(binding) !== canonical(previous)) throw new Error('Use the exact previous key binding.');
    return replacement;
  };
  return AccessPolicy.parse({
    ...policy, revision: policy.revision + 1,
    readers: policy.readers.map(replace), authorities: policy.authorities.map(replace),
    grants: policy.grants.map(grant => 'actor' in grant
      ? { ...grant, actor: replace(grant.actor), executor: replace(grant.executor) }
      : { ...grant, executor: replace(grant.executor) }),
    producers: policy.producers.map(producer => ({ ...producer, executor: replace(producer.executor) })),
  });
}

export async function prepareRotatedContent(
  content: CustodyContent, previous: BoundKeys, replacement: BoundKeys,
  signer: BoundKeys, keys: KeyMaterial, replacementKeys?: KeyMaterial,
) {
  const bytes = await reveal(content, signer, keys.encryption);
  const prepared = await protect(bytes, rotationPolicy(content.policy, previous, replacement),
    content.materialRevision + 1, signer, keys, content.metadata, content);
  if (signer.id !== previous.id) return prepared;
  if (!replacementKeys) throw new Error('Keep the replacement keys before preparing rotated content.');
  const { signature: _signature, ...body } = prepared;
  const value = { ...body, authorityId: replacement.id, signerId: replacement.id,
    authorization: await sign(prepared.policy, replacementKeys.signing, 'access-policy') };
  return verifyContent({ ...value, signature: await sign(value, replacementKeys.signing, 'resource') });
}

// Signed with the previous keys, so that possession of an API token alone cannot prepare a rotation.
export async function rotationPreparationProof(
  rotationId: string, principalId: string, replacementId: string, itemId: string,
  sourceDigest: string, payload: PreparedRotationPayload,
) {
  return { rotationId, principalId, replacementId, itemId, sourceDigest, payloadDigest: await hash(payload) };
}

export async function signRotationPreparation(
  rotationId: string, principalId: string, replacementId: string, itemId: string,
  sourceDigest: string, payload: PreparedRotationPayload, key: KeyMaterial['signing'],
) {
  return { sourceDigest, payload, signature: await sign(
    await rotationPreparationProof(rotationId, principalId, replacementId, itemId, sourceDigest, payload),
    key, 'key-rotation-preparation') };
}

// The replacement private keys, sealed for whoever holds the previous ones. Each passkey, sign-in key and device that
// opened the previous keys moves to the new ones with it, without the rotating device knowing their unlock secrets. A
// rotation therefore never excludes a holder of the previous keys; removing one is revocation, not rotation.
export const handoffContext = (replacement: BoundKeys) => 'key-handoff:' + replacement.principalId + ':' + replacement.id;
export function sealHandoff(previous: BoundKeys, replacement: BoundKeys, keys: IdentityKeys) {
  return seal(encode(JSON.stringify(keys)), [{ id: previous.id, publicKey: previous.encryption }], handoffContext(replacement));
}
export async function openHandoff(
  value: z.infer<typeof RotationHandoff>, previous: BoundKeys, key: KeyMaterial['encryption'],
): Promise<{ binding: BoundKeys; keys: IdentityKeys }> {
  const { replacement, handoff } = RotationHandoff.parse(value);
  if (canonical(replacement.previous.binding) !== canonical(previous))
    throw new Error('This key handoff follows other keys.');
  const binding = replacement.replacement.binding;
  if (!(await verifiesReplacement(previous, binding, [replacement])))
    throw new Error('The previous keys did not authorize these replacement keys.');
  const keys = PrivateKeys.parse(JSON.parse(decode(await open(handoff, key, previous.id, handoffContext(binding)))));
  await signBinding(binding, keys);
  return { binding, keys };
}

// The keys a device holds once it has followed every rotation since the keys it had: each handoff is opened with the
// keys before it. A passkey's wrap holds the private keys alone, so those are found by their public encryption key.
// Keys made again by a key reset have no handoff, and are opened with a passkey that holds them.
export async function followKeys(api: JsonApi, held: { binding: BoundKeys; keys: KeyMaterial }
  | { principalId: string; keys: IdentityKeys }) {
  const id = Id.parse('binding' in held ? held.binding.principalId : held.principalId);
  const handoffs = '/api/principals/' + id + '/key-handoffs';
  let binding: BoundKeys | null = 'binding' in held ? held.binding : null, keys: KeyMaterial = held.keys,
    followed: IdentityKeys | null = null;
  for (let step = 0; step <= 32; step++) {
    const { binding: current } = await api.json('/api/identities/' + id + '/binding', {}, SignedBinding);
    if (binding ? canonical(current) === canonical(binding)
      : await thumbprint(current.encryption) === await thumbprint(publicPart(held.keys.encryption as JWK)))
      return followed ? { binding: current, keys: followed } : null;
    if ((binding && current.generation <= binding.generation) || step === 32)
      throw new KeysReplaced('The keys of this identity were made again. Sign in with a passkey that holds them.');
    const handoff = await api.json(binding ? handoffs + '/' + Id.parse(binding.id)
      : handoffs + '?' + new URLSearchParams({ encryption: await thumbprint(publicPart(held.keys.encryption as JWK)) }),
    {}, RotationHandoff);
    const previous = binding ?? handoff.replacement.previous.binding;
    if (!binding && await thumbprint(previous.encryption) !== await thumbprint(publicPart(held.keys.encryption as JWK)))
      throw new Error('This key handoff follows other keys.');
    const next = await openHandoff(handoff, previous, keys.encryption);
    ({ binding } = next);
    keys = followed = next.keys;
  }
  return null;
}
export class KeysReplaced extends Error {
  readonly code = 'keys_replaced';
  constructor(message: string, readonly environmentId?: string) { super(message); }
}

type Item = z.infer<typeof RotationItem>;
const RotationState = z.object({ rotation: RotationView.nullable() });
export type RotationResult =
  | { state: 'committed'; binding: BoundKeys; keys: IdentityKeys }
  | { state: 'blocked'; rotationId: string; blockers: Array<z.infer<typeof RotationBlocker>> }
  | { state: 'waiting'; rotationId: string; waiting: Array<{ kind: string; id: string; name: string | null; signers: string[] }> };

// Replaces this principal's keys with new ones. It prepares every item the principal signs, and commits once all are
// prepared; items that other principals sign wait for them, and calling it again continues the same rotation.
export async function rotateKeys(api: JsonApi, held: { binding: BoundKeys; keys: IdentityKeys }): Promise<RotationResult> {
  const { binding: previous, keys } = held, principalId = Id.parse(previous.principalId);
  const base = '/api/principals/' + principalId + '/key-rotations';
  let { rotation } = await api.json(base, {}, RotationState), next: { binding: BoundKeys; keys: IdentityKeys };
  if (rotation) {
    next = await openHandoff({ replacement: { previous: rotation.previous, replacement: rotation.replacement,
      previousSignature: rotation.previousSignature }, handoff: rotation.handoff }, previous, keys.encryption);
  } else {
    const replacementKeys = await newIdentityKeys();
    const binding = { ...bindKeys(principalId, replacementKeys), generation: previous.generation + 1,
      previous: await hash(previous) };
    next = { binding, keys: replacementKeys };
    rotation = await api.json(base, { method: 'POST', body: { id: crypto.randomUUID(),
      replacement: await signBinding(binding, replacementKeys),
      previousSignature: await sign(binding, keys.signing, 'key-replacement'),
      handoff: await sealHandoff(previous, binding, replacementKeys) } }, RotationView);
  }
  const path = base + '/' + Id.parse(rotation.id);
  for (let attempt = 0; attempt < 5; attempt++) {
    const waiting: Item[] = [];
    let after: string | null = null, blockers: Array<z.infer<typeof RotationBlocker>> = [];
    do {
      const page: z.infer<typeof RotationView> = await api.json(path + '?' + new URLSearchParams({ limit: '100',
        ...(after ? { after } : {}) }), {}, RotationView);
      blockers = page.blockers.filter(blocker => blocker.reason === 'authority_history_full');
      for (const item of page.items) {
        if (item.state === 'prepared' || blockers.some(blocker => blocker.id === item.id)) continue;
        if (item.signers) { waiting.push(item); continue; }
        const payload = await rotationPayload(item, previous, next, keys);
        await api.json(path + '/items/' + item.kind + '/' + item.id, { method: 'PUT', body: await signRotationPreparation(
          rotation.id, principalId, next.binding.id, item.id, item.sourceDigest, payload, keys.signing) });
      }
      after = page.next;
    } while (after);
    // An item that accepts no further change of its authorities keeps this rotation from finishing; it stays prepared
    // as far as it can be, and can be cancelled.
    if (blockers.length) return { state: 'blocked', rotationId: rotation.id, blockers };
    if (waiting.length) return { state: 'waiting', rotationId: rotation.id,
      waiting: waiting.map(item => ({ kind: item.kind, id: item.id, name: item.name, signers: item.signers! })) };
    try {
      await api.json(path + '/commit', { method: 'POST' }, RotationView);
      return { state: 'committed', ...next };
    } catch (error) {
      // An item changed while it was prepared, or another write held the keys: prepare what changed and try again.
      if (!(error && typeof error === 'object' && 'code' in error &&
        ['rotation_not_ready', 'rotation_busy', 'changed'].includes(String(error.code)))) throw error;
    }
  }
  throw new Error('The items kept changing during the key rotation. Try again later.');
}

async function rotationPayload(item: Item, previous: BoundKeys, next: { binding: BoundKeys; keys: IdentityKeys },
  keys: IdentityKeys): Promise<PreparedRotationPayload> {
  const source = item.source as Record<string, any> | null;
  if (!source) throw new Error('This identity cannot read an item it must prepare.');
  switch (item.kind) {
    case 'content':
    case 'result':
      return { kind: item.kind, content: await prepareRotatedContent(ProtectedContent.parse(
        item.kind === 'content' ? source.content : source.receipt.content), previous, next.binding, previous, keys, next.keys) };
    case 'environment': {
      const { manifest } = SignedEnvironment.parse(source.registration);
      return { kind: 'environment', registration: await signEnvironment({ ...manifest, executor: next.binding,
        revision: manifest.revision + 1 }, next.keys) };
    }
    case 'keyring': {
      const keyring = await openKeyring(String(source.signature), previous);
      return { kind: 'keyring', signature: await signKeyring({ ...keyring, signerId: next.binding.id,
        revision: keyring.revision + 1, keys: keyring.keys.map(entry => entry.binding.id === previous.id
          ? { ...entry, binding: next.binding } : entry) }, next.keys.signing) };
    }
    case 'functionSettings': {
      const { signature: _signature, ...approval } = FunctionSettingsApproval.parse(source.approval);
      return { kind: 'functionSettings', approval: await approveFunctionSettings({ ...approval, revision: approval.revision + 1,
        executor: next.binding, author: next.binding }, next.keys) };
    }
  }
}

// What an authority of an item signs for another principal's rotation: the item with that principal's keys replaced,
// signed with the authority's own keys as any change to the item. The caller checks the replacement first.
export async function endorsementPayload(request: z.infer<typeof RotationRequest>, signer: BoundKeys,
  keys: KeyMaterial): Promise<PreparedRotationPayload> {
  const previous = request.rotation.previous.binding, next = request.rotation.replacement.binding;
  const source = request.source as Record<string, any>;
  switch (request.kind) {
    case 'content':
    case 'result':
      return { kind: request.kind, content: await prepareRotatedContent(ProtectedContent.parse(
        request.kind === 'content' ? source.content : source.receipt.content), previous, next, signer, keys) };
    case 'functionSettings': {
      const { signature: _signature, ...approval } = FunctionSettingsApproval.parse(source.approval);
      if (canonical(approval.author) !== canonical(signer)) throw new Error('Another identity approved these settings.');
      return { kind: 'functionSettings', approval: await approveFunctionSettings({ ...approval,
        revision: approval.revision + 1, executor: next }, keys) };
    }
    default: throw new Error('Only the rotating identity prepares this item.');
  }
}
