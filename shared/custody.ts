import { z } from 'zod';
import type { JWK } from 'jose';
import { Id, JsonObject, Sealed, Time } from './contracts.js';
import type { JsonValue } from './contracts.js';
import { base64url, encode, open, seal } from './encryption.js';
import {
  Fingerprint, KeyBinding, Signature, canonical, hash, sign, validateBinding, verify,
} from './authority.js';
import type { BoundKeys, KeyMaterial } from './authority.js';

export const Origin = z.url().refine(value => {
  const url = new URL(value);
  return url.origin === value && !url.username && !url.password &&
    (url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)));
}, 'Use an HTTPS origin, or HTTP on localhost.');
// Signed data names things only by fixed ids. These values never change and are never shown;
// product names (variable, connection, application) map to them outside the seal.
export const ContentTypes = {
  value: '03546b17-fa44-409f-b151-8da1a398b324',
  tokenSet: '7d4b64dd-4546-4acb-8e96-91f864bccea6',
  clientCredential: '714fc044-2cce-4f3f-a477-281ee64fe632',
} as const;
export const ContentType = z.enum([ContentTypes.value, ContentTypes.tokenSet, ContentTypes.clientCredential]);
export type ContentTypeId = z.infer<typeof ContentType>;
export const contentLimit = 1_000_000;
// A token set is renewed by whoever it is sealed for: renewing changes no one who can open it.
export const renewable = (type: ContentTypeId) => type === ContentTypes.tokenSet;
// Who opens an item and who may change it and whom it is sealed for: readers open it, authorities also sign its policy and
// its content, and observers only see that it is there.
export const AccessPolicy = z.object({
  format: z.literal(3),
  origin: Origin,
  id: Id,
  ownerId: Id,
  contentType: ContentType,
  revision: z.number().int().positive(),
  authorities: z.array(KeyBinding).min(1).max(100),
  readers: z.array(KeyBinding).min(1).max(100),
  observers: z.array(Id).max(100).optional(),
}).strict();
export type CustodyPolicy = z.infer<typeof AccessPolicy>;
// The parts of a policy that its handoffs and changes of readers are judged by, whatever format sealed it.
export type PolicyParties = Pick<CustodyPolicy, 'origin' | 'id' | 'ownerId' | 'contentType' | 'revision' | 'authorities' | 'readers' | 'observers'>;
const AuthoritySet = z.object({ ownerId: Id, authorities: z.array(KeyBinding).min(1).max(100) }).strict();
const HandoffBody = z.object({ origin: Origin, id: Id, revision: z.number().int().positive(),
  from: AuthoritySet, to: AuthoritySet, policyDigest: Fingerprint, previous: Fingerprint.nullable(), signerId: Id }).strict();
export const AuthorityHandoff = HandoffBody.extend({ signature: Signature });
// Each change of an item's authorities adds a handoff; an item with this many accepts no further change of them.
export const lineageLimit = 16;
const Lineage = z.array(AuthorityHandoff).max(lineageLimit);
export const ProtectedContent = z.object({
  policy: AccessPolicy,
  authorityId: Id,
  authorization: Signature,
  lineage: Lineage.optional(),
  materialRevision: z.number().int().positive(),
  updatedAt: Time,
  metadata: JsonObject,
  sealed: Sealed,
  signerId: Id,
  signature: Signature,
}).strict();
export type CustodyContent = z.infer<typeof ProtectedContent>;

const authoritySet = (policy: Pick<PolicyParties, 'ownerId' | 'authorities'>) => ({ ownerId: policy.ownerId, authorities: policy.authorities });

export async function validateLineage(policy: PolicyParties, lineage: z.infer<typeof Lineage> = []) {
  let preceding: z.infer<typeof AuthorityHandoff> | undefined;
  for (const entry of lineage) {
    const { signature, ...body } = entry;
    if (entry.origin !== policy.origin || entry.id !== policy.id ||
      entry.revision > policy.revision || (preceding && (entry.revision <= preceding.revision ||
        canonical(preceding.to) !== canonical(entry.from))) ||
      entry.previous !== (preceding ? await hash(preceding) : null))
      throw new Error('Keep the signed chain of authority changes for this item.');
    const signer = entry.from.authorities.find(binding => binding.id === entry.signerId);
    if (!signer) throw new Error('Only an existing authority can hand over this item.');
    await verify(body, signature, signer.signing, 'authority-handoff');
    preceding = entry;
  }
  if (preceding && canonical(preceding.to) !== canonical(authoritySet(policy)))
    throw new Error('Use the authorities approved by the latest handoff.');
}

export function policyAuthority(content: { policy: PolicyParties } & Pick<CustodyContent, 'authorityId' | 'lineage'>): BoundKeys {
  const current = content.policy.authorities.find(binding => binding.id === content.authorityId);
  if (current) return current;
  const handoff = content.lineage?.at(-1);
  const prior = handoff?.revision === content.policy.revision
    ? handoff.from.authorities.find(binding => binding.id === content.authorityId) : undefined;
  if (!prior || prior.id !== handoff?.signerId) throw new Error('The policy must be signed by an approved authority.');
  return prior;
}

export function continuesPolicy(previous: PolicyParties, content: { policy: PolicyParties } & Pick<CustodyContent, 'lineage'>) {
  if (previous.id !== content.policy.id || previous.origin !== content.policy.origin ||
    previous.contentType !== content.policy.contentType) return false;
  const expected = canonical(authoritySet(previous));
  if (expected === canonical(authoritySet(content.policy))) return true;
  return Boolean(content.lineage?.some(entry => entry.revision > previous.revision && canonical(entry.from) === expected));
}

// The previous content is what its caller verified when it read it.
async function nextLineage(previous: Previous | undefined, policy: CustodyPolicy, signer: BoundKeys, keys: KeyMaterial) {
  const lineage = [...(previous?.lineage ?? [])];
  if (previous && canonical(authoritySet(previous.policy)) !== canonical(authoritySet(policy))) {
    if (!previous.policy.authorities.some(authority => canonical(authority) === canonical(signer)) ||
      previous.policy.id !== policy.id || previous.policy.origin !== policy.origin ||
      previous.policy.contentType !== policy.contentType ||
      policy.revision !== previous.policy.revision + 1)
      throw new Error('An existing authority must approve this handoff at the next policy revision.');
    const body = HandoffBody.parse({ origin: policy.origin, id: policy.id, revision: policy.revision,
      from: authoritySet(previous.policy), to: authoritySet(policy), policyDigest: await hash(policy),
      previous: lineage.length ? await hash(lineage.at(-1)) : null, signerId: signer.id });
    lineage.push({ ...body, signature: await sign(body, keys.signing, 'authority-handoff') });
  }
  return lineage.length ? { lineage: Lineage.parse(lineage) } : {};
}

type Previous = { policy: PolicyParties } & Pick<CustodyContent, 'lineage'>;

export async function validatePolicy(input: CustodyPolicy) {
  const policy = AccessPolicy.parse(input);
  const known = new Map<string, string>();
  for (const binding of [...policy.authorities, ...policy.readers]) {
    await validateBinding(binding);
    const serialized = canonical(binding);
    if (known.has(binding.id) && known.get(binding.id) !== serialized)
      throw new Error('Each key binding must identify the same keys throughout a policy.');
    known.set(binding.id, serialized);
  }
  for (const group of [policy.readers, policy.authorities])
    if (new Set(group.map(binding => binding.id)).size !== group.length)
      throw new Error('Choose distinct key bindings.');
  for (const authority of policy.authorities)
    if (!policy.readers.some(reader => reader.id === authority.id))
      throw new Error('A policy authority must be able to open its content.');
  return policy;
}

// The policy digest already covers the item, its owner and its content type.
export async function contentContext(policy: object, materialRevision: number) {
  return canonical({ purpose: 'resource', policyDigest: await hash(policy), materialRevision });
}

export async function protect(
  bytes: Uint8Array, input: CustodyPolicy, materialRevision: number,
  signer: BoundKeys, keys: KeyMaterial,
  metadata?: Record<string, JsonValue>,
  previous?: Previous,
): Promise<CustodyContent> {
  if (bytes.byteLength > contentLimit) throw new Error('The content exceeds its storage limit.');
  const policy = await validatePolicy(input);
  const lineage = await nextLineage(previous, policy, signer, keys);
  if (!policy.authorities.some(binding => canonical(binding) === canonical(signer)) &&
    lineage.lineage?.at(-1)?.revision !== policy.revision)
    throw new Error('Only a policy authority can replace its content.');
  const sealed = await seal(bytes, policy.readers.map(binding => ({
    id: binding.id, publicKey: binding.encryption,
  })), await contentContext(policy, materialRevision));
  const value = {
    policy, ...lineage, authorityId: signer.id, authorization: await sign(policy, keys.signing, 'access-policy'),
    materialRevision, updatedAt: new Date().toISOString(),
    metadata: metadata ?? (policy.contentType === ContentTypes.value ? { bytes: bytes.byteLength } : {}), sealed, signerId: signer.id,
  };
  const result = ProtectedContent.parse({ ...value, signature: await sign(value, keys.signing, 'resource') });
  await verifyContent(result);
  return result;
}

export async function verifyContent(input: CustodyContent) {
  const content = ProtectedContent.parse(input);
  const { signature, ...value } = content;
  await validatePolicy(content.policy);
  await validateLineage(content.policy, content.lineage);
  const authority = policyAuthority(content);
  const handoff = content.lineage?.at(-1);
  if (handoff?.revision === content.policy.revision && handoff.policyDigest !== await hash(content.policy))
    throw new Error('The handoff approves a different access policy.');
  await verify(content.policy, content.authorization, authority.signing, 'access-policy');
  // An authority replaces the content; a reader may also renew a token set it opens.
  const signer = (content.signerId === authority.id ? authority : undefined) ??
    content.policy.authorities.find(binding => binding.id === content.signerId) ??
    (renewable(content.policy.contentType) ? content.policy.readers.find(binding => binding.id === content.signerId) : undefined);
  if (!signer || Date.parse(content.updatedAt) > Date.now() + 30_000)
    throw new Error('The signer cannot replace this content.');
  await verify(value, signature, signer.signing, 'resource');
  const expected = content.policy.readers.map(binding => binding.id).sort();
  const addressed = content.sealed.recipients.map(recipient => recipient.header.kid).sort();
  if (canonical(expected) !== canonical(addressed) ||
    content.sealed.aad !== base64url(encode(await contentContext(content.policy, content.materialRevision))))
    throw new Error('Encrypt content for exactly the readers its policy names.');
  return content;
}

export async function renewContent(
  input: CustodyContent, bytes: Uint8Array, reader: BoundKeys, keys: KeyMaterial,
  metadata: Record<string, JsonValue> = input.metadata,
): Promise<CustodyContent> {
  const content = await verifyContent(input);
  if (!renewable(content.policy.contentType) || !content.policy.readers.some(binding => canonical(binding) === canonical(reader)))
    throw new Error('Only a reader of this connection can renew it.');
  if (bytes.byteLength > contentLimit) throw new Error('The content exceeds its storage limit.');
  const materialRevision = content.materialRevision + 1;
  const sealed = await seal(bytes, content.policy.readers.map(binding => ({
    id: binding.id, publicKey: binding.encryption,
  })), await contentContext(content.policy, materialRevision));
  const { signature: _signature, ...previous } = content;
  const value = { ...previous, materialRevision, updatedAt: new Date().toISOString(), metadata, sealed, signerId: reader.id };
  const result = { ...value, signature: await sign(value, keys.signing, 'resource') };
  await verifyContent(result);
  return result;
}

export async function reveal(
  input: CustodyContent, binding: BoundKeys, privateKey: JWK | CryptoKey,
): Promise<Uint8Array> {
  const content = await verifyContent(input);
  if (!content.policy.readers.some(reader => canonical(reader) === canonical(binding)))
    throw new Error('This identity cannot reveal the content.');
  return open(content.sealed, privateKey, binding.id,
    await contentContext(content.policy, content.materialRevision));
}
