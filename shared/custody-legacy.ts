import { z } from 'zod';
import type { JWK } from 'jose';
import { Id, JsonObject, Sealed, Time } from './contracts.js';
import { base64url, encode, open } from './encryption.js';
import { KeyBinding, Signature, canonical, hash, validateBinding, verify } from './authority.js';
import type { BoundKeys } from './authority.js';
import { AuthorityHandoff, ContentType, ContentTypes, Origin, contentContext, lineageLimit, policyAuthority, validateLineage } from './custody.js';

// Items were once sealed under a policy that could also let a principal use them on an execution environment for a
// while, and let the environment renew a connection. This reads such an item so that one of its authorities can seal it
// again under the current policy, keeping as readers the principals who could still use it. It lives in its own file so
// that it can be removed once production holds none.
const refresh = '00bc45aa-7b68-4350-b73e-eda476c6236c';
const Grant = z.object({ executor: KeyBinding, actor: KeyBinding.optional(), operations: z.array(z.string()),
  expiresAt: Time.nullable() }).passthrough();
export const EarlierPolicy = z.object({
  format: z.literal(2), origin: Origin, id: Id, ownerId: Id, contentType: ContentType,
  revision: z.number().int().positive(),
  authorities: z.array(KeyBinding).min(1).max(100), readers: z.array(KeyBinding).min(1).max(100),
  grants: z.array(Grant).max(100), observers: z.array(Id).max(100).optional(),
  producers: z.array(z.never()).optional(),
}).strict();
export const EarlierContent = z.object({
  policy: EarlierPolicy, authorityId: Id, authorization: Signature,
  lineage: z.array(AuthorityHandoff).max(lineageLimit).optional(),
  materialRevision: z.number().int().positive(), updatedAt: Time, creationRunId: z.null(), metadata: JsonObject,
  sealed: Sealed, signerId: Id, signature: Signature,
}).strict();
export type EarlierSealed = z.infer<typeof EarlierContent>;
export const isEarlier = (content: { policy: { format: number } }): content is EarlierSealed => content.policy.format === 2;
const active = (grant: z.infer<typeof Grant>, at: number) => grant.expiresAt === null || Date.parse(grant.expiresAt) > at;

export async function verifyEarlier(input: EarlierSealed) {
  const content = EarlierContent.parse(input), { policy } = content, { signature, ...value } = content;
  for (const binding of [...policy.authorities, ...policy.readers, ...policy.grants.flatMap(grant =>
    grant.actor ? [grant.actor, grant.executor] : [grant.executor])]) await validateBinding(binding);
  await validateLineage(policy, content.lineage);
  const authority = policyAuthority(content);
  const handoff = content.lineage?.at(-1);
  if (handoff?.revision === policy.revision && handoff.policyDigest !== await hash(policy))
    throw new Error('The handoff approves a different access policy.');
  await verify(policy, content.authorization, authority.signing, 'access-policy');
  // An executor that could renew a connection also signed the renewed content.
  const signer = (content.signerId === authority.id ? authority : undefined) ??
    policy.authorities.find(binding => binding.id === content.signerId) ??
    (policy.contentType === ContentTypes.tokenSet ? policy.grants.find(grant => grant.executor.id === content.signerId &&
      grant.operations.includes(refresh) && active(grant, Date.parse(content.updatedAt)))?.executor : undefined);
  if (!signer) throw new Error('The signer cannot replace this content.');
  await verify(value, signature, signer.signing, 'resource');
  const expected = [...new Set([...policy.readers, ...policy.grants.map(grant => grant.executor)].map(binding => binding.id))].sort();
  if (canonical(expected) !== canonical(content.sealed.recipients.map(recipient => recipient.header.kid).sort()) ||
    content.sealed.aad !== base64url(encode(await contentContext(policy, content.materialRevision))))
    throw new Error('Encrypt content for exactly the recipients authorized by its policy.');
  return content;
}

export async function revealEarlier(input: EarlierSealed, binding: BoundKeys, privateKey: JWK | CryptoKey) {
  const content = await verifyEarlier(input);
  if (!content.policy.readers.some(reader => canonical(reader) === canonical(binding)))
    throw new Error('This identity cannot reveal the content.');
  return open(content.sealed, privateKey, binding.id, await contentContext(content.policy, content.materialRevision));
}

// The principals the policy still let use the item for themselves, by the keys they used it with.
export function earlierUsers(input: EarlierSealed, now = Date.now()) {
  return [...new Map(input.policy.grants.filter(grant => grant.actor && grant.actor.id === grant.executor.id && active(grant, now))
    .map(grant => [grant.executor.principalId, grant.executor])).values()];
}
