// Reads items saved in the first custody format, which named content kinds and operations by
// their product names, so that an authority can re-protect them in the current format.
// Delete this file once no item in the first format remains.
import { z } from 'zod';
import type { JWK } from 'jose';
import { Id, JsonObject, Sealed, Time } from './contracts.js';
import type { JsonValue } from './contracts.js';
import { base64url, encode, open } from './encryption.js';
import { Fingerprint, KeyBinding, Signature, canonical, hash, validateBinding, verify } from './authority.js';
import type { BoundKeys } from './authority.js';
import { AccessPolicy, ContentTypes, Operations, Origin, permittedOperations } from './custody.js';
import type { CustodyPolicy } from './custody.js';

const Kind = z.enum(['secret', 'connection', 'app']);
const OperationName = z.enum(['http', 'command', 'function', 'connect', 'refresh', 'revoke']);
const Grant = z.object({
  actor: KeyBinding, executor: KeyBinding, operations: z.array(OperationName).min(1).max(6),
  functionDigests: z.array(Fingerprint).max(100).default([]), origins: z.array(Origin).max(100).default([]),
  callerProgram: z.boolean().default(false), expiresAt: Time,
}).strict();
const Policy = z.object({
  format: z.literal(1), origin: Origin, id: Id, ownerId: Id, kind: Kind,
  revision: z.number().int().positive(),
  authorities: z.array(KeyBinding).min(1).max(100), readers: z.array(KeyBinding).min(1).max(100),
  grants: z.array(Grant).max(100), observers: z.array(Id).max(100).optional(),
  producers: z.array(z.unknown()).max(100).default([]),
}).strict();
export const LegacyContent = z.object({
  policy: Policy, authorityId: Id, authorization: Signature, lineage: z.array(z.unknown()).max(16).optional(),
  materialRevision: z.number().int().positive(), updatedAt: Time, creationRunId: Id.nullable(),
  metadata: JsonObject, sealed: Sealed, signerId: Id, signature: Signature,
}).strict();
export type LegacyItem = z.infer<typeof LegacyContent>;

export const isLegacy = (value: unknown): value is LegacyItem =>
  Boolean(value && typeof value === 'object' && (value as { policy?: { format?: unknown } }).policy?.format === 1);

const contentTypes = { secret: ContentTypes.value, connection: ContentTypes.tokenSet, app: ContentTypes.clientCredential } as const;

async function context(policy: z.infer<typeof Policy>, materialRevision: number) {
  return canonical({
    purpose: 'resource', origin: policy.origin, id: policy.id, ownerId: policy.ownerId,
    kind: policy.kind, policyDigest: await hash(policy), materialRevision,
  });
}

// Every first-format item was written by one of its authorities without a handoff; anything else
// must be re-protected by hand.
export async function verifyLegacy(input: unknown) {
  const content = LegacyContent.parse(input);
  if (content.lineage?.length) throw new Error('Re-protect items with a handoff history by hand.');
  for (const binding of [...content.policy.authorities, ...content.policy.readers,
    ...content.policy.grants.flatMap(grant => [grant.actor, grant.executor])]) await validateBinding(binding);
  const authority = content.policy.authorities.find(binding => binding.id === content.authorityId);
  const signer = content.policy.authorities.find(binding => binding.id === content.signerId);
  if (!authority || !signer) throw new Error('The item must be signed by one of its authorities.');
  await verify(content.policy, content.authorization, authority.signing, 'access-policy');
  const { signature, ...value } = content;
  await verify(value, signature, signer.signing, 'resource');
  if (content.sealed.aad !== base64url(encode(await context(content.policy, content.materialRevision))))
    throw new Error('The encrypted content belongs to a different item.');
  return content;
}

export async function revealLegacy(input: LegacyItem, binding: BoundKeys, privateKey: JWK | CryptoKey) {
  const content = await verifyLegacy(input);
  if (!content.policy.readers.some(reader => canonical(reader) === canonical(binding)))
    throw new Error('This identity cannot reveal the content.');
  return open(content.sealed, privateKey, binding.id, await context(content.policy, content.materialRevision));
}

// The current policy for a first-format item: the same item, owner, authorities, readers and
// grants, with ids in place of names and without operations its content type never supported.
export function upgradePolicy(legacy: LegacyItem['policy']): CustodyPolicy {
  const contentType = contentTypes[legacy.kind];
  const grants = legacy.grants.map(grant => ({
    ...grant, operations: grant.operations.map(name => Operations[name])
      .filter(operation => permittedOperations(contentType).includes(operation)),
  })).filter(grant => grant.operations.length);
  return AccessPolicy.parse({
    format: 2, origin: legacy.origin, id: legacy.id, ownerId: legacy.ownerId, contentType,
    revision: legacy.revision + 1, authorities: legacy.authorities, readers: legacy.readers, grants,
    ...(legacy.observers ? { observers: legacy.observers } : {}), producers: [],
  });
}

// Display names leave the signed metadata and travel as plain labels.
export function upgradeMetadata(legacy: LegacyItem) {
  const { methodName, account, ...metadata } = legacy.metadata as Record<string, JsonValue>;
  const labels = legacy.policy.kind === 'connection'
    ? { methodName: String(methodName ?? ''), account: String(account ?? '') } : undefined;
  return { metadata, ...(labels ? { labels } : {}) };
}
