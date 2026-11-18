import { z } from 'zod';
import { RequestView } from './operations.js';
import { CatalogMethod, Id, Resource, listOf } from './contracts.js';
import { catalogDefinition, methodDigest, methodRules } from './connection-methods.js';
import { connectionLabels, connectionMetadata, openConnection, sealedConnection } from './connections.js';
import { earlierConnection } from './connection-legacy.js';
import type { JsonValue, ResourceView } from './contracts.js';
import { endorsementPayload, RotationRequest } from './key-rotations.js';
import { KeyReplacement, SignedBinding, canonical, fingerprint, hash, verifyBinding, verifiesReplacement } from './authority.js';
import type { BoundKeys, KeyMaterial } from './authority.js';
import {
  AccessPolicy, ContentTypes, continuesPolicy, policyAuthority, protect, reveal, verifyContent,
} from './custody.js';
import type { ContentTypeId, CustodyContent, CustodyPolicy, PolicyParties } from './custody.js';
import { earlierUsers, isEarlier, revealEarlier, verifyEarlier } from './custody-legacy.js';
import type { EarlierSealed } from './custody-legacy.js';
import { BoundRecipient, KeySharingItem, Reprotection, StoredRead, TransferRecipients } from './protocol.js';
import type { ProtectedWrite } from './protocol.js';
import { isProtected } from './protected.js';
import { KeyringState, keyringClaim, openKeyring, signKeyring } from './keyring.js';
import type { KeyringEntryValue, KeyringValue } from './keyring.js';

export interface JsonApi {
  json<T = unknown>(path: string, options?: { method?: string; body?: unknown; signal?: AbortSignal }, schema?: z.ZodType<T>): Promise<T>;
}
export interface TrustStore {
  // Keys this device verified before identities kept them in their keyrings. They still count, and are moved there.
  binding(principalId: string): Promise<BoundKeys | null>;
  bindings(): Promise<BoundKeys[]>;
  rememberBinding(binding: BoundKeys): Promise<void>;
  // The last revision of this identity's keyring the device saw, so that an older list is not taken for it.
  keyring(): Promise<{ revision: number; digest: string } | null>;
  rememberKeyring(seen: { revision: number; digest: string }): Promise<void>;
  // What this device last observed of the content's item. Each policy format keeps its own record, so a
  // new format starts fresh instead of reading records written in another one.
  checkpoint(content: { policy: { format: number; id: string } }):
    Promise<{ policy: PolicyParties; materialRevision: number; digest: string } | null>;
  rememberContent(content: CustodyContent | EarlierSealed): Promise<void>;
}
export class ClientFailure extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}
export type RecipientVerification = { id: string; name: string; code: 'identity_untrusted' | 'identity_changed' };
export type RecipientAccess = { id: string; name: string; excluded: RecipientVerification[]; operation?: 'transfer' };
export class IdentityVerificationRequired extends ClientFailure {
  constructor(readonly recipient: RecipientVerification) {
    super(recipient.code, 'Verify the public keys of ' + recipient.name + ' (' + recipient.id + ') before continuing.');
  }
}
const errorIs = (error: unknown, ...codes: Array<string | number>) => !!error && typeof error === 'object' &&
  (('code' in error && codes.includes(String(error.code))) || ('status' in error && codes.includes(Number(error.status))));
// Items without encrypted content use the same transfer operation without opening this device's private keys.
export async function transferResource(api: JsonApi, id: string, to: string, open: () => CustodyClient | Promise<CustodyClient>) {
  Id.parse(to);
  const resource = await api.json('/api/resources/' + Id.parse(id), {}, Resource);
  if (isProtected(resource.kind)) return (await open()).transferProtected(resource, to);
  return api.json('/api/resources/' + id + '/transfer', { method: 'POST', body: { to, version: resource.version } },
    z.union([Resource, RequestView]));
}
export class CustodyClient {
  private verifiedKeys?: Promise<Map<string, KeyringEntryValue>>;
  private readonly exclusions = new Map<string, RecipientVerification[]>();
  private readonly pendingExclusions = new Map<string, RecipientVerification[]>();
  constructor(readonly api: JsonApi, readonly origin: string, readonly binding: BoundKeys,
    readonly keys: KeyMaterial, readonly trust: TrustStore, readonly onRecipientAccess?: (access: RecipientAccess) => void) {}

  async trusted(binding: BoundKeys) {
    if (!(await this.verifies(binding))) {
      const known = binding.principalId === this.binding.principalId ? this.binding : await this.known(binding.principalId);
      if (known && binding.principalId !== this.binding.principalId && binding.generation > known.generation) {
        if (await this.connectedKeys(known, binding)) {
          const verifiedAt = new Date().toISOString();
          try {
            await this.changeKeyring(keys => [...keys.filter(entry => entry.binding.principalId !== binding.principalId),
              { binding, verifiedAt }]);
          } catch (error) { if (!errorIs(error, 401, 403)) throw error; }
          (await this.keyring()).set(binding.principalId, { binding, verifiedAt });
          await this.trust.rememberBinding(binding);
          return binding;
        }
      }
      // Keys verified before and since replaced are told apart from keys never verified, to be verified again.
      if (binding.principalId !== this.binding.principalId && await this.known(binding.principalId))
        throw new ClientFailure('identity_changed', 'Identity ' + binding.principalId + ' replaced the keys verified before. Verify its current keys.');
      throw new ClientFailure('identity_untrusted', 'Verify and trust the encryption and signing keys for identity ' + binding.principalId + ' before sharing.');
    }
    return binding;
  }
  private async connectedKeys(previous: BoundKeys, next: BoundKeys) {
    if (previous.principalId !== next.principalId) return false;
    // Each step is one request; an identity rotated more often than this is verified again by hand instead.
    if (next.generation - previous.generation > 32) return false;
    let current = previous;
    while (current.generation < next.generation) {
      const { replacement } = await this.api.json('/api/identities/' + Id.parse(next.principalId) +
        '/key-replacements/' + Id.parse(current.id), {}, z.object({ replacement: KeyReplacement.nullable() }));
      if (!replacement || !await verifiesReplacement(current, replacement.replacement.binding, [replacement])) return false;
      current = replacement.replacement.binding;
    }
    return canonical(current) === canonical(next);
  }
  // Whether this identity verified the keys: its own, those in its keyring, or those this device verified before
  // keyrings. A keyring's entry for a principal decides over what this device verified earlier.
  private async verifies(binding: BoundKeys) {
    if (binding.principalId === this.binding.principalId) return canonical(this.binding) === canonical(binding);
    const known = await this.known(binding.principalId);
    return !!known && canonical(known) === canonical(binding);
  }
  private async known(principalId: string) {
    return (await this.keyring()).get(principalId)?.binding ?? await this.trust.binding(principalId);
  }
  // Whether this identity verified another's current keys: not until it does, and not again once they change.
  async verifiedIdentity(id: string) {
    return this.verifies((await this.inspectIdentity(id)).binding);
  }
  // The keys this identity verified on any of its devices, by principal.
  keyring() {
    return this.verifiedKeys ??= this.loadKeyring().catch(error => { this.verifiedKeys = undefined; throw error; });
  }
  private async loadKeyring() {
    let keys: KeyringEntryValue[];
    try { keys = (await this.readKeyring()).keyring?.keys ?? []; }
    catch (error) {
      // Where this identity may not read its keyring, as through a link made for one request, only this device's keys count.
      if (errorIs(error, 401, 403)) return new Map<string, KeyringEntryValue>();
      throw error;
    }
    const listed = new Set(keys.map(entry => entry.binding.principalId)), verifiedAt = new Date().toISOString();
    const moving = (await this.trust.bindings())
      .filter(binding => binding.principalId !== this.binding.principalId && !listed.has(binding.principalId));
    if (moving.length) {
      try {
        keys = (await this.changeKeyring(current => [...current, ...moving
          .filter(binding => !current.some(entry => entry.binding.principalId === binding.principalId))
          .map(binding => ({ binding, verifiedAt }))])).keys;
      } catch (error) {
        // They still count on this device and are moved another time.
        if (error instanceof ClientFailure) throw error;
      }
    }
    return new Map(keys.map(entry => [entry.binding.principalId, entry]));
  }
  // The keyring as this identity signed it, refused when it is older than the one this device last saw.
  private async readKeyring(): Promise<{ version: number | null; revision: number; keyring: KeyringValue | null }> {
    const path = '/api/principals/' + this.binding.principalId + '/keyring';
    const { keyring: stored } = await this.api.json(path, {}, KeyringState), seen = await this.trust.keyring();
    const conflict = () => new ClientFailure('keyring_conflict',
      'The list of verified public keys does not match what this device saw before.');
    if (!stored) {
      if (seen) throw conflict();
      return { version: null, revision: 0, keyring: null };
    }
    const claim = keyringClaim(stored.signature);
    // A list signed with keys this identity has since replaced is not read; the next change writes over it.
    if (claim.signerId !== this.binding.id) return { version: stored.version, revision: claim.revision, keyring: null };
    const keyring = await openKeyring(stored.signature, this.binding).catch(() => { throw conflict(); });
    const digest = await hash(keyring);
    if (keyring.ownerId !== this.binding.principalId || keyring.origin !== this.origin || (seen &&
      (keyring.revision < seen.revision || (keyring.revision === seen.revision && digest !== seen.digest)))) throw conflict();
    if (!seen || keyring.revision > seen.revision) await this.trust.rememberKeyring({ revision: keyring.revision, digest });
    return { version: stored.version, revision: keyring.revision, keyring };
  }
  // Signs the changed list as the next revision, reading it again when another device changed it first.
  private async changeKeyring(change: (keys: KeyringEntryValue[]) => KeyringEntryValue[]) {
    for (let attempt = 1; ; attempt++) {
      const current = await this.readKeyring();
      const keyring: KeyringValue = { origin: this.origin, ownerId: this.binding.principalId, signerId: this.binding.id,
        revision: current.revision + 1, keys: change(current.keyring?.keys ?? []) };
      try {
        await this.api.json('/api/principals/' + this.binding.principalId + '/keyring', { method: 'PUT',
          body: { version: current.version, signature: await signKeyring(keyring, this.keys.signing) } }, KeyringState);
      } catch (error) {
        if (attempt < 3 && errorIs(error, 'changed')) continue;
        throw error;
      }
      await this.trust.rememberKeyring({ revision: keyring.revision, digest: await hash(keyring) });
      return keyring;
    }
  }
  async inspectIdentity(id: string) {
    const signed = await this.api.json('/api/identities/' + Id.parse(id) + '/binding', {}, SignedBinding);
    await verifyBinding(signed);
    return { ...signed, fingerprint: await fingerprint(signed.binding) };
  }
  // Adds the verified keys to this identity's keyring, for each of its devices to use.
  async trustIdentity(id: string, expectedFingerprint: string) {
    const identity = await this.inspectIdentity(id);
    if (identity.fingerprint !== expectedFingerprint) throw new ClientFailure('fingerprint_mismatch', 'The identity fingerprint does not match.');
    if (id === this.binding.principalId || canonical((await this.keyring()).get(id)?.binding ?? null) === canonical(identity.binding))
      return identity;
    const verifiedAt = new Date().toISOString();
    try {
      const keyring = await this.changeKeyring(keys =>
        [...keys.filter(entry => entry.binding.principalId !== id), { binding: identity.binding, verifiedAt }]);
      this.verifiedKeys = Promise.resolve(new Map(keyring.keys.map(entry => [entry.binding.principalId, entry])));
    } catch (error) {
      // Where this identity may not change its keyring, as through a link made for one request, this device keeps it.
      if (!errorIs(error, 401, 403)) throw error;
      await this.trust.rememberBinding(identity.binding);
    }
    return identity;
  }
  async recipients(ownerId: string) {
    const { items } = await this.api.json('/api/principals/' + Id.parse(ownerId) + '/bound-recipients', {}, listOf(BoundRecipient));
    const delegates = await this.api.json('/api/principals/' + ownerId + '/bound-delegates', {}, listOf(BoundRecipient));
    return this.verifiedRecipients(ownerId, items, delegates.items);
  }
  private async verifiedRecipients(ownerId: string, items: z.infer<typeof BoundRecipient>[], delegates: z.infer<typeof BoundRecipient>[]) {
    if (!items.length) throw new Error('Set up an encryption key for the owner before saving private content.');
    for (const { name, ...item } of items) {
      await verifyBinding(item);
      try { await this.trusted(item.binding); }
      catch (error) {
        if (!(error instanceof ClientFailure) || error.code !== 'identity_untrusted' && error.code !== 'identity_changed') throw error;
        throw new IdentityVerificationRequired({ id: item.binding.principalId, name, code: error.code });
      }
    }
    // The owner permits its delegates, but only this identity's verified keys authorize encryption for them.
    const verified: BoundKeys[] = [], unverified: RecipientVerification[] = [];
    for (const { name, ...item } of delegates) {
      await verifyBinding(item);
      try { verified.push(await this.trusted(item.binding)); }
      catch (error) {
        if (!(error instanceof ClientFailure) || error.code !== 'identity_untrusted' && error.code !== 'identity_changed') throw error;
        unverified.push({ id: item.binding.principalId, name, code: error.code });
      }
    }
    this.exclusions.set(ownerId, unverified);
    return [...items.map(item => item.binding), ...verified];
  }
  private async ownerRecipients(ownerId: string, previous?: CustodyPolicy) {
    const current = new Map([...(await this.recipients(ownerId)), this.binding].map(binding => [binding.principalId, binding]));
    const excluded = new Set(this.exclusions.get(ownerId)?.map(recipient => recipient.id));
    const include = (values: BoundKeys[]) => [...new Map([
      ...values.filter(binding => !excluded.has(binding.principalId)).map(binding => current.get(binding.principalId) ?? binding), ...current.values(),
    ].map(binding => [binding.principalId, binding])).values()];
    return { readers: include(previous?.readers ?? []), authorities: include(previous?.authorities ?? []) };
  }
  // Everyone who uses what the owner holds, whether or not this identity has verified their keys.
  async ownerSide(ownerId: string) {
    const verified = await this.recipients(ownerId);
    return new Set([...verified.map(binding => binding.principalId), ...(this.exclusions.get(ownerId) ?? []).map(recipient => recipient.id)]);
  }
  async refreshRecipients(policy: CustodyPolicy) {
    const recipients = await this.ownerRecipients(policy.ownerId, policy);
    const changed = canonical(recipients) !== canonical({ readers: policy.readers, authorities: policy.authorities });
    return { ...policy, ...recipients, revision: policy.revision + (changed ? 1 : 0) };
  }
  async read(id: string) {
    const item = await this.latest(id);
    if (item.replaced)
      throw new ClientFailure('key_replaced', 'This item is sealed only for keys this identity has since replaced. Enter its value again.');
    return item;
  }
  // The item as sealed now, to seal its next value: what this identity opens, or, sealed only for keys this identity has
  // since replaced, the item to seal anew with its current keys. Nothing opens its earlier value any more.
  async latest(id: string): Promise<{ content: CustodyContent; version: number; replaced: boolean }> {
    const item = await this.api.json('/api/custody/' + Id.parse(id), {}, StoredRead);
    if (isEarlier(item.content)) {
      // Sealed under the earlier policy: one of its authorities seals it again under the current one first.
      await this.reformat(id, { content: item.content, version: item.version });
      const current = await this.api.json('/api/custody/' + Id.parse(id), {}, StoredRead);
      if (isEarlier(current.content)) throw new ClientFailure('content_conflict', 'The item was not sealed again.');
      return this.checked(id, { content: current.content, version: current.version });
    }
    return this.checked(id, { content: item.content, version: item.version });
  }
  private async checked(id: string, item: { content: CustodyContent; version: number }) {
    if (this.replaces(item.content.policy)) return { ...item, replaced: true };
    await this.observe(item.content, id);
    return { ...item, replaced: false };
  }
  private replaces(policy: Pick<PolicyParties, 'readers'>) {
    return !policy.readers.some(reader => canonical(reader) === canonical(this.binding)) &&
      policy.readers.some(reader => reader.principalId === this.binding.principalId);
  }
  async observe(input: CustodyContent, id = input.policy.id) {
    const content = await verifyContent(input);
    if (content.policy.id !== id || content.policy.origin !== this.origin) throw new Error('The encrypted content belongs to another item.');
    const author = policyAuthority(content);
    await this.trusted(author);
    const observed = await this.trust.checkpoint(content);
    if (observed) AccessPolicy.parse(observed.policy);
    if (observed) {
      if (content.policy.revision < observed.policy.revision || content.materialRevision < observed.materialRevision ||
        (content.policy.revision === observed.policy.revision && canonical(content.policy) !== canonical(observed.policy)) ||
        (content.materialRevision === observed.materialRevision && await hash(content) !== observed.digest))
        throw new ClientFailure('content_conflict', 'The encrypted content is older than this device has already observed.');
      // A signer that replaced its keys continues what it signed for with its current keys, verified here as above.
      if (content.policy.revision > observed.policy.revision &&
        !continuesPolicy(observed.policy, content) && !observed.policy.authorities.some(authority =>
          authority.principalId === author.principalId && authority.id !== author.id))
        throw new ClientFailure('content_conflict', 'An existing policy authority must approve the new recipients.');
    }
    await this.trust.rememberContent(content);
    return content;
  }
  async reveal(id: string) {
    return reveal((await this.read(id)).content, this.binding, this.keys.encryption);
  }
  // A connection as its holder reads it to change it: what is sealed of it, with its method as the method now is.
  async connection(id: string) {
    const { content } = await this.read(id), bytes = await reveal(content, this.binding, this.keys.encryption);
    const method = catalogDefinition(await this.api.json('/api/connections/' + Id.parse(id) + '/method', {}, CatalogMethod));
    return openConnection(bytes, content.metadata, method);
  }
  async sharing(input: string | Array<z.infer<typeof KeySharingItem>>) {
    const items = typeof input === 'string' ? (await this.api.json(input, {}, listOf(KeySharingItem))).items : input;
    const updates: Record<string, { version: number; content: CustodyContent }> = {};
    for (const item of items) {
      const current = await this.read(item.id);
      if (current.version !== item.version || canonical(current.content) !== canonical(item.content))
        throw new ClientFailure('content_conflict', 'Review the current content before changing its readers.');
      for (const recipient of item.policy.readers) await this.trusted(recipient);
      updates[item.id] = { version: item.version,
        content: await protect(await reveal(current.content, this.binding, this.keys.encryption), item.policy,
          current.content.materialRevision + 1, this.binding, this.keys, current.content.metadata, current.content) };
    }
    return updates;
  }
  // The policy for an item: carried on from its previous one, or new. One sealed only for keys this identity has since
  // replaced is sealed anew as the same item, at its next revision.
  async policy(ownerId: string, contentType: ContentTypeId,
    options: { id?: string; previous?: CustodyPolicy; replacing?: CustodyPolicy } = {}) {
    const { readers, authorities } = await this.ownerRecipients(ownerId, options.previous);
    if (!readers.some(reader => canonical(reader) === canonical(this.binding)))
      throw new Error('Include your own identity as a reader before creating this item.');
    return AccessPolicy.parse({ format: 3, id: options.id ?? options.previous?.id ?? options.replacing?.id ?? crypto.randomUUID(),
      origin: this.origin, ownerId, contentType, revision: (options.previous?.revision ?? options.replacing?.revision ?? 0) + 1,
      authorities, readers, ...(options.previous?.observers ? { observers: options.previous.observers } : {}) });
  }
  async save(name: string, bytes: Uint8Array, policy: CustodyPolicy,
    options: { metadata?: Record<string, JsonValue>; labels?: z.infer<typeof import('./connections.js').ConnectionLabels>;
      previous?: { content: CustodyContent | EarlierSealed; version: number };
      commit?: (write: z.infer<typeof ProtectedWrite>) => Promise<ResourceView> } = {}) {
    const previous = options.previous;
    if (previous && canonical(policy) === canonical({ ...previous.content.policy, revision: policy.revision }))
      policy = { ...policy, revision: previous.content.policy.revision };
    // What only replaced keys signed for is not handed over: it is sealed anew, following on from its revisions.
    const content = await protect(bytes, policy, (previous?.content.materialRevision ?? 0) + 1,
      this.binding, this.keys, options.metadata, previous && !this.replaces(previous.content.policy) ? previous.content : undefined);
    const write = { name, content, ...(options.labels ? { labels: options.labels } : {}), ...(previous ? { version: previous.version } : {}) };
    const resource = options.commit ? await options.commit(write) : await this.api.json('/api/resources/' + policy.id + '/custody',
      { method: 'PUT', body: write }, Resource);
    await this.trust.rememberContent(content);
    this.onRecipientAccess?.({ id: resource.id, name: resource.name, excluded: this.exclusions.get(policy.ownerId) ?? [] });
    return resource;
  }
  // The device opens and re-encrypts the item. The server keeps its current ownership and content until acceptance.
  async transferProtected(resource: ResourceView, to: string) {
    const path = '/api/resources/' + resource.id + '/transfer';
    const previous = await this.read(resource.id);
    if (previous.version !== resource.version)
      throw new ClientFailure('changed', 'This item changed. Reload it before transferring it.');
    const recipients = await this.api.json(path + '-recipients?to=' + encodeURIComponent(to), {}, TransferRecipients);
    const readers = await this.verifiedRecipients(to, recipients.required, recipients.delegates);
    const policy = { ...previous.content.policy, ownerId: to, revision: previous.content.policy.revision + 1,
      readers, authorities: readers, observers: [] };
    const content = await protect(await reveal(previous.content, this.binding, this.keys.encryption), policy, previous.content.materialRevision + 1,
      this.binding, this.keys, previous.content.metadata, previous.content);
    const result = await this.api.json(path, { method: 'POST',
      body: { to, content, version: previous.version } }, z.union([Resource, RequestView]));
    if ('kind' in result) await this.trust.rememberContent(content);
    this.onRecipientAccess?.({ id: result.id, name: resource.name, operation: 'transfer', excluded: this.exclusions.get(to) ?? [] });
    // The recipient verifies the sender from the link it received, rather than trusting a key supplied by the server.
    return 'kind' in result ? result : { ...result,
      url: result.url + (result.url.includes('#') ? '&' : '#') + 'fingerprint=' + await fingerprint(this.binding) };
  }
  // Items the server cannot seal again itself, because only their readers can open them. The list
  // only says where to look: each item is checked here before anything changes.
  async pendingProtection() {
    return (await this.api.json('/api/principals/' + this.binding.principalId + '/reprotection', {}, listOf(Reprotection))).items;
  }
  // Seals the item again without the principals that may no longer open it, for whoever now uses what its owner holds
  // and whose keys this device has verified, and for the current keys of those it is sealed for. An item still sealed
  // under the earlier policy is sealed again under the current one when it is read.
  async reprotect(id: string, reason: z.infer<typeof Reprotection>['reason'] = 'recipients', remove: string[] = []) {
    if (reason === 'format') return (await this.latest(id)).content.policy.id;
    const previous = await this.read(id), { policy } = previous.content;
    const next = { ...policy, ...await this.resealed(id, policy, new Set(remove)) };
    if (canonical({ ...next, revision: policy.revision }) === canonical(policy)) return null;
    const resource = await this.api.json('/api/resources/' + policy.id, {}, Resource);
    return this.save(resource.name, await reveal(previous.content, this.binding, this.keys.encryption), next,
      { metadata: previous.content.metadata, previous });
  }
  // The parties of an item sealed again: without the principals removed, with the current verified keys of those it
  // names, and with whoever now uses what its owner holds.
  private async resealed(id: string, policy: PolicyParties, removed: Set<string>) {
    const current = await this.recipients(policy.ownerId);
    const excluded = this.exclusions.get(policy.ownerId) ?? [];
    this.pendingExclusions.set(id, excluded);
    for (const recipient of excluded) removed.add(recipient.id);
    // A principal that has replaced its keys is sealed for with its current keys only, in each of its roles, once this
    // device verified them: those who use what the owner holds as listed, and anyone else it is shared with as found.
    const latest = new Map(current.map(binding => [binding.principalId, binding]));
    const named = [...policy.readers, ...policy.authorities];
    for (const principalId of new Set(named.map(binding => binding.principalId))) {
      if (principalId === this.binding.principalId || latest.has(principalId) || removed.has(principalId)) continue;
      const found = await this.inspectIdentity(principalId).then(identity => identity.binding, () => null);
      if (found && named.some(binding => binding.principalId === principalId && binding.id !== found.id))
        latest.set(principalId, await this.trusted(found));
    }
    const replace = (binding: BoundKeys) => latest.get(binding.principalId) ?? binding;
    const unique = (values: BoundKeys[]) => [...new Map(values.map(binding => [binding.id, binding])).values()];
    const kept = (binding: BoundKeys) => !removed.has(binding.principalId);
    const readers = unique(policy.readers.filter(kept).map(replace)), authorities = unique(policy.authorities.filter(kept).map(replace));
    const added = current.filter(binding => !readers.some(reader => reader.id === binding.id));
    return { revision: policy.revision + 1, readers: [...readers, ...added],
      authorities: [...authorities, ...added.filter(binding => !authorities.some(authority => authority.id === binding.id))],
      ...(policy.observers ? { observers: policy.observers.filter(principal => !removed.has(principal)) } : {}) };
  }
  // An item sealed under the earlier policy, sealed again under the current one by one of its authorities, for the same
  // parties and, as readers, for the principals it still let use it for themselves. A connection signs what its method
  // is now when the method changed only by losing its HTTP settings, and one sealed with its method inside is sealed
  // without it.
  private async reformat(id: string, stored: { content: EarlierSealed; version: number }) {
    const { content } = stored, { policy } = content;
    if (!policy.authorities.some(authority => canonical(authority) === canonical(this.binding)))
      throw new ClientFailure('reseal_required', 'One of its authorities must seal this item again before it can be used.');
    await verifyEarlier(content);
    if (policy.id !== id || policy.origin !== this.origin) throw new Error('The encrypted content belongs to another item.');
    await this.trusted(policyAuthority(content));
    const observed = await this.trust.checkpoint(content);
    if (await this.trust.checkpoint({ policy: { format: 3, id } }) || observed && (policy.revision < observed.policy.revision ||
      content.materialRevision < observed.materialRevision ||
      content.materialRevision === observed.materialRevision && await hash(content) !== observed.digest))
      throw new ClientFailure('content_conflict', 'The encrypted content is older than this device has already observed.');
    const users: BoundKeys[] = [];
    for (const user of earlierUsers(content)) {
      if (policy.readers.some(reader => reader.principalId === user.principalId)) continue;
      const found = await this.inspectIdentity(user.principalId).then(identity => identity.binding, () => null);
      try { if (found) users.push(await this.trusted(found)); }
      catch (error) {
        if (!(error instanceof ClientFailure) || error.code !== 'identity_untrusted' && error.code !== 'identity_changed') throw error;
      }
    }
    const next = AccessPolicy.parse({ format: 3, origin: policy.origin, id, ownerId: policy.ownerId, contentType: policy.contentType,
      ...await this.resealed(id, { ...policy, readers: [...policy.readers, ...users] }, new Set()) });
    let bytes = await revealEarlier(content, this.binding, this.keys.encryption), metadata = content.metadata;
    let labels: z.infer<typeof import('./connections.js').ConnectionLabels> | undefined;
    if (policy.contentType === ContentTypes.tokenSet && typeof metadata.methodDigest !== 'string') {
      const state = earlierConnection(bytes);
      bytes = sealedConnection(state); metadata = await connectionMetadata(state); labels = connectionLabels(state);
    } else if (policy.contentType === ContentTypes.tokenSet) {
      const { http, revocable: _revocable, ...rest } = metadata;
      const method = catalogDefinition(await this.api.json('/api/connections/' + id + '/method', {}, CatalogMethod));
      const digest = await methodDigest(method);
      const approved = http === undefined ? digest : await hash({ ...methodRules(method), http });
      metadata = { ...rest, methodDigest: approved === metadata.methodDigest ? digest : String(metadata.methodDigest) };
    }
    const resource = await this.api.json('/api/resources/' + id, {}, Resource);
    await this.save(resource.name, bytes, next, { metadata, previous: stored, ...(labels ? { labels } : {}) });
  }
  // Seals each listed item again on its own: one that cannot change now is left, with the reason, for another time.
  async reprotectPending(onProgress?: (progress: { completed: number; total: number }) => void) {
    const done: string[] = [], failed: Array<{ id: string; code: string; verification?: RecipientVerification[] }> = [];
    const items = await this.pendingProtection();
    let completed = 0;
    onProgress?.({ completed, total: items.length });
    for (const item of items) {
      try {
        if (await this.reprotect(item.id, item.reason, item.remove)) done.push(item.id);
        const verification = this.pendingExclusions.get(item.id);
        if (verification?.length) failed.push({ id: item.id, code: 'recipient_excluded', verification });
      } catch (error) {
        failed.push({ id: item.id, code: error && typeof error === 'object' && 'code' in error && typeof error.code === 'string'
          ? error.code : 'failure' });
      }
      onProgress?.({ completed: ++completed, total: items.length });
    }
    const endorsed = await this.endorseKeyRotations();
    return { done: [...done, ...endorsed.done], failed: [...failed, ...endorsed.failed] };
  }
  // Signs the items that other identities' key rotations wait for, as an authority of those items: only for keys this
  // identity verified, replaced by keys those signed for.
  async endorseKeyRotations() {
    const done: string[] = [], failed: Array<{ id: string; code: string }> = [];
    const { items } = await this.api.json('/api/key-rotations/requests', {}, z.object({ items: z.array(RotationRequest) }));
    for (const request of items) {
      try {
        const { rotation } = request, previous = rotation.previous.binding, next = rotation.replacement.binding;
        await this.trusted(previous);
        if (!await verifiesReplacement(previous, next, [{ previous: rotation.previous, replacement: rotation.replacement,
          previousSignature: rotation.previousSignature }]))
          throw new ClientFailure('identity_changed', 'The replacement keys were not signed with the verified keys.');
        await this.api.json('/api/principals/' + Id.parse(rotation.principalId) + '/key-rotations/' + Id.parse(rotation.id) +
          '/items/' + request.kind + '/' + Id.parse(request.id) + '/endorsement', { method: 'PUT', body: {
          sourceDigest: request.sourceDigest, payload: await endorsementPayload(request, this.binding, this.keys) } });
        done.push(request.id);
      } catch (error) {
        failed.push({ id: request.id, code: error && typeof error === 'object' && 'code' in error && typeof error.code === 'string'
          ? error.code : 'failure' });
      }
    }
    return { done, failed };
  }
  async sourceContents(ids: string[]) {
    const sources = new Map<string, CustodyContent>();
    for (const id of new Set(ids)) sources.set(id, (await this.read(id)).content);
    for (const source of [...sources.values()]) {
      if (source.policy.contentType === ContentTypes.tokenSet && typeof source.metadata.appId === 'string' && !sources.has(source.metadata.appId))
        sources.set(source.metadata.appId, (await this.read(source.metadata.appId)).content);
    }
    return [...sources.values()];
  }
}
