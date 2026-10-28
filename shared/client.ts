import { z } from 'zod';
import { Execution } from './executions.js';
import { Id, Ok, Resource, listOf } from './contracts.js';
import type { JsonValue, ResourceView } from './contracts.js';
import { SignedBinding, canonical, fingerprint, hash, signedValue, verifyBinding } from './authority.js';
import type { BoundKeys, KeyMaterial } from './authority.js';
import {
  AccessPolicy, ContentTypes, Operations, approvePolicy, authorizeUse, continuesPolicy, permittedOperations, policyAuthority,
  prepareRun, protect, reveal, verifyContent, grantActive, grantExpiration,
} from './custody.js';
import type { ContentTypeId, CustodyContent, CustodyPolicy, ExecutionIntent, SealedRun, UseGrant } from './custody.js';
import { BoundRecipient, KeySharingItem, ProtectedRead, Registration, Reprotection, TransferRecipients } from './protocol.js';
import type { ProtectedWrite } from './protocol.js';
import { isProtected } from './protected.js';
import { HTTP_RUNTIME_VERSION, RuntimeOperation, Task, authorizeEnvironment, makeSharedReceipt, readReceipt, verifyEnvironment } from './runtime-protocol.js';
import type { ExecutionOperation, RegisteredEnvironment, TaskView } from './runtime-protocol.js';
import { KeyringState, keyringClaim, openKeyring, signKeyring } from './keyring.js';
import { httpSources } from './http-connections.js';
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
  checkpoint(content: CustodyContent): Promise<{ policy: CustodyPolicy; materialRevision: number; digest: string } | null>;
  rememberContent(content: CustodyContent): Promise<void>;
  run(id: string): Promise<SealedRun | null>;
  rememberRun(request: SealedRun): Promise<void>;
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
export class SubmissionPending extends Error {
  constructor(readonly id: string) {
    super('The execution request has been saved. Check execution ' + id + ' before starting another operation.');
  }
}
const errorIs = (error: unknown, ...codes: Array<string | number>) => !!error && typeof error === 'object' &&
  (('code' in error && codes.includes(String(error.code))) || ('status' in error && codes.includes(Number(error.status))));
export class CustodyClient {
  private verifiedKeys?: Promise<Map<string, KeyringEntryValue>>;
  private readonly exclusions = new Map<string, RecipientVerification[]>();
  private readonly pendingExclusions = new Map<string, RecipientVerification[]>();
  constructor(readonly api: JsonApi, readonly origin: string, readonly binding: BoundKeys,
    readonly keys: KeyMaterial, readonly trust: TrustStore, readonly onRecipientAccess?: (access: RecipientAccess) => void) {}

  async trusted(binding: BoundKeys) {
    if (!(await this.verifies(binding))) {
      // Keys verified before and since replaced are told apart from keys never verified, to be verified again.
      if (binding.principalId !== this.binding.principalId && await this.known(binding.principalId))
        throw new ClientFailure('identity_changed', 'Identity ' + binding.principalId + ' replaced the keys verified before. Verify its current keys.');
      throw new ClientFailure('identity_untrusted', 'Verify and trust the encryption and signing keys for identity ' + binding.principalId + ' before sharing.');
    }
    return binding;
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
  async environment(id: string, trusted = true) {
    const { registration, stoppedAt } = await this.api.json('/api/environments/' + Id.parse(id) + '/registration', {}, Registration);
    await verifyEnvironment(registration);
    if (registration.manifest.origin !== this.origin || registration.manifest.id !== id || stoppedAt)
      throw new Error('Choose an active execution environment on this Foundation server.');
    if (trusted) await this.trusted(registration.manifest.executor);
    return registration;
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
  async latest(id: string) {
    const item = await this.api.json('/api/custody/' + Id.parse(id), {}, ProtectedRead);
    if (this.replaces(item.content.policy)) return { ...item, replaced: true };
    await this.observe(item.content, id);
    return { ...item, replaced: false };
  }
  private replaces(policy: CustodyPolicy) {
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
  async policy(ownerId: string, contentType: ContentTypeId, environments: RegisteredEnvironment[] = [],
    options: { id?: string; previous?: CustodyPolicy; replacing?: CustodyPolicy; expiresAt?: string } = {}) {
    const { readers, authorities } = await this.ownerRecipients(ownerId, options.previous);
    if (!readers.some(reader => canonical(reader) === canonical(this.binding)))
      throw new Error('Include your own identity as a reader before creating this item.');
    const expiresAt = options.expiresAt ?? new Date(Date.now() + 30 * 86_400_000).toISOString();
    const grants = options.previous ? options.previous.grants.filter(grant =>
      (!('actor' in grant) || grant.actor.id !== this.binding.id) && grantActive(grant)) : [];
    for (const environment of environments) {
      await this.trusted(environment.manifest.executor);
      grants.push({ actor: this.binding, executor: environment.manifest.executor,
        operations: [...permittedOperations(contentType)],
        origins: [], functionDigests: [], callerProgram: contentType !== ContentTypes.clientCredential, expiresAt });
    }
    return AccessPolicy.parse({ format: 2, id: options.id ?? options.previous?.id ?? options.replacing?.id ?? crypto.randomUUID(),
      origin: this.origin, ownerId, contentType, revision: (options.previous?.revision ?? options.replacing?.revision ?? 0) + 1,
      authorities, readers, grants, producers: [] });
  }
  async save(name: string, bytes: Uint8Array, policy: CustodyPolicy,
    options: { metadata?: Record<string, JsonValue>; labels?: z.infer<typeof import('./connections.js').ConnectionLabels>; previous?: { content: CustodyContent; version: number };
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
  async transfer(id: string, to: string) {
    Id.parse(to);
    const resource = await this.api.json('/api/resources/' + Id.parse(id), {}, Resource);
    const path = '/api/resources/' + id + '/transfer';
    if (!isProtected(resource.kind)) return this.api.json(path, { method: 'POST', body: { to } }, z.union([Ok, Execution]));
    const previous = await this.read(id);
    const recipients = await this.api.json(path + '-recipients?to=' + encodeURIComponent(to), {}, TransferRecipients);
    const readers = await this.verifiedRecipients(to, recipients.required, recipients.delegates);
    const policy = { ...previous.content.policy, ownerId: to, revision: previous.content.policy.revision + 1,
      readers, authorities: readers, grants: [], observers: [], producers: [] };
    const content = await protect(await reveal(previous.content, this.binding, this.keys.encryption), policy, previous.content.materialRevision + 1,
      this.binding, this.keys, previous.content.metadata, previous.content);
    const result = await this.api.json(path, { method: 'POST',
      body: { to, content, version: previous.version } }, z.union([Resource, Execution]));
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
  // Seals the item again without its expired grants and without the principals that may no longer open or use it,
  // and, when asked, for whoever now uses what its owner holds and whose keys this device has verified, unless an
  // execution may still write to it. An execution result is written once it exists, so nothing waits on it.
  async reprotect(id: string, reason: z.infer<typeof Reprotection>['reason'] = 'grantExpired', remove: string[] = []) {
    const previous = await this.read(id);
    const { policy } = previous.content, now = Date.now(), removed = new Set(remove);
    const current = reason === 'recipients' ? await this.recipients(policy.ownerId) : [];
    const excluded = reason === 'recipients' ? this.exclusions.get(policy.ownerId) ?? [] : [];
    this.pendingExclusions.set(id, excluded);
    for (const recipient of excluded) removed.add(recipient.id);
    // A principal that has replaced its keys is sealed for with its current keys only, in each of its roles, once this
    // device verified them: those who use what the owner holds as listed, and anyone else it is shared with as found.
    const latest = new Map(current.map(binding => [binding.principalId, binding]));
    const named = [...policy.readers, ...policy.authorities,
      ...policy.grants.flatMap(grant => 'actor' in grant ? [grant.actor, grant.executor] : [grant.executor])];
    if (reason === 'recipients') for (const principalId of new Set(named.map(binding => binding.principalId))) {
      if (principalId === this.binding.principalId || latest.has(principalId) || removed.has(principalId)) continue;
      const found = await this.inspectIdentity(principalId).then(identity => identity.binding, () => null);
      if (found && named.some(binding => binding.principalId === principalId && binding.id !== found.id))
        latest.set(principalId, await this.trusted(found));
    }
    const replace = (binding: BoundKeys) => latest.get(binding.principalId) ?? binding;
    const unique = (values: BoundKeys[]) => [...new Map(values.map(binding => [binding.id, binding])).values()];
    const kept = (binding: BoundKeys) => !removed.has(binding.principalId);
    const grants = policy.grants.filter(grant => grantActive(grant, now) && kept(grant.executor) &&
      (!('actor' in grant) || kept(grant.actor))).map(grant => 'actor' in grant
      ? { ...grant, actor: replace(grant.actor), executor: replace(grant.executor) } : { ...grant, executor: replace(grant.executor) });
    const readers = unique(policy.readers.filter(kept).map(replace)), authorities = unique(policy.authorities.filter(kept).map(replace));
    const added = current.filter(binding => !readers.some(reader => reader.id === binding.id));
    const next = { ...policy, revision: policy.revision + 1, grants, producers: [],
      readers: [...readers, ...added],
      authorities: [...authorities, ...added.filter(binding => !authorities.some(authority => authority.id === binding.id))],
      ...(policy.observers ? { observers: policy.observers.filter(principal => !removed.has(principal)) } : {}) };
    const writing = policy.contentType !== ContentTypes.executionResult &&
      policy.producers.some(producer => Date.parse(producer.expiresAt) > now);
    if (canonical({ ...next, revision: policy.revision }) === canonical(policy) || writing) return null;
    const bytes = await reveal(previous.content, this.binding, this.keys.encryption);
    if (policy.contentType === ContentTypes.executionResult) {
      const content = await protect(bytes, next, previous.content.materialRevision + 1, this.binding, this.keys,
        previous.content.metadata, previous.content);
      await this.api.json('/api/custody/' + id, { method: 'PUT',
        body: { name: 'Execution result', content, version: previous.version } }, ProtectedRead);
      await this.trust.rememberContent(content);
      this.onRecipientAccess?.({ id, name: 'Execution result', excluded });
      return id;
    }
    const resource = await this.api.json('/api/resources/' + policy.id, {}, Resource);
    return this.save(resource.name, bytes, next, { metadata: previous.content.metadata, previous });
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
  async output(ownerId: string, name: string, runId: string, environment: { manifest: { executor: BoundKeys } }, expiresAt: string) {
    let existing: ResourceView | undefined, after: string | null = null;
    do {
      const query = new URLSearchParams({ kind: 'variable', query: name, ...(after ? { after } : {}) });
      const page = await this.api.json('/api/principals/' + ownerId + '/resources?' + query, {}, listOf(Resource));
      existing = page.items.find(item => item.name === name); after = page.next;
    } while (!existing && after);
    const latest = existing ? await this.latest(existing.id) : undefined, previous = latest?.content;
    const policy: CustodyPolicy = previous && !latest.replaced ? { ...previous.policy, revision: previous.policy.revision + 1, producers: [] }
      : await this.policy(ownerId, ContentTypes.value, [], { replacing: previous?.policy });
    policy.producers = [{ executor: environment.manifest.executor, runId, expiresAt,
      materialRevision: (previous?.materialRevision ?? 0) + 1 }];
    return { name, approval: await approvePolicy(policy, this.binding, this.keys, latest?.replaced ? undefined : previous) };
  }
  async prepare(ownerId: string, environmentId: string, input: ExecutionOperation,
    options: { id?: string; sourceIds?: string[]; save?: Record<string, string>; expiresAt?: string;
      approval?: ExecutionIntent['approval']; operationContext?: ExecutionIntent['operationContext'] } = {}) {
    const operation = RuntimeOperation.parse(input);
    const environment = await this.environment(environmentId);
    await this.trusted(environment.manifest.executor);
    const id = options.id ?? crypto.randomUUID();
    let expiresAt = options.expiresAt ?? new Date(Date.now() + 3_600_000).toISOString();
    const program = operation;
    const request = program.kind === 'http' ? program.request : null;
    if (request?.connectionId && environment.manifest.httpVersion !== HTTP_RUNTIME_VERSION)
      throw new ClientFailure('http_runtime_required', 'Update this execution environment to use HTTP connections.');
    if (operation.kind === 'http') {
      const save = options.save ?? {};
      const outputs = Object.fromEntries(await Promise.all(Object.entries(save).map(async ([pointer, name]) =>
        [pointer, await this.output(ownerId, name, id, environment, expiresAt)])));
      operation.save = outputs;
    }
    const ids = program.kind === 'command' ? program.inputs.map(input => input.source.id)
      : request ? httpSources(request).map(source => source.id) : [];
    const sources = await this.sourceContents([...ids, ...(options.sourceIds ?? [])]);
    for (let index = 0; index < sources.length; index++) {
      const source = sources[index]!, credential = source.policy.contentType === ContentTypes.clientCredential;
      const use = credential && operation.kind !== 'revoke' ? Operations.refresh : Operations[operation.kind];
      const destination = credential || !request?.url ? undefined : new URL(request.url).origin;
      const permitted = source.policy.grants.some(grant => 'actor' in grant &&
        canonical(grant.actor) === canonical(this.binding) && canonical(grant.executor) === canonical(environment.manifest.executor) &&
        grant.operations.includes(use) && grantExpiration(grant) >= Date.parse(expiresAt) &&
        (!destination || !grant.origins.length || grant.origins.includes(destination)) &&
        (credential || grant.callerProgram));
      if (permitted || !source.policy.authorities.some(authority => canonical(authority) === canonical(this.binding))) continue;
      const previous = await this.read(source.policy.id), resource = await this.api.json('/api/resources/' + source.policy.id, {}, Resource);
      const grant = { actor: this.binding, executor: environment.manifest.executor,
        operations: [...new Set([use, ...(source.policy.contentType === ContentTypes.tokenSet ? [Operations.refresh] : [])])],
        origins: destination ? [destination] : [], functionDigests: [], callerProgram: !credential, expiresAt };
      // Expired grants allow nothing, and grants differing only in expiry allow what the latest one does.
      // Dropping the former and merging the latter keeps one grant per scope however often it is used.
      const scope = (value: UseGrant) => canonical({ ...value, expiresAt: null });
      const same = previous.content.policy.grants.filter(item => scope(item) === scope(grant));
      const policy = AccessPolicy.parse({ ...previous.content.policy, revision: previous.content.policy.revision + 1, grants: [
        ...previous.content.policy.grants.filter(item => grantActive(item) && scope(item) !== scope(grant)),
        { ...grant, expiresAt: new Date(Math.max(Date.parse(expiresAt), ...same.map(item => grantExpiration(item)))).toISOString() }] });
      await this.save(resource.name, await reveal(previous.content, this.binding, this.keys.encryption), policy,
        { previous, metadata: previous.content.metadata });
      sources[index] = (await this.read(source.policy.id)).content;
    }
    const resultPolicy = await this.policy(ownerId, ContentTypes.executionResult, [], { id });
    resultPolicy.producers = [{ executor: environment.manifest.executor, runId: id, expiresAt, materialRevision: 1 }];
    const intent: ExecutionIntent = { format: 2, id, origin: this.origin, ownerId, actor: this.binding,
      environmentId, executor: environment.manifest.executor, environmentDigest: await hash(environment.manifest),
      operation: Operations[operation.kind], operationDigest: await hash(operation),
      ...(options.approval ? { approval: options.approval } : {}),
      ...(options.operationContext ? { operationContext: options.operationContext } : {}),
      functionDigest: null,
      sources: await Promise.all(sources.map(async content => ({ id: content.policy.id,
        materialRevision: content.materialRevision, policyDigest: await hash(content.policy),
        ...(content.policy.contentType === ContentTypes.tokenSet && typeof content.metadata.authorizationDigest === 'string'
          ? { authorizationDigest: content.metadata.authorizationDigest } : {}),
      }))), resultRecipients: resultPolicy.readers,
      ...(environment.manifest.resultVersion ? { resultApproval: await approvePolicy(resultPolicy, this.binding, this.keys) } : {}),
      createdAt: new Date().toISOString(), expiresAt };
    await authorizeEnvironment(environment, intent);
    const credential = (content: CustodyContent) => content.policy.contentType === ContentTypes.clientCredential;
    for (const source of sources) await authorizeUse(source, credential(source) &&
      intent.operation !== Operations.connect && intent.operation !== Operations.revoke ? { ...intent, operation: Operations.refresh } : intent,
      credential(source) ? {} : { destination: request?.url,
        destinationPending: Boolean(request?.connectionId && !request.url) });
    return prepareRun(intent, operation, this.keys);
  }
  async submit(ownerId: string, environmentId: string, operation: ExecutionOperation,
    options: Parameters<CustodyClient['prepare']>[3] = {}) {
    return this.submitPrepared(await this.prepare(ownerId, environmentId, operation, options));
  }
  async submitPrepared(request: SealedRun) {
    await this.trust.rememberRun(request);
    try { return await this.api.json('/api/runtime/runs', { method: 'POST', body: request }, Task); }
    catch (error) {
      if (error && typeof error === 'object' && 'status' in error) throw error;
      throw new SubmissionPending(request.intent.id);
    }
  }
  async resume(id: string) {
    const request = await this.trust.run(Id.parse(id));
    if (!request) throw new Error('Resume this execution from the device that saved its signed request.');
    if (canonical(request.intent.actor) !== canonical(this.binding) || request.intent.origin !== this.origin)
      throw new Error('Use the identity that signed this execution request.');
    try {
      const previous = await this.api.json('/api/runtime/runs/' + id, {}, Task);
      if (canonical(previous.intent) !== canonical(request.intent) || previous.requestSignature !== request.signature)
        throw new Error('Use the saved request that started this execution.');
      return previous;
    } catch (error) {
      if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'not_found') throw error;
    }
    return this.submitPrepared(request);
  }
  async result(task: TaskView) {
    if (task.intent.origin !== this.origin || task.intent.id !== task.id)
      throw new Error('This execution belongs to another Foundation server.');
    await this.trusted(task.intent.actor);
    const signed = await signedValue(task.requestSignature, task.intent.actor.signing, 'run') as { intent: unknown };
    if (canonical(signed.intent) !== canonical(task.intent)) throw new Error('The result belongs to a different signed request.');
    await this.trusted(task.intent.executor);
    const readers = task.receipt && 'content' in task.receipt ? task.receipt.content.policy.readers : task.intent.resultRecipients;
    if (!readers.some(reader => canonical(reader) === canonical(this.binding)))
      throw new ClientFailure('not_recipient', 'This identity is not a reader of the execution result.');
    if (task.receipt && 'content' in task.receipt) await this.observe(task.receipt.content, task.id);
    return task.receipt ? readReceipt(task.receipt, task.intent, this.binding.id, this.keys) : null;
  }
  async shareLegacyResult(task: TaskView) {
    if (!task.receipt || 'content' in task.receipt) return task;
    if (canonical(task.intent.actor) !== canonical(this.binding) || canonical(task.intent.executor) !== canonical(this.binding))
      throw new ClientFailure('executor_required', 'The original executor and requester must attest this legacy result.');
    const result = await this.result(task);
    if (!result) throw new Error('Wait for this execution to finish before sharing its result.');
    const policy = await this.policy(task.ownerId, ContentTypes.executionResult, [], { id: task.id });
    policy.producers = [{ executor: this.binding, runId: task.id,
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(), materialRevision: 1 }];
    const receipt = await makeSharedReceipt(task.intent, task.receipt.state, result, this.keys,
      await approvePolicy(policy, this.binding, this.keys), task.receipt);
    return this.api.json('/api/runtime/runs/' + task.id + '/result', { method: 'PUT', body: { receipt } }, Task);
  }
}
