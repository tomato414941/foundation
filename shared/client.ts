import { z } from 'zod';
import { ApprovalRequest, Id, Resource, listOf } from './contracts.js';
import type { JsonValue, ResourceView } from './contracts.js';
import { SignedBinding, canonical, fingerprint, hash, signedValue, verifyBinding } from './authority.js';
import type { BoundKeys, KeyMaterial } from './authority.js';
import {
  AccessPolicy, ContentTypes, Operations, approvePolicy, authorizeUse, continuesPolicy, permittedOperations, policyAuthority,
  prepareRun, protect, reveal, verifyContent,
} from './custody.js';
import type { ContentTypeId, CustodyContent, CustodyPolicy, ExecutionIntent, SealedRun } from './custody.js';
import { BoundRecipient, ProtectedRead, Registration, Reprotection } from './protocol.js';
import { RuntimeOperation, Task, authorizeEnvironment, readReceipt, verifyEnvironment } from './execution.js';
import type { ExecutionOperation, RegisteredEnvironment, TaskView } from './execution.js';
import { functionRequest } from './function-request.js';

export interface JsonApi {
  json<T = unknown>(path: string, options?: { method?: string; body?: unknown; signal?: AbortSignal }, schema?: z.ZodType<T>): Promise<T>;
}
export interface TrustStore {
  binding(principalId: string): Promise<BoundKeys | null>;
  rememberBinding(binding: BoundKeys): Promise<void>;
  checkpoint(id: string): Promise<{ policy: CustodyPolicy; materialRevision: number; digest: string } | null>;
  rememberContent(content: CustodyContent): Promise<void>;
  run(id: string): Promise<SealedRun | null>;
  rememberRun(request: SealedRun): Promise<void>;
}
export class ClientFailure extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}
export class SubmissionPending extends Error {
  constructor(readonly id: string) {
    super('The execution request is saved locally. Check execution ' + id + ' before starting another operation.');
  }
}
export class CustodyClient {
  constructor(readonly api: JsonApi, readonly origin: string, readonly binding: BoundKeys,
    readonly keys: KeyMaterial, readonly trust: TrustStore) {}

  async trusted(binding: BoundKeys) {
    const pinned = binding.principalId === this.binding.principalId ? this.binding : await this.trust.binding(binding.principalId);
    if (!pinned || canonical(pinned) !== canonical(binding))
      throw new ClientFailure('identity_untrusted', 'Verify and trust the encryption and signing keys for identity ' + binding.principalId + ' before sharing.');
    return binding;
  }
  async inspectIdentity(id: string) {
    const signed = await this.api.json('/api/identities/' + Id.parse(id) + '/binding', {}, SignedBinding);
    await verifyBinding(signed);
    return { ...signed, fingerprint: await fingerprint(signed.binding) };
  }
  async trustIdentity(id: string, expectedFingerprint: string) {
    const identity = await this.inspectIdentity(id);
    if (identity.fingerprint !== expectedFingerprint) throw new ClientFailure('fingerprint_mismatch', 'The identity fingerprint does not match.');
    await this.trust.rememberBinding(identity.binding);
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
    if (!items.length) throw new Error('Set up an encryption key for the owner before saving private content.');
    for (const { name: _name, ...item } of items) { await verifyBinding(item); await this.trusted(item.binding); }
    return items.map(item => item.binding);
  }
  async read(id: string) {
    const item = await this.api.json('/api/resources/' + Id.parse(id) + '/custody', {}, ProtectedRead);
    await this.observe(item.content, id);
    return item;
  }
  async observe(input: CustodyContent, id = input.policy.id) {
    const content = await verifyContent(input);
    if (content.policy.id !== id || content.policy.origin !== this.origin) throw new Error('The encrypted content belongs to another item.');
    const author = policyAuthority(content);
    await this.trusted(author);
    const observed = await this.trust.checkpoint(id);
    if (observed) AccessPolicy.parse(observed.policy);
    if (observed) {
      if (content.policy.revision < observed.policy.revision || content.materialRevision < observed.materialRevision ||
        (content.policy.revision === observed.policy.revision && canonical(content.policy) !== canonical(observed.policy)) ||
        (content.materialRevision === observed.materialRevision && await hash(content) !== observed.digest))
        throw new Error('The encrypted content is older than this device has already observed.');
      if (content.policy.revision > observed.policy.revision &&
        !continuesPolicy(observed.policy, content))
        throw new Error('An existing policy authority must approve the new recipients.');
    }
    await this.trust.rememberContent(content);
    return content;
  }
  async reveal(id: string) {
    return reveal((await this.read(id)).content, this.binding, this.keys.encryption);
  }
  async policy(ownerId: string, contentType: ContentTypeId, environments: RegisteredEnvironment[] = [],
    options: { id?: string; previous?: CustodyPolicy; expiresAt?: string } = {}) {
    const readers = options.previous?.readers ?? [...new Map([...(await this.recipients(ownerId)), this.binding]
      .map(binding => [binding.id, binding])).values()];
    if (!readers.some(reader => canonical(reader) === canonical(this.binding)))
      throw new Error('Include your own identity as a reader before creating this item.');
    const expiresAt = options.expiresAt ?? new Date(Date.now() + 30 * 86_400_000).toISOString();
    const grants = options.previous ? options.previous.grants.filter(grant =>
      grant.actor.id !== this.binding.id && Date.parse(grant.expiresAt) > Date.now()) : [];
    for (const environment of environments) {
      await this.trusted(environment.manifest.executor);
      grants.push({ actor: this.binding, executor: environment.manifest.executor,
        operations: [...permittedOperations(contentType)],
        origins: [], functionDigests: [], callerProgram: contentType !== ContentTypes.clientCredential, expiresAt });
    }
    return AccessPolicy.parse({ format: 2, id: options.id ?? options.previous?.id ?? crypto.randomUUID(),
      origin: this.origin, ownerId, contentType, revision: (options.previous?.revision ?? 0) + 1,
      authorities: options.previous?.authorities ?? readers, readers, grants, producers: [] });
  }
  async save(name: string, bytes: Uint8Array, policy: CustodyPolicy,
    options: { metadata?: Record<string, JsonValue>; previous?: { content: CustodyContent; version: number } } = {}) {
    const previous = options.previous;
    if (previous && canonical(policy) === canonical({ ...previous.content.policy, revision: policy.revision }))
      policy = { ...policy, revision: previous.content.policy.revision };
    const content = await protect(bytes, policy, (previous?.content.materialRevision ?? 0) + 1,
      this.binding, this.keys, options.metadata, previous?.content);
    const resource = await this.api.json('/api/resources/' + policy.id + '/custody', { method: 'PUT',
      body: { name, content, ...(previous ? { version: previous.version } : {}) } }, Resource);
    await this.trust.rememberContent(content);
    return resource;
  }
  // Seals an item for the new owner its policy names. The item comes back once it is theirs; while the new owner has
  // not agreed, the request that asks it comes back instead, and nothing here changes.
  async pass(name: string, bytes: Uint8Array, policy: CustodyPolicy, previous: { content: CustodyContent; version: number }) {
    const content = await protect(bytes, policy, previous.content.materialRevision + 1,
      this.binding, this.keys, previous.content.metadata, previous.content);
    const result = await this.api.json('/api/resources/' + policy.id + '/custody', { method: 'PUT',
      body: { name, content, version: previous.version } }, z.union([Resource, ApprovalRequest]));
    if ('kind' in result) await this.trust.rememberContent(content);
    return result;
  }
  // Items the server cannot seal again itself, because only their readers can open them. The list
  // only says where to look: each item is checked here before anything changes.
  async pendingProtection() {
    return (await this.api.json('/api/principals/' + this.binding.principalId + '/reprotection', {}, listOf(Reprotection))).items;
  }
  // Seals the item again without its expired grants, unless an execution may still write to it.
  async reprotect(id: string) {
    const previous = await this.read(id);
    const { policy } = previous.content, now = Date.now();
    const grants = policy.grants.filter(grant => Date.parse(grant.expiresAt) > now);
    if (grants.length === policy.grants.length || policy.producers.some(producer => Date.parse(producer.expiresAt) > now))
      return null;
    const resource = await this.api.json('/api/resources/' + policy.id, {}, Resource);
    const bytes = await reveal(previous.content, this.binding, this.keys.encryption);
    return this.save(resource.name, bytes, { ...policy, revision: policy.revision + 1, grants, producers: [] },
      { metadata: previous.content.metadata, previous });
  }
  async reprotectPending() {
    const done: string[] = [], failed: string[] = [];
    for (const item of await this.pendingProtection()) {
      try {
        if (await this.reprotect(item.id)) done.push(item.id);
      } catch {
        failed.push(item.id);
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
  async output(ownerId: string, name: string, runId: string, environment: RegisteredEnvironment, expiresAt: string) {
    let existing: ResourceView | undefined, after: string | null = null;
    do {
      const query = new URLSearchParams({ kind: 'variable', query: name, ...(after ? { after } : {}) });
      const page = await this.api.json('/api/principals/' + ownerId + '/resources?' + query, {}, listOf(Resource));
      existing = page.items.find(item => item.name === name); after = page.next;
    } while (!existing && after);
    const previous = existing ? (await this.read(existing.id)).content : undefined;
    const policy: CustodyPolicy = previous ? { ...previous.policy, revision: previous.policy.revision + 1, producers: [] }
      : await this.policy(ownerId, ContentTypes.value);
    policy.producers = [{ executor: environment.manifest.executor, runId, expiresAt,
      materialRevision: (previous?.materialRevision ?? 0) + 1 }];
    return { name, approval: await approvePolicy(policy, this.binding, this.keys, previous) };
  }
  async prepare(ownerId: string, environmentId: string, input: ExecutionOperation,
    options: { id?: string; sourceIds?: string[]; save?: Record<string, string>; expiresAt?: string;
      approval?: ExecutionIntent['approval'] } = {}) {
    const environment = await this.environment(environmentId), operation = RuntimeOperation.parse(input);
    const id = options.id ?? crypto.randomUUID(), expiresAt = options.expiresAt ?? new Date(Date.now() + 3_600_000).toISOString();
    const request = operation.kind === 'http' ? operation.request : operation.kind === 'function'
      ? functionRequest(operation.definition, operation.arguments) : null;
    if (operation.kind === 'http' || operation.kind === 'function') {
      const save = operation.kind === 'function' ? operation.definition.save : options.save ?? {};
      if (operation.kind === 'function' && Object.keys(save).length && operation.definition.outputOwnerId !== ownerId)
        throw new Error('Run this function for its approved output owner.');
      const outputs = Object.fromEntries(await Promise.all(Object.entries(save).map(async ([pointer, name]) =>
        [pointer, await this.output(ownerId, name, id, environment, expiresAt)])));
      if (operation.kind === 'http') operation.save = outputs;
      else operation.outputs = outputs;
    }
    const ids = operation.kind === 'command' ? operation.inputs.map(input => input.source.id)
      : request ? request.bindings.flatMap(binding => binding.parts.flatMap(part => typeof part === 'string' ? [] : [part.id])) : [];
    const sources = await this.sourceContents([...ids, ...(options.sourceIds ?? [])]);
    const intent: ExecutionIntent = { format: 2, id, origin: this.origin, ownerId, actor: this.binding,
      environmentId, executor: environment.manifest.executor, environmentDigest: await hash(environment.manifest),
      operation: Operations[operation.kind], operationDigest: await hash(operation),
      ...(options.approval ? { approval: options.approval } : {}),
      functionDigest: operation.kind === 'function' ? await hash(operation.definition) : null,
      sources: await Promise.all(sources.map(async content => ({ id: content.policy.id,
        materialRevision: content.materialRevision, policyDigest: await hash(content.policy),
        ...(content.policy.contentType === ContentTypes.tokenSet && typeof content.metadata.authorizationDigest === 'string'
          ? { authorizationDigest: content.metadata.authorizationDigest } : {}),
      }))), resultRecipients: [this.binding], createdAt: new Date().toISOString(), expiresAt };
    await authorizeEnvironment(environment, intent);
    const credential = (content: CustodyContent) => content.policy.contentType === ContentTypes.clientCredential;
    for (const source of sources) await authorizeUse(source, credential(source) &&
      intent.operation !== Operations.connect && intent.operation !== Operations.revoke ? { ...intent, operation: Operations.refresh } : intent,
      credential(source) ? {} : { destination: request?.url });
    return prepareRun(intent, operation, this.keys);
  }
  async submit(ownerId: string, environmentId: string, operation: ExecutionOperation,
    options: Parameters<CustodyClient['prepare']>[3] = {}) {
    return this.submitPrepared(await this.prepare(ownerId, environmentId, operation, options));
  }
  async submitPrepared(request: SealedRun) {
    await this.trust.rememberRun(request);
    try { return await this.api.json('/api/executions', { method: 'POST', body: request }, Task); }
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
    return this.submitPrepared(request);
  }
  async result(task: TaskView) {
    if (canonical(task.intent.actor) !== canonical(this.binding) || task.intent.origin !== this.origin || task.intent.id !== task.id)
      throw new Error('This execution belongs to another requester.');
    const signed = await signedValue(task.requestSignature, this.binding.signing, 'run') as { intent: unknown };
    if (canonical(signed.intent) !== canonical(task.intent)) throw new Error('The result belongs to a different signed request.');
    await this.trusted(task.intent.executor);
    return task.receipt ? readReceipt(task.receipt, task.intent, this.binding.id, this.keys) : null;
  }
}
