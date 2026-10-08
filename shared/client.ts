import { z } from 'zod';
import { Id, Resource, listOf } from './contracts.js';
import type { JsonValue, ResourceView } from './contracts.js';
import { SignedBinding, canonical, hash, signedValue, verifyBinding } from './authority.js';
import type { BoundKeys, KeyMaterial } from './authority.js';
import {
  AccessPolicy, approvePolicy, authorizeUse, continuesPolicy, policyAuthority, prepareRun, protect, reveal, verifyContent,
} from './custody.js';
import type { CustodyContent, CustodyPolicy, ExecutionIntent, SealedRun } from './custody.js';
import { BoundRecipient, LegacySecretPlan, ProtectedRead, Registration } from './protocol.js';
import { open } from './encryption.js';
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
    return { ...signed, fingerprint: await hash(signed.binding) };
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
    Id.parse(id);
    let item;
    try { item = await this.api.json('/api/resources/' + id + '/custody', {}, ProtectedRead); }
    catch (error) {
      if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'custody_required') throw error;
      await this.migrateSecret(id);
      item = await this.api.json('/api/resources/' + id + '/custody', {}, ProtectedRead);
    }
    await this.observe(item.content, id);
    return item;
  }
  async migrateSecret(id: string) {
    let plan;
    try { plan = await this.api.json('/api/resources/' + Id.parse(id) + '/legacy-secret', {}, LegacySecretPlan); }
    catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'already_migrated') return;
      throw error;
    }
    if (plan.id !== id || plan.policy.id !== id || plan.policy.origin !== this.origin ||
      !plan.policy.authorities.some(authority => canonical(authority) === canonical(this.binding)))
      throw new Error('Migrate the secret as its existing owner.');
    const current = await this.trust.checkpoint(id);
    if (current) throw new Error('This device has already observed signed content for this secret.');
    for (const signed of plan.bindings) {
      await verifyBinding(signed);
      const pinned = signed.binding.principalId === this.binding.principalId
        ? this.binding : await this.trust.binding(signed.binding.principalId);
      if (pinned && canonical(pinned) !== canonical(signed.binding))
        throw new Error('A recipient changed keys. Verify its keys before migration.');
    }
    for (const binding of [...plan.policy.readers, ...plan.policy.authorities,
      ...plan.policy.grants.flatMap(grant => [grant.actor, grant.executor])]) {
      if (!plan.bindings.some(signed => canonical(signed.binding) === canonical(binding)))
        throw new Error('Verify every recipient binding before migration.');
    }
    const bytes = await open(plan.sealed, this.keys.encryption, this.binding.principalId, 'resource:' + id);
    try {
      const content = await protect(bytes, plan.policy, 1, this.binding, this.keys);
      const checked = await reveal(content, this.binding, this.keys.encryption);
      try {
        if (checked.length !== bytes.length || checked.some((value, index) => value !== bytes[index]))
          throw new Error('The migrated secret could not be verified.');
      } finally { checked.fill(0); }
      try {
        await this.api.json('/api/resources/' + id + '/legacy-secret', { method: 'POST',
          body: { name: plan.name, version: plan.version, content } }, Resource);
      } catch (error) {
        if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'changed') throw error;
        // A concurrent owner can complete migration first. Never overwrite it.
        const migrated = await this.api.json('/api/resources/' + id + '/custody', {}, ProtectedRead);
        if (canonical(migrated.content.policy) !== canonical(plan.policy)) throw error;
        const value = await reveal(migrated.content, this.binding, this.keys.encryption);
        try {
          if (value.length !== bytes.length || value.some((byte, index) => byte !== bytes[index])) throw error;
        } finally { value.fill(0); }
      }
      // The legacy store had no signatures to pin. Bootstrap its current
      // recipients once, after owner-side decryption and a successful commit.
      for (const signed of plan.bindings) await this.trust.rememberBinding(signed.binding);
    } finally { bytes.fill(0); }
  }
  async migrateSecrets() {
    const { items } = await this.api.json('/api/migrations/secrets', {}, listOf(Id));
    for (const id of items) await this.read(id);
  }
  async observe(input: CustodyContent, id = input.policy.id) {
    const content = await verifyContent(input);
    if (content.policy.id !== id || content.policy.origin !== this.origin) throw new Error('The encrypted content belongs to another item.');
    const author = policyAuthority(content);
    await this.trusted(author);
    const observed = await this.trust.checkpoint(id);
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
  async policy(ownerId: string, kind: CustodyPolicy['kind'], environments: RegisteredEnvironment[] = [],
    options: { id?: string; previous?: CustodyPolicy; expiresAt?: string } = {}) {
    const readers = options.previous?.readers ?? [...new Map([...(await this.recipients(ownerId)), this.binding]
      .map(binding => [binding.id, binding])).values()];
    if (!readers.some(reader => canonical(reader) === canonical(this.binding)))
      throw new Error('Include your own identity as a reader before creating this item.');
    const expiresAt = options.expiresAt ?? new Date(Date.now() + 30 * 86_400_000).toISOString();
    const grants = options.previous ? options.previous.grants.filter(grant => grant.actor.id !== this.binding.id) : [];
    for (const environment of environments) {
      await this.trusted(environment.manifest.executor);
      if (!environment.manifest.callers.some(caller => canonical(caller) === canonical(this.binding)))
        throw new Error('This execution environment has not accepted your identity.');
      grants.push({ actor: this.binding, executor: environment.manifest.executor,
        operations: kind === 'app' ? ['connect', 'refresh', 'revoke'] : ['http', 'command', 'function', 'refresh', 'revoke'],
        origins: [], functionDigests: [], callerProgram: kind !== 'app', expiresAt });
    }
    return AccessPolicy.parse({ format: 1, id: options.id ?? options.previous?.id ?? crypto.randomUUID(),
      origin: this.origin, ownerId, kind, revision: (options.previous?.revision ?? 0) + 1,
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
  async sourceContents(ids: string[]) {
    const sources = new Map<string, CustodyContent>();
    for (const id of new Set(ids)) sources.set(id, (await this.read(id)).content);
    for (const source of [...sources.values()]) {
      if (source.policy.kind === 'connection' && typeof source.metadata.appId === 'string' && !sources.has(source.metadata.appId))
        sources.set(source.metadata.appId, (await this.read(source.metadata.appId)).content);
    }
    return [...sources.values()];
  }
  async output(ownerId: string, name: string, runId: string, environment: RegisteredEnvironment, expiresAt: string) {
    let existing: ResourceView | undefined, after: string | null = null;
    do {
      const query = new URLSearchParams({ kind: 'secret', query: name, ...(after ? { after } : {}) });
      const page = await this.api.json('/api/principals/' + ownerId + '/resources?' + query, {}, listOf(Resource));
      existing = page.items.find(item => item.name === name); after = page.next;
    } while (!existing && after);
    const previous = existing ? (await this.read(existing.id)).content : undefined;
    const policy: CustodyPolicy = previous ? { ...previous.policy, revision: previous.policy.revision + 1, producers: [] }
      : await this.policy(ownerId, 'secret');
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
    const intent: ExecutionIntent = { format: 1, id, origin: this.origin, ownerId, actor: this.binding,
      environmentId, executor: environment.manifest.executor, environmentDigest: await hash(environment.manifest),
      operation: operation.kind, operationDigest: await hash(operation),
      ...(options.approval ? { approval: options.approval } : {}),
      functionDigest: operation.kind === 'function' ? await hash(operation.definition) : null,
      sources: await Promise.all(sources.map(async content => ({ id: content.policy.id, kind: content.policy.kind,
        materialRevision: content.materialRevision, policyDigest: await hash(content.policy),
        ...(content.policy.kind === 'connection' && typeof content.metadata.authorizationDigest === 'string'
          ? { authorizationDigest: content.metadata.authorizationDigest } : {}),
      }))), resultRecipients: [this.binding], createdAt: new Date().toISOString(), expiresAt };
    await authorizeEnvironment(environment, intent);
    for (const source of sources) await authorizeUse(source, source.policy.kind === 'app' &&
      !['connect', 'revoke'].includes(intent.operation) ? { ...intent, operation: 'refresh' } : intent,
      source.policy.kind === 'app' ? {} : { destination: request?.url });
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
