import { z } from 'zod';
import { FunctionDefinition, FunctionResource, Id, listOf } from './contracts.js';
import type { FunctionSpec, JsonValue } from './contracts.js';
import { KeyBinding, canonical, hash } from './authority.js';
import { AccessPolicy, functionOperations, protect, reveal } from './custody.js';
import { FunctionWrite, Invocation, publishFunction } from './function-api.js';
import type { CustodyClient, JsonApi } from './client.js';
import { ProtectedRead } from './protocol.js';
import { functionSources } from './functions.js';

export class InvocationSubmissionError extends Error {
  constructor(readonly invocationId: string, cause: unknown) {
    super('The function invocation could not be confirmed. Invocation ID: ' + invocationId +
      '. Check its result or retry with the same ID.', { cause });
  }
}

export class FunctionClient {
  constructor(readonly api: JsonApi, readonly custody?: CustodyClient) {}
  get(id: string) { return this.api.json('/api/functions/' + Id.parse(id), {}, FunctionResource); }
  async save(input: { ownerId: string; name: string; definition: FunctionSpec; resourceId?: string; version?: number }) {
    if (!this.custody) throw new Error('Use your encryption keys to approve a function definition.');
    const client = this.custody, definition = FunctionDefinition.parse(input.definition);
    const environment = await client.environment(definition.environmentId);
    if (environment.manifest.functionVersion !== 2)
      throw new Error('Update the execution environment to Foundation CLI 6.');
    const functionId = input.resourceId ?? crypto.randomUUID();
    const sources = await client.sourceContents(functionSources(definition).map(source => source.id));
    const current = new Set(sources.map(source => source.policy.id));
    if (input.resourceId) {
      const previous = await this.api.json('/api/functions/' + functionId + '/authorizations', {}, listOf(ProtectedRead));
      for (const item of previous.items) if (!current.has(item.content.policy.id)) {
        await client.observe(item.content); sources.push(item.content);
      }
    }
    const contents: z.infer<typeof FunctionWrite>['contents'] = {};
    const reference = { id: functionId, digest: await hash(definition) };
    for (const source of sources) {
      const previous = await client.read(source.policy.id);
      if (!previous.content.policy.authorities.some(authority => canonical(authority) === canonical(client.binding)))
        throw new Error('An authority of each input must approve its use by this function.');
      const policy = AccessPolicy.parse({ ...previous.content.policy, revision: previous.content.policy.revision + 1,
        grants: [...previous.content.policy.grants.filter(grant => !('function' in grant) || grant.function.id !== functionId),
          ...(current.has(source.policy.id) ? [{ function: reference, executor: environment.manifest.executor,
            operations: functionOperations(source.policy.contentType), expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString() }] : [])] });
      contents[source.policy.id] = { version: previous.version, content: await protect(
        await reveal(previous.content, client.binding, client.keys.encryption), policy,
        previous.content.materialRevision + 1, client.binding, client.keys, previous.content.metadata, previous.content) };
    }
    const publication = await publishFunction({ format: 1, functionId, ownerId: input.ownerId,
      revision: input.resourceId ? (input.version ?? 0) + 1 : 1, definition, author: client.binding,
      executor: environment.manifest.executor, createdAt: new Date().toISOString() }, client.keys);
    const authorization = FunctionWrite.parse({ functionId, publication, contents });
    const path = input.resourceId ? '/api/functions/' + functionId : '/api/principals/' + input.ownerId + '/functions';
    const resource = await this.api.json(path, { method: input.resourceId ? 'PUT' : 'POST',
      body: { name: input.name, definition, authorization, ...(input.resourceId ? { version: input.version } : {}) } }, FunctionResource);
    for (const { content } of Object.values(contents)) await client.trust.rememberContent(content);
    return resource;
  }
  async invoke(id: string, arguments_: Record<string, JsonValue> = {}, options: {
    id?: string; ownerId?: string; save?: Record<string, string>;
  } = {}) {
    const invocationId = options.id ?? crypto.randomUUID(), outputs: Record<string, unknown> = {};
    if (Object.keys(options.save ?? {}).length) {
      if (!this.custody) throw new Error('Use your keys to approve encrypted output destinations.');
      const { executor } = await this.api.json('/api/functions/' + Id.parse(id) + '/output-recipient', {}, z.object({ executor: KeyBinding }));
      await this.custody.trusted(executor);
      const environment = { manifest: { executor } };
      for (const [pointer, name] of Object.entries(options.save!)) outputs[pointer] = await this.custody.output(
        options.ownerId ?? this.custody.binding.principalId, name, invocationId, environment, new Date(Date.now() + 3_600_000).toISOString());
    }
    try {
      return await this.api.json('/api/functions/' + Id.parse(id) + '/invocations', { method: 'POST',
        body: { id: invocationId, arguments: arguments_, outputs, ...(options.ownerId ? { ownerId: options.ownerId } : {}) } }, Invocation);
    } catch (error) {
      if (error instanceof Error && 'status' in error) throw error;
      throw new InvocationSubmissionError(invocationId, error);
    }
  }
  result(id: string) { return this.api.json('/api/invocations/' + Id.parse(id), {}, Invocation); }
  cancel(id: string) { return this.api.json('/api/invocations/' + Id.parse(id) + '/cancel', { method: 'POST', body: {} }, Invocation); }
  remove(id: string) { return this.api.json('/api/functions/' + Id.parse(id), { method: 'DELETE' }); }
}
