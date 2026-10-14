import { FUNCTION_RUNTIME_VERSION } from './runtime-protocol.js';
import { z } from 'zod';
import { FunctionDefinition, FunctionExecutionSettings, FunctionResource, Id, JsonObject, listOf } from './contracts.js';
import type { FunctionSpec, JsonValue } from './contracts.js';
import { KeyBinding, canonical, hash } from './authority.js';
import { AccessPolicy, functionOperations, protect, reveal } from './custody.js';
import { FunctionWrite, FunctionSettingsWrite, approveFunctionSettings, publishFunction } from './function-api.js';
import type { CustodyClient, JsonApi } from './client.js';
import { ProtectedRead } from './protocol.js';
import { FunctionSave, FunctionConfigure, Execution } from './executions.js';
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
  async prepare(input: { ownerId: string; name: string; definition: FunctionSpec; resourceId?: string; version?: number }) {
    if (!this.custody) throw new Error('Use your encryption keys to approve a function definition.');
    const client = this.custody, definition = FunctionDefinition.parse(input.definition);
    if (definition.program.kind === 'http' && definition.result !== 'json')
      throw new Error('HTTP functions return a JSON response containing status, headers, and body.');
    const functionId = input.resourceId ?? crypto.randomUUID();
    const publication = await publishFunction({ format: 2, functionId, ownerId: input.ownerId,
      revision: input.resourceId ? (input.version ?? 0) + 1 : 1, definition, author: client.binding,
      createdAt: new Date().toISOString() }, client.keys);
    return FunctionWrite.parse({ functionId, publication });
  }
  settings(id: string) {
    return this.api.json('/api/functions/' + Id.parse(id) + '/execution-settings', {}, FunctionExecutionSettings);
  }
  async prepareSettings(input: z.infer<typeof FunctionConfigure>) {
    if (!this.custody) throw new Error('Use your encryption keys to approve function execution settings.');
    const client = this.custody, fn = await this.get(input.functionId);
    if (fn.version !== input.functionVersion) throw new Error('Reload this function before configuring its execution.');
    const definition = FunctionDefinition.parse(fn.data), functionId = fn.id;
    if (input.inputAccess.expiresAt !== null && Date.parse(input.inputAccess.expiresAt) <= Date.now())
      throw new Error('Choose a future expiration for this function’s input access.');
    const environment = input.environmentId ? await client.environment(input.environmentId) : null;
    if (environment && environment.manifest.functionVersion !== FUNCTION_RUNTIME_VERSION)
      throw new Error('Update this execution environment to the current Foundation CLI.');
    const sources = environment ? await client.sourceContents(functionSources(definition).map(source => source.id)) : [];
    const current = new Set(sources.map(source => source.policy.id));
    const previous = await this.api.json('/api/functions/' + functionId + '/authorizations', {}, listOf(ProtectedRead));
    for (const item of previous.items) if (!current.has(item.content.policy.id)) {
      await client.observe(item.content); sources.push(item.content);
    }
    const contents: z.infer<typeof FunctionSettingsWrite>['contents'] = {};
    const reference = { id: functionId, digest: await hash(definition) };
    for (const source of sources) {
      const previous = await client.read(source.policy.id);
      if (!previous.content.policy.authorities.some(authority => canonical(authority) === canonical(client.binding)))
        throw new Error('An authority of each input must approve its use by this function.');
      const policy = AccessPolicy.parse({ ...previous.content.policy, revision: previous.content.policy.revision + 1,
        grants: [...previous.content.policy.grants.filter(grant => !('function' in grant) || grant.function.id !== functionId),
          ...(current.has(source.policy.id) ? [{ function: reference, executor: environment!.manifest.executor,
            operations: functionOperations(source.policy.contentType), expiresAt: input.inputAccess.expiresAt }] : [])] });
      contents[source.policy.id] = { version: previous.version, content: await protect(
        await reveal(previous.content, client.binding, client.keys.encryption), policy,
        previous.content.materialRevision + 1, client.binding, client.keys, previous.content.metadata, previous.content) };
    }
    const approval = await approveFunctionSettings({ format: 1, functionId, ownerId: fn.ownerId,
      definitionDigest: reference.digest, revision: input.version + 1, environmentId: input.environmentId,
      executor: environment?.manifest.executor ?? null, inputAccess: input.inputAccess,
      author: client.binding, createdAt: new Date().toISOString() }, client.keys);
    return FunctionSettingsWrite.parse({ approval, contents });
  }
  async remember(authorization: z.infer<typeof FunctionSettingsWrite>) {
    if (!this.custody) return;
    for (const { content } of Object.values(authorization.contents)) await this.custody.trust.rememberContent(content);
  }
  async save(input: { ownerId: string; name: string; definition: FunctionSpec; resourceId?: string; version?: number }) {
    if (!this.custody) throw new Error('Use your encryption keys to approve a function definition.');
    const prepared = FunctionSave.parse(input);
    const execution = await this.api.json('/api/executions', { method: 'POST',
      body: { operations: [{ name: 'function.save', input: JsonObject.parse(prepared) }] } }, Execution);
    const authorization = await this.prepare(prepared);
    const completed = await this.api.json('/api/executions/' + execution.id + '/complete', { method: 'POST',
      body: { index: execution.index, proof: authorization } }, Execution);
    return FunctionResource.parse(completed.results[execution.index]);
  }
  async configure(id: string, settings: { environmentId: string | null; inputAccess?: { expiresAt: string | null } },
    expected?: { functionVersion: number; version: number }) {
    const fn = await this.get(id), current = expected ?? { functionVersion: fn.version, version: (await this.settings(id)).version };
    const input = FunctionConfigure.parse({ functionId: fn.id, ...current, ...settings });
    const execution = await this.api.json('/api/executions', { method: 'POST',
      body: { operations: [{ name: 'function.configure', input: JsonObject.parse(input) }] } }, Execution);
    const authorization = await this.prepareSettings(input);
    await this.api.json('/api/executions/' + execution.id + '/complete', { method: 'POST',
      body: { index: execution.index, proof: authorization } }, Execution);
    await this.remember(authorization);
    return this.settings(id);
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
      return await this.api.json('/api/functions/' + Id.parse(id) + '/executions', { method: 'POST',
        body: { id: invocationId, arguments: arguments_, outputs, ...(options.ownerId ? { ownerId: options.ownerId } : {}) } }, Execution);
    } catch (error) {
      if (error instanceof Error && 'status' in error) throw error;
      throw new InvocationSubmissionError(invocationId, error);
    }
  }
  result(id: string) { return this.api.json('/api/executions/' + Id.parse(id), {}, Execution); }
  cancel(id: string) { return this.api.json('/api/executions/' + Id.parse(id) + '/cancel', { method: 'POST', body: {} }, Execution); }
  remove(id: string) { return this.api.json('/api/functions/' + Id.parse(id), { method: 'DELETE' }); }
}
