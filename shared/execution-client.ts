import { z } from 'zod';
import { AppSave, AuthorizeConnection, ConnectService, FunctionSave, Invocation, Execution, RevokeConnection, RunOperation, ValueSave, WaitingOperation } from './executions.js';
import type { DefinitionCall, ExecutionView } from './executions.js';
import { CatalogMethod, Id, Json, Resource, listOf } from './contracts.js';
import type { JsonValue, ResourceView } from './contracts.js';
import type { CustodyClient } from './client.js';
import type { ConnectionClient, FlowProgress } from './connection-client.js';
import { canonical, hash } from './authority.js';
import { AccessPolicy, ContentTypes, permittedOperations } from './custody.js';
import { AppMaterial, ConnectionMaterial, connectionLabels, connectionMetadata, requiresApp } from './connections.js';
import { connectionFields } from './connection-fields.js';
import { decode, encode } from './encryption.js';
import { Task, RuntimeOperation } from './runtime-protocol.js';
import type { TaskView } from './runtime-protocol.js';
import type { AwsConnectionRequest } from './aws.js';
import { AwsConnectionInput } from './aws.js';
import { SealedContinuationStore } from './operation-continuations.js';
import { DelegatedRun } from './custody.js';
import { FunctionClient } from './function-client.js';
import { PrivateProgram, reviewedProgram } from './operation-authorization.js';

export interface PrivateOperationInput {
  value?: string | Uint8Array;
  clientSecret?: string;
  fields?: Record<string, string>;
  scopes?: string[];
  aws?: AwsConnectionRequest;
}
export const OperationMaterial = z.object({ value: z.string().optional(), clientSecret: z.string().optional(),
  fields: z.record(z.string(), z.string()).optional(), scopes: z.array(z.string()).optional(), aws: AwsConnectionInput.optional() }).strict();
export type ExecutionResultView = ExecutionView | FlowProgress | { kind: 'saved'; resource: ResourceView; executionId: string }
  | { kind: 'run'; task: TaskView; executionId: string };

// Normal forms, the CLI, and an execution awaiting input use this same keyholder implementation.
export class ExecutionClient {
  readonly records: SealedContinuationStore;
  constructor(readonly custody: CustodyClient, readonly connections: ConnectionClient) { this.records = new SealedContinuationStore(custody); }
  async start(invocation: DefinitionCall) {
    if (invocation.name === 'run.execute') {
      const run = RunOperation.parse(invocation.input);
      if (!('programId' in run.operation)) {
        const operation = await this.program(run.operation);
        const programId = crypto.randomUUID();
        await this.records.put(programId, { operation, save: run.save });
        invocation = { ...invocation, input: { ...run,
          operation: { kind: run.operation.kind, programId,
          programDigest: await hash(reviewedProgram(operation)) } } };
      }
    }
    return this.custody.api.json('/api/executions', { method: 'POST', body: { operations: [Invocation.parse(invocation)] } }, Execution);
  }
  async plan(id: string) {
    return this.custody.api.json('/api/executions/' + Id.parse(id) + '/input', {}, WaitingOperation.extend({ id: Id }));
  }
  async complete(id: string, index: number, proof: JsonValue) {
    return this.custody.api.json('/api/executions/' + id + '/complete', { method: 'POST', body: { index, proof } }, Execution);
  }
  async configure(id: string, values: Record<string, JsonValue>) {
    const plan = await this.plan(id);
    return this.custody.api.json('/api/executions/' + id + '/input', { method: 'PATCH', body: { index: plan.index, values } }, Execution);
  }
  async execute(invocation: DefinitionCall, material: PrivateOperationInput = {}): Promise<ExecutionResultView> {
    const execution = await this.start(invocation);
    if (!execution.waiting) return execution;
    return this.continue(execution.id, material);
  }
  private async method(id: string) {
    const selected = (await this.custody.api.json('/api/connection-methods', {}, listOf(CatalogMethod))).items.find(item => item.id === id);
    if (!selected) throw new Error('Choose an available connection method.');
    const { id: _id, builtin: _builtin, availability: _availability, ...definition } = selected;
    return definition;
  }
  private async program(input: Exclude<z.infer<typeof RunOperation>['operation'], { programId: string }>) {
    return RuntimeOperation.parse(input);
  }
  async continue(id: string, material: PrivateOperationInput = {}): Promise<ExecutionResultView> {
    const execution = await this.custody.api.json('/api/executions/' + Id.parse(id), {}, Execution);
    if (!execution.waiting) return execution;
    const plan = await this.plan(id), { name, input } = plan.invocation;
    if (name === 'connection.authorize') {
      const permission = AuthorizeConnection.parse(input), previous = await this.custody.read(permission.connectionId);
      if (previous.version !== permission.version || previous.content.policy.ownerId !== permission.ownerId ||
        previous.content.policy.contentType !== ContentTypes.tokenSet) throw new Error('Review the current connection before changing its permissions.');
      const policy = await this.userPolicy(previous.content.policy, permission.users, permission.expiresAt);
      const current = await this.custody.api.json('/api/resources/' + permission.connectionId, {}, Resource);
      const resource = await this.custody.save(current.name, await this.custody.reveal(permission.connectionId), policy,
        { previous, metadata: previous.content.metadata,
          commit: async write => Resource.parse((await this.complete(id, plan.index, write as unknown as JsonValue)).results[plan.index]) });
      return { kind: 'saved', resource, executionId: id };
    }
    if (name === 'function.save') {
      const client = new FunctionClient(this.custody.api, this.custody), authorization = await client.prepare(FunctionSave.parse(input));
      const completed = await this.complete(id, plan.index, Json.parse(authorization));
      await client.remember(authorization);
      return { kind: 'saved', resource: Resource.parse(completed.results[plan.index]), executionId: id };
    }
    if (name === 'variable.save' || name === 'app.save') {
      const destination = name === 'app.save' ? AppSave.parse(input) : ValueSave.parse(input);
      const previous = destination.resourceId ? await this.custody.read(destination.resourceId) : undefined;
      if (previous && previous.version !== destination.version) throw new Error('This item changed. Reload it before saving.');
      const environments = await Promise.all((destination.environmentIds ?? []).map(id => this.custody.environment(id)));
      const type = name === 'app.save' ? ContentTypes.clientCredential : ContentTypes.value;
      if (previous && (previous.content.policy.contentType !== type || previous.content.policy.ownerId !== destination.ownerId))
        throw new Error('Choose the item prepared by this operation.');
      const policy = previous && destination.environmentIds === undefined ? previous.content.policy
        : await this.custody.policy(destination.ownerId, type, environments, { previous: previous?.content.policy });
      let bytes: Uint8Array, metadata: Record<string, JsonValue> | undefined;
      if (name === 'app.save') {
        const application = AppSave.parse(input);
        const old = previous ? AppMaterial.parse(JSON.parse(decode(await this.custody.reveal(previous.content.policy.id)))) : null;
        const fields = { ...application.fields, ...material.fields };
        const same = old && old.methodId === application.methodId && old.clientId === application.clientId && canonical(old.fields) === canonical(fields);
        const app = AppMaterial.parse({ format: 1, methodId: application.methodId, clientId: application.clientId, fields,
          generation: same ? old.generation : crypto.randomUUID(),
          ...(material.clientSecret || old?.clientSecret ? { clientSecret: material.clientSecret || old?.clientSecret } : {}) });
        bytes = encode(canonical(app)); metadata = { methodId: app.methodId, clientId: app.clientId, generation: app.generation };
      } else {
        if (material.value === undefined) throw new Error('Enter the value to save.');
        bytes = typeof material.value === 'string' ? encode(material.value) : material.value;
      }
      const resource = await this.custody.save(destination.name, bytes, policy, { previous, metadata,
        commit: async write => Resource.parse((await this.complete(id, plan.index, write as unknown as JsonValue)).results[plan.index]) });
      return { kind: 'saved' as const, resource, executionId: id };
    }
    if (name === 'connection.connect') {
      if (plan.continuation?.kind === 'connection') return this.connections.progress(plan.continuation.id);
      const connection = ConnectService.parse(input), method = await this.method(connection.methodId);
      if (method.kind === 'token') {
        if (await hash(method) !== connection.methodDigest) throw new Error('Review the current connection method.');
        const previous = connection.connectionId ? await this.custody.read(connection.connectionId) : undefined;
        if (previous && (previous.content.policy.ownerId !== connection.ownerId || previous.content.policy.contentType !== ContentTypes.tokenSet))
          throw new Error('Choose a connection belonging to this owner.');
        const old = previous ? ConnectionMaterial.parse(JSON.parse(decode(await this.custody.reveal(connection.connectionId!)))) : null;
        const fields = connectionFields(method.config.fields, material.fields ?? {}, old?.method.kind === 'token' ? old.fields : {});
        const state = ConnectionMaterial.parse({ format: 2, methodId: connection.methodId, method,
          generation: crypto.randomUUID(), appId: null, appGeneration: null, fields });
        let policy = await this.custody.policy(connection.ownerId, ContentTypes.tokenSet, [], { previous: previous?.content.policy });
        if (connection.users) policy = await this.userPolicy(policy, connection.users, undefined, false);
        else if (previous) policy = previous.content.policy;
        const resource = await this.custody.save(connection.name ?? method.name, encode(canonical(state)), policy,
          { previous, metadata: await connectionMetadata(state), labels: connectionLabels(state),
            commit: async write => {
              const completed = await this.complete(id, plan.index, write as unknown as JsonValue);
              const result = completed.results[plan.index] as { id: string };
              return this.custody.api.json('/api/resources/' + result.id, {}, Resource);
            } });
        return { kind: 'saved', resource, executionId: id };
      }
      if (!connection.environmentId) throw new Error('Choose an execution environment before connecting.');
      let appId = connection.appId;
      if (requiresApp(method) && !appId) {
        if (!connection.clientId) throw new Error('Enter the application client ID.');
        const app = AppMaterial.parse({ format: 1, methodId: connection.methodId, clientId: connection.clientId,
          generation: crypto.randomUUID(), fields: material.fields ?? {},
          ...(material.clientSecret ? { clientSecret: material.clientSecret } : {}) });
        const environment = await this.custody.environment(connection.environmentId);
        const policy = await this.custody.policy(connection.ownerId, ContentTypes.clientCredential, [environment]);
        const saved = await this.custody.save((connection.name ?? method.name).slice(0, 185) + ' application', encode(canonical(app)), policy,
          { metadata: { methodId: app.methodId, clientId: app.clientId, generation: app.generation },
            commit: async write => {
              const prepared = await this.custody.api.json('/api/executions/' + id + '/preparation', { method: 'POST',
                body: { index: plan.index, proof: write } }, Execution);
              return this.custody.api.json('/api/resources/' + prepared.operations[plan.index]!.input.appId, {}, Resource);
            } });
        appId = saved.id;
      }
      return this.connections.start({ ownerId: connection.ownerId, environmentId: connection.environmentId,
        name: connection.name ?? method.name, methodId: connection.methodId, method, appId,
        connectionId: connection.connectionId, fields: material.fields, scopes: material.scopes, aws: material.aws,
        environments: connection.environments, redirectUri: connection.redirectUri,
        execution: { id, index: plan.index } });
    }
    if (name === 'run.execute' || name === 'connection.revoke') {
      if (plan.continuation?.kind === 'run') {
        let task: TaskView;
        try { task = await this.custody.api.json('/api/runtime/runs/' + plan.continuation.id, {}, Task); }
        catch (error) {
          if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'not_found') throw error;
          const request = await this.records.get(plan.continuation.id, DelegatedRun);
          if (!request) throw error;
          task = await this.custody.submitPrepared(request);
        }
        if (!['queued', 'running'].includes(task.state)) await this.complete(id, plan.index, { runId: task.id });
        return { kind: 'run' as const, task, executionId: id };
      }
      const revocation = name === 'connection.revoke' ? RevokeConnection.parse(input) : null;
      const run = revocation ? { ...revocation, operation: { kind: 'revoke' as const, input: { action: 'revoke', id: revocation.connectionId } }, save: {} } : RunOperation.parse(input);
      let operation;
      if ('programId' in run.operation) {
        const program = await this.records.get(run.operation.programId, PrivateProgram);
        if (!program || await hash(reviewedProgram(program.operation)) !== run.operation.programDigest)
          throw new Error('Use the reviewed private program.');
        operation = program.operation;
      } else operation = run.operation.kind === 'revoke' ? run.operation : await this.program(run.operation);
      const runId = crypto.randomUUID();
      const environmentId = run.environmentId;
      if (!environmentId) throw new Error('Choose an execution environment.');
      const prepared = await this.custody.prepare(run.ownerId, environmentId, operation, { id: runId, save: run.save, approval: plan.approval,
        ...(revocation ? { sourceIds: [revocation.connectionId] } : {}),
        operationContext: { id, index: plan.index, invocation: plan.invocation } });
      await this.records.put(prepared.intent.id, prepared);
      await this.custody.api.json('/api/executions/' + id + '/continuation', { method: 'PUT',
        body: { index: plan.index, continuation: { kind: 'run', id: prepared.intent.id } } }, Execution);
      const task = await this.custody.submitPrepared(prepared);
      return { kind: 'run' as const, task, executionId: id };
    }
    throw new Error('Choose a supported keyholder operation.');
  }
  private async userPolicy(policy: z.infer<typeof AccessPolicy>, users: string[], expiresAt?: string, advance = true) {
    const expiry = expiresAt ?? new Date(Date.now() + 30 * 86_400_000).toISOString();
    const bindings = await Promise.all([...new Set(users)].map(async id => {
      const { binding } = await this.custody.inspectIdentity(id);
      await this.custody.trusted(binding);
      return binding;
    }));
    return AccessPolicy.parse({ ...policy, revision: policy.revision + (advance ? 1 : 0),
      grants: [...policy.grants.filter(grant => !('actor' in grant)), ...bindings.map(binding => ({ actor: binding, executor: binding,
        operations: [...permittedOperations(policy.contentType)], origins: [], functionDigests: [], callerProgram: true, expiresAt: expiry }))] });
  }
}
