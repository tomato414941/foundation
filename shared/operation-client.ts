import { z } from 'zod';
import { AppSave, ConnectService, FunctionSave, Invocation, OperationExecution, RunOperation, ValueSave, WaitingOperation } from './operations.js';
import type { OperationInvocation, OperationExecutionView } from './operations.js';
import { CatalogMethod, Id, Resource, listOf } from './contracts.js';
import type { JsonValue, ResourceView } from './contracts.js';
import type { CustodyClient } from './client.js';
import type { ConnectionClient, FlowProgress } from './connection-client.js';
import { canonical, hash } from './authority.js';
import { ContentTypes } from './custody.js';
import { AppMaterial, requiresApp } from './connections.js';
import { decode, encode } from './encryption.js';
import { Task, RuntimeOperation } from './execution.js';
import type { TaskView } from './execution.js';
import type { AwsConnectionRequest } from './aws.js';
import { AwsConnectionInput } from './aws.js';
import { SealedContinuationStore } from './operation-continuations.js';
import { DelegatedRun } from './custody.js';
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
export type OperationResult = OperationExecutionView | FlowProgress | { kind: 'saved'; resource: ResourceView }
  | { kind: 'run'; task: TaskView };

// Normal forms, the CLI, and an execution awaiting input use this same keyholder implementation.
export class OperationClient {
  readonly records: SealedContinuationStore;
  constructor(readonly custody: CustodyClient, readonly connections: ConnectionClient) { this.records = new SealedContinuationStore(custody); }
  async start(invocation: OperationInvocation) {
    if (invocation.name === 'run.execute') {
      const run = RunOperation.parse(invocation.input);
      if (!('programId' in run.operation)) {
        const operation = await this.program(run.operation);
        if (operation.kind === 'function' && run.environmentId && run.environmentId !== operation.definition.environmentId)
          throw new Error('Run the function in its configured environment.');
        const programId = crypto.randomUUID();
        await this.records.put(programId, { operation, save: run.save });
        invocation = { ...invocation, input: { ...run,
          ...(operation.kind === 'function' ? { environmentId: operation.definition.environmentId } : {}), operation: { kind: run.operation.kind, programId,
          programDigest: await hash(reviewedProgram(operation)), ...(run.operation.kind === 'function'
            ? { functionId: run.operation.functionId, definitionDigest: await hash(operation.kind === 'function' ? operation.definition : null) } : {}) } } };
      }
    }
    return this.custody.api.json('/api/operation-executions', { method: 'POST', body: Invocation.parse(invocation) }, OperationExecution);
  }
  async plan(id: string) {
    return this.custody.api.json('/api/operation-executions/' + Id.parse(id) + '/input', {}, WaitingOperation.extend({ id: Id }));
  }
  async complete(id: string, index: number, proof: JsonValue) {
    return this.custody.api.json('/api/operation-executions/' + id + '/complete', { method: 'POST', body: { index, proof } }, OperationExecution);
  }
  async configure(id: string, values: Record<string, JsonValue>) {
    const plan = await this.plan(id);
    return this.custody.api.json('/api/operation-executions/' + id + '/input', { method: 'PATCH', body: { index: plan.index, values } }, OperationExecution);
  }
  async execute(invocation: OperationInvocation, material: PrivateOperationInput = {}): Promise<OperationResult> {
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
    if (input.kind !== 'function') return RuntimeOperation.parse(input);
    const resource = await this.custody.api.json('/api/resources/' + input.functionId, {}, Resource);
    if (resource.kind !== 'function' || (input.definitionDigest && await hash(resource.data) !== input.definitionDigest))
      throw new Error('Choose the reviewed function.');
    return RuntimeOperation.parse({ kind: 'function', functionId: resource.id, definition: resource.data, arguments: input.arguments });
  }
  async continue(id: string, material: PrivateOperationInput = {}): Promise<OperationResult> {
    const execution = await this.custody.api.json('/api/operation-executions/' + Id.parse(id), {}, OperationExecution);
    if (!execution.waiting) return execution;
    const plan = await this.plan(id), { name, input } = plan.invocation;
    if (name === 'function.save') {
      const destination = FunctionSave.parse(input);
      const write = await this.custody.prepareFunction(destination.definition, destination.resourceId ?? crypto.randomUUID(), Boolean(destination.resourceId));
      const completed = await this.complete(id, plan.index, write as unknown as JsonValue);
      for (const { content } of Object.values(write.contents)) await this.custody.trust.rememberContent(content);
      return { kind: 'saved' as const, resource: Resource.parse(completed.results[plan.index]) };
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
      return { kind: 'saved' as const, resource };
    }
    if (name === 'connection.connect') {
      if (plan.continuation?.kind === 'connection') return this.connections.progress(plan.continuation.id);
      const connection = ConnectService.parse(input), method = await this.method(connection.methodId);
      if (!connection.environmentId) throw new Error('Choose an execution environment before connecting.');
      let appId = connection.appId;
      if (requiresApp(method) && !appId) {
        if (!connection.clientId) throw new Error('Enter the application client ID.');
        const saved = await this.execute({ name: 'app.save', input: { ownerId: connection.ownerId,
          name: (connection.name ?? method.name).slice(0, 185) + ' application', methodId: connection.methodId,
          clientId: connection.clientId, environmentIds: [connection.environmentId] } },
          { clientSecret: material.clientSecret, fields: material.fields });
        if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Save the application before connecting.');
        appId = saved.resource.id;
      }
      return this.connections.start({ ownerId: connection.ownerId, environmentId: connection.environmentId,
        name: connection.name ?? method.name, methodId: connection.methodId, method, appId,
        connectionId: connection.connectionId, fields: material.fields, scopes: material.scopes, aws: material.aws,
        environments: connection.environments, redirectUri: connection.redirectUri,
        execution: { id, index: plan.index } });
    }
    if (name === 'run.execute') {
      if (plan.continuation?.kind === 'run') {
        let task: TaskView;
        try { task = await this.custody.api.json('/api/executions/' + plan.continuation.id, {}, Task); }
        catch (error) {
          if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'not_found') throw error;
          const request = await this.records.get(plan.continuation.id, DelegatedRun);
          if (!request) throw error;
          task = await this.custody.submitPrepared(request);
        }
        if (!['queued', 'running'].includes(task.state)) await this.complete(id, plan.index, { runId: task.id });
        return { kind: 'run' as const, task };
      }
      const run = RunOperation.parse(input);
      let operation;
      if ('programId' in run.operation) {
        const program = await this.records.get(run.operation.programId, PrivateProgram);
        if (!program || await hash(reviewedProgram(program.operation)) !== run.operation.programDigest)
          throw new Error('Use the reviewed private program.');
        operation = program.operation;
      } else operation = await this.program(run.operation);
      const runId = crypto.randomUUID();
      const environmentId = operation.kind === 'function' ? operation.definition.environmentId : run.environmentId;
      if (!environmentId) throw new Error('Choose an execution environment.');
      const prepared = await this.custody.prepare(run.ownerId, environmentId, operation, { id: runId, save: run.save, approval: plan.approval,
        operationContext: { id, index: plan.index, invocation: plan.invocation } });
      await this.records.put(prepared.intent.id, prepared);
      await this.custody.api.json('/api/operation-executions/' + id + '/continuation', { method: 'PUT',
        body: { index: plan.index, continuation: { kind: 'run', id: prepared.intent.id } } }, OperationExecution);
      const task = await this.custody.submitPrepared(prepared);
      return { kind: 'run' as const, task };
    }
    throw new Error('Choose a supported keyholder operation.');
  }
}
