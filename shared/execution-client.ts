import { z } from 'zod';
import { Invocation, Execution, WaitingOperation } from './executions.js';
import type { DefinitionCall, ExecutionView } from './executions.js';
import { Id } from './contracts.js';
import type { JsonValue, ResourceView } from './contracts.js';
import type { CustodyClient } from './client.js';
import type { ConnectionClient, FlowProgress } from './connection-client.js';
import type { TaskView } from './runtime-protocol.js';
import type { AwsConnectionRequest } from './aws.js';
import { AwsConnectionInput } from './aws.js';
import { SealedContinuationStore } from './operation-continuations.js';
import { keyholderOperations } from './keyholder-operations/index.js';

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

// Forms, CLI calls, and approval flows dispatch through the same operation handlers.
export class ExecutionClient {
  readonly records: SealedContinuationStore;
  readonly operations;
  constructor(readonly custody: CustodyClient, readonly connections: ConnectionClient) {
    this.records = new SealedContinuationStore(custody);
    this.operations = keyholderOperations(this);
  }
  async start(invocation: DefinitionCall) {
    invocation = await this.operations.get(invocation.name)?.prepare?.(invocation) ?? invocation;
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
  async continue(id: string, material: PrivateOperationInput = {}): Promise<ExecutionResultView> {
    const execution = await this.custody.api.json('/api/executions/' + Id.parse(id), {}, Execution);
    if (!execution.waiting) return execution;
    const plan = await this.plan(id), operation = this.operations.get(plan.invocation.name);
    if (!operation) throw new Error('Choose a supported keyholder operation.');
    return operation.continue(plan, material);
  }
}
