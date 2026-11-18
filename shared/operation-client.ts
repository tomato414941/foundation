import { z } from 'zod';
import { Id } from './contracts.js';
import type { JsonValue, ResourceView } from './contracts.js';
import { Invocation, OperationView, RequestView } from './operations.js';
import type { OperationCall, OperationContinuation, OperationRecordView, RequestRecordView } from './operations.js';
import type { CustodyClient } from './client.js';
import type { ConnectionClient, FlowProgress } from './connection-client.js';
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
export type OperationResultView = OperationRecordView | RequestRecordView | FlowProgress
  | { kind: 'saved'; resource: ResourceView; operationId: string };
// An operation this device makes: one it makes now, or one Foundation holds already, which a request asked for or
// which waits on its service.
export interface KeyholderPlan extends OperationCall {
  id: string;
  held: boolean;
  continuation: OperationContinuation | null;
}
const MadeOrAsked = z.union([OperationView, RequestView]);

// Forms, CLI calls, and approved requests make operations through the same handlers.
export class OperationClient {
  readonly records: SealedContinuationStore;
  readonly operations;
  constructor(readonly custody: CustodyClient, readonly connections: ConnectionClient) {
    this.records = new SealedContinuationStore(custody);
    this.operations = keyholderOperations(this);
  }
  get(id: string) {
    return this.custody.api.json('/api/operations/' + Id.parse(id), {}, OperationView);
  }
  // The input Foundation will make the operation with.
  async review(call: OperationCall, id: string = crypto.randomUUID()): Promise<KeyholderPlan> {
    const reviewed = await this.custody.api.json('/api/operations/review', { method: 'POST', body: Invocation.parse(call) }, Invocation);
    return { id, ...reviewed, held: false, continuation: null };
  }
  private held(view: OperationRecordView): KeyholderPlan {
    return { id: view.id, name: view.name, input: view.input, held: true, continuation: view.continuation };
  }
  // Makes an operation now. One that saves what only keys can open is sealed on this device first.
  async perform(call: OperationCall, material: PrivateOperationInput = {}): Promise<OperationResultView> {
    if (!this.operations.has(call.name))
      return this.custody.api.json('/api/operations', { method: 'POST', body: Invocation.parse(call) }, MadeOrAsked);
    return this.proceed(await this.review(call), material);
  }
  // Goes on with an operation not made yet, one that failed, or one waiting on its service.
  async continue(id: string, material: PrivateOperationInput = {}): Promise<OperationResultView> {
    const view = await this.get(id);
    if (!view.canPerform) return view;
    if (!view.keyholder) return this.custody.api.json('/api/operations/' + view.id + '/perform', { method: 'POST', body: {} }, MadeOrAsked);
    return this.proceed(this.held(view), material);
  }
  proceed(plan: KeyholderPlan, material: PrivateOperationInput): Promise<OperationResultView> {
    const operation = this.operations.get(plan.name);
    if (!operation) throw new Error('Choose an operation this device can make.');
    return operation.continue(plan, material);
  }
  // Fills what the operation leaves to the one making it.
  async configure(plan: KeyholderPlan, values: Record<string, JsonValue>): Promise<KeyholderPlan> {
    if (!plan.held) return this.review({ name: plan.name, input: { ...plan.input, ...values } }, plan.id);
    return this.held(await this.custody.api.json('/api/operations/' + plan.id, { method: 'PATCH', body: { values } }, OperationView));
  }
  // Makes the operation with what this device sealed for it.
  async commit(plan: KeyholderPlan, proof: JsonValue) {
    return plan.held
      ? this.custody.api.json('/api/operations/' + plan.id + '/perform', { method: 'POST', body: { proof } }, OperationView)
      : this.custody.api.json('/api/operations', { method: 'POST', body: { id: plan.id, name: plan.name, input: plan.input, proof } }, OperationView);
  }
}
