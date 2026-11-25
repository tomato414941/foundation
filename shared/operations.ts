import { z } from 'zod';
import { Id, Invocation, Json, JsonObject, Name, Operation as RequestedOperation, OperationTitle, Principal, Proposal, Time } from './contracts.js';

export { Invocation } from './contracts.js';
export type OperationCall = z.infer<typeof Invocation>;

const destination = z.object({ ownerId: Id, name: Name, resourceId: Id.optional(),
  version: z.number().int().positive().optional() }).strict();
// Secret material is supplied to the keyholder implementation, never to these public inputs.
export const ValueSave = destination.extend({ value: z.literal('').optional() });
export const AppSave = destination.extend({ methodId: z.string().min(1).max(200), clientId: z.string().max(1000),
  fields: z.record(z.string(), z.string()).optional(), clientSecret: z.literal('').optional() });
export const AuthorizeConnection = z.object({ ownerId: Id, connectionId: Id, version: z.number().int().positive(),
  users: z.array(Id).max(32) }).strict();
export const ConnectService = z.object({ ownerId: Id, methodId: z.string().min(1).max(200),
  connectionId: Id.optional(), name: Name.optional(), appId: Id.optional(),
  redirectUri: z.url().optional(),
  users: z.array(Id).max(32).optional(),
  scopes: z.array(z.string().min(1).max(1000)).max(200).optional(),
  clientId: z.string().max(1000).optional(), fields: z.record(z.string(), z.string()).optional(),
  clientSecret: z.literal('').optional() }).strict();

// A kind of operation, and whether its holder's device seals what it saves.
export const OperationKind = z.object({ name: Invocation.shape.name, title: OperationTitle, keyholder: z.boolean(),
  configure: z.array(z.string()), input: JsonObject }).strict();
// Where an operation waits on the service it connects to, which the device making it keeps, and for how long.
export const serviceStep = 86_400_000;
export const Continuation = z.object({ kind: z.literal('connection'), id: Id }).strict();
export type OperationContinuation = z.infer<typeof Continuation>;
// A stopped operation has not started or is waiting for the device that seals it.
export const OperationState = z.enum(['stopped', 'in_progress', 'succeeded', 'failed', 'uncertain', 'cancelled']);
export const OperationView = z.object({
  id: Id, name: Invocation.shape.name, title: OperationTitle, input: JsonObject, keyholder: z.boolean(),
  configure: z.array(z.string()), ownerId: Id.nullable(), actor: Principal.pick({ id: true, name: true }),
  requestId: Id.nullable(),
  state: OperationState, result: Json.nullable(),
  error: z.object({ code: z.string(), message: z.string() }).strict().nullable(),
  continuation: Continuation.nullable(), canPerform: z.boolean(), canCancel: z.boolean(),
  url: z.url(), createdAt: Time, updatedAt: Time, expiresAt: Time.nullable(),
}).strict();
export type OperationRecordView = z.infer<typeof OperationView>;
// An operation made now: a holder's device sends what it sealed, or the service step it waits on.
export const OperationInput = Invocation.extend({ id: Id.optional(), proof: Json.optional(),
  continuation: Continuation.optional() }).strict();
export const OperationPerform = z.object({ proof: Json.optional() }).strict();

export const DisplayedOperation = RequestedOperation.extend({ title: OperationTitle, keyholder: z.boolean(),
  configure: z.array(z.string()) });
const Named = Principal.pick({ id: true, name: true });
export const RequestState = z.enum(['pending', 'approved', 'declined', 'withdrawn', 'expired']);
export const RequestView = z.object({
  id: Id, from: Named, to: Named.nullable(), message: z.string(),
  operation: DisplayedOperation, proposal: Proposal.nullable(),
  state: RequestState, createdAt: Time, expiresAt: Time, answeredAt: Time.nullable(),
  performed: z.object({ id: Id, state: OperationState }).strict().nullable(),
  url: z.url(), code: z.string().optional(), returnUrl: z.url().nullable(), refreshUrl: z.url().nullable(),
  canAnswer: z.boolean(), canWithdraw: z.boolean(),
}).strict();
export type RequestRecordView = z.infer<typeof RequestView>;
export const RequestCreate = z.object({
  id: Id.optional(), to: Id.optional(), message: z.string().max(1000).default(''),
  operation: RequestedOperation,
  expiresInMinutes: z.number().int().min(1).max(1440).default(30),
}).strict();
export const RequestApproval = z.object({
  values: JsonObject.default({}),
  configuration: JsonObject.default({}),
  code: z.string().max(20).optional(),
}).strict();
