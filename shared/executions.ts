import { z } from 'zod';
import { Command, DisplayedOperation, FunctionDefinition, HttpRequest, Id, Invocation, Json, JsonObject, Name, Operation, OperationTitle, Principal, Proposal } from './contracts.js';

export { Invocation } from './contracts.js';
export type DefinitionCall = z.infer<typeof Invocation>;

const destination = z.object({ ownerId: Id, name: Name, resourceId: Id.optional(),
  version: z.number().int().positive().optional(), environmentIds: z.array(Id).max(32).optional() }).strict();
// Secret material is supplied to the keyholder implementation, never to these public inputs.
export const ValueSave = destination.extend({ value: z.literal('').optional() });
export const AppSave = destination.extend({ methodId: z.string().min(1).max(200), clientId: z.string().max(1000),
  fields: z.record(z.string(), z.string()).optional(), clientSecret: z.literal('').optional() });
export const FunctionSave = z.object({ ownerId: Id, name: Name, definition: FunctionDefinition,
  resourceId: Id.optional(), version: z.number().int().positive().optional() }).strict();
export const RevokeConnection = z.object({ ownerId: Id, connectionId: Id, environmentId: Id }).strict();
export const AuthorizeConnection = z.object({ ownerId: Id, connectionId: Id, version: z.number().int().positive(),
  users: z.array(Id).max(32), expiresAt: z.iso.datetime().optional() }).strict();
export const ConnectService = z.object({ ownerId: Id, methodId: z.string().min(1).max(200),
  connectionId: Id.optional(), environmentId: Id.optional(), name: Name.optional(), appId: Id.optional(),
  environments: z.array(Id).max(32).optional(), redirectUri: z.url().optional(),
  users: z.array(Id).max(32).optional(),
  scopes: z.array(z.string().min(1).max(1000)).max(200).optional(),
  methodDigest: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional(),
  clientId: z.string().max(1000).optional(), fields: z.record(z.string(), z.string()).optional(),
  clientSecret: z.literal('').optional() }).strict();
export const RunOperation = z.object({ ownerId: Id, environmentId: Id.optional(),
  operation: z.union([
    z.object({ kind: z.literal('http'), request: HttpRequest }).strict(),
    Command.extend({ kind: z.literal('command') }),
    z.object({ kind: z.enum(['http', 'command']), programId: Id, programDigest: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict(),
  ]), save: z.record(z.string(), Name).default({}) }).strict().superRefine((value, context) => {
    if (!value.environmentId)
      context.addIssue({ code: 'custom', path: ['environmentId'], message: 'Choose an execution environment.' });
  });

export const DefinitionDescription = z.object({ name: Invocation.shape.name, title: OperationTitle,
  execution: z.enum(['server', 'keyholder']), configure: z.array(z.string()), input: JsonObject }).strict();
export const ExecutionInput = z.object({ id: Id.optional(), operations: z.array(Operation).min(1).max(8), responderId: Id.optional(),
  message: z.string().max(1000).default(''), expiresInMinutes: z.number().int().min(1).max(1440).default(1440) }).strict();
export const ExecutionResponse = z.object({ values: z.array(JsonObject).max(8).default([]),
  configuration: z.array(JsonObject).max(8).default([]), code: z.string().max(20).optional() }).strict();
export const WaitingOperation = z.object({ index: z.number().int().nonnegative(), invocation: Invocation,
  approval: z.object({ id: Id, index: z.number().int().nonnegative() }).strict().optional(),
  continuation: z.object({ kind: z.enum(['connection', 'run']), id: Id }).strict().nullable() }).strict();
export type OperationWaiting = z.infer<typeof WaitingOperation>;
export const Execution = z.object({ id: Id, actorId: Id,
  ownerId: Id,
  requests: z.array(Id),
  steps: z.array(z.object({ index: z.number().int().nonnegative(), name: Invocation.shape.name,
    state: z.enum(['waiting', 'running', 'succeeded', 'failed', 'uncertain', 'cancelled']),
    runs: z.array(z.object({ kind: z.enum(['run', 'function']), id: Id }).strict()) }).strict()),
  creator: Principal.pick({ id: true, name: true }), operations: z.array(DisplayedOperation),
  approval: z.object({ requestId: Id.nullable(), proposal: Proposal.nullable() }).strict().nullable(),
  canContinue: z.boolean(), canCancel: z.boolean(), url: z.url(), code: z.string().optional(),
  error: z.object({ code: z.string(), message: z.string() }).strict().nullable(),
  index: z.number().int().nonnegative(),
  state: z.enum(['waiting', 'running', 'succeeded', 'failed', 'uncertain', 'cancelled']),
  wait: z.enum(['approval', 'input', 'execution']).nullable(), waiting: WaitingOperation.nullable(),
  results: z.array(Json.nullable()), createdAt: z.iso.datetime(), expiresAt: z.iso.datetime() }).strict();
export type ExecutionView = z.infer<typeof Execution>;
export const OperationContext = z.object({ id: Id, index: z.number().int().nonnegative(), invocation: Invocation,
  continuationId: Id.optional() }).strict();
