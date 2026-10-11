import { z } from 'zod';
import { Command, FunctionDefinition, HttpRequest, Id, Invocation, Json, JsonObject, Name, OperationTitle } from './contracts.js';

export { Invocation } from './contracts.js';
export type OperationInvocation = z.infer<typeof Invocation>;

const destination = z.object({ ownerId: Id, name: Name, resourceId: Id.optional(),
  version: z.number().int().positive().optional(), environmentIds: z.array(Id).max(32).optional() }).strict();
// Secret material is supplied to the keyholder implementation, never to these public inputs.
export const ValueSave = destination.extend({ value: z.literal('').optional() });
export const AppSave = destination.extend({ methodId: z.string().min(1).max(200), clientId: z.string().max(1000),
  fields: z.record(z.string(), z.literal('')).default({}), clientSecret: z.literal('').optional() });
export const FunctionSave = z.object({ ownerId: Id, name: Name, definition: FunctionDefinition,
  resourceId: Id.optional(), version: z.number().int().positive().optional() }).strict();
export const ConnectService = z.object({ ownerId: Id, methodId: z.string().min(1).max(200),
  connectionId: Id.optional(), environmentId: Id.optional(), name: Name.optional(), appId: Id.optional(),
  environments: z.array(Id).max(32).optional(), redirectUri: z.url().optional(),
  methodDigest: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional(),
  clientId: z.string().max(1000).optional(), fields: z.record(z.string(), z.literal('')).optional(),
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

export const OperationDescription = z.object({ name: Invocation.shape.name, title: OperationTitle,
  execution: z.enum(['server', 'keyholder']), input: JsonObject }).strict();
export const WaitingOperation = z.object({ index: z.number().int().nonnegative(), invocation: Invocation,
  approval: z.object({ id: Id, index: z.number().int().nonnegative() }).strict().optional(),
  continuation: z.object({ kind: z.enum(['connection', 'run']), id: Id }).strict().nullable() }).strict();
export type OperationWaiting = z.infer<typeof WaitingOperation>;
export const OperationExecution = z.object({ id: Id, actorId: Id,
  index: z.number().int().nonnegative(),
  state: z.enum(['waiting', 'running', 'succeeded', 'failed', 'uncertain', 'cancelled']),
  wait: z.enum(['approval', 'input']).nullable(), waiting: WaitingOperation.nullable(),
  results: z.array(Json.nullable()), createdAt: z.iso.datetime(), expiresAt: z.iso.datetime() }).strict();
export type OperationExecutionView = z.infer<typeof OperationExecution>;
export const OperationContext = z.object({ id: Id, index: z.number().int().nonnegative(), invocation: Invocation,
  continuationId: Id.optional() }).strict();
