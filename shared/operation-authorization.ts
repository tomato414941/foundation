import { canonical, hash } from './authority.js';
import type { ExecutionIntent } from './custody.js';
import { RuntimeOperation } from './runtime-protocol.js';
import type { ExecutionOperation } from './runtime-protocol.js';
import { ConnectService, RevokeConnection, RunOperation } from './executions.js';
import { JsonObject, Name } from './contracts.js';
import { z } from 'zod';

export const PrivateProgram = z.object({ operation: RuntimeOperation, save: z.record(z.string(), Name) }).strict();
export function reviewedProgram(operation: ExecutionOperation) {
  if (operation.kind === 'http') return { kind: operation.kind, request: operation.request };
  return operation;
}

// Check after decryption and before dispatch: a signature binds the task to the reviewed operation.
export async function authorizeOperationContext(intent: ExecutionIntent, operation: ExecutionOperation) {
  const context = intent.operationContext;
  if (!context) return;
  if (context.invocation.name === 'connection.revoke') {
    const expected = RevokeConnection.parse(context.invocation.input);
    if (operation.kind !== 'revoke' || canonical(operation.input) !== canonical({ action: 'revoke', id: expected.connectionId }) ||
      expected.ownerId !== intent.ownerId || expected.environmentId !== intent.environmentId)
      throw new Error('Revoke the reviewed connection on its selected executor.');
    return;
  }
  if (context.invocation.name === 'connection.connect') {
    const expected = ConnectService.parse(context.invocation.input), input = JsonObject.parse(operation.kind === 'connect' ? operation.input : null);
    if (operation.kind !== 'connect' || input.flowId !== context.continuationId || expected.ownerId !== intent.ownerId ||
      expected.environmentId !== intent.environmentId) throw new Error('Use the reviewed connection and execution environment.');
    if (input.action === 'start' && (input.methodId !== expected.methodId || input.name !== expected.name ||
      input.appId !== (expected.appId ?? null) || await hash(input.method) !== expected.methodDigest))
      throw new Error('Use the reviewed connection method and application.');
    if (input.action === 'start') {
      const fields = z.record(z.string(), z.string()).parse(input.fields ?? {});
      if (Object.entries(expected.fields ?? {}).some(([key, value]) => value && fields[key] !== value))
        throw new Error('Use the reviewed service settings.');
    }
    if (!['start', 'exchange', 'commit'].includes(String(input.action))) throw new Error('Continue the reviewed connection.');
    return;
  }
  if (context.invocation.name !== 'run.execute') throw new Error('Use the reviewed operation.');
  const expected = RunOperation.parse(context.invocation.input);
  if (expected.ownerId !== intent.ownerId || expected.environmentId !== intent.environmentId || expected.operation.kind !== operation.kind)
    throw new Error('Use the reviewed run and execution environment.');
  if ('programDigest' in expected.operation) {
    if (await hash(reviewedProgram(operation)) !== expected.operation.programDigest) throw new Error('Run the reviewed private program.');
  } else if (operation.kind === 'http' && expected.operation.kind === 'http') {
    if (canonical(operation.request) !== canonical(expected.operation.request))
      throw new Error('Run the reviewed HTTP request and output destinations.');
  } else if (canonical(operation) !== canonical(RuntimeOperation.parse(expected.operation))) throw new Error('Run the reviewed command.');
  if (operation.kind === 'http' && canonical(Object.fromEntries(Object.entries(operation.save).map(([pointer, output]) => [pointer, output.name]))) !== canonical(expected.save))
    throw new Error('Use the reviewed output destinations.');
}
