import { canonical, hash } from './authority.js';
import type { ExecutionIntent } from './custody.js';
import { RuntimeOperation } from './runtime-protocol.js';
import type { ExecutionOperation } from './runtime-protocol.js';
import { RunOperation } from './executions.js';
import type { DefinitionCall } from './executions.js';
import { z } from 'zod';

// A run's program kept sealed for its keyholder until the run is carried out; where it keeps values stays with the run.
export const PrivateProgram = z.object({ operation: RuntimeOperation }).strict();
export function reviewedProgram(operation: ExecutionOperation) {
  if (operation.kind === 'http') return { kind: operation.kind, request: operation.request };
  return operation;
}

// An operation as the keyholder that carries it out signs it. The names a run gives new variables are labels Foundation
// keeps beside it.
export function signedInvocation(invocation: DefinitionCall): DefinitionCall {
  if (invocation.name !== 'run.execute') return invocation;
  const { names: _names, ...input } = invocation.input;
  return { ...invocation, input };
}

// Check after decryption and before dispatch: a signature binds the task to the reviewed operation.
export async function authorizeOperationContext(intent: ExecutionIntent, operation: ExecutionOperation) {
  const context = intent.operationContext;
  if (!context) return;
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
  if (operation.kind === 'http' && (canonical(Object.keys(operation.save).sort()) !== canonical(Object.keys(expected.save).sort()) ||
    Object.entries(operation.save).some(([pointer, approval]) => approval.policy.id !== expected.save[pointer])))
    throw new Error('Use the reviewed output destinations.');
}
