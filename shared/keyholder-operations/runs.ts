import { Execution, RevokeConnection, RunOperation } from '../executions.js';
import { hash } from '../authority.js';
import { Task, RuntimeOperation } from '../runtime-protocol.js';
import type { TaskView } from '../runtime-protocol.js';
import { DelegatedRun } from '../custody.js';
import { PrivateProgram, reviewedProgram } from '../operation-authorization.js';
import type { KeyholderClient, KeyholderOperation } from './types.js';

export function runOperation(client: KeyholderClient): KeyholderOperation {
  return { prepare: async invocation => {
    if (invocation.name === 'run.execute') {
    const run = RunOperation.parse(invocation.input);
    if (!('programId' in run.operation)) {
      const operation = RuntimeOperation.parse(run.operation);
      const programId = crypto.randomUUID();
      await client.records.put(programId, { operation, save: run.save });
      invocation = { ...invocation, input: { ...run,
        operation: { kind: run.operation.kind, programId,
        programDigest: await hash(reviewedProgram(operation)) } } };
    }
    }
    return invocation;
  }, continue: async plan => {
    const id = plan.id, { name, input } = plan.invocation;

    if (plan.continuation?.kind === 'run') {
      let task: TaskView;
      try { task = await client.custody.api.json('/api/runtime/runs/' + plan.continuation.id, {}, Task); }
      catch (error) {
        if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'not_found') throw error;
        const request = await client.records.get(plan.continuation.id, DelegatedRun);
        if (!request) throw error;
        task = await client.custody.submitPrepared(request);
      }
      if (!['queued', 'running'].includes(task.state)) await client.complete(id, plan.index, { runId: task.id });
      return { kind: 'run' as const, task, executionId: id };
    }
    const revocation = name === 'connection.revoke' ? RevokeConnection.parse(input) : null;
    const run = revocation ? { ...revocation, operation: { kind: 'revoke' as const, input: { action: 'revoke', id: revocation.connectionId } }, save: {} } : RunOperation.parse(input);
    let operation;
    if ('programId' in run.operation) {
      const program = await client.records.get(run.operation.programId, PrivateProgram);
      if (!program || await hash(reviewedProgram(program.operation)) !== run.operation.programDigest)
        throw new Error('Use the reviewed private program.');
      operation = program.operation;
    } else operation = run.operation.kind === 'revoke' ? run.operation : RuntimeOperation.parse(run.operation);
    const runId = crypto.randomUUID();
    const environmentId = run.environmentId;
    if (!environmentId) throw new Error('Choose an execution environment.');
    const prepared = await client.custody.prepare(run.ownerId, environmentId, operation, { id: runId, save: run.save, approval: plan.approval,
      ...(revocation ? { sourceIds: [revocation.connectionId] } : {}),
      operationContext: { id, index: plan.index, invocation: plan.invocation } });
    await client.records.put(prepared.intent.id, prepared);
    await client.custody.api.json('/api/executions/' + id + '/continuation', { method: 'PUT',
      body: { index: plan.index, continuation: { kind: 'run', id: prepared.intent.id } } }, Execution);
    const task = await client.custody.submitPrepared(prepared);
    return { kind: 'run' as const, task, executionId: id };
  } };
}
