import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import * as P from '../../shared/protocol.js';
import { RunOperation } from '../../shared/executions.js';
import { Operations } from '../../shared/custody.js';
import { fail } from '../errors.js';
import { OperationFailed, DefinitionRegistry } from '../definitions.js';
import type { OperationServices } from '../builtin-definitions.js';
import { idInput, keyholder } from './support.js';

export function defineRuns(definitions: DefinitionRegistry, services: Pick<OperationServices, 'delegation'>) {
  const { delegation } = services;
  const bind = definitions.bind.bind(definitions);
  definitions.define('run.cancel', idInput, ['実行を中止する', 'Cancel a run'], (who, input) => delegation.cancel(who, input.id));
  bind({ name: 'run.cancel', method: 'POST', path: '/api/runtime/runs/:id/cancel', schema: { params: C.IdParams,
    body: z.object({}).strict(), response: { 200: P.Task } }, input: params => params });
  definitions.define('run.execute', RunOperation, ['実行する', 'Run an operation'], keyholder,
    { execution: 'keyholder', continuation: 'run', delegatedOperation: input => Operations[input.operation.kind], configure: ['environmentId'], environmentReason: ['HTTPリクエストやコマンドを実行環境で処理します。', 'Send the HTTP request or run the command in an execution environment.'], secret: () => false,
      complete: async (who, input, proof, execution) => {
        const { runId } = z.object({ runId: C.Id }).strict().parse(proof), task = await delegation.get(who, runId);
        if (!['succeeded', 'failed', 'cancelled', 'uncertain'].includes(task.state) || task.intent.actor.principalId !== who.id ||
          task.intent.operationContext?.id !== execution.id || task.intent.operationContext.index !== execution.index ||
          task.intent.ownerId !== input.ownerId || task.environmentId !== input.environmentId ||
          task.intent.operation !== Operations[input.operation.kind] ||
          (who.approvalId && (task.intent.approval?.id !== who.approvalId || task.intent.approval.index !== who.approvalIndex)))
          fail(409, 'execution_required', 'Finish the run prepared by this operation.');
        const result = { kind: 'run', id: task.id, state: task.state };
        if (task.state !== 'succeeded') throw new OperationFailed(result, task.state === 'uncertain');
        return result;
      } });
}
