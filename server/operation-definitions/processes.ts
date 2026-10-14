import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import { CreateProcess, CreatedProcess, ProcessView } from '../../shared/process.js';
import { DefinitionRegistry } from '../definitions.js';
import type { OperationServices } from '../builtin-definitions.js';
import { idInput } from './support.js';

export function defineProcesses(definitions: DefinitionRegistry, services: Pick<OperationServices, 'processes'>) {
  const { processes } = services;
  const bind = definitions.bind.bind(definitions);
  const process = z.object({ environmentId: C.Id, command: CreateProcess }).strict();
  definitions.define('process.start', process, ['コマンドを実行する', 'Start a command'], async (who, input) => {
    const { id, environmentId, ownerId, actorId, state, createdAt } = await processes.create(who, input.environmentId, input.command);
    return { id, environmentId, ownerId, actorId, state, createdAt };
  }, { environmentReason: ['指定した実行環境でコマンドを動かします。', 'Run the command in the selected execution environment.'],
    observe: async (who, result) => {
      const process = await processes.get(who, C.Id.parse((result as Record<string, C.JsonValue>).id));
      return { state: process.state === 'queued' || process.state === 'running' ? 'pending' : process.state, result: C.Json.parse(process) };
    }, cancel: (who, result) => processes.cancel(who, C.Id.parse((result as Record<string, C.JsonValue>).id)),
    runtimeReference: result => {
      const process = CreatedProcess.strip().safeParse(result);
      return process.success ? { kind: 'process', id: process.data.id } : null;
    },
  });
  bind({ name: 'process.start', method: 'POST', path: '/api/environments/:id/processes', schema: { params: C.IdParams,
    body: CreateProcess, response: { 202: CreatedProcess } }, input: (params, body) => ({ environmentId: params.id, command: body }), status: 202,
    output: result => C.Json.parse(CreatedProcess.strip().parse(result)) });
  definitions.define('process.cancel', idInput, ['コマンドを中止する', 'Cancel a command'], (who, input) => processes.cancel(who, input.id));
  bind({ name: 'process.cancel', method: 'POST', path: '/api/processes/:id/cancel', schema: { params: C.IdParams,
    body: z.object({}).strict(), response: { 200: ProcessView } }, input: params => params });
}
