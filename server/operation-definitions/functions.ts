import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import { FunctionSave, FunctionConfigure } from '../../shared/executions.js';
import { canonical } from '../../shared/authority.js';
import { FunctionWrite, FunctionSettingsWrite, Invocation as FunctionInvocation, InvocationInput } from '../../shared/function-api.js';
import { fail } from '../errors.js';
import { DefinitionRegistry } from '../definitions.js';
import type { OperationServices } from '../builtin-definitions.js';
import { idInput, keyholder } from './support.js';

export function defineFunctions(definitions: DefinitionRegistry, services: Pick<OperationServices, 'resources' | 'custody' | 'delegation' | 'functions' | 'invocations'>) {
  const { resources, custody, delegation, functions, invocations } = services;
  const bind = definitions.bind.bind(definitions);
  definitions.define('function.save', FunctionSave, ['関数を保存する', 'Save a function'], keyholder,
    { execution: 'keyholder', configure: [], complete: async (who, input, proof) => {
      const write = FunctionWrite.parse(proof);
      if (input.resourceId && input.resourceId !== write.functionId || write.publication.ownerId !== input.ownerId ||
        canonical(write.publication.definition) !== canonical(input.definition) || write.publication.revision !== (input.resourceId ? (input.version ?? 0) + 1 : 1))
        fail(409, 'operation_changed', 'Publish the function definition approved by this operation.');
      return functions.save(who, input, write, custody);
    } });
  definitions.define('function.configure', FunctionConfigure, ['関数の実行設定を保存する', 'Save function execution settings'], keyholder,
    { execution: 'keyholder', configure: [], complete: (who, input, proof) =>
      functions.configure(who, input, FunctionSettingsWrite.parse(proof), custody, delegation) });
  const invokeFunction = InvocationInput.extend({ functionId: C.Id, functionVersion: z.number().int().positive().optional() });
  const reviewedFunction = async (input: Record<string, C.JsonValue>) => {
    const row = await resources.get(C.Id.parse(input.functionId));
    if (row.kind !== 'function') fail(400, 'wrong_kind', 'Choose a function.');
    if (input.functionVersion && input.functionVersion !== row.version) fail(409, 'changed', 'The function changed. Review it again.');
    return { ...input, id: input.id ?? crypto.randomUUID(), functionVersion: row.version };
  };
  definitions.define('function.invoke', invokeFunction, ['関数を実行する', 'Invoke a function'],
    async (who, { functionId, functionVersion, ...input }) => {
      await reviewedFunction({ functionId, ...(functionVersion ? { functionVersion } : {}) });
      return invocations.create(who, functionId, input);
    }, { environmentReason: ['関数に設定された実行環境で処理します。', 'Run in the execution environment configured for this function.'],
      review: (_who, input) => reviewedFunction(input), resolve: (_who, input) => reviewedFunction(C.JsonObject.parse(input)),
      observe: async (who, result) => {
        const current = await invocations.get(who, FunctionInvocation.parse(result).id);
        return { state: current.state === 'queued' || current.state === 'running' ? 'pending' : current.state, result: C.Json.parse(current) };
      }, cancel: (who, result) => invocations.cancel(who, FunctionInvocation.parse(result).id),
      runtimeReference: result => {
        const invocation = FunctionInvocation.safeParse(result);
        return invocation.success ? { kind: 'function', id: invocation.data.id } : null;
      }, resultView: result => {
        const invocation = FunctionInvocation.safeParse(result);
        return invocation.success ? invocation.data.result : result;
      },
    });
  definitions.define('function.delete', idInput, ['関数を削除する', 'Delete a function'], async (who, input) => {
    const row = await resources.get(input.id);
    if (row.kind !== 'function') fail(400, 'wrong_kind', 'Choose a function.');
    await resources.delete(who, row); return null;
  });
  bind({ name: 'function.delete', method: 'DELETE', path: '/api/functions/:id', schema: { params: C.IdParams, response: { 204: z.null() } }, input: params => params, status: 204 });
  definitions.define('function.cancel', idInput, ['関数の実行を中止する', 'Cancel a function invocation'], (who, input) => invocations.cancel(who, input.id));
  bind({ name: 'function.cancel', method: 'POST', path: '/api/runtime/functions/:id/cancel', schema: { params: C.IdParams, body: z.object({}).strict(),
    response: { 200: FunctionInvocation } }, input: params => params });
}
