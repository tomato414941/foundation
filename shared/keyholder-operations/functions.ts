import { FunctionSave, FunctionConfigure } from '../executions.js';
import { Json, Resource } from '../contracts.js';
import { FunctionClient } from '../function-client.js';
import type { KeyholderClient, KeyholderOperation } from './types.js';

export function functionOperation(client: KeyholderClient): KeyholderOperation {
  return { continue: async plan => {
    const id = plan.id, { name, input } = plan.invocation;

    const functions = new FunctionClient(client.custody.api, client.custody);
    const authorization = name === 'function.save' ? await functions.prepare(FunctionSave.parse(input))
      : await functions.prepareSettings(FunctionConfigure.parse(input));
    const completed = await client.complete(id, plan.index, Json.parse(authorization));
    if ('contents' in authorization) await functions.remember(authorization);
    return { kind: 'saved', resource: Resource.parse(completed.results[plan.index]), executionId: id };
  } };
}
