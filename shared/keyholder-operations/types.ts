import type { DefinitionCall, OperationWaiting } from '../executions.js';
import type { ExecutionClient, ExecutionResultView, PrivateOperationInput } from '../execution-client.js';

export type KeyholderPlan = OperationWaiting & { id: string };
export interface KeyholderOperation {
  prepare?(invocation: DefinitionCall): Promise<DefinitionCall>;
  continue(plan: KeyholderPlan, material: PrivateOperationInput): Promise<ExecutionResultView>;
}
export type KeyholderClient = Pick<ExecutionClient, 'custody' | 'connections' | 'records' | 'configure' | 'complete' | 'continue'>;
