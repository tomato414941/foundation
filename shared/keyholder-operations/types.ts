import type { KeyholderPlan, OperationClient, OperationResultView, PrivateOperationInput } from '../operation-client.js';

export interface KeyholderOperation {
  continue(plan: KeyholderPlan, material: PrivateOperationInput): Promise<OperationResultView>;
}
export type KeyholderClient = Pick<OperationClient, 'custody' | 'connections' | 'records' | 'configure' | 'commit' | 'proceed' | 'review'>;
