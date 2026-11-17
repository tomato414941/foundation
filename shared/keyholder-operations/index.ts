import type { KeyholderClient } from './types.js';
import { connectionOperations } from './connections.js';
import { variableOperation } from './variables.js';

export function keyholderOperations(client: KeyholderClient) {
  const operations = connectionOperations(client);
  operations.set('variable.save', variableOperation(client));
  return operations;
}
