import type { KeyholderClient } from './types.js';
import { connectionOperations } from './connections.js';
import { functionOperation } from './functions.js';
import { variableOperation } from './variables.js';
import { runOperation } from './runs.js';

export function keyholderOperations(client: KeyholderClient) {
  const operations = connectionOperations(client), functions = functionOperation(client), runs = runOperation(client);
  operations.set('variable.save', variableOperation(client));
  operations.set('function.save', functions); operations.set('function.configure', functions);
  operations.set('run.execute', runs); operations.set('connection.revoke', runs);
  return operations;
}
