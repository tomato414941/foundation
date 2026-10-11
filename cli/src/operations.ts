import type { Client } from './client.js';
import { privateClient } from './custody.js';
import { ConnectionClient } from '../../shared/connection-client.js';
import { RemoteFlowStore } from '../../shared/operation-continuations.js';
import { OperationClient } from '../../shared/operation-client.js';

export function operationClient(client: Client) {
  const { custody } = privateClient(client);
  const connections = new ConnectionClient(custody, new RemoteFlowStore(custody));
  return new OperationClient(custody, connections);
}
