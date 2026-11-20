import { PublicTransport } from '../../server/transport.js';
import type { Client } from './client.js';
import { privateClient } from './custody.js';
import { ConnectionClient } from '../../shared/connection-client.js';
import { RemoteFlowStore } from '../../shared/operation-continuations.js';
import { OperationClient } from '../../shared/operation-client.js';
import type { CustodyClient } from '../../shared/client.js';

export async function operationClient(client: Client, given?: CustodyClient) {
  const custody = given ?? (await privateClient(client)).custody;
  const connections = new ConnectionClient(custody, new RemoteFlowStore(custody), new PublicTransport(custody.origin), 'cli');
  return new OperationClient(custody, connections);
}
