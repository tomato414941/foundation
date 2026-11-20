import { PublicTransport } from '../../server/transport.js';
import type { Client } from './client.js';
import { privateClient } from './custody.js';
import { ConnectionClient } from '../../shared/connection-client.js';
import { RemoteFlowStore } from '../../shared/operation-continuations.js';
import { OperationClient } from '../../shared/operation-client.js';

// Goes on with what a browser handed to this machine: a connection whose service gives its tokens only outside a browser.
export async function operationClient(client: Client) {
  const { custody } = await privateClient(client);
  const connections = new ConnectionClient(custody, new RemoteFlowStore(custody), new PublicTransport(custody.origin), 'cli');
  return new OperationClient(custody, connections);
}
