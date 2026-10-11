import type { Client } from './client.js';
import { privateClient } from './custody.js';
import { ConnectionClient, FlowRecord } from '../../shared/connection-client.js';
import { RemoteFlowStore } from '../../shared/operation-continuations.js';
import { OperationClient } from '../../shared/operation-client.js';
import type { ConnectionFlow } from '../../shared/connection-client.js';

export function operationClient(client: Client) {
  const { custody, journal } = privateClient(client), remote = new RemoteFlowStore(custody);
  const connections = new ConnectionClient(custody, {
    async get(id) {
      const saved = await remote.get(id);
      if (saved) return saved;
      const previous = await journal.read<ConnectionFlow>('flow_' + id);
      if (!previous) return null;
      const flow = FlowRecord.parse(previous);
      await remote.put(flow); return flow;
    },
    put: flow => remote.put(flow),
  });
  return new OperationClient(custody, connections);
}
