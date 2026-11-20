import { dirname, join } from 'node:path';
import type { Client } from './client.js';
import { configPath } from './config.js';
import { CustodyClient } from '../../shared/client.js';
import type { InjectionInput } from '../../shared/contracts.js';
import { publicPart, thumbprint } from '../../shared/encryption.js';
import { FileJournal } from '../../runtime/journal.js';
import { HttpBroker } from '../../runtime/broker.js';
import { Connections } from '../../runtime/connections.js';
import { PublicTransport } from '../../server/transport.js';
import { openInputs } from '../../runtime/inputs.js';

// What this machine opens and seals with the identity's private key, and the token updates it records meanwhile.
export async function privateClient(client: Client) {
  const { keys, origin, principalId } = client.identity;
  if (!keys) throw new Error('Use a sign-in key that carries the encryption key for this operation.');
  const device = { publicKey: publicPart(keys.encryption), privateKey: keys.encryption };
  const custody = new CustodyClient(client, origin, principalId, device);
  const directory = join(dirname(configPath()), 'custody', await thumbprint(device.publicKey));
  const broker = new HttpBroker(client), transport = new PublicTransport(origin);
  const connections = new Connections(custody, broker.connections(),
    new FileJournal(join(directory, 'connections'), origin, device), transport);
  return { custody, directory, broker, transport, connections };
}

export async function localInputs(client: Client, inputs: InjectionInput[]) {
  const { custody, connections } = await privateClient(client);
  // Token updates this machine recorded but could not give Foundation are given now, before anything is renewed again.
  await connections.reconcile();
  return openInputs(custody, connections, inputs);
}
