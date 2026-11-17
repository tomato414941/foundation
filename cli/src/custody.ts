import { dirname, join } from 'node:path';
import type { Client } from './client.js';
import { configPath } from './config.js';
import { CustodyClient } from '../../shared/client.js';
import type { InjectionInput } from '../../shared/contracts.js';
import { FileJournal } from '../../runtime/journal.js';
import { JournalTrust } from '../../runtime/trust.js';
import { HttpBroker } from '../../runtime/broker.js';
import { Connections } from '../../runtime/connections.js';
import { PublicTransport } from '../../server/transport.js';
import { openInputs } from '../../runtime/inputs.js';

export function privateClient(client: Client) {
  const { keys, binding, origin } = client.identity;
  if (!keys || !binding) throw new Error('Use a sign-in key with encryption and signing keys for this operation.');
  const directory = join(dirname(configPath()), 'custody', binding.id);
  const journal = new FileJournal(join(directory, 'client'), origin, binding, keys);
  const notified = new Set<string>();
  const custody = new CustodyClient(client, origin, binding, keys, new JournalTrust(journal), access => {
    for (const recipient of access.excluded) {
      if (notified.has(recipient.id)) continue;
      notified.add(recipient.id);
      process.stderr.write('foundation: ' + recipient.name + ' (' + recipient.id + ') cannot open ' +
        (access.operation === 'transfer' ? 'the item after the transfer: ' : 'the saved item: ') +
        (recipient.code === 'identity_changed' ? 'the previously verified public keys changed.' : 'its public keys are not verified by this identity.') +
        (access.operation === 'transfer' ? '\nAfter acceptance, the recipient can verify this delegate\'s fingerprint and run foundation trust '
          : '\nVerify the fingerprint with this principal, then run foundation trust ') + recipient.id +
        ' --fingerprint <verified-fingerprint> to encrypt existing items for it.\n');
    }
  });
  const broker = new HttpBroker(client), transport = new PublicTransport(origin);
  const connections = new Connections(binding, keys, broker.connections(),
    new FileJournal(join(directory, 'connections'), origin, binding, keys), transport);
  return { custody, journal, directory, keys, binding, broker, transport, connections };
}

export async function localInputs(client: Client, inputs: InjectionInput[]) {
  const { custody, connections } = privateClient(client);
  return openInputs(custody, connections, inputs);
}
