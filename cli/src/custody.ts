import { dirname, join } from 'node:path';
import type { Client } from './client.js';
import { configPath } from './config.js';
import { CustodyClient } from '../../shared/client.js';
import { hash } from '../../shared/authority.js';
import { ContentTypes, Operations, useContent } from '../../shared/custody.js';
import type { ExecutionIntent } from '../../shared/custody.js';
import type { InjectionInput } from '../../shared/contracts.js';
import { encode } from '../../shared/encryption.js';
import { FileJournal } from '../../runtime/journal.js';
import { JournalTrust } from '../../runtime/trust.js';
import { HttpBroker } from '../../runtime/broker.js';
import { Connections } from '../../runtime/connections.js';
import { PublicTransport } from '../../server/transport.js';
import { processInputs } from '../../runtime/inputs.js';

export function privateClient(client: Client) {
  const { keys, binding, origin } = client.identity;
  if (!keys || !binding) throw new Error('Use a sign-in key with encryption and signing keys for this operation.');
  const directory = join(dirname(configPath()), 'custody', binding.id);
  const journal = new FileJournal(join(directory, 'client'), origin, binding, keys);
  const custody = new CustodyClient(client, origin, binding, keys, new JournalTrust(journal));
  const broker = new HttpBroker(client), transport = new PublicTransport(origin);
  const connections = new Connections(binding, keys, broker.connections(),
    new FileJournal(join(directory, 'connections'), origin, binding, keys), transport);
  return { custody, journal, directory, keys, binding, broker, transport, connections };
}

export async function localInputs(client: Client, inputs: InjectionInput[]) {
  const { custody, keys, binding, connections } = privateClient(client);
  const sources = await custody.sourceContents(inputs.map(input => input.source.id));
  const intent: ExecutionIntent = {
    format: 2, id: crypto.randomUUID(), origin: client.identity.origin, ownerId: binding.principalId,
    actor: binding, executor: binding, environmentId: binding.id, environmentDigest: await hash(binding),
    operation: Operations.command, functionDigest: null, operationDigest: await hash(inputs),
    sources: await Promise.all(sources.map(async content => ({ id: content.policy.id,
      policyDigest: await hash(content.policy), materialRevision: content.materialRevision,
      ...(content.policy.contentType === ContentTypes.tokenSet ? { authorizationDigest: String(content.metadata.authorizationDigest) } : {}),
    }))), resultRecipients: [binding], createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  };
  const outputs = new Map<string, Promise<Record<string, string>>>();
  return processInputs(inputs, async source => {
    const content = sources.find(content => content.policy.id === source.id)!;
    if (content.policy.contentType === ContentTypes.value) return useContent(content, intent, keys);
    if (!outputs.has(source.id)) outputs.set(source.id, connections.outputs(content, intent, sources, new AbortController().signal));
    const values = await outputs.get(source.id)!;
    if (!source.output || !Object.hasOwn(values, source.output)) throw new Error('Choose an available connection output.');
    return encode(values[source.output]!);
  });
}
