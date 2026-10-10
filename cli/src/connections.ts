import { z } from 'zod';
import type { Client } from './client.js';
import { privateClient } from './custody.js';
import { CatalogMethod, Id, Name, Resource, listOf } from '../../shared/contracts.js';
import { AppMaterial, ConnectionMaterial } from '../../shared/connections.js';
import { ConnectionClient, FlowRecord } from '../../shared/connection-client.js';
import type { ConnectionFlow, FlowProgress } from '../../shared/connection-client.js';
import { canonical } from '../../shared/authority.js';
import { decode, encode } from '../../shared/encryption.js';
import { ContentTypes } from '../../shared/custody.js';
import { AwsConnectionInput } from '../../shared/aws.js';

export async function method(client: Client, id: string) {
  const catalog = await client.json('/api/connection-methods', {}, listOf(CatalogMethod));
  const selected = catalog.items.find(method => method.id === id);
  if (!selected) throw new Error('Choose an available connection method.');
  const { id: _id, builtin: _builtin, availability: _availability, ...definition } = selected;
  return definition;
}
export function connectionClient(client: Client) {
  const { custody, journal } = privateClient(client);
  return new ConnectionClient(custody, {
    async get(id) { const value = await journal.read<ConnectionFlow>('flow_' + id); return value ? FlowRecord.parse(value) : null; },
    put: flow => journal.write('flow_' + flow.id, flow),
  });
}
export async function saveApp(client: Client, input: {
  ownerId: string; name: string; id?: string; methodId: string; clientId: string;
  clientSecret?: string; fields: unknown; environments?: string[];
}) {
  const definition = await method(client, input.methodId);
  if (definition.kind !== 'oauth') throw new Error('Choose an OAuth connection method for this application.');
  const { custody } = privateClient(client);
  const previous = input.id ? await custody.read(Id.parse(input.id)) : undefined;
  if (previous && previous.content.policy.contentType !== ContentTypes.clientCredential) throw new Error('Choose an OAuth application to update.');
  const old = previous ? AppMaterial.parse(JSON.parse(decode(await custody.reveal(previous.content.policy.id)))) : null;
  const identity = { methodId: input.methodId, clientId: input.clientId,
    fields: z.record(z.string(), z.string()).parse(input.fields) };
  const sameIdentity = old && canonical(identity) === canonical({ methodId: old.methodId, clientId: old.clientId, fields: old.fields });
  const material = AppMaterial.parse({ format: 1, ...identity, generation: sameIdentity ? old.generation : crypto.randomUUID(),
    ...(input.clientSecret !== undefined ? { clientSecret: input.clientSecret } : old?.clientSecret ? { clientSecret: old.clientSecret } : {}) });
  const environments = await Promise.all((input.environments ?? []).map(id => custody.environment(Id.parse(id))));
  const policy = previous && !input.environments ? previous.content.policy
    : await custody.policy(input.ownerId, ContentTypes.clientCredential, environments, { previous: previous?.content.policy });
  return custody.save(Name.parse(input.name), encode(canonical(material)), policy, { previous,
    metadata: { methodId: material.methodId, clientId: material.clientId, generation: material.generation } });
}
export async function startConnection(client: Client, input: {
  ownerId: string; environmentId: string; methodId: string; name?: string; appId?: string;
  connectionId?: string; fields: unknown; scopes: unknown; role?: unknown; aws?: unknown; environments?: string[]; redirectUri?: string;
}) {
  const definition = await method(client, input.methodId);
  const existing = input.connectionId ? await client.json('/api/resources/' + Id.parse(input.connectionId), {}, Resource) : null;
  return connectionClient(client).start({ ownerId: input.ownerId, environmentId: Id.parse(input.environmentId),
    name: Name.parse(input.name ?? existing?.name ?? definition.name), methodId: input.methodId, method: definition,
    appId: input.appId, connectionId: input.connectionId, fields: z.record(z.string(), z.string()).parse(input.fields),
    scopes: z.array(z.string()).parse(input.scopes), role: ConnectionMaterial.shape.role.parse(input.role),
    ...(input.aws !== undefined ? { aws: AwsConnectionInput.parse(input.aws) } : {}),
    environments: input.environments, redirectUri: input.redirectUri });
}
export function flowOutput(progress: FlowProgress) {
  return { kind: progress.kind, flowId: progress.flow.id,
    ...('task' in progress ? { taskId: progress.task.id, state: progress.task.state } : {}),
    ...(progress.kind === 'authorize' ? { url: progress.url, next: 'Open the URL, then run foundation connect wait ' + progress.flow.id } : {}),
    ...(progress.kind === 'review' ? { metadata: progress.metadata, next: 'Review the account and permissions, then run foundation connect accept ' + progress.flow.id } : {}),
    ...(progress.kind === 'connected' ? { id: progress.id } : {}),
    ...(progress.kind === 'failed' ? { error: progress.error } : {}),
  };
}
