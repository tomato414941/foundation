import { z } from 'zod';
import type { Client } from './client.js';
import { operationClient } from './operations.js';
import { CatalogMethod, Id, Name, Resource, listOf } from '../../shared/contracts.js';
import type { FlowProgress } from '../../shared/connection-client.js';
import { AwsConnectionInput } from '../../shared/aws.js';

export async function method(client: Client, id: string) {
  const catalog = await client.json('/api/connection-methods', {}, listOf(CatalogMethod));
  const selected = catalog.items.find(method => method.id === id);
  if (!selected) throw new Error('Choose an available connection method.');
  const { id: _id, builtin: _builtin, availability: _availability, ...definition } = selected;
  return definition;
}
export function connectionClient(client: Client) {
  return operationClient(client).connections;
}
export async function saveApp(client: Client, input: {
  ownerId: string; name: string; id?: string; methodId: string; clientId: string;
  clientSecret?: string; fields: unknown; environments?: string[];
}) {
  const definition = await method(client, input.methodId);
  if (definition.kind !== 'oauth') throw new Error('Choose an OAuth connection method for this application.');
  const operations = operationClient(client);
  const previous = input.id ? await operations.custody.read(Id.parse(input.id)) : undefined;
  const result = await operations.execute({ name: 'app.save', input: { ownerId: input.ownerId, name: Name.parse(input.name),
    methodId: input.methodId, clientId: input.clientId,
    ...(input.id ? { resourceId: input.id, version: previous!.version } : {}),
    ...(input.environments ? { environmentIds: input.environments } : {}) } },
    { clientSecret: input.clientSecret, fields: z.record(z.string(), z.string()).parse(input.fields) });
  if (!('kind' in result) || result.kind !== 'saved') throw new Error('Finish saving the application.');
  return result.resource;
}
export async function startConnection(client: Client, input: {
  ownerId: string; environmentId: string; methodId: string; name?: string; appId?: string;
  connectionId?: string; fields: unknown; scopes: unknown; aws?: unknown; environments?: string[]; redirectUri?: string;
}) {
  const definition = await method(client, input.methodId);
  const existing = input.connectionId ? await client.json('/api/resources/' + Id.parse(input.connectionId), {}, Resource) : null;
  const result = await operationClient(client).execute({ name: 'connection.connect', input: {
    ownerId: input.ownerId, environmentId: Id.parse(input.environmentId), methodId: input.methodId,
    name: Name.parse(input.name ?? existing?.name ?? definition.name),
    ...(input.appId ? { appId: input.appId } : {}), ...(input.connectionId ? { connectionId: input.connectionId } : {}),
    ...(input.environments ? { environments: input.environments } : {}), ...(input.redirectUri ? { redirectUri: input.redirectUri } : {}),
  } }, { fields: z.record(z.string(), z.string()).parse(input.fields), scopes: z.array(z.string()).optional().parse(input.scopes),
    ...(input.aws !== undefined ? { aws: AwsConnectionInput.parse(input.aws) } : {}) });
  if (!('flow' in result)) throw new Error('Continue the pending connection.');
  return result;
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
