import { z } from 'zod';
import { setTimeout as delay } from 'node:timers/promises';
import type { Client } from './client.js';
import { executionClient } from './executions.js';
import { ApprovalRequest, CatalogEntry, CatalogMethod, Id, Name, Relation, Resource, listOf } from '../../shared/contracts.js';
import type { CatalogConnectionMethod, CatalogService } from '../../shared/contracts.js';
import { Execution } from '../../shared/executions.js';
import type { FlowProgress } from '../../shared/connection-client.js';
import { AwsConnectionInput } from '../../shared/aws.js';
import { connectionMethod } from '../../shared/connection-methods.js';

async function catalogMethod(client: Client, id: string) {
  const catalog = await client.json('/api/connection-methods', {}, listOf(CatalogMethod));
  const selected = catalog.items.find(method => method.id === id);
  if (!selected) throw new Error('Choose an available connection method.');
  return selected;
}
export async function method(client: Client, id: string) {
  const selected = await catalogMethod(client, id);
  const { id: _id, builtin: _builtin, availability: _availability, registration: _registration, defaultName: _defaultName, ...definition } = selected;
  return definition;
}
export function connectionClient(client: Client) {
  return executionClient(client).connections;
}
export async function saveApp(client: Client, input: {
  ownerId: string; name: string; id?: string; methodId: string; clientId: string;
  clientSecret?: string; fields: unknown; environments?: string[];
}) {
  const selected = await catalogMethod(client, input.methodId);
  if (connectionMethod(selected).application === 'none') throw new Error('Choose a connection method that uses an application.');
  const operations = executionClient(client);
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
  ownerId: string; methodId: string; name?: string; appId?: string;
  connectionId?: string; fields: unknown; scopes: unknown; aws?: unknown; redirectUri?: string;
}) {
  const selected = await catalogMethod(client, input.methodId);
  const existing = input.connectionId ? await client.json('/api/resources/' + Id.parse(input.connectionId), {}, Resource) : null;
  const result = await executionClient(client).execute({ name: 'connection.connect', input: {
    ownerId: input.ownerId, methodId: input.methodId,
    name: Name.parse(input.name ?? existing?.name ?? selected.defaultName),
    ...(input.appId ? { appId: input.appId } : {}), ...(input.connectionId ? { connectionId: input.connectionId } : {}),
    ...(input.redirectUri ? { redirectUri: input.redirectUri } : {}),
  } }, { fields: z.record(z.string(), z.string()).parse(input.fields), scopes: z.array(z.string()).optional().parse(input.scopes),
    ...(input.aws !== undefined ? { aws: AwsConnectionInput.parse(input.aws) } : {}) });
  if ('kind' in result && result.kind === 'saved') return result;
  if (!('flow' in result)) throw new Error('Continue the pending connection.');
  return result;
}
export function flowOutput(progress: FlowProgress | { kind: 'saved'; resource: z.infer<typeof Resource>; executionId: string }) {
  if (progress.kind === 'saved') return { kind: 'connected', id: progress.executionId, connectionId: progress.resource.id, resource: progress.resource };
  return { kind: progress.kind, id: progress.flow.execution.id,
    ...(progress.kind === 'pending' ? { state: 'running' } : {}),
    ...(progress.kind === 'authorize' ? { authorizationUrl: progress.url,
      ...(progress.device ? { userCode: progress.device.userCode, verificationUri: progress.device.verificationUri,
        expiresAt: new Date(progress.device.expiresAt).toISOString() } : {}),
      next: (progress.device ? 'Open the URL and enter the user code, then run foundation connect wait ' : 'Open the URL, then run foundation connect wait ') + progress.flow.execution.id } : {}),
    ...(progress.kind === 'cli' ? { next: progress.command } : {}),
    ...(progress.kind === 'connected' ? { connectionId: progress.id } : {}),
    ...(progress.kind === 'failed' ? { error: progress.error } : {}),
  };
}

type Connection = Extract<z.infer<typeof Resource>, { kind: 'connection' }>;
const outputsOf = (method: CatalogConnectionMethod) => connectionMethod(method).outputs;
const describe = (method: CatalogConnectionMethod) => method.id + ' (' + outputsOf(method).join(', ') + ')';

// The principal a new connection is asked of: the one named, or else the only one that delegates to this machine.
export async function connectionOwner(client: Client, self: string, named?: string) {
  if (named) return Id.parse(named);
  const lines = await client.json('/api/relations?' + new URLSearchParams({ subject: self, relation: 'delegate', objectType: 'principal', limit: '200' }),
    {}, listOf(Relation));
  const owners = lines.items;
  if (owners.length === 1) return owners[0]!.objectId;
  if (!owners.length) throw new Error('No principal delegates to this machine. Choose --owner ID, or ask for delegation with foundation request-access.');
  throw new Error('Several principals delegate to this machine. Choose one with --owner: ' +
    owners.map(line => line.objectId + ' (' + line.objectName + ')').join(', '));
}
// The service and method a connection is asked with: --method alone, or a service by id or name, narrowed to the
// methods that give every output named in needs. Methods giving the same outputs are one kind of connection; when kinds
// still differ, this stops and lists them.
export async function chooseMethod(client: Client, input: { service?: string; methodId?: string; needs: string[] }) {
  const catalog = await client.json('/api/catalog', {}, listOf(CatalogEntry));
  const wanted = input.service?.toLowerCase();
  const service = wanted ? catalog.items.find(entry => entry.id.toLowerCase() === wanted || entry.name.toLowerCase() === wanted)
    : catalog.items.find(entry => Object.values(entry.methods).some(method => method.id === input.methodId));
  if (!service) throw new Error(input.service ? 'No service is named ' + input.service + '. Check foundation api GET /api/catalog.'
    : 'Choose an available connection method.');
  let candidates = Object.values(service.methods).filter(method => method.availability !== 'unavailable' &&
    (!input.methodId || method.id === input.methodId) && input.needs.every(name => outputsOf(method).includes(name)));
  if (!candidates.length) throw new Error(service.name + ' has no available method' +
    (input.methodId ? ' ' + input.methodId : '') + (input.needs.length ? ' giving ' + input.needs.join(', ') : '') + '. Its methods: ' +
    Object.values(service.methods).map(describe).join(', '));
  const kinds = new Set(candidates.map(method => [...outputsOf(method)].sort().join(',')));
  if (kinds.size > 1) throw new Error(service.name + ' connections give different values. Choose one with --needs NAME or --method ID: ' +
    candidates.map(describe).join(', '));
  // Of methods giving the same values, prefer one ready to use whose values the owner enters in the browser.
  candidates = [...candidates].sort((a, b) => Number(b.availability === 'ready') - Number(a.availability === 'ready') ||
    Number(b.registration.kind === 'input') - Number(a.registration.kind === 'input'));
  return { service, method: candidates[0]! };
}
// A ready connection of the owner's to the service that already gives every value wanted.
export async function existingConnection(client: Client, owner: string, service: CatalogService, outputs: string[]) {
  let after: string | null = null;
  do {
    const page: { items: z.infer<typeof Resource>[]; next: string | null } = await client.json('/api/principals/' + owner + '/resources?' +
      new URLSearchParams({ kind: 'connection', limit: '200', ...(after ? { after } : {}) }), {}, listOf(Resource));
    const found = page.items.find((item): item is Connection => item.kind === 'connection' && item.data.state === 'ready' &&
      item.data.services.some(entry => entry.id === service.id) && outputs.every(name => item.data.outputs.includes(name)));
    if (found) return found;
    after = page.next;
  } while (after);
  return null;
}
export function connectionOutput(connection: Connection) {
  return { connectionId: connection.id, name: connection.name, ownerId: connection.ownerId, outputs: connection.data.outputs };
}
// Asks the owner to make the connection in their browser, entering what it needs there.
export async function requestConnection(client: Client, input: {
  owner: string; method: CatalogConnectionMethod; why?: string; name?: string; appId?: string; connectionId?: string; scopes?: string[];
}) {
  return client.json('/api/requests', { method: 'POST', body: { to: input.owner, message: input.why ?? '', operations: [{
    name: 'connection.connect', input: { ownerId: input.owner, methodId: input.method.id,
      name: Name.parse(input.name ?? input.method.defaultName),
      ...(input.appId ? { appId: input.appId } : {}), ...(input.connectionId ? { connectionId: input.connectionId } : {}),
      ...(input.scopes ? { scopes: input.scopes } : {}) } }] } }, ApprovalRequest);
}
// Waits for the owner to answer, then for the connection they made.
export async function awaitRequestedConnection(client: Client, request: z.infer<typeof ApprovalRequest>, timeout: number) {
  const deadline = Date.now() + timeout * 1000;
  while (true) {
    const answer = await client.json('/api/requests/' + request.id, {}, ApprovalRequest);
    if (!['pending', 'accepted'].includes(answer.state)) return { kind: answer.state, requestId: request.id };
    const execution = await client.json('/api/executions/' + request.executionId, {}, Execution);
    if (execution.state === 'succeeded') {
      const connection = await client.json('/api/resources/' + Id.parse((execution.results[0] as { id?: unknown } | null)?.id), {}, Resource);
      if (connection.kind !== 'connection') throw new Error('The request did not make a connection.');
      return { kind: 'connected', requestId: request.id, ...connectionOutput(connection) };
    }
    if (['failed', 'cancelled', 'uncertain'].includes(execution.state))
      return { kind: execution.state, requestId: request.id, error: execution.error };
    if (Date.now() >= deadline)
      throw new Error('The owner has not finished yet. Run foundation connect wait-request ' + request.id + ' to keep waiting.');
    await delay(1500);
  }
}
