import { z } from 'zod';
import { setTimeout as delay } from 'node:timers/promises';
import type { Client } from './client.js';
import { CatalogEntry, Id, Name, Relation, Resource, listOf } from '../../shared/contracts.js';
import type { CatalogConnectionMethod, CatalogService } from '../../shared/contracts.js';
import { ConnectService, OperationView, RequestView } from '../../shared/operations.js';
import type { OperationRecordView, RequestRecordView } from '../../shared/operations.js';
import { connectionMethod } from '../../shared/connection-methods.js';
import type { FlowProgress } from '../../shared/connection-client.js';

// What a connection a browser handed over has come to, and what is left to do.
export function flowOutput(progress: FlowProgress) {
  return { kind: progress.kind, id: progress.flow.operationId,
    ...(progress.kind === 'authorize' ? { authorizationUrl: progress.url,
      ...(progress.device ? { userCode: progress.device.userCode, verificationUri: progress.device.verificationUri,
        expiresAt: new Date(progress.device.expiresAt).toISOString() } : {}),
      next: 'Have whoever signs in at the service open the URL and allow it, then run foundation connect continue ' +
        progress.flow.operationId } : {}),
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
  if (!owners.length) throw new Error('Choose the principal to ask with --owner ID.');
  throw new Error('Several principals delegate to this machine. Choose one with --owner: ' +
    owners.map(line => line.objectId + ' (' + line.objectName + ')').join(', '));
}
// The service and method a connection is asked with: --method alone, or a service by id or name, narrowed to the
// methods that give every output named in needs. Methods giving the same outputs are one kind of connection; when kinds
// still differ, this stops and lists them.
export async function chooseMethod(client: Client, input: { service?: string; methodId?: string; needs: string[]; making?: boolean }) {
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
  // Of methods giving the same values, a machine making the connection prefers one it authorizes at the service, so
  // that a person only allows it there; otherwise prefer one ready to use whose values the owner enters in the browser.
  const authorizes = (method: CatalogConnectionMethod) => Number(input.making === true && connectionMethod(method).browserAuthorization);
  candidates = [...candidates].sort((a, b) => authorizes(b) - authorizes(a) ||
    Number(b.availability === 'ready') - Number(a.availability === 'ready') ||
    Number(b.registration.kind === 'input') - Number(a.registration.kind === 'input'));
  return { service, method: candidates[0]! };
}
// The application of the owner's that a new connection is authorized through: the one named, or the only one the owner
// holds for the method. Undefined when the owner holds none this machine may open.
export async function ownerApplication(client: Client, owner: string, method: CatalogConnectionMethod, named?: string) {
  if (named) return Id.parse(named);
  const apps: string[] = [];
  let after: string | null = null;
  do {
    const page: { items: z.infer<typeof Resource>[]; next: string | null } = await client.json('/api/principals/' + owner + '/resources?' +
      new URLSearchParams({ kind: 'app', limit: '200', ...(after ? { after } : {}) }), {}, listOf(Resource));
    for (const item of page.items)
      if (item.kind === 'app' && item.ownerId === owner && item.data.methodId === method.id && item.permissions.includes('reveal'))
        apps.push(item.id);
    after = page.next;
  } while (after);
  if (apps.length > 1) throw new Error('The owner has several applications for ' + method.id + '. Choose one with --app: ' + apps.join(', '));
  return apps[0];
}
// What a connection is made with when this machine makes it: the owner, method and connection, and what the owner
// already decided of it. Who else may open it is the owner's to decide, so a machine makes no connection that lets
// others in.
export function connectionInput(input: {
  ownerId: string; method: CatalogConnectionMethod; name: string; connectionId?: string; appId?: string | null;
  scopes?: string[]; fields?: Record<string, string>;
}) {
  return { ownerId: input.ownerId, methodId: input.method.id, name: Name.parse(input.name),
    ...(input.connectionId ? { connectionId: input.connectionId } : {}),
    ...(input.appId ? { appId: input.appId } : {}),
    ...(input.scopes?.length ? { scopes: input.scopes } : {}),
    ...(input.fields && Object.keys(input.fields).length ? { fields: input.fields } : {}) };
}
// The connection an operation a browser could not finish was making, for this machine to make itself instead.
export function handedOver(operation: OperationRecordView, method: CatalogConnectionMethod) {
  if (operation.name !== 'connection.connect' || !['in_progress', 'stopped', 'failed'].includes(operation.state))
    throw new Error('Choose a connection that is still being made.');
  const input = ConnectService.parse(operation.input);
  if (input.users?.length)
    throw new Error('This connection lets others open it, which its owner decides. Finish it signed in as ' + operation.actor.name + '.');
  return connectionInput({ ownerId: input.ownerId, method, name: input.name ?? method.defaultName, connectionId: input.connectionId,
    appId: input.appId, scopes: input.scopes, fields: input.fields });
}
// A ready connection the caller may use, from the owner's list or among items shared with the caller.
export async function existingConnection(client: Client, input: {
  owner: string; canListOwner: boolean; service: CatalogService; outputs: string[];
}) {
  const { owner, canListOwner, service, outputs } = input;
  const matches = (item: z.infer<typeof Resource>): item is Connection => item.ownerId === owner &&
    item.kind === 'connection' && item.permissions.includes('reveal') && item.data.state === 'ready' &&
    item.data.services.some(entry => entry.id === service.id) && outputs.every(name => item.data.outputs.includes(name));
  if (!canListOwner) {
    const shared = await client.json('/api/resources/shared', {}, listOf(Resource));
    return shared.items.find(matches) ?? null;
  }
  let after: string | null = null;
  do {
    const page: { items: z.infer<typeof Resource>[]; next: string | null } = await client.json('/api/principals/' + owner + '/resources?' +
      new URLSearchParams({ kind: 'connection', limit: '200', ...(after ? { after } : {}) }), {}, listOf(Resource));
    const found = page.items.find(matches);
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
  owner: string; method: CatalogConnectionMethod; why?: string; connectionId?: string; userId?: string;
}) {
  return client.json('/api/requests', { method: 'POST', body: { to: input.owner, message: input.why ?? '', operations: [{
    name: 'connection.connect', input: { ownerId: input.owner, methodId: input.method.id, name: Name.parse(input.method.defaultName),
      ...(input.connectionId ? { connectionId: input.connectionId } : {}),
      ...(!input.connectionId && input.userId ? { users: [input.userId] } : {}) } }] } }, RequestView);
}
// Waits for the owner to answer, then for the connection they made.
export async function awaitRequestedConnection(client: Client, request: RequestRecordView, timeout: number) {
  const deadline = Date.now() + timeout * 1000;
  while (true) {
    const answer = await client.json('/api/requests/' + request.id, {}, RequestView);
    if (!['pending', 'approved'].includes(answer.state)) return { kind: answer.state, requestId: request.id };
    const made = answer.performed[0];
    if (made && ['succeeded', 'failed', 'cancelled', 'uncertain'].includes(made.state)) {
      const operation = await client.json('/api/operations/' + made.id, {}, OperationView);
      if (operation.state !== 'succeeded') return { kind: operation.state, requestId: request.id, operationId: operation.id, error: operation.error };
      const connection = await client.json('/api/resources/' + Id.parse((operation.result as { id?: unknown } | null)?.id), {}, Resource);
      if (connection.kind !== 'connection') throw new Error('The request did not make a connection.');
      return { kind: 'connected', requestId: request.id, operationId: operation.id, ...connectionOutput(connection) };
    }
    if (Date.now() >= deadline)
      throw new Error('The owner has not finished yet. Run foundation connect wait ' + request.id + ' to keep waiting.');
    await delay(1500);
  }
}
