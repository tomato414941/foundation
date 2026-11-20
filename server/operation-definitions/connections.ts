import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import * as P from '../../shared/protocol.js';
import { AppSave, AuthorizeConnection, ConnectService, ValueSave } from '../../shared/operations.js';
import { canonical } from '../../shared/digest.js';
import { connectionMethod, selectScopes } from '../../shared/connection-methods.js';
import { publicConnectionFields, ConnectionFieldError } from '../../shared/connection-fields.js';
import type { ProtectedKindName } from '../../shared/protected.js';
import type { Catalog } from '../catalog.js';
import type { Custody } from '../custody.js';
import { fail } from '../errors.js';
import { DefinitionRegistry } from '../definitions.js';
import type { OperationServices } from '../builtin-definitions.js';
import { keyholder } from './support.js';

export function defineConnections(definitions: DefinitionRegistry,
  services: Pick<OperationServices, 'resources' | 'custody' | 'catalog' | 'relations'>) {
  const { resources, custody, catalog, relations } = services;
  const bind = definitions.bind.bind(definitions);
  // A value sealed for those who may open it, saved under its current owner.
  definitions.define('custody.write', P.ProtectedWrite, ['機密情報を保存する', 'Save private content'], async (who, input) => resources.view(who, await custody.put(who, input)));
  bind({ name: 'custody.write', method: 'PUT', path: '/api/resources/:id/custody', schema: { params: C.IdParams,
    body: P.ProtectedWrite, response: { 200: C.Resource } }, input: (params, body) => {
      const input = P.ProtectedWrite.parse(body);
      if (params.id !== input.id) fail(400, 'wrong_resource', 'Save the sealed content at its own item.');
      return input;
    } });
  const reviewFields = async (who: Parameters<Catalog['method']>[0], input: Record<string, C.JsonValue>) => {
    const method = await catalog.method(who, z.string().parse(input.methodId));
    if (input.fields === undefined) return input;
    try { return { ...input, fields: publicConnectionFields(connectionMethod(method).fields, z.record(z.string(), z.string()).parse(input.fields)) }; }
    catch (error) { if (error instanceof ConnectionFieldError) fail(400, error.code, error.message); throw error; }
  };
  // Saved secrets carry over when a connection changes its method, so keep it with the service it belongs to.
  const sameService = async (who: Parameters<Catalog['method']>[0], input: { connectionId?: string; methodId: string }) => {
    if (!input.connectionId) return;
    const previous = String((await resources.get(input.connectionId)).data.methodId);
    if (previous === input.methodId) return;
    const services = await catalog.servicesForMethod(who, previous);
    const next = new Set((await catalog.servicesForMethod(who, input.methodId)).map(service => service.id));
    if (services.length && !services.some(service => next.has(service.id)))
      fail(409, 'service_changed', 'Create a new connection for another service.');
  };
  const requireFields = async (who: Parameters<Catalog['method']>[0], input: { methodId: string; fields?: Record<string, string> },
    metadata: Record<string, C.JsonValue>) => {
    await reviewFields(who, { methodId: input.methodId, fields: metadata.fields ?? {} });
    const fields = z.record(z.string(), z.string()).parse(metadata.fields ?? {});
    if (Object.entries(input.fields ?? {}).some(([key, value]) => value && fields[key] !== value))
      fail(409, 'operation_changed', 'Use the service settings approved by this operation.');
  };
  const savePrivate = async (who: Parameters<Custody['put']>[0], input: z.infer<typeof ValueSave> | z.infer<typeof AppSave>,
    proof: C.JsonValue, kind: ProtectedKindName) => {
    const write = P.ProtectedWrite.parse(proof);
    if (write.ownerId !== input.ownerId || write.kind !== kind || write.name !== input.name ||
      (input.resourceId && write.id !== input.resourceId) || write.version !== input.version ||
      (!input.resourceId && await resources.db.one('SELECT 1 FROM resources WHERE id=$1', [write.id])))
      fail(409, 'operation_changed', 'Save the item prepared by this operation.');
    if ('methodId' in input && (write.content.metadata.methodId !== input.methodId || write.content.metadata.clientId !== input.clientId))
      fail(409, 'operation_changed', 'Save the application prepared by this operation.');
    if ('methodId' in input) await requireFields(who, input, write.content.metadata);
    return resources.view(who, await custody.put(who, write));
  };
  definitions.define('variable.save', ValueSave, ['変数を保存する', 'Save a variable'], keyholder,
    { keyholder: true, configure: ['name'], secret: pointer => pointer === '/value',
      complete: (who, input, proof) => savePrivate(who, input, proof, 'variable') });
  definitions.define('app.save', AppSave, ['アプリを保存する', 'Save an application'], keyholder,
    { keyholder: true, configure: ['name', 'clientId', 'fields'],
      secret: pointer => pointer === '/clientSecret' || /^\/fields\/[^/]+$/.test(pointer),
      review: reviewFields, resolve: reviewFields,
      complete: (who, input, proof) => savePrivate(who, input, proof, 'app') });
  // A connection's users open it on their own machines beyond whoever uses what its owner holds. Approving them draws
  // their lines at once; the device that approves seals the connection for them right after.
  definitions.define('connection.authorize', AuthorizeConnection, ['接続の使用を許可する', 'Authorize connection use'],
    async (who, input) => resources.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      const row = await resources.get(input.connectionId, connection);
      if (row.kind !== 'connection' || row.version !== input.version || row.owner_id !== input.ownerId)
        fail(409, 'operation_changed', 'Change permissions for the current connection.');
      await relations.openers(who, row, input.users, connection);
      return resources.view(who, await resources.get(row.id, connection));
    }));
  definitions.define('connection.connect', ConnectService, ['サービスに接続する', 'Connect a service'], keyholder,
    { keyholder: true, continuation: 'connection', configure: ['name', 'appId', 'clientId', 'users', 'fields', 'scopes'],
      secret: pointer => pointer === '/clientSecret' || /^\/fields\/[^/]+$/.test(pointer),
      review: async (who, input) => {
        await catalog.method(who, z.string().parse(input.methodId));
        await sameService(who, z.object({ connectionId: C.Id.optional(), methodId: z.string() }).parse(input));
        return reviewFields(who, input);
      },
      resolve: async (who, input) => {
        await catalog.method(who, input.methodId);
        await sameService(who, input);
        return reviewFields(who, input);
      },
      complete: async (who, input, proof) => {
        await sameService(who, input);
        const method = await catalog.method(who, input.methodId), write = P.ProtectedWrite.parse(proof);
        if (write.ownerId !== input.ownerId || write.kind !== 'connection' ||
          write.name !== (input.name ?? method.name) || input.connectionId && write.id !== input.connectionId ||
          write.content.metadata.methodId !== input.methodId || write.content.metadata.methodKind !== method.kind ||
          write.content.metadata.appId !== (input.appId ?? null) || write.content.metadata.state !== 'ready')
          fail(409, 'operation_changed', 'Save the connection approved by this operation.');
        await requireFields(who, input, write.content.metadata);
        if (input.scopes && (method.kind === 'oauth' || method.kind === 'ovh') &&
          canonical([...selectScopes(method.config.scopes, input.scopes)].sort()) !== canonical([...z.array(z.string()).parse(write.content.metadata.scopes)].sort()))
          fail(409, 'operation_changed', 'Save the service permissions approved by this operation.');
        // Its users, when approved with it, are let in once it is saved; the device that saved it seals it for them.
        const row = await resources.db.transaction(async connection => {
          const saved = await custody.put(who, write, connection);
          if (input.users) await relations.openers(who, saved, input.users, connection);
          return saved;
        });
        return { kind: 'connected', id: row.id, metadata: write.content.metadata };
      } });
}
