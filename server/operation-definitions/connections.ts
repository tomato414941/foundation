import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import * as P from '../../shared/protocol.js';
import { AppSave, AuthorizeConnection, ConnectService, ValueSave } from '../../shared/operations.js';
import { canonical } from '../../shared/authority.js';
import { connectionMethod, methodDigest, selectScopes } from '../../shared/connection-methods.js';
import { publicConnectionFields, ConnectionFieldError } from '../../shared/connection-fields.js';
import { ContentTypes } from '../../shared/custody.js';
import type { PolicyParties } from '../../shared/custody.js';
import type { Catalog } from '../catalog.js';
import type { Custody } from '../custody.js';
import { succeeds } from '../custody.js';
import { fail } from '../errors.js';
import { DefinitionRegistry } from '../definitions.js';
import type { OperationServices } from '../builtin-definitions.js';
import { keyholder } from './support.js';

export function defineConnections(definitions: DefinitionRegistry, services: Pick<OperationServices, 'resources' | 'custody' | 'catalog'>) {
  const { resources, custody, catalog } = services;
  const bind = definitions.bind.bind(definitions);
  // Signed encrypted writes update content under its current owner.
  definitions.define('custody.write', P.ProtectedWrite, ['機密情報を保存する', 'Save private content'], async (who, input) => resources.view(who, await custody.put(who, input)));
  bind({ name: 'custody.write', method: 'PUT', path: '/api/resources/:id/custody', schema: { params: C.IdParams,
    body: P.ProtectedWrite, response: { 200: C.Resource } }, input: (params, body) => {
      const input = P.ProtectedWrite.parse(body);
      if (params.id !== input.content.policy.id) fail(400, 'wrong_resource', 'Save the encrypted content at its approved destination.');
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
    proof: C.JsonValue, type: string) => {
    const write = P.ProtectedWrite.parse(proof), policy = write.content.policy;
    if (policy.ownerId !== input.ownerId || policy.contentType !== type || write.name !== input.name ||
      (input.resourceId && policy.id !== input.resourceId) || write.version !== input.version ||
      (!input.resourceId && await resources.db.one('SELECT 1 FROM resources WHERE id=$1', [policy.id])))
      fail(409, 'operation_changed', 'Save the item prepared by this operation.');
    if ('methodId' in input && (write.content.metadata.methodId !== input.methodId || write.content.metadata.clientId !== input.clientId))
      fail(409, 'operation_changed', 'Save the application prepared by this operation.');
    if ('methodId' in input) await requireFields(who, input, write.content.metadata);
    return resources.view(who, await custody.put(who, write));
  };
  definitions.define('variable.save', ValueSave, ['変数を保存する', 'Save a variable'], keyholder,
    { keyholder: true, configure: ['name'], secret: pointer => pointer === '/value',
      complete: (who, input, proof) => savePrivate(who, input, proof, ContentTypes.value) });
  definitions.define('app.save', AppSave, ['アプリを保存する', 'Save an application'], keyholder,
    { keyholder: true, configure: ['name', 'clientId', 'fields'],
      secret: pointer => pointer === '/clientSecret' || /^\/fields\/[^/]+$/.test(pointer),
      review: reviewFields, resolve: reviewFields,
      complete: (who, input, proof) => savePrivate(who, input, proof, ContentTypes.clientCredential) });
  // A connection's users are its readers beyond those who use what its owner holds: the readers among those stay as
  // they are, and the users are the principals approved for it.
  const parties = async (policy: PolicyParties) => {
    const owners = new Set((await custody.recipients(policy.ownerId)).map(recipient => recipient.binding.principalId));
    return { owners, own: policy.readers.filter(reader => owners.has(reader.principalId)),
      users: [...new Set(policy.readers.map(reader => reader.principalId).filter(id => !owners.has(id)))].sort() };
  };
  const approvedUsers = async (policy: PolicyParties, users: string[]) => {
    const { owners, users: given } = await parties(policy);
    if (canonical(given) !== canonical([...new Set(users)].filter(id => !owners.has(id)).sort()))
      fail(409, 'operation_changed', 'Use the principals approved for this connection.');
  };
  definitions.define('connection.authorize', AuthorizeConnection, ['接続の使用を許可する', 'Authorize connection use'], keyholder,
    { keyholder: true, configure: [], complete: async (who, input, proof) => {
      const write = P.ProtectedWrite.parse(proof), previous = await custody.get(input.connectionId);
      const row = await resources.get(input.connectionId), policy = write.content.policy;
      if (row.version !== input.version || write.version !== input.version || write.name !== row.name ||
        policy.id !== input.connectionId || policy.ownerId !== input.ownerId || previous.policy.ownerId !== input.ownerId ||
        policy.contentType !== ContentTypes.tokenSet || canonical(write.content.metadata) !== canonical(previous.metadata) ||
        canonical(policy.authorities) !== canonical(previous.policy.authorities) ||
        canonical((await parties(policy)).own) !== canonical((await parties(previous.policy)).own))
        fail(409, 'operation_changed', 'Change permissions for the current connection.');
      await approvedUsers(policy, input.users);
      return resources.view(who, await custody.put(who, write));
    } });
  definitions.define('connection.connect', ConnectService, ['サービスに接続する', 'Connect a service'], keyholder,
    { keyholder: true, continuation: 'connection', configure: ['name', 'appId', 'clientId', 'users', 'fields', 'scopes'],
      secret: pointer => pointer === '/clientSecret' || /^\/fields\/[^/]+$/.test(pointer),
      review: async (who, input) => {
        const digest = await methodDigest(await catalog.method(who, z.string().parse(input.methodId)));
        if (input.methodDigest && input.methodDigest !== digest) fail(409, 'changed', 'The connection method changed. Review it again.');
        await sameService(who, z.object({ connectionId: C.Id.optional(), methodId: z.string() }).parse(input));
        return { ...await reviewFields(who, input), methodDigest: digest };
      },
      resolve: async (who, input) => {
        const digest = await methodDigest(await catalog.method(who, input.methodId));
        if (input.methodDigest && input.methodDigest !== digest) fail(409, 'changed', 'The connection method changed. Review it again.');
        await sameService(who, input);
        return { ...await reviewFields(who, input), methodDigest: digest };
      },
      complete: async (who, input, proof) => {
        await sameService(who, input);
        const method = await catalog.method(who, input.methodId), write = P.ProtectedWrite.parse(proof), policy = write.content.policy;
        const previous = input.connectionId ? await custody.get(input.connectionId) : null;
        if (await methodDigest(method) !== input.methodDigest || policy.ownerId !== input.ownerId || policy.contentType !== ContentTypes.tokenSet ||
          write.name !== (input.name ?? method.name) || input.connectionId && policy.id !== input.connectionId ||
          write.content.metadata.methodId !== input.methodId || write.content.metadata.methodDigest !== input.methodDigest ||
          write.content.metadata.methodKind !== method.kind ||
          write.content.metadata.appId !== (input.appId ?? null) || write.content.metadata.state !== 'ready')
          fail(409, 'operation_changed', 'Save the connection approved by this operation.');
        await requireFields(who, input, write.content.metadata);
        if (input.scopes && (method.kind === 'oauth' || method.kind === 'ovh') &&
          canonical([...selectScopes(method.config.scopes, input.scopes)].sort()) !== canonical([...z.array(z.string()).parse(write.content.metadata.scopes)].sort()))
          fail(409, 'operation_changed', 'Save the service permissions approved by this operation.');
        // A connection sealed only for keys its signer has since replaced is connected anew, without its users.
        const binding = (await custody.bindings.current(who.id)).binding;
        if (input.users) await approvedUsers(policy, input.users);
        else if (canonical((await parties(policy)).users) !==
          canonical(previous && !succeeds(previous.policy, binding) ? (await parties(previous.policy)).users : []))
          fail(409, 'operation_changed', 'Keep the approved users of this connection.');
        const row = await custody.put(who, write);
        return { kind: 'connected', id: row.id, metadata: write.content.metadata };
      } });
}
