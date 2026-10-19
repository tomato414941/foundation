import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import * as P from '../../shared/protocol.js';
import { AppSave, AuthorizeConnection, ConnectService, Execution, RevokeConnection, ValueSave } from '../../shared/executions.js';
import { canonical, hash } from '../../shared/authority.js';
import { connectionMethod, selectScopes } from '../../shared/connection-methods.js';
import { publicConnectionFields, ConnectionFieldError } from '../../shared/connection-fields.js';
import { ContentTypes, Operations, permittedOperations } from '../../shared/custody.js';
import type { CustodyPolicy } from '../../shared/custody.js';
import type { Catalog } from '../catalog.js';
import type { Custody } from '../custody.js';
import { DomainError, fail } from '../errors.js';
import { OperationFailed, DefinitionRegistry } from '../definitions.js';
import type { Queryable } from '../database.js';
import { requiresApp } from '../../shared/connections.js';
import type { OperationServices } from '../builtin-definitions.js';
import { keyholder } from './support.js';

export function defineConnections(definitions: DefinitionRegistry, services: Pick<OperationServices, 'resources' | 'custody' | 'delegation' | 'catalog' | 'authorization'>) {
  const { resources, custody, delegation, catalog, authorization } = services;
  const bind = definitions.bind.bind(definitions);
  // Signed encrypted writes also use an operation. Consent can resume the exact signed write.
  definitions.define('custody.write', P.ProtectedWrite, ['機密情報を保存する', 'Save private content'], async (who, input) => resources.view(who, await custody.put(who, input)));
  bind({ name: 'custody.write', method: 'PUT', path: '/api/resources/:id/custody', schema: { params: C.IdParams,
    body: P.ProtectedWrite, response: { 200: C.Resource, 202: Execution } }, input: (params, body) => {
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
    proof: C.JsonValue, type: string, connection?: Queryable) => {
    const write = P.ProtectedWrite.parse(proof), policy = write.content.policy;
    if (policy.ownerId !== input.ownerId || policy.contentType !== type || write.name !== input.name ||
      (input.resourceId && policy.id !== input.resourceId) || write.version !== input.version ||
      (!input.resourceId && await resources.db.one('SELECT 1 FROM resources WHERE id=$1', [policy.id])))
      fail(409, 'operation_changed', 'Save the item prepared by this operation.');
    const binding = await custody.bindings.current(who.id);
    const previous = input.resourceId ? await custody.get(input.resourceId) : null;
    const executors = previous && input.environmentIds === undefined
      ? previous.policy.grants.filter(grant => 'actor' in grant && grant.actor.id === binding.binding.id).map(grant => grant.executor.id)
      : await Promise.all((input.environmentIds ?? []).map(async id => (await delegation.environment(id)).registration.manifest.executor.id));
    const grants = policy.grants.filter(grant => 'actor' in grant && grant.actor.id === binding.binding.id).map(grant => grant.executor.id);
    if (canonical([...new Set(executors)].sort()) !== canonical([...new Set(grants)].sort()))
      fail(409, 'operation_changed', 'Use the execution environments approved for this item.');
    if ('methodId' in input && (write.content.metadata.methodId !== input.methodId || write.content.metadata.clientId !== input.clientId))
      fail(409, 'operation_changed', 'Save the application prepared by this operation.');
    if ('methodId' in input) await requireFields(who, input, write.content.metadata);
    return resources.view(who, await custody.put(who, write, connection));
  };
  definitions.define('variable.save', ValueSave, ['変数を保存する', 'Save a variable'], keyholder,
    { execution: 'keyholder', configure: ['environmentIds', 'name'], secret: pointer => pointer === '/value',
      complete: (who, input, proof) => savePrivate(who, input, proof, ContentTypes.value) });
  definitions.define('app.save', AppSave, ['アプリを保存する', 'Save an application'], keyholder,
    { execution: 'keyholder', configure: ['environmentIds', 'name', 'clientId', 'fields'],
      secret: pointer => pointer === '/clientSecret' || /^\/fields\/[^/]+$/.test(pointer),
      review: reviewFields, resolve: reviewFields,
      complete: (who, input, proof) => savePrivate(who, input, proof, ContentTypes.clientCredential) });
  const approvedUsers = async (policy: CustodyPolicy, users: string[], expiresAt?: string) => {
    const expected = [...new Set(users)].sort();
    const grants = policy.grants.filter(grant => 'actor' in grant);
    if (canonical(grants.map(grant => 'actor' in grant ? grant.actor.principalId : '').sort()) !== canonical(expected))
      fail(409, 'operation_changed', 'Use the principals approved for this connection.');
    for (const grant of grants) {
      if (!('actor' in grant) || canonical(grant.actor) !== canonical(grant.executor) ||
        canonical([...grant.operations].sort()) !== canonical([...permittedOperations(ContentTypes.tokenSet)].sort()) ||
        grant.origins.length || grant.functionDigests.length || !grant.callerProgram ||
        Date.parse(grant.expiresAt) <= Date.now() || Date.parse(grant.expiresAt) > Date.now() + 30 * 86_400_000 + 60_000 ||
        expiresAt && grant.expiresAt !== expiresAt)
        fail(409, 'operation_changed', 'Use the connection permissions approved by this execution.');
    }
  };
  definitions.define('connection.authorize', AuthorizeConnection, ['接続の使用を許可する', 'Authorize connection use'], keyholder,
    { execution: 'keyholder', configure: [], complete: async (who, input, proof) => {
      const write = P.ProtectedWrite.parse(proof), previous = await custody.get(input.connectionId);
      const row = await resources.get(input.connectionId), policy = write.content.policy;
      if (row.version !== input.version || write.version !== input.version || write.name !== row.name ||
        policy.id !== input.connectionId || policy.ownerId !== input.ownerId || previous.policy.ownerId !== input.ownerId ||
        policy.contentType !== ContentTypes.tokenSet || canonical(write.content.metadata) !== canonical(previous.metadata) ||
        canonical(policy.readers) !== canonical(previous.policy.readers) || canonical(policy.authorities) !== canonical(previous.policy.authorities) ||
        canonical(policy.grants.filter(grant => !('actor' in grant))) !== canonical(previous.policy.grants.filter(grant => !('actor' in grant))))
        fail(409, 'operation_changed', 'Change permissions for the current connection.');
      await approvedUsers(policy, input.users, input.expiresAt);
      return resources.view(who, await custody.put(who, write));
    } });
  definitions.define('connection.connect', ConnectService, ['サービスに接続する', 'Connect a service'], keyholder,
    { execution: 'keyholder', continuation: 'connection', delegatedOperation: () => Operations.connect, configure: ['name', 'appId', 'clientId', 'users', 'fields', 'scopes'],
      secret: pointer => pointer === '/clientSecret' || /^\/fields\/[^/]+$/.test(pointer),
      prepareInput: async (who, input, proof, connection) => {
        const method = await catalog.method(who, input.methodId);
        if (!requiresApp(method) || !input.clientId || input.appId || await hash(method) !== input.methodDigest)
          fail(409, 'operation_changed', 'Prepare the application approved for this connection.');
        const app = await savePrivate(who, AppSave.parse({ ownerId: input.ownerId,
          name: (input.name ?? method.name).slice(0, 185) + ' application', methodId: input.methodId,
          clientId: input.clientId, fields: input.fields, environmentIds: [] }), proof, ContentTypes.clientCredential, connection);
        return { ...input, appId: app.id, fields: app.kind === 'app' ? app.data.fields : input.fields };
      },
      review: async (who, input) => {
        const methodDigest = await hash(await catalog.method(who, z.string().parse(input.methodId)));
        if (input.methodDigest && input.methodDigest !== methodDigest) fail(409, 'changed', 'The connection method changed. Review it again.');
        await sameService(who, z.object({ connectionId: C.Id.optional(), methodId: z.string() }).parse(input));
        return { ...await reviewFields(who, input), methodDigest };
      },
      resolve: async (who, input) => {
        const methodDigest = await hash(await catalog.method(who, input.methodId));
        if (input.methodDigest && input.methodDigest !== methodDigest) fail(409, 'changed', 'The connection method changed. Review it again.');
        await sameService(who, input);
        return { ...await reviewFields(who, input), methodDigest };
      },
      complete: async (who, input, proof) => {
        await sameService(who, input);
        const method = await catalog.method(who, input.methodId), write = P.ProtectedWrite.parse(proof), policy = write.content.policy;
        const previous = input.connectionId ? await custody.get(input.connectionId) : null;
        if (await hash(method) !== input.methodDigest || policy.ownerId !== input.ownerId || policy.contentType !== ContentTypes.tokenSet ||
          write.name !== (input.name ?? method.name) || input.connectionId && policy.id !== input.connectionId ||
          write.content.metadata.methodId !== input.methodId || write.content.metadata.methodKind !== method.kind ||
          write.content.metadata.appId !== (input.appId ?? null) || write.content.metadata.state !== 'ready')
          fail(409, 'operation_changed', 'Save the connection approved by this execution.');
        await requireFields(who, input, write.content.metadata);
        if (input.scopes && (method.kind === 'oauth' || method.kind === 'ovh') &&
          canonical([...selectScopes(method.config.scopes, input.scopes)].sort()) !== canonical([...z.array(z.string()).parse(write.content.metadata.scopes)].sort()))
          fail(409, 'operation_changed', 'Save the service permissions approved by this execution.');
        if (input.users) await approvedUsers(policy, input.users);
        else if (canonical(policy.grants) !== canonical(previous?.policy.grants ?? []))
          fail(409, 'operation_changed', 'Keep the approved connection permissions.');
        const row = await custody.put(who, write);
        return { kind: 'connected', id: row.id, metadata: write.content.metadata };
      } });
  // Disconnecting removes what Foundation holds whatever the service answers. Only a cancelled run keeps the connection.
  definitions.define('connection.revoke', RevokeConnection, ['接続を解除する', 'Disconnect a service'], keyholder,
    { execution: 'keyholder', continuation: 'run', delegatedOperation: () => Operations.revoke, configure: [], environmentReason: ['外部サービスの認可を実行環境から取り消します。', 'Revoke external service access from an execution environment.'],
      review: async (who, input) => {
        await authorization.requireResource(who, await resources.get(RevokeConnection.parse(input).connectionId), 'delete');
        return input;
      },
      complete: async (who, input, proof, execution) => {
        const { runId } = z.object({ runId: C.Id }).strict().parse(proof), task = await delegation.get(who, runId);
        if (!['succeeded', 'failed', 'cancelled', 'uncertain'].includes(task.state) || task.kind !== 'revoke' ||
          task.intent.actor.principalId !== who.id || task.intent.ownerId !== input.ownerId || task.environmentId !== input.environmentId ||
          task.intent.operationContext?.id !== execution.id || task.intent.operationContext.index !== execution.index ||
          !task.intent.sources.some(source => source.id === input.connectionId))
          fail(409, 'execution_required', 'Finish the revocation prepared by this operation.');
        const result = { kind: 'run', id: task.id, state: task.state };
        if (task.state === 'cancelled') throw new OperationFailed(result, false);
        const connection = await resources.get(input.connectionId).catch(error => {
          if (error instanceof DomainError && error.code === 'not_found') return null;
          throw error;
        });
        if (connection) await resources.delete(who, connection);
        return result;
      } });
}
