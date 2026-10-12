import { z } from 'zod';
import * as C from '../shared/contracts.js';
import * as P from '../shared/protocol.js';
import { AppSave, AuthorizeConnection, ConnectService, FunctionSave, Execution, RevokeConnection, RunOperation, ValueSave } from '../shared/executions.js';
import { CreateProcess, CreatedProcess, ProcessView } from '../shared/process.js';
import { SSHUpdate, SSHView } from '../shared/ssh.js';
import { canonical, hash } from '../shared/authority.js';
import { connectionMethod, selectScopes } from '../shared/connection-methods.js';
import { publicConnectionFields, ConnectionFieldError } from '../shared/connection-fields.js';
import { ContentTypes, Operations, permittedOperations } from '../shared/custody.js';
import type { CustodyPolicy } from '../shared/custody.js';
import type { Authorization } from './authorization.js';
import type { Principals } from './principals.js';
import type { Relations } from './relations.js';
import type { Resources } from './resources.js';
import type { Catalog } from './catalog.js';
import type { Environments } from './environments.js';
import type { Objects } from './objects.js';
import type { Billing } from './billing.js';
import type { Processes } from './processes.js';
import type { Integrations } from './integrations.js';
import type { Custody } from './custody.js';
import type { Delegation } from './delegation.js';
import type { Functions } from './functions.js';
import type { Invocations } from './invocations.js';
import { FunctionWrite, Invocation as FunctionInvocation, InvocationInput } from '../shared/function-api.js';
import { fail } from './errors.js';
import { OperationFailed, DefinitionRegistry } from './definitions.js';
import type { Queryable } from './database.js';
import { requiresApp } from '../shared/connections.js';

interface Services {
  authorization: Authorization; principals: Principals; relations: Relations; resources: Resources;
  catalog: Catalog; environments: Environments; objects: Objects; billing: Billing;
  processes: Processes; integrations: Integrations; custody: Custody; delegation: Delegation; functions: Functions; invocations: Invocations;
}
const CREATED: Record<string, readonly [string, string]> = {
  service: ['サービス定義を作る', 'Create a service definition'],
  method: ['接続方法を作る', 'Create a connection method'],
  environment: ['実行環境を作る', 'Create an environment'],
};
const lineTitles: Record<string, readonly [readonly [string, string], readonly [string, string]]> = {
  agent: [['代理にする', 'Make an agent'], ['代理を外す', 'Remove an agent']],
  member: [['メンバーに加える', 'Add a member'], ['メンバーから外す', 'Remove a member']],
  payer: [['支払いを引き受ける', 'Pay for a principal'], ['支払いをやめる', 'Stop paying for a principal']],
};
function lineTitle(input: Record<string, C.JsonValue>, erase: boolean): readonly [string, string] {
  if (!erase && input.relation === 'agent' && input.objectId === '$approver') return ['アクセスを許可する', 'Allow access'];
  return lineTitles[String(input.relation)]?.[erase ? 1 : 0] ??
    (erase ? ['権限を外す', 'Take back a permission'] : ['権限を渡す', 'Give a permission']);
}
const idInput = z.object({ id: C.Id }).strict();
const bodyObject = (body: unknown) => C.JsonObject.parse(body);
const withId = (params: Record<string, string>, body: unknown) => ({ ...bodyObject(body), id: params.id });
const ok = () => ({ ok: true as const });

export function builtinDefinitions(services: Services) {
  const { authorization, principals, relations, resources, catalog, environments, objects,
    billing, processes, integrations, custody, delegation, functions, invocations } = services;
  const definitions = new DefinitionRegistry();
  const bind = definitions.bind.bind(definitions);

  const createPrincipal = z.object({ name: C.Name, ownerId: C.Id }).strict();
  definitions.define('principal.create', createPrincipal, ['プリンシパルを作る', 'Create a principal'], async (who, input) => {
    await authorization.requirePrincipal(who, input.ownerId, 'create');
    return principals.view(who, await principals.create(input.name, null, input.ownerId));
  });
  bind({ name: 'principal.create', method: 'POST', path: '/api/principals', schema: { body: createPrincipal,
    response: { 201: C.Principal } }, input: (_params, body) => body, status: 201 });
  const renamePrincipal = idInput.extend({ name: C.Name });
  definitions.define('principal.rename', renamePrincipal, ['プリンシパルを変更する', 'Change a principal'],
    (who, input) => principals.rename(who, input.id, input.name));
  bind({ name: 'principal.rename', method: 'PATCH', path: '/api/principals/:id', schema: { params: C.IdParams,
    body: renamePrincipal.omit({ id: true }), response: { 200: C.Principal } }, input: withId });
  const line = C.RelationInput.extend({ contents: P.KeyUpdates.optional() });
  definitions.define('relation.draw', line, input => lineTitle(input, false), async (who, { contents, ...input }) => {
    await relations.draw(who, input, contents); return ok();
  });
  definitions.define('relation.erase', line, input => lineTitle(input, true), async (who, { contents, ...input }) => {
    await relations.erase(who, input, contents); return ok();
  });
  for (const [name, method] of [['relation.draw', 'POST'], ['relation.erase', 'DELETE']] as const)
    bind({ name, method, path: '/api/relations', bodyLimit: 32 * 1024 * 1024, schema: { body: line,
      response: { 200: C.Ok, 202: Execution } }, input: (_params, body) => body });
  const revoke = idInput.extend({ principalId: C.Id });
  definitions.define('principal.revoke', revoke, ['アクセスを取り消す', 'Revoke access'], async (who, input) => {
    await relations.revoke(who, input.id, input.principalId); return ok();
  });
  bind({ name: 'principal.revoke', method: 'POST', path: '/api/principals/:id/revoke', schema: { params: C.IdParams,
    body: revoke.omit({ id: true }), response: { 200: C.Ok } }, input: withId });
  const transfer = idInput.extend({ to: C.Id, contents: P.KeyUpdates.optional() });
  definitions.define('principal.transfer', transfer, ['プリンシパルを譲る', 'Transfer a principal'], async (who, input) => {
    await principals.get(input.id); await relations.transfer(who, input.id, input.to, input.contents); return ok();
  });
  bind({ name: 'principal.transfer', method: 'POST', path: '/api/principals/:id/transfer', bodyLimit: 32 * 1024 * 1024,
    schema: { params: C.IdParams, body: transfer.omit({ id: true }), response: { 200: C.Ok, 202: Execution } }, input: withId });

  definitions.define('resource.create', z.object({ ownerId: C.Id, resource: C.NewResource }).strict(),
    input => CREATED[String((input.resource as Record<string, C.JsonValue>)?.kind)] ?? ['項目を作る', 'Create an item'],
    async (who, { ownerId: owner, resource: body }) => {
      const row = body.kind === 'service'
        ? await catalog.createService(who, owner, body.name, body.definition)
        : body.kind === 'method'
          ? await (async () => {
              if (!(await authorization.canCreate(who, owner, 'method')))
                fail(403, 'forbidden', 'You cannot create this connection method.');
              return resources.insert(owner, 'method', body.name, C.MethodDefinition.parse({
                ...body.definition, name: body.name }) as unknown as Record<string, C.JsonValue>);
            })()
          : await environments.create(who, owner, body.options, body.name);
      return resources.view(who, row);
    });
  bind({ name: 'resource.create', method: 'POST', path: '/api/principals/:id/resources', schema: { params: C.IdParams,
    body: C.NewResource, response: { 201: C.Resource } }, input: (params, body) => ({ ownerId: params.id, resource: body }), status: 201 });
  definitions.define('resource.update', z.object({ id: C.Id, changes: C.UpdateResource }).strict(),
    ['項目を変更する', 'Change an item'], async (who, { id, changes: body }) => {
      let row = await resources.get(id);
      await authorization.requireResource(who, row, 'update');
      if (body.version !== row.version) fail(409, 'changed', 'This item changed. Reload it before saving.');
      const fields = ['version', 'name', ...(['service', 'method'].includes(row.kind) ? ['definition'] : [])];
      if (Object.keys(body).some(field => !fields.includes(field)))
        fail(400, 'invalid_input', 'Choose fields that can be edited for this item.');
      if (body.name && body.name !== row.name) await authorization.requireResource(who, row, 'rename');
      if (body.definition) {
        if (row.kind === 'service') {
          row = await resources.db.transaction(async connection => {
            await connection.query('SELECT pg_advisory_xact_lock(736023747)');
            const definition = await catalog.prepareDefinition(who, row.owner_id, C.ServiceInputDefinition.parse(body.definition), connection);
            const updated = await resources.update(row, { data: definition, ...(body.name ? { name: body.name } : {}) }, connection);
            await resources.references(row.id, Object.values(definition.methods).filter(id => !catalog.methods.has(id)), connection); return updated;
          });
        } else if (row.kind === 'method') {
          const definition = C.MethodDefinition.parse({ ...body.definition, name: body.name ?? row.name });
          const previous = C.MethodDefinition.parse(row.data);
          const reference = await resources.db.one(
            "SELECT 1 FROM resource_references ref JOIN resources r ON r.id=ref.resource_id WHERE ref.referenced_id=$1 AND r.kind IN ('connection','app') LIMIT 1", [row.id]);
          if (reference && (previous.kind !== definition.kind || JSON.stringify(previous.config) !== JSON.stringify(definition.config)))
            fail(409, 'in_use', 'Create another connection method to change how existing connections authenticate.');
          row = await resources.update(row, { data: definition, ...(body.name ? { name: body.name } : {}) });
        } else fail(400, 'wrong_kind', 'This item does not have an editable definition.');
      }
      if (body.name && body.name !== row.name) row = await resources.rename(who, row, body.name);
      return resources.view(who, row);
    });
  bind({ name: 'resource.update', method: 'PATCH', path: '/api/resources/:id', schema: { params: C.IdParams,
    body: C.UpdateResource, response: { 200: C.Resource } }, input: (params, body) => ({ id: params.id, changes: body }) });
  definitions.define('resource.delete', idInput, ['項目を削除する', 'Delete an item'], async (who, input) => {
    const row = await resources.get(input.id);
    if (row.kind === 'environment') return environments.remove(who, row);
    if (row.kind === 'object') await objects.remove(who, row); else await resources.delete(who, row);
    return ok();
  });
  bind({ name: 'resource.delete', method: 'DELETE', path: '/api/resources/:id', schema: { params: C.IdParams,
    querystring: z.object({}).strict(), response: { 200: C.Ok, 202: C.EnvironmentDeletion } }, input: params => params,
    status: result => result && typeof result === 'object' && 'ok' in result ? 200 : 202 });
  const transferResource = idInput.extend({ to: C.Id });
  definitions.define('resource.transfer', transferResource, ['項目を譲る', 'Transfer an item'], async (who, input) => {
    const row = await resources.get(input.id); await relations.transfer(who, row.id, input.to); return ok();
  });
  bind({ name: 'resource.transfer', method: 'POST', path: '/api/resources/:id/transfer', schema: { params: C.IdParams,
    body: transferResource.omit({ id: true }), response: { 200: C.Ok, 202: Execution } }, input: withId });
  definitions.define('environment.stop', idInput, ['実行環境を止める', 'Stop an environment'], async (who, input) =>
    resources.view(who, await environments.stop(who, await resources.get(input.id))));
  bind({ name: 'environment.stop', method: 'POST', path: '/api/resources/:id/stop', schema: { params: C.IdParams,
    body: z.object({}).strict(), response: { 200: C.Resource } }, input: params => params });
  const ssh = SSHUpdate.extend({ id: C.Id });
  definitions.define('environment.ssh', ssh, ['SSH公開鍵を設定する', 'Set SSH public keys'], async (who, { id, ...input }) => environments.updateSSH(who, id, input));
  bind({ name: 'environment.ssh', method: 'PUT', path: '/api/environments/:id/ssh', schema: { params: C.IdParams,
    body: SSHUpdate, response: { 200: SSHView } }, input: withId });
  const process = z.object({ environmentId: C.Id, command: CreateProcess }).strict();
  definitions.define('process.start', process, ['コマンドを実行する', 'Start a command'], async (who, input) => {
    const { id, environmentId, ownerId, actorId, state, createdAt } = await processes.create(who, input.environmentId, input.command);
    return { id, environmentId, ownerId, actorId, state, createdAt };
  }, { environmentReason: ['指定した実行環境でコマンドを動かします。', 'Run the command in the selected execution environment.'] });
  bind({ name: 'process.start', method: 'POST', path: '/api/environments/:id/processes', schema: { params: C.IdParams,
    body: CreateProcess, response: { 202: CreatedProcess } }, input: (params, body) => ({ environmentId: params.id, command: body }), status: 202 });
  definitions.define('process.cancel', idInput, ['コマンドを中止する', 'Cancel a command'], (who, input) => processes.cancel(who, input.id));
  bind({ name: 'process.cancel', method: 'POST', path: '/api/processes/:id/cancel', schema: { params: C.IdParams,
    body: z.object({}).strict(), response: { 200: ProcessView } }, input: params => params });
  definitions.define('run.cancel', idInput, ['実行を中止する', 'Cancel a run'], (who, input) => delegation.cancel(who, input.id));
  bind({ name: 'run.cancel', method: 'POST', path: '/api/runtime/runs/:id/cancel', schema: { params: C.IdParams,
    body: z.object({}).strict(), response: { 200: P.Task } }, input: params => params });
  const fileLimit = 25 * 1024 * 1024;
  const fileContent = z.object({ bytes: z.string().max(Math.ceil(fileLimit * 4 / 3)).regex(/^[A-Za-z0-9_-]*$/),
    contentType: z.string().max(200).default('application/octet-stream') }).strict();
  const binary = (body: unknown) => {
    if (!Buffer.isBuffer(body)) fail(400, 'binary_required', 'Upload the file as application/octet-stream.');
    return body.toString('base64url');
  };
  definitions.define('object.create', fileContent.extend({ ownerId: C.Id, name: C.Name }), ['ファイルを保存する', 'Save a file'],
    async (who, input) => resources.view(who, await objects.upload(who, input.ownerId, input.name,
      Buffer.from(input.bytes, 'base64url'), input.contentType)));
  bind({ name: 'object.create', method: 'POST', path: '/api/principals/:id/objects', bodyLimit: fileLimit,
    schema: { params: C.IdParams, querystring: fileContent.omit({ bytes: true }).extend({ name: C.Name }), response: { 201: C.Resource } },
    input: (params, body, query) => ({ ...bodyObject(query), ownerId: params.id, bytes: binary(body) }), status: 201 });
  definitions.define('object.update', fileContent.extend({ id: C.Id, version: z.number().int().positive() }),
    ['ファイルを更新する', 'Update a file'], async (who, input) => {
      const row = await resources.get(input.id);
      if (row.version !== input.version) fail(409, 'changed', 'This file changed. Reload it before saving.');
      return resources.view(who, await objects.upload(who, row.owner_id, row.name, Buffer.from(input.bytes, 'base64url'), input.contentType, row));
    });
  bind({ name: 'object.update', method: 'PUT', path: '/api/resources/:id/content', bodyLimit: fileLimit,
    schema: { params: C.IdParams, querystring: fileContent.omit({ bytes: true }).extend({ version: z.coerce.number().int().positive() }),
      response: { 200: C.Resource } }, input: (params, body, query) => ({ ...bodyObject(query), id: params.id, bytes: binary(body) }) });
  const link = idInput.extend({ minutes: z.number().int().min(1).max(1440).default(15) });
  definitions.define('object.link', link, ['ファイルのリンクを作る', 'Create a file link'], async (who, input) => objects.link(who, await resources.get(input.id), input.minutes));
  bind({ name: 'object.link', method: 'POST', path: '/api/resources/:id/link', schema: { params: C.IdParams,
    body: link.omit({ id: true }), response: { 200: z.object({ url: z.url(), expiresAt: C.Time }) } }, input: withId });
  const limits = idInput.extend({ storageBytes: z.number().int().min(1).max(1_000_000_000_000),
    computeSeconds: z.number().int().min(1).max(10_000_000) });
  definitions.define('billing.limits', limits, ['利用上限を設定する', 'Set usage limits'], async (who, input) => {
    await billing.limits(who, input.id, input.storageBytes, input.computeSeconds); return ok();
  });
  bind({ name: 'billing.limits', method: 'PUT', path: '/api/principals/:id/limits', schema: { params: C.IdParams,
    body: limits.omit({ id: true }), response: { 200: C.Ok } }, input: withId });
  for (const name of ['checkout', 'portal'] as const) {
    definitions.define('billing.' + name, idInput, name === 'checkout' ? ['支払い方法を登録する', 'Add a payment method'] : ['支払いを管理する', 'Manage payment'],
      (who, input) => billing[name](who, input.id));
    bind({ name: 'billing.' + name, method: 'POST', path: '/api/principals/:id/payment/' + name, schema: { params: C.IdParams,
      body: z.object({}).strict(), response: { 200: z.object({ url: z.url() }) } }, input: params => params });
  }
  definitions.define('settings.update', z.object({ id: C.Id, settings: C.Settings }).strict(), ['連携設定を変更する', 'Change integration settings'],
    (who, input) => integrations.set(who, input.id, input.settings));
  bind({ name: 'settings.update', method: 'PUT', path: '/api/principals/:id/settings', schema: { params: C.IdParams,
    body: C.Settings, response: { 200: z.object({ settings: C.Settings }) } }, input: (params, body) => ({ id: params.id, settings: body }) });
  // Signed encrypted writes also use an operation. Consent can resume the exact signed write.
  definitions.define('custody.write', P.ProtectedWrite, ['機密情報を保存する', 'Save private content'], async (who, input) => resources.view(who, await custody.put(who, input)));
  bind({ name: 'custody.write', method: 'PUT', path: '/api/resources/:id/custody', schema: { params: C.IdParams,
    body: P.ProtectedWrite, response: { 200: C.Resource, 202: Execution } }, input: (params, body) => {
      const input = P.ProtectedWrite.parse(body);
      if (params.id !== input.content.policy.id) fail(400, 'wrong_resource', 'Save the encrypted content at its approved destination.');
      return input;
    } });
  const keyholder = async () => fail(400, 'keyholder_required', 'Continue this operation with your encryption keys.');
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
    const binding = await services.custody.bindings.current(who.id);
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
  definitions.define('function.save', FunctionSave, ['関数を保存する', 'Save a function'], keyholder,
    { execution: 'keyholder', configure: [], complete: async (who, input, proof) => {
      const write = FunctionWrite.parse(proof);
      if (input.resourceId && input.resourceId !== write.functionId || write.publication.ownerId !== input.ownerId ||
        canonical(write.publication.definition) !== canonical(input.definition) || write.publication.revision !== (input.resourceId ? (input.version ?? 0) + 1 : 1))
        fail(409, 'operation_changed', 'Publish the function definition approved by this operation.');
      return functions.save(who, input, write, custody, delegation);
    } });
  const invokeFunction = InvocationInput.extend({ functionId: C.Id, functionVersion: z.number().int().positive().optional() });
  const reviewedFunction = async (input: Record<string, C.JsonValue>) => {
    const row = await resources.get(C.Id.parse(input.functionId));
    if (row.kind !== 'function') fail(400, 'wrong_kind', 'Choose a function.');
    if (input.functionVersion && input.functionVersion !== row.version) fail(409, 'changed', 'The function changed. Review it again.');
    return { ...input, id: input.id ?? crypto.randomUUID(), functionVersion: row.version };
  };
  definitions.define('function.invoke', invokeFunction, ['関数を実行する', 'Invoke a function'],
    async (who, { functionId, functionVersion, ...input }) => {
      await reviewedFunction({ functionId, ...(functionVersion ? { functionVersion } : {}) });
      return invocations.create(who, functionId, input);
    }, { environmentReason: ['関数に設定された実行環境で処理します。', 'Run in the execution environment configured for this function.'],
      review: (_who, input) => reviewedFunction(input), resolve: (_who, input) => reviewedFunction(C.JsonObject.parse(input)),
      observe: async (who, result) => {
        const current = await invocations.get(who, FunctionInvocation.parse(result).id);
        return { state: current.state === 'queued' || current.state === 'running' ? 'pending' : current.state, result: C.Json.parse(current) };
      }, cancel: (who, result) => invocations.cancel(who, FunctionInvocation.parse(result).id),
    });
  definitions.define('function.delete', idInput, ['関数を削除する', 'Delete a function'], async (who, input) => {
    const row = await resources.get(input.id);
    if (row.kind !== 'function') fail(400, 'wrong_kind', 'Choose a function.');
    await resources.delete(who, row); return null;
  });
  bind({ name: 'function.delete', method: 'DELETE', path: '/api/functions/:id', schema: { params: C.IdParams, response: { 204: z.null() } }, input: params => params, status: 204 });
  definitions.define('function.cancel', idInput, ['関数の実行を中止する', 'Cancel a function invocation'], (who, input) => invocations.cancel(who, input.id));
  bind({ name: 'function.cancel', method: 'POST', path: '/api/runtime/functions/:id/cancel', schema: { params: C.IdParams, body: z.object({}).strict(),
    response: { 200: FunctionInvocation } }, input: params => params });
  const approvedUsers = async (policy: CustodyPolicy, users: string[], expiresAt?: string) => {
    const expected = [...new Set(users)].sort();
    const grants = policy.grants.filter(grant => 'actor' in grant);
    if (canonical(grants.map(grant => 'actor' in grant ? grant.actor.principalId : '').sort()) !== canonical(expected))
      fail(409, 'operation_changed', 'Use the people and agents approved for this connection.');
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
    { execution: 'keyholder', configure: ['name', 'appId', 'clientId', 'users', 'fields', 'scopes'],
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
  definitions.define('connection.revoke', RevokeConnection, ['接続を解除する', 'Revoke a connection'], keyholder,
    { execution: 'keyholder', configure: [], environmentReason: ['外部サービスの認可を実行環境から取り消します。', 'Revoke external service access from an execution environment.'], complete: async (who, input, proof, execution) => {
      const { runId } = z.object({ runId: C.Id }).strict().parse(proof), task = await delegation.get(who, runId);
      if (!['succeeded', 'failed', 'cancelled', 'uncertain'].includes(task.state) || task.kind !== 'revoke' ||
        task.intent.actor.principalId !== who.id || task.intent.ownerId !== input.ownerId || task.environmentId !== input.environmentId ||
        task.intent.operationContext?.id !== execution.id || task.intent.operationContext.index !== execution.index ||
        !task.intent.sources.some(source => source.id === input.connectionId))
        fail(409, 'execution_required', 'Finish the revocation prepared by this operation.');
      const result = { kind: 'run', id: task.id, state: task.state };
      if (task.state !== 'succeeded') throw new OperationFailed(result, task.state === 'uncertain');
      return result;
    } });
  definitions.define('run.execute', RunOperation, ['実行する', 'Run an operation'], keyholder,
    { execution: 'keyholder', configure: ['environmentId'], environmentReason: ['HTTPリクエストやコマンドを実行環境で処理します。', 'Send the HTTP request or run the command in an execution environment.'], secret: () => false,
      complete: async (who, input, proof, execution) => {
        const { runId } = z.object({ runId: C.Id }).strict().parse(proof), task = await delegation.get(who, runId);
        if (!['succeeded', 'failed', 'cancelled', 'uncertain'].includes(task.state) || task.intent.actor.principalId !== who.id ||
          task.intent.operationContext?.id !== execution.id || task.intent.operationContext.index !== execution.index ||
          task.intent.ownerId !== input.ownerId || task.environmentId !== input.environmentId ||
          task.intent.operation !== Operations[input.operation.kind] ||
          (who.approvalId && (task.intent.approval?.id !== who.approvalId || task.intent.approval.index !== who.approvalIndex)))
          fail(409, 'execution_required', 'Finish the run prepared by this operation.');
        const result = { kind: 'run', id: task.id, state: task.state };
        if (task.state !== 'succeeded') throw new OperationFailed(result, task.state === 'uncertain');
        return result;
      } });
  return definitions;
}
