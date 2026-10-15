import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import { Execution } from '../../shared/executions.js';
import { fail } from '../errors.js';
import { DefinitionRegistry } from '../definitions.js';
import type { OperationServices } from '../builtin-definitions.js';
import { idInput, withId, ok } from './support.js';

const CREATED: Record<string, readonly [string, string]> = {
  service: ['サービス定義を作る', 'Create a service definition'],
  method: ['接続方法を作る', 'Create a connection method'],
  environment: ['実行環境を作る', 'Create an environment'],
};

export function defineResources(definitions: DefinitionRegistry, services: Pick<OperationServices, 'authorization' | 'resources' | 'catalog' | 'environments' | 'files' | 'relations'>) {
  const { authorization, resources, catalog, environments, files, relations } = services;
  const bind = definitions.bind.bind(definitions);
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
    if (row.kind === 'file') await files.remove(who, row); else await resources.delete(who, row);
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
}
