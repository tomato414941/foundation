import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import * as P from '../../shared/protocol.js';
import { Execution } from '../../shared/executions.js';
import { DefinitionRegistry } from '../definitions.js';
import type { OperationServices } from '../builtin-definitions.js';
import { idInput, withId, ok } from './support.js';

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

export function definePrincipals(definitions: DefinitionRegistry, services: Pick<OperationServices, 'authorization' | 'principals' | 'relations'>) {
  const { authorization, principals, relations } = services;
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
  const line = C.RelationInput;
  definitions.define('relation.draw', line, input => lineTitle(input, false), async (who, input) => {
    await relations.draw(who, input); return ok();
  });
  definitions.define('relation.erase', line, input => lineTitle(input, true), async (who, input) => {
    await relations.erase(who, input); return ok();
  });
  for (const [name, method] of [['relation.draw', 'POST'], ['relation.erase', 'DELETE']] as const)
    bind({ name, method, path: '/api/relations', schema: { body: line,
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

}
