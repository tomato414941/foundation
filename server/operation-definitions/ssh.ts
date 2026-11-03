import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import { DefinitionRegistry } from '../definitions.js';
import type { OperationServices } from '../builtin-definitions.js';
import { SSHAuthorizationView, SSHGrant, SSHHostChange, SSHHostInput, SSHKeyInput } from '../ssh-access.js';
import { idInput, withId } from './support.js';

export function defineSSH(definitions: DefinitionRegistry, services: Pick<OperationServices, 'resources' | 'sshAccess'>) {
  const { resources, sshAccess } = services;
  const bind = definitions.bind.bind(definitions);
  const owned = (params: Record<string, string>, body: unknown) => ({ ...C.JsonObject.parse(body), ownerId: params.id });
  definitions.define('ssh.key.create', SSHKeyInput.extend({ ownerId: C.Id }), ['SSH公開鍵を登録する', 'Register an SSH public key'],
    async (who, { ownerId, ...input }) => resources.view(who, await sshAccess.createKey(who, ownerId, input)));
  bind({ name: 'ssh.key.create', method: 'POST', path: '/api/principals/:id/ssh-keys', schema: { params: C.IdParams,
    body: SSHKeyInput, response: { 201: C.Resource } }, input: owned, status: 201 });
  definitions.define('ssh.key.revoke', idInput, ['SSH鍵を失効させる', 'Revoke an SSH key'],
    async (who, input) => resources.view(who, await sshAccess.revokeKey(who, input.id)),
    { confirmation: input => sshAccess.keyRevokeConfirmation(input.id) });
  bind({ name: 'ssh.key.revoke', method: 'POST', path: '/api/ssh-keys/:id/revoke', schema: { params: C.IdParams,
    body: z.object({}).strict(), response: { 200: C.Resource } }, input: params => params });
  definitions.define('ssh.host.create', SSHHostInput.extend({ ownerId: C.Id }), ['SSH接続先を登録する', 'Register an SSH host'],
    async (who, { ownerId, ...input }) => resources.view(who, await sshAccess.createHost(who, ownerId, input)));
  bind({ name: 'ssh.host.create', method: 'POST', path: '/api/principals/:id/ssh-hosts', schema: { params: C.IdParams,
    body: SSHHostInput, response: { 201: C.Resource } }, input: owned, status: 201 });
  definitions.define('ssh.host.update', SSHHostChange.extend({ id: C.Id }), ['SSH接続先を変更する', 'Change an SSH host'],
    async (who, { id, ...input }) => resources.view(who, await sshAccess.updateHost(who, id, input)),
    { confirmation: ({ id, ...input }) => sshAccess.hostConfirmation(id, input) });
  bind({ name: 'ssh.host.update', method: 'PUT', path: '/api/ssh-hosts/:id', schema: { params: C.IdParams,
    body: SSHHostChange, response: { 200: C.Resource } }, input: withId });
  definitions.define('ssh.access.grant', SSHGrant, ['SSH鍵での接続を許可する', 'Let an SSH key into a host account'],
    (who, input) => sshAccess.grant(who, input), { confirmation: input => sshAccess.grantConfirmation(input) });
  bind({ name: 'ssh.access.grant', method: 'POST', path: '/api/ssh-access', schema: {
    body: SSHGrant, response: { 201: SSHAuthorizationView } }, input: (_params, body) => body, status: 201 });
  definitions.define('ssh.access.revoke', idInput, ['SSH鍵での接続許可を取り消す', 'Take an SSH key out of a host account'],
    (who, input) => sshAccess.revoke(who, input.id), { confirmation: input => sshAccess.revokeConfirmation(input.id) });
  bind({ name: 'ssh.access.revoke', method: 'DELETE', path: '/api/ssh-access/:id', schema: { params: C.IdParams,
    response: { 200: SSHAuthorizationView } }, input: params => params });
}
