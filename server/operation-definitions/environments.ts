import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import { SSHUpdate, SSHView } from '../../shared/ssh.js';
import { DefinitionRegistry } from '../definitions.js';
import type { OperationServices } from '../builtin-definitions.js';
import { idInput, withId } from './support.js';

export function defineEnvironments(definitions: DefinitionRegistry, services: Pick<OperationServices, 'resources' | 'environments'>) {
  const { resources, environments } = services;
  const bind = definitions.bind.bind(definitions);
  definitions.define('environment.start', idInput, ['実行環境を起動する', 'Start an environment'], async (who, input) =>
    resources.view(who, await environments.start(who, await resources.get(input.id))));
  bind({ name: 'environment.start', method: 'POST', path: '/api/resources/:id/start', schema: { params: C.IdParams,
    body: z.object({}).strict(), response: { 200: C.Resource } }, input: params => params });
  definitions.define('environment.stop', idInput, ['実行環境を止める', 'Stop an environment'], async (who, input) =>
    resources.view(who, await environments.stop(who, await resources.get(input.id))));
  bind({ name: 'environment.stop', method: 'POST', path: '/api/resources/:id/stop', schema: { params: C.IdParams,
    body: z.object({}).strict(), response: { 200: C.Resource } }, input: params => params });
  const ssh = SSHUpdate.extend({ id: C.Id });
  definitions.define('environment.ssh', ssh, ['SSH公開鍵を設定する', 'Set SSH public keys'], async (who, { id, ...input }) => environments.updateSSH(who, id, input));
  bind({ name: 'environment.ssh', method: 'PUT', path: '/api/environments/:id/ssh', schema: { params: C.IdParams,
    body: SSHUpdate, response: { 200: SSHView } }, input: withId });
}
