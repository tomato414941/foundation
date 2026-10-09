import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { IdParams } from '../shared/contracts.js';
import { SSHHeartbeat, SSHUpdate, SSHView, SSHWorkerState } from '../shared/ssh.js';

export async function routesSSH(app: ApiApp, { environments }: Context) {
  app.get('/api/environments/:id/ssh', {
    schema: { summary: 'Get SSH connection information', params: IdParams, response: { 200: SSHView.nullable() } },
  }, request => environments.ssh(actor(request), request.params.id));
  app.put('/api/environments/:id/ssh', {
    config: { approval: { title: ['SSH公開鍵を設定する', 'Set SSH public keys'] } },
    schema: { summary: 'Replace authorized SSH public keys', params: IdParams, body: SSHUpdate, response: { 200: SSHView } },
  }, request => environments.updateSSH(actor(request), request.params.id, request.body));
  app.post('/api/environments/:id/ssh/heartbeat', {
    schema: { summary: 'Report SSH activity and receive settings', params: IdParams, body: SSHHeartbeat,
      response: { 200: SSHWorkerState } },
  }, request => environments.sshHeartbeat(actor(request), request.params.id, request.body));
}
