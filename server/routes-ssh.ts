import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { IdParams } from '../shared/contracts.js';
import { SSHView } from '../shared/ssh.js';

export async function routesSSH(app: ApiApp, { environments }: Context) {
  app.get('/api/environments/:id/ssh', {
    schema: { summary: 'Get SSH connection information', params: IdParams, response: { 200: SSHView.nullable() } },
  }, request => environments.ssh(actor(request), request.params.id));
}
