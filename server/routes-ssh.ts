import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { IdParams, Ok } from '../shared/contracts.js';
import { SSHView } from '../shared/ssh.js';
import { SSHPlan, SSHReport } from '../shared/ssh-access.js';
import { SSHAccessQuery, SSHAuthorizationView, SSHHostAccountView } from './ssh-access.js';

export async function routesSSH(app: ApiApp, { environments, sshAccess }: Context) {
  app.get('/api/environments/:id/ssh', {
    schema: { summary: 'Get SSH connection information', params: IdParams, response: { 200: SSHView.nullable() } },
  }, request => environments.ssh(actor(request), request.params.id));
  app.get('/api/ssh-access', {
    schema: { summary: 'List SSH keys let into host accounts, as decided and as the hosts last showed',
      querystring: SSHAccessQuery, response: { 200: z.object({ items: z.array(SSHAuthorizationView) }) } },
  }, request => sshAccess.list(actor(request), request.query));
  app.get('/api/ssh-hosts/:id/accounts', {
    schema: { summary: 'Show what each account of an SSH host last showed', params: IdParams,
      response: { 200: z.object({ items: z.array(SSHHostAccountView) }) } },
  }, request => sshAccess.accounts(actor(request), request.params.id));
  app.get('/api/ssh-hosts/:id/plan', {
    schema: { summary: 'Read the authorized key lines to apply to each account of an SSH host', params: IdParams,
      response: { 200: SSHPlan } },
  }, request => sshAccess.plan(actor(request), request.params.id));
  app.post('/api/ssh-hosts/:id/reports', {
    schema: { summary: 'Report what an account of an SSH host showed after applying or checking it', params: IdParams,
      body: SSHReport, response: { 200: Ok } },
  }, request => sshAccess.report(actor(request), request.params.id, request.body));
}
