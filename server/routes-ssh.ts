import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { SSHAccessQuery, SSHAuthorizationView } from './ssh-access.js';

export async function routesSSH(app: ApiApp, { sshAccess }: Context) {
  app.get('/api/ssh-access', {
    schema: { summary: 'List which SSH keys sign in to which accounts of SSH hosts',
      querystring: SSHAccessQuery, response: { 200: z.object({ items: z.array(SSHAuthorizationView) }) } },
  }, request => sshAccess.list(actor(request), request.query));
}
