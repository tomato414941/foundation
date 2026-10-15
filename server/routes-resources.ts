import { readFileSync } from 'node:fs';
import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { fail } from './errors.js';
import * as C from '../shared/contracts.js';

const roleTemplate = () => readFileSync(new URL('./aws-connection.yaml', import.meta.url));
export async function routesResources(app: ApiApp, context: Context) {
  const { resources, authorization, catalog, files, environments, billing } = context;
  app.get('/api/catalog', { schema: { response: { 200: C.listOf(C.CatalogEntry) } } }, async (request) => ({
    items: await catalog.list(actor(request)),
    next: null,
  }));
  app.get(
    '/api/connection-methods',
    { schema: { response: { 200: C.listOf(C.CatalogMethod) } } },
    async (request) => ({
      items: await catalog.listMethods(actor(request)),
      next: null,
    }),
  );
  // The account owner makes the role in their own console, from a template Foundation hands over as a one-hour link.
  app.get('/api/aws/role-template', { schema: { response: { 200: z.object({ url: z.string() }) } } }, async (request) => {
    actor(request);
    return { url: await files.store.publish('aws-connection.yaml', roleTemplate(), 'text/plain', 3600) };
  });
  app.get(
    '/api/connections/:id/method',
    {
      schema: { params: C.IdParams, response: { 200: C.CatalogMethod } },
    },
    async (request) => {
      const row = await resources.get(request.params.id);
      await authorization.requireResource(actor(request), row, 'read');
      if (row.kind !== 'connection') fail(400, 'wrong_kind', 'Choose a connection.');
      const id = String(row.data.methodId);
      return catalog.methodView(id, await catalog.method(actor(request), id));
    },
  );
  app.get(
    '/api/identities/:id',
    {
      schema: {
        params: C.IdParams,
        response: { 200: z.object({ id: C.Id, name: C.Name, publicKey: C.PublicKey.nullable() }) },
      },
    },
    async (request) => {
      actor(request);
      const row = await context.principals.get(request.params.id);
      return { id: row.id, name: row.name, publicKey: row.public_key };
    },
  );
  app.get(
    '/api/principals/:id/resources',
    {
      schema: {
        params: C.IdParams,
        querystring: C.PageQuery.extend({
          kind: C.ResourceKind.optional(),
          query: z.string().max(200).optional(),
          includeOwned: z.enum(['true', 'false']).optional(),
        }),
        response: { 200: C.listOf(C.Resource) },
      },
    },
    (request) => resources.list(actor(request), request.params.id, {
      ...request.query,
      includeOwned: request.query.includeOwned === 'true',
    }),
  );
  app.get('/api/resources/shared', { schema: { response: { 200: C.listOf(C.Resource) } } }, (request) =>
    resources.shared(actor(request)),
  );
  app.get(
    '/api/principals/:id/recipients',
    { schema: { params: C.IdParams, response: { 200: C.listOf(C.Recipient) } } },
    async (request) => {
      await authorization.requirePrincipal(actor(request), request.params.id, 'read');
      return { items: await resources.recipients(request.params.id), next: null };
    },
  );
  app.get(
    '/api/resources/:id',
    { schema: { params: C.IdParams, response: { 200: C.Resource } } },
    async (request) => {
      const who = actor(request),
        row = await resources.get(request.params.id);
      if (row.kind !== 'function' || !await authorization.can(who, row, 'execute'))
        await authorization.requireResource(who, row, 'read');
      return resources.view(who, row);
    },
  );
  app.get('/api/resources/:id/deletion', {
    schema: { params: C.IdParams, response: { 200: C.EnvironmentDeletion } },
  }, request => environments.deletion(actor(request), request.params.id));
  app.get(
    '/api/resources/:id/recipients',
    { schema: { params: C.IdParams, response: { 200: C.listOf(C.Recipient) } } },
    async (request) => {
      const row = await resources.get(request.params.id);
      await authorization.requireResource(actor(request), row, 'update');
      return { items: await resources.recipients(row.owner_id), next: null };
    },
  );
  app.get(
    '/api/resources/:id/transfer-recipients',
    {
      schema: {
        params: C.IdParams,
        querystring: z.object({ to: C.Id }),
        response: { 200: C.listOf(C.Recipient) },
      },
    },
    async (request) => {
      await authorization.requireResource(actor(request), await resources.get(request.params.id), 'transfer');
      await context.principals.get(request.query.to);
      return { items: await resources.recipients(request.query.to), next: null };
    },
  );
  app.get(
    '/oauth/callback',
    {
      schema: {
        querystring: z
          .object({
            state: z.string().min(1).max(1000),
            code: z.string().max(16384).optional(),
            error: z.string().max(200).optional(),
          })
          .passthrough(),
        hide: true,
      },
    },
    async (request, reply) => {
      try {
        const result = await context.oauthRelays.receive(new URL(request.url, context.config.origin).searchParams);
        return reply.redirect('/connections/complete?flow=' + result.id);
      } catch {
        return reply.redirect('/connections/complete?error=connection_expired');
      }
    },
  );
  app.addContentTypeParser(
    'application/octet-stream',
    { parseAs: 'buffer', bodyLimit: 25 * 1024 * 1024 },
    (_request, body, done) => done(null, body),
  );
  app.get('/api/resources/:id/content', { schema: { params: C.IdParams } }, async (request, reply) => {
    const row = await resources.get(request.params.id),
      bytes = await files.content(actor(request), row);
    return reply
      .header('content-type', 'application/octet-stream')
      .header('content-disposition', "attachment; filename*=UTF-8''" + encodeURIComponent(row.name))
      .send(Buffer.from(bytes));
  });
  app.get(
    '/api/principals/:id/payment',
    { schema: { params: C.IdParams, response: { 200: C.Payment } } },
    (request) => billing.payment(actor(request), request.params.id),
  );
  app.get(
    '/api/principals/:id/usage',
    { schema: { params: C.IdParams, response: { 200: C.Usage } } },
    async (request) => {
      await authorization.requirePrincipal(actor(request), request.params.id, 'read');
      return billing.usage(request.params.id);
    },
  );
  await app.register(async (scope) => {
    scope.removeContentTypeParser('application/json');
    scope.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_request, body, done) =>
      done(null, body),
    );
    scope.post('/api/webhooks/stripe', { schema: { hide: true } }, async (request, reply) => {
      if (!Buffer.isBuffer(request.body) || typeof request.headers['stripe-signature'] !== 'string')
        fail(400, 'invalid_signature', 'The webhook signature could not be verified.');
      await billing.webhook(request.body, request.headers['stripe-signature']);
      return reply.send({ ok: true });
    });
  });
}
