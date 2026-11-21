import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { fail } from './errors.js';
import * as C from '../shared/contracts.js';
import { isProtected } from '../shared/protected.js';

export async function routesResources(app: ApiApp, context: Context) {
  const { resources, authorization, catalog, objects } = context;
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
  app.get(
    '/api/connections/:id/method',
    {
      schema: { params: C.IdParams, response: { 200: C.CatalogMethod } },
    },
    async (request) => {
      const row = await resources.get(request.params.id);
      await authorization.requireResource(actor(request), row, 'read');
      if (row.kind !== 'connection') fail(400, 'wrong_kind', 'Choose a connection.');
      // Whoever may read a connection reads the method it names, as its readers do before they use it.
      const id = String(row.data.methodId), method = await catalog.connectionMethod(id);
      if (!method) fail(404, 'not_found', 'The connection method was not found.');
      return catalog.methodView(id, method);
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
      await authorization.requireResource(who, row, 'read');
      return resources.view(who, row);
    },
  );
  app.get(
    '/api/resources/:id/recipients',
    { schema: { params: C.IdParams, response: { 200: C.listOf(C.Recipient) } } },
    async (request) => {
      // Whoever may open an item may know whom it is sealed for, to seal its next value or renew it.
      const row = await resources.get(request.params.id);
      if (!isProtected(row.kind)) fail(400, 'wrong_kind', 'Only sealed items have recipients.');
      await authorization.requireResource(actor(request), row, 'reveal');
      return { items: await context.custody.recipients(row), next: null };
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
      return { items: await context.custody.ownerRecipients(request.query.to), next: null };
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
        return reply.redirect('/connections/complete?' + new URLSearchParams({ flow: result.id, operation: result.operationId }));
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
      bytes = await objects.content(actor(request), row);
    return reply
      .header('content-type', 'application/octet-stream')
      .header('content-disposition', "attachment; filename*=UTF-8''" + encodeURIComponent(row.name))
      .send(Buffer.from(bytes));
  });
}
