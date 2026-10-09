import { readFileSync } from 'node:fs';
import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { fail } from './errors.js';
import * as C from '../shared/contracts.js';
import * as P from '../shared/protocol.js';
import { atPointer } from '../shared/values.js';

// What creating each kind of item is called, for the one asked to approve it.
const CREATED: Record<string, readonly [string, string]> = {
  service: ['サービス定義を作る', 'Create a service definition'],
  method: ['接続方法を作る', 'Create a connection method'],
  environment: ['実行環境を作る', 'Create an environment'],
  function: ['関数を作る', 'Create a function'],
} satisfies Record<z.infer<typeof C.NewResource>['kind'], readonly [string, string]>;

const roleTemplate = () => readFileSync(new URL('./aws-connection.yaml', import.meta.url));
export async function routesResources(app: ApiApp, context: Context) {
  const { resources, authorization, catalog, functions, objects, environments, billing } = context;
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
    return { url: await objects.store.publish('aws-connection.yaml', roleTemplate(), 'text/plain', 3600) };
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
        }),
        response: { 200: C.listOf(C.Resource) },
      },
    },
    (request) => resources.list(actor(request), request.params.id, request.query),
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
  app.post(
    '/api/principals/:id/resources',
    {
      config: { approval: { title: (body) => CREATED[String(atPointer(body, '/kind'))] ?? ['項目を作る', 'Create an item'] } },
      schema: { params: C.IdParams, body: C.NewResource, response: { 201: C.Resource } },
    },
    async (request, reply) => {
      const who = actor(request),
        body = request.body,
        owner = request.params.id;
      const row = body.kind === 'service'
        ? await catalog.createService(who, owner, body.name, body.definition)
        : body.kind === 'method'
          ? await (async () => {
              if (!(await authorization.canCreate(who, owner, 'method')))
                fail(403, 'forbidden', 'You cannot create this connection method.');
              return resources.insert(owner, 'method', body.name, C.MethodDefinition.parse({
                ...body.definition, name: body.name }) as unknown as Record<string, C.JsonValue>);
            })()
          : body.kind === 'environment'
            ? await environments.create(who, owner, body.options, body.name)
            : await functions.create(who, owner, body.name, body.definition);
      return reply.code(201).send(await resources.view(who, row));
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
  app.patch(
    '/api/resources/:id',
    {
      config: { approval: { title: ['項目を変更する', 'Change an item'] } },
      schema: { params: C.IdParams, body: C.UpdateResource, response: { 200: C.Resource } },
    },
    async (request) => {
      const who = actor(request),
        body = request.body;
      let row = await resources.get(request.params.id);
      await authorization.requireResource(who, row, 'update');
      if (body.version !== row.version) fail(409, 'changed', 'This item changed. Reload it before saving.');
      const fields = [
        'version',
        'name',
        ...(['function', 'service', 'method'].includes(row.kind) ? ['definition'] : []),
      ];
      if (Object.keys(body).some((field) => !fields.includes(field)))
        fail(400, 'invalid_input', 'Choose fields that can be edited for this item.');
      if (body.name && body.name !== row.name) await authorization.requireResource(who, row, 'rename');
      if (body.definition) {
        if (row.kind === 'function') {
          const spec = await functions.validateFunction(who, C.FunctionDefinition.parse(body.definition));
          await functions.validateFunction({ id: row.owner_id }, spec);
          row = await resources.db.transaction(async (connection) => {
            const updated = await resources.update(
              row,
              {
                data: spec as unknown as Record<string, C.JsonValue>,
                ...(body.name ? { name: body.name } : {}),
              },
              connection,
            );
            await resources.references(row.id, functions.references(spec.request), connection);
            return updated;
          });
        } else if (row.kind === 'service') {
          row = await resources.db.transaction(async (connection) => {
            await connection.query('SELECT pg_advisory_xact_lock(736023747)');
            const definition = await catalog.prepareDefinition(
              who,
              row.owner_id,
              row.id,
              C.ServiceInputDefinition.parse(body.definition),
              connection,
            );
            const updated = await resources.update(
              row,
              {
                data: definition,
                ...(body.name ? { name: body.name } : {}),
              },
              connection,
            );
            await resources.references(
              row.id,
              Object.values(definition.methods).filter((id) => !catalog.methods.has(id)),
              connection,
            );
            return updated;
          });
        } else if (row.kind === 'method') {
          const definition = C.MethodDefinition.parse({ ...body.definition, name: body.name ?? row.name });
          const previous = C.MethodDefinition.parse(row.data);
          const reference = await resources.db.one(
            "SELECT 1 FROM resource_references ref JOIN resources r ON r.id=ref.resource_id WHERE ref.referenced_id=$1 AND r.kind IN ('connection','app') LIMIT 1",
            [row.id],
          );
          if (
            reference &&
            (previous.kind !== definition.kind ||
              JSON.stringify(previous.config) !== JSON.stringify(definition.config))
          )
            fail(
              409,
              'in_use',
              'Create another connection method to change how existing connections authenticate.',
            );
          row = await resources.update(row, {
            data: definition,
            ...(body.name ? { name: body.name } : {}),
          });
        } else fail(400, 'wrong_kind', 'This item does not have an editable definition.');
      }
      if (body.name && body.name !== row.name) row = await resources.rename(who, row, body.name);
      return resources.view(who, row);
    },
  );
  app.delete(
    '/api/resources/:id',
    {
      config: { approval: { title: ['項目を削除する', 'Delete an item'] } },
      schema: {
        params: C.IdParams,
        querystring: z.object({}).strict(),
        response: { 200: C.Ok, 202: C.EnvironmentDeletion },
      },
    },
    async (request, reply) => {
      const who = actor(request),
        row = await resources.get(request.params.id);
      if (row.kind === 'environment') return reply.code(202).send(await environments.remove(who, row));
      else if (row.kind === 'object') await objects.remove(who, row);
      else await resources.delete(who, row);
      return { ok: true as const };
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
  app.post(
    '/api/resources/:id/transfer',
    {
      config: { approval: { title: ['項目を譲る', 'Transfer an item'] } },
      schema: {
        params: C.IdParams,
        body: z.object({ to: C.Id }).strict(),
        response: { 200: C.Ok, 202: C.ApprovalRequest },
      },
    },
    async (request) => {
      const row = await resources.get(request.params.id);
      await context.relations.transfer(actor(request), row.id, request.body.to);
      return { ok: true as const };
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
  app.post(
    '/api/resources/:id/stop',
    {
      config: { approval: { title: ['実行環境を止める', 'Stop an environment'] } },
      schema: { params: C.IdParams, body: z.object({}).strict(), response: { 200: C.Resource } },
    },
    async (request) =>
      resources.view(
        actor(request),
        await environments.stop(actor(request), await resources.get(request.params.id)),
      ),
  );
  app.post('/api/environments/:id/enroll', {
    config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
    schema: { params: C.IdParams, body: P.EnvironmentEnrollment, response: { 200: C.Ok }, security: [] },
  }, async request => {
    await environments.enroll(request.params.id, request.body);
    return { ok: true as const };
  });
  app.addContentTypeParser(
    'application/octet-stream',
    { parseAs: 'buffer', bodyLimit: 25 * 1024 * 1024 },
    (_request, body, done) => done(null, body),
  );
  app.post(
    '/api/principals/:id/objects',
    {
      bodyLimit: 25 * 1024 * 1024,
      schema: {
        params: C.IdParams,
        querystring: z.object({
          name: C.Name,
          contentType: z.string().max(200).default('application/octet-stream'),
        }),
        response: { 201: C.Resource },
      },
    },
    async (request, reply) => {
      if (!Buffer.isBuffer(request.body))
        fail(400, 'binary_required', 'Upload the file as application/octet-stream.');
      return reply
        .code(201)
        .send(
          await resources.view(
            actor(request),
            await objects.upload(
              actor(request),
              request.params.id,
              request.query.name,
              request.body,
              request.query.contentType,
            ),
          ),
        );
    },
  );
  app.put(
    '/api/resources/:id/content',
    {
      bodyLimit: 25 * 1024 * 1024,
      schema: {
        params: C.IdParams,
        querystring: z.object({
          version: z.coerce.number().int().positive(),
          contentType: z.string().max(200).default('application/octet-stream'),
        }),
        response: { 200: C.Resource },
      },
    },
    async (request) => {
      const row = await resources.get(request.params.id);
      if (row.version !== request.query.version)
        fail(409, 'changed', 'This file changed. Reload it before saving.');
      if (!Buffer.isBuffer(request.body))
        fail(400, 'binary_required', 'Upload the file as application/octet-stream.');
      return resources.view(
        actor(request),
        await objects.upload(
          actor(request),
          row.owner_id,
          row.name,
          request.body,
          request.query.contentType,
          row,
        ),
      );
    },
  );
  app.get('/api/resources/:id/content', { schema: { params: C.IdParams } }, async (request, reply) => {
    const row = await resources.get(request.params.id),
      bytes = await objects.content(actor(request), row);
    return reply
      .header('content-type', 'application/octet-stream')
      .header('content-disposition', "attachment; filename*=UTF-8''" + encodeURIComponent(row.name))
      .send(Buffer.from(bytes));
  });
  app.post(
    '/api/resources/:id/link',
    {
      schema: {
        params: C.IdParams,
        body: z.object({ minutes: z.number().int().min(1).max(1440).default(15) }).strict(),
        response: { 200: z.object({ url: z.url(), expiresAt: C.Time }) },
      },
    },
    (request) =>
      resources.get(request.params.id).then((row) => objects.link(actor(request), row, request.body.minutes)),
  );
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
  app.put(
    '/api/principals/:id/limits',
    {
      schema: {
        params: C.IdParams,
        body: z
          .object({
            storageBytes: z.number().int().min(1).max(1_000_000_000_000),
            computeSeconds: z.number().int().min(1).max(10_000_000),
          })
          .strict(),
        response: { 200: C.Ok },
      },
    },
    async (request) => {
      await billing.limits(
        actor(request),
        request.params.id,
        request.body.storageBytes,
        request.body.computeSeconds,
      );
      return { ok: true as const };
    },
  );
  app.post(
    '/api/principals/:id/payment/checkout',
    {
      schema: {
        params: C.IdParams,
        body: z.object({}).strict(),
        response: { 200: z.object({ url: z.url() }) },
      },
    },
    (request) => billing.checkout(actor(request), request.params.id),
  );
  app.post(
    '/api/principals/:id/payment/portal',
    {
      schema: {
        params: C.IdParams,
        body: z.object({}).strict(),
        response: { 200: z.object({ url: z.url() }) },
      },
    },
    (request) => billing.portal(actor(request), request.params.id),
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
