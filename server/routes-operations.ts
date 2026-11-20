import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { fail } from './errors.js';
import * as C from '../shared/contracts.js';
import { Continuation, Invocation, OperationInput, OperationKind, OperationPerform, OperationView, RequestView } from '../shared/operations.js';
import { ContinuationEnvelope, continuationContext } from '../shared/operation-continuations.js';
import { base64url, encode } from '../shared/encryption.js';

export async function routesOperations(app: ApiApp, context: Context) {
  const { definitions, operations } = context;
  const madeOrAsked = z.union([OperationView, RequestView]);
  for (const endpoint of definitions.endpoints) {
    app.route({ method: endpoint.method, url: endpoint.path, schema: { ...endpoint.schema, response: Object.assign({} as Record<number, z.ZodType>,
      endpoint.schema.response, { 202: RequestView }) },
      ...(endpoint.bodyLimit ? { bodyLimit: endpoint.bodyLimit } : {}),
      handler: async (request, reply) => {
        const who = actor(request), input = C.JsonObject.parse(endpoint.input(
          request.params as Record<string, string>, request.body, request.query));
        const made = await operations.perform(who, { name: endpoint.name, input });
        // A change that needs another principal's agreement waits for it as a request.
        if (!('name' in made)) return reply.code(202).send(made);
        const result = made.result;
        const status = typeof endpoint.status === 'function' ? endpoint.status(result ?? null) : endpoint.status ?? 200;
        return reply.code(status).send(endpoint.output ? endpoint.output(result ?? null) : result);
      },
    });
  }
  app.get('/api/operation-kinds', { schema: { response: { 200: C.listOf(OperationKind) } } }, request => {
    actor(request);
    return { items: [...definitions.definitions.values()].map(definition => {
      const [ja, en] = typeof definition.title === 'function' ? definition.title({}) : definition.title;
      return { name: definition.name, title: { ja, en }, keyholder: definition.keyholder, configure: [...definition.configure],
        input: C.JsonObject.parse(z.toJSONSchema(definition.schema)) };
    }), next: null };
  });
  // The input an operation will be made with, for a device to seal what it saves against.
  app.post('/api/operations/review', { schema: { body: Invocation, response: { 200: Invocation } } }, async request => {
    const who = actor(request);
    await context.authorization.active(who);
    const definition = definitions.get(request.body.name);
    const reviewed = definition.review ? await definition.review(who, request.body.input) : request.body.input;
    return (await definitions.prepareFor(who, { name: request.body.name, input: reviewed })).invocation;
  });
  app.post('/api/operations', { bodyLimit: 40 * 1024 * 1024, schema: { body: OperationInput, response: { 201: OperationView, 202: RequestView } } },
    async (request, reply) => {
      const made = await operations.perform(actor(request), request.body);
      return reply.code('name' in made ? 201 : 202).send(made);
    });
  app.get('/api/operations', { schema: { querystring: C.PageQuery.extend({ request: C.Id.optional() }), response: { 200: C.listOf(OperationView) } } },
    request => operations.list(actor(request), { limit: request.query.limit, after: request.query.after, requestId: request.query.request }));
  app.get('/api/principals/:id/operations', { schema: { params: C.IdParams, querystring: C.PageQuery, response: { 200: C.listOf(OperationView) } } },
    request => operations.list(actor(request), { limit: request.query.limit, after: request.query.after, ownerId: request.params.id }));
  app.get('/api/operations/:id', { schema: { params: C.IdParams, response: { 200: OperationView } } },
    request => operations.get(actor(request), request.params.id));
  app.post('/api/operations/:id/perform', { bodyLimit: 40 * 1024 * 1024, schema: { params: C.IdParams, body: OperationPerform,
    response: { 200: madeOrAsked } } }, request => operations.continue(actor(request), request.params.id, request.body.proof));
  app.patch('/api/operations/:id', { schema: { params: C.IdParams, body: z.object({ values: C.JsonObject }).strict(),
    response: { 200: OperationView } } }, request => operations.configure(actor(request), request.params.id, request.body.values));
  app.put('/api/operations/:id/continuation', { schema: { params: C.IdParams, body: z.object({ continuation: Continuation }).strict(),
    response: { 200: OperationView } } }, request => operations.track(actor(request), request.params.id, request.body.continuation));
  app.post('/api/operations/:id/cancel', { schema: { params: C.IdParams, body: z.object({}).strict(), response: { 200: OperationView } } },
    request => operations.cancel(actor(request), request.params.id));
  app.get('/api/operation-continuations/:id', { schema: { params: C.IdParams, response: { 200: ContinuationEnvelope.nullable() } } }, async request => {
    const who = actor(request);
    if (who.requestId) fail(403, 'forbidden', 'Sign in with your keys to continue this operation.');
    const row = await context.db.one<{ actor_id: string; envelope: unknown }>('SELECT * FROM operation_continuations WHERE id=$1', [request.params.id]);
    if (row && row.actor_id !== who.id) fail(403, 'forbidden', 'This operation belongs to another identity.');
    return row ? ContinuationEnvelope.parse(row.envelope) : null;
  });
  app.put('/api/operation-continuations/:id', { schema: { params: C.IdParams, body: ContinuationEnvelope,
    response: { 200: ContinuationEnvelope } } }, async request => {
    const who = actor(request), value = request.body;
    if (who.requestId || value.actorId !== who.id || value.origin !== context.config.origin ||
      value.id !== request.params.id || value.sealed.aad !== base64url(encode(continuationContext(value.origin, value.id))))
      fail(403, 'forbidden', 'Save progress sealed for this identity.');
    const saved = await context.db.one<{ envelope: unknown }>(
      `INSERT INTO operation_continuations(id,actor_id,revision,envelope) SELECT $1,$2,$3,$4
       WHERE $3=1 OR EXISTS(SELECT 1 FROM operation_continuations WHERE id=$1)
       ON CONFLICT(id) DO UPDATE SET revision=$3,envelope=$4,updated_at=now()
       WHERE operation_continuations.actor_id=$2 AND operation_continuations.revision=$3-1
       RETURNING envelope`, [value.id, who.id, value.revision, JSON.stringify(value)]);
    if (!saved) fail(409, 'operation_changed', 'This operation changed. Reload its progress.');
    return ContinuationEnvelope.parse(saved.envelope);
  });
}
