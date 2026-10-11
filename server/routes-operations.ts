import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { fail } from './errors.js';
import * as C from '../shared/contracts.js';
import { ExecutionInput, ExecutionResponse, Invocation, OperationDescription, OperationExecution, WaitingOperation } from '../shared/operations.js';
import { ContinuationEnvelope, continuationContext } from '../shared/operation-continuations.js';
import { verify } from '../shared/authority.js';
import { base64url, encode } from '../shared/encryption.js';

export async function routesOperations(app: ApiApp, context: Context) {
  const { operations, operationExecutions: executions } = context;
  for (const endpoint of operations.endpoints) {
    app.route({ method: endpoint.method, url: endpoint.path, schema: { ...endpoint.schema, response: Object.assign({} as Record<number, z.ZodType>, endpoint.schema.response, { 202: endpoint.schema.response?.[202] ? z.union([endpoint.schema.response[202], OperationExecution]) : OperationExecution }) }, bodyLimit: endpoint.bodyLimit,
      handler: async (request, reply) => {
        const who = actor(request), input = C.JsonObject.parse(endpoint.input(
          request.params as Record<string, string>, request.body, request.query));
        const execution = await executions.start(who, [{ name: endpoint.name, input }]);
        if (execution.wait === 'approval' || execution.wait === 'input') return reply.code(202).send(execution);
        const result = execution.results[0];
        const status = typeof endpoint.status === 'function' ? endpoint.status(result ?? null) : endpoint.status ?? 200;
        return reply.code(status).send(result);
      },
    });
  }
  app.get('/api/operations', { schema: { response: { 200: C.listOf(OperationDescription) } } }, request => {
    actor(request);
    return { items: [...operations.definitions.values()].map(definition => {
      const [ja, en] = typeof definition.title === 'function' ? definition.title({}) : definition.title;
      return { name: definition.name, title: { ja, en }, execution: definition.execution, configure: [...definition.configure],
        input: C.JsonObject.parse(z.toJSONSchema(definition.schema)) };
    }), next: null };
  });
  app.post('/api/operations/:name', { schema: { params: Invocation.pick({ name: true }), body: C.JsonObject,
    response: { 200: C.Json, 202: OperationExecution } } }, async (request, reply) => {
    const who = actor(request), execution = await executions.start(who, [{ name: request.params.name, input: request.body }]);
    if (execution.wait) return reply.code(202).send(execution);
    return execution.results[0];
  });
  app.post('/api/operation-executions', { schema: { body: ExecutionInput, response: { 201: OperationExecution } } },
    async (request, reply) => reply.code(201).send(await executions.create(actor(request), request.body)));
  app.get('/api/operation-executions', { schema: { querystring: C.PageQuery, response: { 200: C.listOf(OperationExecution) } } },
    request => executions.list(actor(request), request.query.limit, request.query.after));
  app.get('/api/operation-executions/:id', { schema: { params: C.IdParams, response: { 200: OperationExecution } } },
    request => executions.get(request.actor, request.params.id));
  app.post('/api/operation-executions/:id/respond', { schema: { params: C.IdParams, body: ExecutionResponse,
    response: { 200: OperationExecution } } }, request => executions.respond(actor(request), request.params.id,
      request.body.values, request.body.code, request.body.configuration));
  app.post('/api/operation-executions/:id/decline', { schema: { params: C.IdParams, body: z.object({}).strict(),
    response: { 200: OperationExecution } } }, request => executions.cancel(actor(request), request.params.id, true));
  app.post('/api/operation-executions/:id/cancel', { schema: { params: C.IdParams, body: z.object({}).strict(),
    response: { 200: OperationExecution } } }, async request => {
    const who = actor(request), id = request.params.id;
    return executions.cancel(who, id);
  });
  app.get('/api/operation-executions/:id/input', { schema: { params: C.IdParams,
    response: { 200: WaitingOperation.extend({ id: C.Id }) } } }, async request => {
    const { plan } = await executions.input(actor(request), request.params.id);
    return { id: request.params.id, ...plan };
  });
  app.patch('/api/operation-executions/:id/input', { schema: { params: C.IdParams,
    body: z.object({ index: z.number().int().nonnegative(), values: C.JsonObject }).strict(), response: { 200: OperationExecution } } },
    request => executions.configure(actor(request), request.params.id, request.body.index, request.body.values));
  app.put('/api/operation-executions/:id/continuation', { schema: { params: C.IdParams,
    body: z.object({ index: z.number().int().nonnegative(), continuation: WaitingOperation.shape.continuation.unwrap() }).strict(),
    response: { 200: OperationExecution } } }, request => executions.track(actor(request), request.params.id,
      request.body.index, request.body.continuation));
  app.post('/api/operation-executions/:id/complete', { bodyLimit: 40 * 1024 * 1024, schema: { params: C.IdParams,
    body: z.object({ index: z.number().int().nonnegative(), proof: C.Json }).strict(), response: { 200: OperationExecution } } },
    request => executions.complete(actor(request), request.params.id, request.body.index, request.body.proof));
  app.get('/api/operation-continuations/:id', { schema: { params: C.IdParams, response: { 200: ContinuationEnvelope.nullable() } } }, async request => {
    const who = actor(request);
    if (who.requestId) fail(403, 'forbidden', 'Sign in with your keys to continue this operation.');
    const row = await context.db.one<{ actor_id: string; envelope: unknown }>('SELECT * FROM operation_continuations WHERE id=$1', [request.params.id]);
    if (row && row.actor_id !== who.id) fail(403, 'forbidden', 'This operation belongs to another identity.');
    return row ? ContinuationEnvelope.parse(row.envelope) : null;
  });
  app.put('/api/operation-continuations/:id', { schema: { params: C.IdParams, body: ContinuationEnvelope,
    response: { 200: ContinuationEnvelope } } }, async request => {
    const who = actor(request), { signature, ...value } = request.body;
    const { binding } = await context.bindings.current(who.id);
    if (who.requestId || value.actorId !== who.id || value.bindingId !== binding.id || value.origin !== context.config.origin ||
      value.id !== request.params.id || value.sealed.aad !== base64url(encode(continuationContext(value.origin, value.id))))
      fail(403, 'forbidden', 'Save progress signed and sealed for this identity.');
    await verify(value, signature, binding.signing, 'operation-continuation');
    const saved = await context.db.one<{ envelope: unknown }>(
      `INSERT INTO operation_continuations(id,actor_id,binding_id,revision,envelope) SELECT $1,$2,$3,$4,$5
       WHERE $4=1 OR EXISTS(SELECT 1 FROM operation_continuations WHERE id=$1)
       ON CONFLICT(id) DO UPDATE SET revision=$4,envelope=$5,updated_at=now()
       WHERE operation_continuations.actor_id=$2 AND operation_continuations.binding_id=$3 AND operation_continuations.revision=$4-1
       RETURNING envelope`, [value.id, who.id, binding.id, value.revision, JSON.stringify(request.body)]);
    if (!saved) fail(409, 'execution_changed', 'This operation changed. Reload its progress.');
    return ContinuationEnvelope.parse(saved.envelope);
  });
}
