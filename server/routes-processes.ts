import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { IdParams, Ok, PageQuery, listOf } from '../shared/contracts.js';
import { ClaimedProcess, CreatedProcess, CreateProcess, ProcessCompletion, ProcessRegistration, ProcessView } from '../shared/process.js';
import { Lease } from '../shared/protocol.js';

export async function routesProcesses(app: ApiApp, { processes }: Context) {
  app.post('/api/environments/:id/processes', {
    schema: { summary: 'Start a command in an environment', params: IdParams, body: CreateProcess, response: { 202: CreatedProcess } },
  }, async (request, reply) => {
    const { id, environmentId, ownerId, actorId, state, createdAt } = await processes.create(actor(request), request.params.id, request.body);
    return reply.code(202).send({ id, environmentId, ownerId, actorId, state, createdAt });
  });
  app.get('/api/environments/:id/processes', {
    schema: { params: IdParams, querystring: PageQuery, response: { 200: listOf(ProcessView) } },
  }, request => processes.list(actor(request), request.params.id, request.query.limit, request.query.after));
  app.get('/api/processes/:id', {
    schema: { params: IdParams, response: { 200: ProcessView } },
  }, request => processes.get(actor(request), request.params.id));
  app.get('/api/processes/:id/output', {
    schema: { params: IdParams, querystring: z.object({
      stream: z.enum(['stdout', 'stderr']).default('stdout'),
      offset: z.coerce.number().int().nonnegative().describe('Offset in Unicode characters.').default(0),
      limit: z.coerce.number().int().min(1).max(10000).default(3000),
    }), response: { 200: z.object({ state: ProcessView.shape.state, stream: z.enum(['stdout', 'stderr']),
      offset: z.number(), text: z.string(), next: z.number().nullable(), truncated: z.boolean(),
      exitCode: z.number().int().nullable(), signal: z.string().nullable(), timedOut: z.boolean(), error: z.string().nullable() }) } },
  }, async request => {
    const process = await processes.get(actor(request), request.params.id), { stream, offset, limit } = request.query;
    const value = Array.from(process.result?.[stream] ?? ''), text = value.slice(offset, offset + limit).join('');
    return { state: process.state, stream, offset, text, next: offset + limit < value.length ? offset + limit : null,
      truncated: process.result?.truncated ?? false, exitCode: process.result?.exitCode ?? null,
      signal: process.result?.signal ?? null, timedOut: process.result?.timedOut ?? false, error: process.error };
  });
  app.post('/api/processes/:id/cancel', {
    schema: { params: IdParams, body: z.object({}).strict(), response: { 200: ProcessView } },
  }, request => processes.cancel(actor(request), request.params.id));
  app.put('/api/environments/:id/processes/registration', {
    schema: { params: IdParams, body: ProcessRegistration, response: { 200: ProcessRegistration } },
  }, request => processes.register(actor(request), request.params.id, request.body));
  app.post('/api/environments/:id/processes/claim', {
    schema: { params: IdParams, body: z.object({}).strict(), response: { 200: ClaimedProcess } },
  }, request => processes.claim(actor(request), request.params.id));
  app.post('/api/processes/:id/dispatch', {
    schema: { params: IdParams, body: Lease, response: { 200: Ok } },
  }, request => processes.dispatch(actor(request), request.params.id, request.body.lease));
  app.post('/api/processes/:id/renew', {
    schema: { params: IdParams, body: Lease, response: { 200: z.object({ active: z.boolean() }) } },
  }, request => processes.renew(actor(request), request.params.id, request.body.lease));
  app.post('/api/processes/:id/finish', {
    schema: { params: IdParams, body: ProcessCompletion.extend({ lease: Lease.shape.lease }), response: { 200: ProcessView } },
  }, request => {
    const { lease, ...completion } = request.body;
    return processes.finish(actor(request), request.params.id, lease, completion);
  });
}
