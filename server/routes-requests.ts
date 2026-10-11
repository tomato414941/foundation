import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import * as C from '../shared/contracts.js';
import * as P from '../shared/protocol.js';
import { fail } from './errors.js';
import { WaitingOperation } from '../shared/operations.js';

export async function routesRequests(
  app: ApiApp,
  context: Context,
  cookieOptions: { httpOnly: boolean; secure: boolean; sameSite: 'lax'; path: string },
) {
  const { requests, integrations } = context;
  app.get('/api/requests/:id/connection', {
    schema: { params: C.IdParams, response: { 200: P.ConnectionPlan } },
  }, request => requests.connectionPlan(actor(request), request.params.id));
  app.get('/api/requests/:id/operation', {
    schema: { params: C.IdParams, response: { 200: WaitingOperation.extend({ id: C.Id }) } },
  }, request => requests.operationPlan(actor(request), request.params.id));
  app.post('/api/requests/:id/connection', {
    schema: { params: C.IdParams, body: z.object({ runId: C.Id, resourceId: C.Id }).strict(),
      response: { 200: C.ApprovalRequest } },
  }, async request => {
    const who = actor(request), id = request.params.id;
    const execution = await context.operationExecutions.get(who, id);
    const index = execution.waiting?.index ?? execution.results.findIndex(result => result && typeof result === 'object' &&
      !Array.isArray(result) && result.kind === 'connected' && result.id === request.body.resourceId);
    if (index < 0) fail(409, 'connection_required', 'Continue the approved connection.');
    await context.operationExecutions.complete(who, id, index, request.body);
    return requests.get(who, id);
  });
  app.get(
    '/api/requests',
    { schema: { querystring: C.PageQuery, response: { 200: C.listOf(C.ApprovalRequest) } } },
    (request) => requests.list(actor(request), request.query.limit, request.query.after),
  );
  app.post(
    '/api/requests',
    { schema: { body: C.RequestInput, response: { 201: C.ApprovalRequest } } },
    async (request, reply) => reply.code(201).send(await requests.create(actor(request), request.body)),
  );
  app.get(
    '/api/requests/:id',
    { schema: { params: C.IdParams, response: { 200: C.ApprovalRequest } } },
    (request) => requests.get(request.actor, request.params.id),
  );
  app.post(
    '/api/requests/:id/approve',
    {
      schema: {
        params: C.IdParams,
        body: z
          .object({
            values: z.array(z.record(z.string(), C.Json)).max(8).default([]),
            code: z.string().max(20).optional(),
            configuration: z.array(C.JsonObject).max(8).default([]),
          })
          .strict(),
        response: { 200: C.ApprovalRequest },
      },
    },
    (request) =>
      requests.approve(
        actor(request),
        request.params.id,
        request.body.values,
        request.body.code,
        request.body.configuration,
      ),
  );
  app.post(
    '/api/requests/:id/decline',
    { schema: { params: C.IdParams, body: z.object({}).strict(), response: { 200: C.ApprovalRequest } } },
    (request) => requests.decline(actor(request), request.params.id),
  );
  app.post(
    '/api/requests/:id/cancel',
    { schema: { params: C.IdParams, body: z.object({}).strict(), response: { 200: C.ApprovalRequest } } },
    (request) => requests.cancel(actor(request), request.params.id),
  );
  app.post(
    '/api/requests/:id/links',
    {
      schema: {
        params: C.IdParams,
        body: z.object({}).strict(),
        response: { 200: z.object({ url: z.url(), expiresAt: C.Time }) },
      },
    },
    (request) => requests.link(actor(request), request.params.id),
  );
  app.post(
    '/api/requests/:id/redeem',
    {
      config: { rateLimit: { max: 30, timeWindow: '1 hour' } },
      schema: {
        params: C.IdParams,
        body: z.object({ token: z.string().max(200) }).strict(),
        response: { 200: C.Ok },
      },
    },
    async (request, reply) => {
      const session = await requests.redeem(request.params.id, request.body.token);
      reply.setCookie('foundation_request', session.token, {
        ...cookieOptions,
        expires: new Date(session.expiresAt),
      });
      return { ok: true as const };
    },
  );
  app.get(
    '/api/principals/:id/settings',
    { schema: { params: C.IdParams, response: { 200: C.Settings } } },
    (request) => integrations.get(actor(request), request.params.id),
  );
}
