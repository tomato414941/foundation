import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import * as C from '../shared/contracts.js';
import { RequestApproval, RequestCreate, RequestView } from '../shared/operations.js';

export async function routesRequests(app: ApiApp, context: Context) {
  const { requests, integrations } = context;
  app.get(
    '/api/requests',
    { schema: { querystring: C.PageQuery, response: { 200: C.listOf(RequestView) } } },
    (request) => requests.list(actor(request), request.query.limit, request.query.after),
  );
  app.post(
    '/api/requests',
    { schema: { body: RequestCreate, response: { 201: RequestView } } },
    async (request, reply) => reply.code(201).send(await requests.create(actor(request), request.body)),
  );
  app.get(
    '/api/requests/:id',
    { schema: { params: C.IdParams, response: { 200: RequestView } } },
    (request) => requests.get(request.actor, request.params.id),
  );
  app.post(
    '/api/requests/:id/approve',
    { schema: { params: C.IdParams, body: RequestApproval, response: { 200: RequestView } } },
    (request) => requests.approve(actor(request), request.params.id, request.body.values, request.body.code, request.body.configuration),
  );
  app.post(
    '/api/requests/:id/decline',
    { schema: { params: C.IdParams, body: z.object({}).strict(), response: { 200: RequestView } } },
    (request) => requests.decline(actor(request), request.params.id),
  );
  app.post(
    '/api/requests/:id/withdraw',
    { schema: { params: C.IdParams, body: z.object({}).strict(), response: { 200: RequestView } } },
    (request) => requests.withdraw(actor(request), request.params.id),
  );
  app.get(
    '/api/principals/:id/settings',
    { schema: { params: C.IdParams, response: { 200: C.Settings } } },
    (request) => integrations.get(actor(request), request.params.id),
  );
}
