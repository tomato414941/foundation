import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import * as C from '../shared/contracts.js';
import { RequestApproval, RequestCreate, RequestView } from '../shared/operations.js';

export async function routesRequests(
  app: ApiApp,
  context: Context,
  cookieOptions: { httpOnly: boolean; secure: boolean; sameSite: 'lax'; path: string },
) {
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
