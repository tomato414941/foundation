import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import * as C from '../shared/contracts.js';
import * as P from '../shared/protocol.js';
import { canonical } from '../shared/authority.js';
import { fail } from './errors.js';

export async function routesRequests(
  app: ApiApp,
  context: Context,
  cookieOptions: { httpOnly: boolean; secure: boolean; sameSite: 'lax'; path: string },
) {
  const { requests, integrations } = context;
  app.get('/api/requests/:id/connection', {
    schema: { params: C.IdParams, response: { 200: P.ConnectionPlan } },
  }, request => requests.connectionPlan(actor(request), request.params.id));
  app.post('/api/requests/:id/connection', {
    schema: { params: C.IdParams, body: z.object({ runId: C.Id, resourceId: C.Id }).strict(),
      response: { 200: C.ApprovalRequest } },
  }, async request => {
    const who = actor(request), id = request.params.id;
    const task = await context.delegation.get(who, request.body.runId);
    const current = await requests.get(who, id);
    if (current.state === 'approved' && task.intent.actor.principalId === who.id && task.intent.approval?.id === id &&
      current.results.some(result => result && typeof result === 'object' && !Array.isArray(result) &&
        result.kind === 'connected' && result.id === request.body.resourceId)) return current;
    const plan = await requests.connectionPlan(who, id);
    const content = await context.custody.get(request.body.resourceId);
    if (task.state !== 'succeeded' || task.kind !== 'connect' || task.intent.approval?.id !== id ||
      task.intent.approval.index !== plan.index || task.intent.actor.principalId !== who.id ||
      content.creationRunId !== task.id || content.policy.kind !== 'connection' ||
      content.policy.ownerId !== plan.input.ownerId || content.metadata.methodId !== plan.input.methodId ||
      !content.policy.authorities.some(binding => canonical(binding) === canonical(task.intent.actor)) ||
      (plan.input.connectionId && content.policy.id !== plan.input.connectionId))
      fail(409, 'connection_required', 'Complete the approved connection on its selected executor.');
    await requests.completed({ ...who, approvalId: id, approvalIndex: plan.index },
      { kind: 'connected', id: content.policy.id, metadata: content.metadata });
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
          })
          .strict(),
        response: { 200: C.ApprovalRequest },
      },
    },
    (request) =>
      requests.approve(
        actor(request),
        request.params.id,
        request.browser,
        request.body.values,
        request.body.code,
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
  app.put(
    '/api/principals/:id/settings',
    {
      schema: {
        params: C.IdParams,
        body: C.Settings,
        response: { 200: z.object({ settings: C.Settings, webhookSecret: z.string().optional() }) },
      },
    },
    (request) => integrations.set(actor(request), request.params.id, request.body),
  );
  app.post(
    '/api/principals/:id/settings/rotate',
    {
      schema: {
        params: C.IdParams,
        body: z.object({}).strict(),
        response: { 200: z.object({ webhookSecret: z.string() }) },
      },
    },
    (request) => integrations.rotate(actor(request), request.params.id),
  );
}
