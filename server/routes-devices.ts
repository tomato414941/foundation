import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import * as C from '../shared/contracts.js';

export async function routesDevices(app: ApiApp, context: Context) {
  const { devices } = context;
  app.post(
    '/api/auth/devices',
    {
      config: { rateLimit: { max: 20, timeWindow: '1 hour' } },
      schema: {
        body: z.object({ name: C.Name, publicKey: C.PublicKey }).strict(),
        response: { 201: z.object({ id: C.Id, code: z.string(), poll: z.string(), url: z.url(), expiresAt: C.Time }) },
        security: [],
      },
    },
    async (request, reply) => reply.code(201).send(await devices.begin(request.body.name, request.body.publicKey)),
  );
  app.get(
    '/api/auth/devices/:id',
    {
      config: { rateLimit: { max: 120, timeWindow: '10 minutes' } },
      schema: {
        params: C.IdParams,
        querystring: z.object({ poll: z.string().optional() }),
        response: {
          200: z.union([
            C.DeviceRequest,
            z.object({ state: z.enum(['pending', 'approving', 'approved']), principalId: C.Id.nullable(), sealed: C.Sealed.nullable() }),
          ]),
        },
        security: [],
      },
    },
    (request) => (request.query.poll ? devices.poll(request.params.id, request.query.poll) : devices.view(request.params.id)),
  );
  app.post(
    '/api/auth/devices/:id/approve',
    {
      schema: {
        params: C.IdParams,
        body: z.object({ code: z.string().min(1).max(16), principalId: C.Id }).strict(),
        response: { 200: C.DeviceRequest },
      },
    },
    (request) => devices.approve(actor(request), request.params.id, request.body.code, request.body.principalId),
  );
  app.post(
    '/api/auth/devices/:id/complete',
    {
      schema: { params: C.IdParams, body: z.object({ sealed: C.Sealed }).strict(), response: { 200: C.DeviceRequest } },
    },
    (request) => devices.complete(actor(request), request.params.id, request.body.sealed),
  );
}
