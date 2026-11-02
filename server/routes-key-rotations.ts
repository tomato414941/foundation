import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { Id, Ok } from '../shared/contracts.js';
import { RotationHandoff, RotationKind, RotationPreparation, RotationStart, RotationView } from '../shared/key-rotations.js';

const RotationParams = z.object({ id: Id, rotationId: Id });
const ItemParams = RotationParams.extend({ kind: RotationKind, itemId: Id });

export async function routesKeyRotations(app: ApiApp, context: Context) {
  const rotations = context.keyRotations;
  app.post('/api/principals/:id/key-rotations', {
    schema: { params: z.object({ id: Id }), body: RotationStart, response: { 201: RotationView } },
  }, async (request, reply) => reply.code(201).send(
    await rotations.start(actor(request), request.params.id, request.body)));
  app.get('/api/principals/:id/key-handoffs/:bindingId', {
    schema: { params: z.object({ id: Id, bindingId: Id }), response: { 200: RotationHandoff } },
  }, request => rotations.handoff(actor(request), request.params.id, request.params.bindingId));
  app.get('/api/principals/:id/key-rotations/:rotationId', {
    schema: { params: RotationParams, querystring: z.object({
      limit: z.coerce.number().int().min(1).max(100).default(20),
      after: z.string().max(100).optional(),
    }).strict(), response: { 200: RotationView } },
  }, request => rotations.get(actor(request), request.params.id, request.params.rotationId,
    request.query.limit, request.query.after));
  app.put('/api/principals/:id/key-rotations/:rotationId/items/:kind/:itemId', {
    schema: { params: ItemParams, body: RotationPreparation, response: { 200: Ok } },
  }, request => rotations.prepare(actor(request), request.params.id, request.params.rotationId,
    request.params.kind, request.params.itemId, request.body));
  app.post('/api/principals/:id/key-rotations/:rotationId/commit', {
    schema: { params: RotationParams, response: { 200: RotationView } },
  }, request => rotations.commit(actor(request), request.params.id, request.params.rotationId));
  app.delete('/api/principals/:id/key-rotations/:rotationId', {
    schema: { params: RotationParams, response: { 200: Ok } },
  }, request => rotations.cancel(actor(request), request.params.id, request.params.rotationId));
}
