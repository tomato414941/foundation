import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import * as C from '../shared/contracts.js';
import * as P from '../shared/protocol.js';

export async function routesCustody(app: ApiApp, context: Context) {
  const { custody, connectionOperations: operations } = context;
  app.post('/api/oauth/relays', {
    schema: { body: P.RegisterRelay, response: { 201: P.OAuthRelay } },
  }, async (request, reply) => reply.code(201).send(await context.oauthRelays.register(actor(request), request.body)));
  app.get('/api/oauth/relays/:id', {
    schema: { params: C.IdParams, response: { 200: P.OAuthRelay } },
  }, request => context.oauthRelays.get(actor(request), request.params.id));
  app.get('/api/principals/:id/reprotection', {
    schema: { params: C.IdParams, response: { 200: C.listOf(P.Reprotection) } },
  }, async request => ({ items: await custody.pending(actor(request), request.params.id), next: null }));
  app.get('/api/resources/:id/custody', {
    schema: { params: C.IdParams, response: { 200: P.ProtectedRead } },
  }, request => custody.read(actor(request), request.params.id));
  app.post('/api/connection-operations', {
    schema: { body: P.PrepareRenewal, response: { 201: P.RenewalOperation } },
  }, async (request, reply) => reply.code(201).send(await operations.prepare(actor(request), request.body.id,
    request.body.resourceId, request.body.expectedRevision)));
  app.get('/api/connections/:id/operation', {
    schema: { params: C.IdParams, response: { 200: P.RenewalOperation.nullable() } },
  }, request => operations.state(actor(request), request.params.id));
  app.post('/api/connection-operations/:id/dispatch', {
    schema: { params: C.IdParams, body: P.Fence, response: { 200: P.RenewalOperation } },
  }, request => operations.dispatch(actor(request), request.params.id, request.body.fence));
  app.post('/api/connection-operations/:id/commit', {
    schema: { params: C.IdParams, body: P.RenewalResult, response: { 200: P.SealedItem } },
  }, request => operations.commit(actor(request), request.params.id, request.body.fence, request.body.content));
  app.post('/api/connection-operations/:id/uncertain', {
    schema: { params: C.IdParams, body: P.Fence, response: { 200: C.Ok } },
  }, async request => { await operations.uncertain(actor(request), request.params.id, request.body.fence); return { ok: true as const }; });
  app.post('/api/connection-operations/:id/abort', {
    schema: { params: C.IdParams, body: P.Fence, response: { 200: P.RenewalOperation } },
  }, request => operations.abort(actor(request), request.params.id, request.body.fence));
}
