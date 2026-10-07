import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { fail } from './errors.js';
import { iso } from './database.js';
import * as C from '../shared/contracts.js';
import * as P from '../shared/protocol.js';
import { SignedBinding } from '../shared/authority.js';

export async function routesExecution(app: ApiApp, context: Context) {
  const { bindings, custody, delegation, connectionOperations: operations, resources, authorization } = context;
  app.get('/api/identities/:id/binding', {
    schema: { params: C.IdParams, response: { 200: SignedBinding } },
  }, request => { actor(request); return bindings.current(request.params.id); });
  app.put('/api/principals/:id/binding', {
    schema: { params: C.IdParams, body: P.PublishBinding, response: { 200: SignedBinding } },
  }, request => {
    if (request.body.binding.principalId !== request.params.id)
      fail(400, 'wrong_principal', 'Publish keys for the selected identity.');
    const { previousSignature, ...binding } = request.body;
    return bindings.publish(actor(request), binding, previousSignature);
  });
  app.get('/api/principals/:id/bound-recipients', {
    schema: { params: C.IdParams, response: { 200: C.listOf(P.BoundRecipient) } },
  }, async request => {
    await authorization.requirePrincipal(actor(request), request.params.id, 'read');
    return { items: await custody.recipients(request.params.id), next: null };
  });
  app.get('/api/resources/:id/custody', {
    schema: { params: C.IdParams, response: { 200: P.ProtectedRead } },
  }, request => custody.read(actor(request), request.params.id));
  app.put('/api/resources/:id/custody', {
    schema: { params: C.IdParams, body: P.ProtectedWrite, response: { 200: C.Resource } },
  }, async request => {
    if (request.params.id !== request.body.content.policy.id)
      fail(400, 'wrong_resource', 'Save the encrypted content at its approved destination.');
    return resources.view(actor(request), await custody.put(actor(request), request.body));
  });
  app.post('/api/executor/outputs', {
    schema: { body: P.ProtectedWrite.omit({ version: true }), response: { 201: z.object({ id: C.Id }) } },
  }, async (request, reply) => {
    const row = await custody.putProduced(actor(request), request.body);
    return reply.code(201).send({ id: row.id });
  });
  app.put('/api/environments/:id/registration', {
    schema: { params: C.IdParams, body: P.SignedEnvironment, response: { 200: z.object({ id: C.Id }) } },
  }, async request => {
    if (request.params.id !== request.body.manifest.id)
      fail(400, 'wrong_environment', 'Register the selected execution environment.');
    const row = await delegation.register(actor(request), request.body);
    return { id: row.id };
  });
  app.get('/api/environments/:id/registration', {
    schema: { params: C.IdParams, response: { 200: P.Registration } },
  }, async request => {
    await authorization.requireResource(actor(request), await resources.get(request.params.id), 'read');
    const environment = await delegation.environment(request.params.id);
    return { registration: environment.registration, stoppedAt: environment.stopped_at ? iso(environment.stopped_at) : null,
      heartbeatAt: environment.heartbeat_at ? iso(environment.heartbeat_at) : null };
  });
  app.post('/api/environments/:id/heartbeat', {
    schema: { params: C.IdParams, body: z.object({}).strict(), response: { 200: z.object({ registration: P.SignedEnvironment }) } },
  }, request => delegation.heartbeat(actor(request), request.params.id));
  app.post('/api/environments/:id/claim', {
    schema: { params: C.IdParams, body: z.object({}).strict(), response: { 200: P.ClaimedExecution } },
  }, request => delegation.claim(actor(request), request.params.id));
  app.post('/api/executions', {
    schema: { body: P.DelegatedRun, response: { 202: P.Task } },
  }, async (request, reply) => reply.code(202).send(await delegation.submit(actor(request), request.body)));
  app.get('/api/principals/:id/executions', {
    schema: { params: C.IdParams, querystring: C.PageQuery, response: { 200: C.listOf(P.Task) } },
  }, request => delegation.list(actor(request), request.params.id, request.query.limit, request.query.after));
  app.get('/api/executions/:id', {
    schema: { params: C.IdParams, response: { 200: P.Task } },
  }, request => delegation.get(actor(request), request.params.id));
  app.post('/api/executions/:id/cancel', {
    schema: { params: C.IdParams, body: z.object({}).strict(), response: { 200: P.Task } },
  }, request => delegation.cancel(actor(request), request.params.id));
  app.post('/api/executions/:id/renew', {
    schema: { params: C.IdParams, body: P.Lease, response: { 200: z.object({ active: z.boolean() }) } },
  }, request => delegation.renew(actor(request), request.params.id, request.body.lease));
  app.post('/api/executions/:id/dispatch', {
    schema: { params: C.IdParams, body: P.Lease, response: { 200: C.Ok } },
  }, request => delegation.dispatch(actor(request), request.params.id, request.body.lease));
  app.post('/api/executions/:id/finish', {
    schema: { params: C.IdParams, body: P.Completion, response: { 200: P.Task } },
  }, request => {
    if (request.params.id !== request.body.receipt.id) fail(400, 'wrong_execution', 'Complete the selected execution.');
    return delegation.finish(actor(request), request.body.lease, request.body.receipt);
  });
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
    schema: { params: C.IdParams, body: P.RenewalResult, response: { 200: P.ProtectedContent } },
  }, request => operations.commit(actor(request), request.params.id, request.body.fence, request.body.content));
  app.post('/api/connection-operations/:id/uncertain', {
    schema: { params: C.IdParams, body: P.Fence, response: { 200: C.Ok } },
  }, async request => { await operations.uncertain(actor(request), request.params.id, request.body.fence); return { ok: true as const }; });
  app.post('/api/connection-operations/:id/abort', {
    schema: { params: C.IdParams, body: P.Fence, response: { 200: P.RenewalOperation } },
  }, request => operations.abort(actor(request), request.params.id, request.body.fence));
}
