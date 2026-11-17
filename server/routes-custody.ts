import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { fail } from './errors.js';
import * as C from '../shared/contracts.js';
import * as P from '../shared/protocol.js';
import { KeyReplacement, SignedBinding } from '../shared/authority.js';
import { KeyringState, KeyringWrite } from '../shared/keyring.js';

export async function routesCustody(app: ApiApp, context: Context) {
  const { bindings, keyrings, custody, connectionOperations: operations, authorization } = context;
  app.post('/api/oauth/relays', {
    schema: { body: P.RegisterRelay, response: { 201: P.OAuthRelay } },
  }, async (request, reply) => reply.code(201).send(await context.oauthRelays.register(actor(request), request.body)));
  app.get('/api/oauth/relays/:id', {
    schema: { params: C.IdParams, response: { 200: P.OAuthRelay } },
  }, request => context.oauthRelays.get(actor(request), request.params.id));
  app.get('/api/identities/:id/binding', {
    schema: { params: C.IdParams, response: { 200: SignedBinding } },
  }, request => { actor(request); return bindings.current(request.params.id); });
  app.get('/api/identities/:id/key-replacements/:bindingId', {
    schema: { params: z.object({ id: C.Id, bindingId: C.Id }),
      response: { 200: z.object({ replacement: KeyReplacement.nullable() }) } },
  }, request => {
    actor(request);
    return bindings.replacement(request.params.id, request.params.bindingId);
  });
  app.put('/api/principals/:id/binding', {
    schema: { params: C.IdParams, body: SignedBinding, response: { 200: SignedBinding } },
  }, request => {
    if (request.body.binding.principalId !== request.params.id)
      fail(400, 'wrong_principal', 'Publish keys for the selected identity.');
    return bindings.publish(actor(request), request.body);
  });
  app.get('/api/principals/:id/keyring', {
    schema: { params: C.IdParams, response: { 200: KeyringState } },
  }, request => keyrings.get(actor(request), request.params.id));
  app.put('/api/principals/:id/keyring', {
    schema: { params: C.IdParams, body: KeyringWrite, response: { 200: KeyringState } },
  }, request => keyrings.put(actor(request), request.params.id, request.body));
  app.get('/api/principals/:id/bound-recipients', {
    schema: { params: C.IdParams, response: { 200: C.listOf(P.BoundRecipient) } },
  }, async request => {
    await authorization.requirePrincipal(actor(request), request.params.id, 'read');
    return { items: await custody.required(request.params.id), next: null };
  });
  app.get('/api/principals/:id/bound-delegates', {
    schema: { params: C.IdParams, response: { 200: C.listOf(P.BoundRecipient) } },
  }, async request => {
    await authorization.requirePrincipal(actor(request), request.params.id, 'read');
    return { items: await custody.delegates(request.params.id), next: null };
  });
  app.get('/api/principals/:id/reprotection', {
    schema: { params: C.IdParams, response: { 200: C.listOf(P.Reprotection) } },
  }, async request => ({ items: await custody.pending(actor(request), request.params.id), next: null }));
  app.get('/api/resources/:id/custody', {
    schema: { params: C.IdParams, response: { 200: P.ProtectedRead } },
  }, request => custody.read(actor(request), request.params.id));
  app.get('/api/custody/:id', {
    schema: { params: C.IdParams, response: { 200: P.ProtectedRead } },
  }, request => custody.read(actor(request), request.params.id));
  app.put('/api/custody/:id', {
    schema: { params: C.IdParams, body: P.ProtectedWrite, response: { 200: P.ProtectedRead } },
  }, async request => {
    if (request.body.content.policy.id !== request.params.id)
      fail(400, 'wrong_content', 'Update the selected protected content.');
    await custody.put(actor(request), request.body);
    return custody.read(actor(request), request.params.id);
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
