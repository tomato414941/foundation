import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { IdParams, Locale, Id, Time } from '../shared/contracts.js';
import { ConfirmationOperation, ConfirmationProof, ConfirmationView } from '../shared/confirmations.js';

// Confirming a change that takes more than a token: start one for the change named by a confirmation_required error,
// prove it by signing its challenge, with a code sent by email, or with a passkey, then send the change again with
// the confirmation's ID in the Foundation-Confirmation header.
export async function routesConfirmations(app: ApiApp, context: Context) {
  const { confirmations } = context;
  app.post('/api/confirmations', {
    config: { rateLimit: { max: 60, timeWindow: '1 hour' } },
    schema: { body: z.object({ operation: ConfirmationOperation }).strict(), response: { 201: ConfirmationView } },
  }, async (request, reply) => reply.code(201).send(await confirmations.start(actor(request), request.body.operation)));
  app.get('/api/confirmations/:id', { schema: { params: IdParams, response: { 200: ConfirmationView } } },
    request => confirmations.get(actor(request), request.params.id));
  app.post('/api/confirmations/:id/email', {
    config: { rateLimit: { max: 10, timeWindow: '1 hour' } },
    schema: { params: IdParams, body: z.object({ credentialId: Id.optional(), locale: Locale.default('ja') }).strict(),
      response: { 200: z.object({ email: z.email(), resendAt: Time }) } },
  }, request => confirmations.sendEmail(actor(request), request.params.id, request.body));
  app.post('/api/confirmations/:id/passkey', {
    schema: { params: IdParams, body: z.object({}).strict(), response: { 200: z.object({ options: z.json() }) } },
  }, async request => {
    const { options } = await confirmations.passkeyOptions(actor(request), request.params.id);
    return { options: JSON.parse(JSON.stringify(options)) as z.infer<ReturnType<typeof z.json>> };
  });
  app.post('/api/confirmations/:id/proof', {
    config: { rateLimit: { max: 60, timeWindow: '1 hour' } },
    schema: { params: IdParams, body: ConfirmationProof, response: { 200: ConfirmationView } },
  }, request => confirmations.prove(actor(request), request.params.id, request.body));
}
