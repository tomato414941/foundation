import { Readable } from 'node:stream';
import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { Accounts } from './accounts.js';
import * as C from '../shared/contracts.js';
import * as P from '../shared/protocol.js';

export async function routesAccounts(app: ApiApp, context: Context) {
  const accounts = new Accounts(context);
  app.get('/api/principals/:id/export', { schema: { params: C.IdParams } }, async (request, reply) => {
    const entries = accounts.export(actor(request), request.params.id),
      first = await entries.next();
    async function* stream() {
      if (!first.done) yield first.value;
      yield* entries;
    }
    return reply
      .type('application/x-ndjson')
      .header('content-disposition', 'attachment; filename="foundation-export.ndjson"')
      .send(Readable.from(stream()));
  });
  app.delete(
    '/api/principals/:id',
    { schema: { params: C.IdParams, response: { 200: C.Ok } } },
    async (request) => {
      await accounts.remove(actor(request), request.params.id);
      return { ok: true as const };
    },
  );
  app.post(
    '/api/account/merge/email',
    {
      config: { rateLimit: { max: 10, timeWindow: '1 hour' } },
      schema: {
        body: z.object({ email: z.email(), locale: C.Locale.default('ja') }).strict(),
        response: { 200: z.object({ email: z.email(), expiresAt: C.Time, resendAt: C.Time }) },
      },
    },
    (request) =>
      context.authentication.beginEmail(
        request.body.email,
        request.browser,
        '/account',
        request.body.locale,
        actor(request),
        undefined,
        actor(request).id,
      ),
  );
  app.post(
    '/api/account/merge/passkey',
    {
      schema: {
        body: z.object({ challengeId: C.Id, credential: C.Json }).strict(),
        response: {
          200: z.object({
            id: C.Id,
            fromId: C.Id,
            wrappedKey: z.string().nullable(),
            publicKey: C.PublicKey.nullable(),
          }),
        },
      },
    },
    (request) => accounts.passkeyProof(actor(request), request.browser, request.body),
  );
  app.get(
    '/api/account/merge/:id',
    {
      schema: {
        params: C.IdParams,
        response: {
          200: z.object({
            id: C.Id,
            from: z.object({ id: C.Id, name: C.Name, publicKey: C.PublicKey.nullable() }),
            resources: z.array(C.Resource),
            protectedItems: z.array(P.ProtectedRead.extend({ id: C.Id })),
            recipients: z.array(P.BoundRecipient),
          }),
        },
      },
    },
    (request) => accounts.plan(actor(request), request.params.id),
  );
  app.post(
    '/api/account/merge/:id',
    {
      schema: {
        params: C.IdParams,
        body: z.object({ contents: P.KeyUpdates.default({}) }).strict(),
        response: { 200: C.Principal },
      },
    },
    (request) => accounts.merge(actor(request), request.params.id, request.body.contents),
  );
}
