import Fastify from 'fastify';
import type { FastifyRequest, FastifyReply } from 'fastify';
import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { validatorCompiler, serializerCompiler, jsonSchemaTransform } from '@fastify/type-provider-zod';
import type { ZodTypeProvider } from '@fastify/type-provider-zod';
import { z } from 'zod';

import type { Context } from './context.js';
import type { Actor } from './authorization.js';
import type { SigninResult } from './authentication.js';
import { fail, failure } from './errors.js';
import { token } from './vault.js';
import * as C from '../shared/contracts.js';
import * as S from '../shared/session.js';
import { routesResources } from './routes-resources.js';
import { routesRequests } from './routes-requests.js';
import { routesAccounts } from './routes-accounts.js';
import { routesMcp } from './mcp.js';
import { web } from './web.js';

declare module 'fastify' {
  interface FastifyRequest {
    actor: Actor | null;
    browser: string;
  }
  interface FastifyContextConfig {
    approval?: boolean;
  }
}
export function actor(request: FastifyRequest): Actor {
  if (!request.actor) fail(401, 'unauthenticated', 'Sign in to continue.');
  return request.actor;
}
export async function buildApp(context: Context) {
  const { config, authentication, principals, authorization, identity } = context;
  const app = Fastify({
    logger: {
      level: config.FOUNDATION_LOG_LEVEL,
      serializers: {
        req: (request) => ({
          method: request.method,
          url: String(request.url).split('?')[0],
          id: request.id,
        }),
      },
      redact: ['req.headers.authorization', 'req.headers.cookie', 'res.headers.set-cookie'],
    },
    bodyLimit: 2_200_000,
    requestTimeout: 90_000,
    trustProxy: config.FOUNDATION_PROXY_ADDRESSES || false,
  }).withTypeProvider<ZodTypeProvider>();
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  await app.register(cookie);
  await app.register(helmet, {
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: 'no-referrer' },
  });
  await app.register(rateLimit, {
    max: 600,
    timeWindow: '1 minute',
    skipOnError: false,
    allowList: (request) => !request.url.startsWith('/api/') || request.url.startsWith('/api/docs/static/'),
  });
  await app.register(swagger, {
    openapi: {
      info: {
        title: 'Foundation API',
        version: '1.0.0',
        description: 'Manage principals, resources, service connections, and runs.',
      },
      servers: [{ url: config.origin }],
      components: { securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } } },
      security: [{ bearer: [] }],
    },
    transform: jsonSchemaTransform,
  });
  await app.register(swaggerUi, {
    routePrefix: '/api/docs',
    uiConfig: { docExpansion: 'list', deepLinking: true },
    staticCSP: true,
  });
  app.decorateRequest('actor', null);
  app.decorateRequest('browser', '');
  const internalActors = new Map<string, Actor>();
  const eligible: Array<{ method: string; pattern: RegExp }> = [];
  app.addHook('onRoute', (route) => {
    if (!route.config?.approval) return;
    const pattern = new RegExp(
      '^' +
        route.url
          .split('/')
          .map((part) => (part.startsWith(':') ? '[^/]+' : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
          .join('/') +
        '$',
    );
    for (const method of Array.isArray(route.method) ? route.method : [route.method])
      eligible.push({ method, pattern });
  });
  context.requests.dispatcher = {
    allows: (operation) => {
      if (!operation.path.startsWith('/api/') || /[\\\u0000-\u001f]/.test(operation.path)) return false;
      const path = operation.path.split('?')[0]!;
      return eligible.some((route) => route.method === operation.method && route.pattern.test(path));
    },
    execute: async (who, operation, browser) => {
      const secret = 'internal_' + token();
      internalActors.set(secret, who);
      try {
        const result = await app.inject({
          method: operation.method,
          url: operation.path,
          headers: {
            authorization: 'Bearer ' + secret,
            cookie: 'foundation_browser=' + encodeURIComponent(browser),
          },
          ...(operation.body !== undefined
            ? {
                payload: JSON.stringify(operation.body),
                headers: {
                  authorization: 'Bearer ' + secret,
                  cookie: 'foundation_browser=' + encodeURIComponent(browser),
                  'content-type': 'application/json',
                },
              }
            : {}),
        });
        const value = result.json() as C.JsonValue;
        if (result.statusCode >= 400) {
          const error = value && typeof value === 'object' && !Array.isArray(value) ? value.error : null;
          const detail = error && typeof error === 'object' && !Array.isArray(error) ? error : {};
          fail(
            result.statusCode,
            String(detail.code ?? 'operation_failed'),
            String(detail.message ?? 'The operation could not be completed.'),
          );
        }
        return value;
      } finally {
        internalActors.delete(secret);
      }
    },
  };
  const secure = new URL(config.origin).protocol === 'https:',
    cookieOptions = { httpOnly: true, secure, sameSite: 'lax' as const, path: '/' };
  const signIn = (reply: FastifyReply, result: SigninResult) => {
    reply.clearCookie('foundation_request', cookieOptions);
    reply.setCookie('foundation_session', result.token, {
      ...cookieOptions,
      expires: new Date(result.expiresAt),
    });
  };
  app.addHook('onRequest', async (request, reply) => {
    if (!request.url.startsWith('/api/') && request.url.split('?')[0] !== '/oauth/callback') return;
    reply.header('cache-control', 'no-store');
    const bearer = request.headers.authorization;
    if (bearer && !/^Bearer [A-Za-z0-9_-]+$/.test(bearer))
      fail(401, 'unauthenticated', 'Use a valid bearer token.');
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
      const origin = request.headers.origin;
      if (
        (origin && origin !== config.origin) ||
        (!bearer &&
          (request.cookies.foundation_session || request.cookies.foundation_request) &&
          origin !== config.origin) ||
        (request.headers['sec-fetch-site'] === 'cross-site' && !bearer)
      )
        fail(403, 'cross_origin', 'Send this request from Foundation.');
    }
    const internal = bearer ? internalActors.get(bearer.slice(7)) : undefined;
    if (internal && !request.routeOptions.config.approval)
      fail(403, 'operation_unavailable', 'This operation cannot be requested for approval.');
    request.actor =
      internal ??
      (!bearer ? await authentication.authenticate(request.cookies.foundation_request) : null) ??
      (await authentication.authenticate(bearer?.slice(7) ?? request.cookies.foundation_session));
    if (bearer && !request.actor) fail(401, 'unauthenticated', 'The API key has expired or was revoked.');
    if (request.actor?.requestId) {
      const path = request.url.split('?')[0]!;
      const ownRequest = '/api/requests/' + request.actor.requestId;
      if (
        path !== '/api/session' &&
        !path.startsWith('/api/auth/') &&
        path !== ownRequest &&
        !path.startsWith(ownRequest + '/') &&
        !/^\/api\/requests\/[^/]+\/redeem$/.test(path) &&
        !/^\/api\/connections\/[^/]+\/(review|role)$/.test(path) &&
        path !== '/oauth/callback'
      )
        fail(403, 'forbidden', 'This link can open only its own request.');
    }
    request.browser = request.cookies.foundation_browser ?? token();
    if (!request.cookies.foundation_browser)
      reply.setCookie('foundation_browser', request.browser, { ...cookieOptions, maxAge: 365 * 86400 });
  });
  app.setErrorHandler((error, request, reply) => {
    const isValidation = typeof error === 'object' && error !== null && 'validation' in error;
    const code = typeof error === 'object' && error !== null && 'code' in error ? error.code : undefined;
    if (isValidation || code === 'FST_ERR_CTP_INVALID_JSON_BODY' || code === 'FST_ERR_CTP_EMPTY_JSON_BODY')
      return reply
        .code(400)
        .send({ error: { code: 'invalid_input', message: 'Check the supplied values.' } });
    const result = failure(error);
    if (result.status >= 500)
      request.log.error({ code: result.code, requestId: request.id }, 'Request failed');
    return reply.code(result.status).send({
      error: {
        code: result.code,
        message: result.message,
        ...(result.details === undefined ? {} : { details: result.details }),
      },
    });
  });
  app.get('/health', { schema: { hide: true } }, async () => {
    await context.db.pool.query('SELECT 1');
    return { ok: true };
  });
  app.get('/api/openapi.json', { schema: { hide: true } }, () => app.swagger());
  app.get('/api/session', { schema: { response: { 200: S.Session } } }, async (request) => ({
    principal: request.actor
      ? await principals.view(request.actor, await principals.get(request.actor.id))
      : null,
    credentialId: request.actor?.credentialId ?? null,
    requestId: request.actor?.requestId ?? null,
    principals: request.actor && !request.actor.requestId ? await principals.accessible(request.actor) : [],
    server: { id: identity.id, name: 'Foundation', publicKey: identity.publicKey },
    features: {
      email: context.mailer.enabled,
      environments: context.environments.runner.enabled,
      objects: context.objects.store.enabled,
      payments: context.billing.provider.enabled,
    },
  }));
  app.post(
    '/api/auth/enroll',
    {
      config: { rateLimit: { max: 20, timeWindow: '1 hour' } },
      schema: {
        body: z.object({ name: C.Name, publicKey: C.P256Key }).strict(),
        response: {
          201: z.object({
            principal: z.object({ id: C.Id, name: C.Name }),
            credential: C.Credential,
            token: z.string(),
          }),
        },
        security: [],
      },
    },
    async (request, reply) =>
      reply.code(201).send(await authentication.enroll(request.body.name, request.body.publicKey)),
  );
  app.post(
    '/api/auth/signout',
    { schema: { body: z.object({}).strict(), response: { 200: C.Ok } } },
    async (request, reply) => {
      await authentication.signout(request.actor);
      await authentication.signout(await authentication.authenticate(request.cookies.foundation_session));
      reply.clearCookie('foundation_session', cookieOptions);
      reply.clearCookie('foundation_request', cookieOptions);
      return { ok: true as const };
    },
  );
  app.post(
    '/api/auth/email',
    {
      config: { rateLimit: { max: 10, timeWindow: '1 hour' } },
      schema: {
        body: S.EmailStart,
        response: { 200: z.object({ email: z.email(), expiresAt: C.Time, resendAt: C.Time }) },
        security: [],
      },
    },
    (request) =>
      authentication.beginEmail(
        request.body.email,
        request.browser,
        request.body.returnTo,
        request.body.locale,
        request.actor ?? undefined,
        request.body.principalId,
      ),
  );
  app.get(
    '/api/auth/email',
    {
      schema: {
        response: { 200: z.object({ email: z.email(), expiresAt: C.Time }).nullable() },
        security: [],
      },
    },
    (request) => authentication.pendingEmail(request.browser),
  );
  app.post(
    '/api/auth/email/verify',
    {
      config: { rateLimit: { max: 30, timeWindow: '1 hour' } },
      schema: {
        body: z.object({ challengeId: C.Id, token: z.string().max(200) }).strict(),
        response: {
          200: z.object({ returnTo: z.string(), attached: z.boolean(), mergeProof: C.Id.optional() }),
        },
        security: [],
      },
    },
    async (request, reply) => {
      const result = await authentication.verifyEmail(request.body.challengeId, request.body.token);
      if ('actor' in result) signIn(reply, result);
      return {
        returnTo: result.returnTo,
        attached: 'attached' in result,
        ...('mergeProof' in result ? { mergeProof: result.mergeProof } : {}),
      };
    },
  );
  app.post(
    '/api/auth/passkeys/options',
    {
      config: { rateLimit: { max: 40, timeWindow: '1 hour' } },
      schema: {
        body: S.PasskeyStart,
        response: { 200: z.object({ challengeId: C.Id, principalId: C.Id.nullable(), options: z.json() }) },
        security: [],
      },
    },
    async (request) => {
      const result = await authentication.passkeyOptions(
        request.browser,
        request.body,
        request.actor ?? undefined,
      );
      return { ...result, options: JSON.parse(JSON.stringify(result.options)) as C.JsonValue };
    },
  );
  app.post(
    '/api/auth/passkeys/verify',
    {
      config: { rateLimit: { max: 40, timeWindow: '1 hour' } },
      schema: {
        body: S.PasskeyVerify,
        response: {
          200: z.object({
            principalId: C.Id,
            credentialId: C.Id,
            wrappedKey: z.string().nullable(),
            publicKey: C.PublicKey.nullable(),
            returnTo: z.string(),
          }),
        },
        security: [],
      },
    },
    async (request, reply) => {
      const result = await authentication.verifyPasskey(
        request.browser,
        request.body,
        request.actor ?? undefined,
      );
      signIn(reply, result);
      return {
        principalId: result.principalId,
        credentialId: result.credentialId,
        wrappedKey: result.wrappedKey,
        publicKey: result.publicKey,
        returnTo: result.returnTo,
      };
    },
  );
  app.get('/api/principals', { schema: { response: { 200: C.listOf(C.Principal) } } }, async (request) => ({
    items: await principals.accessible(actor(request)),
    next: null,
  }));
  app.post(
    '/api/principals',
    {
      config: { approval: true },
      schema: { body: z.object({ name: C.Name, ownerId: C.Id }).strict(), response: { 201: C.Principal } },
    },
    async (request, reply) => {
      const who = actor(request);
      await authorization.requirePrincipal(who, request.body.ownerId, 'create');
      return reply
        .code(201)
        .send(
          await principals.view(who, await principals.create(request.body.name, null, request.body.ownerId)),
        );
    },
  );
  app.get(
    '/api/principals/:id',
    { schema: { params: C.IdParams, response: { 200: C.Principal } } },
    async (request) => {
      const who = actor(request);
      await authorization.requirePrincipal(who, request.params.id, 'read');
      return principals.view(who, await principals.get(request.params.id));
    },
  );
  app.patch(
    '/api/principals/:id',
    {
      config: { approval: true },
      schema: {
        params: C.IdParams,
        body: z.object({ name: C.Name }).strict(),
        response: { 200: C.Principal },
      },
    },
    (request) => principals.rename(actor(request), request.params.id, request.body.name),
  );
  app.put(
    '/api/principals/:id/encryption-key',
    {
      schema: {
        params: C.IdParams,
        body: z
          .object({ publicKey: C.P256Key, wraps: z.record(C.Id, C.WrappedKey).default({}) })
          .strict(),
        response: { 200: C.Ok },
      },
    },
    async (request) => {
      await principals.publishKey(
        actor(request),
        request.params.id,
        request.body.publicKey,
        request.body.wraps,
      );
      return { ok: true as const };
    },
  );
  app.get(
    '/api/principals/:id/credentials',
    { schema: { params: C.IdParams, response: { 200: C.listOf(C.Credential) } } },
    async (request) => ({
      items: await authentication.credentials(actor(request), request.params.id),
      next: null,
    }),
  );
  app.post(
    '/api/principals/:id/credentials',
    {
      schema: {
        params: C.IdParams,
        body: z.object({ name: C.Name, expiresAt: C.Time.nullable().default(null) }).strict(),
        response: { 201: z.object({ credential: C.Credential, token: z.string() }) },
      },
    },
    async (request, reply) => {
      const who = actor(request);
      await authorization.requirePrincipal(who, request.params.id, 'credentials');
      if (request.body.expiresAt && new Date(request.body.expiresAt).getTime() <= Date.now())
        fail(400, 'invalid_expiry', 'Choose a future expiry.');
      return reply
        .code(201)
        .send(await authentication.issueKey(request.params.id, request.body.name, request.body.expiresAt));
    },
  );
  app.delete(
    '/api/principals/:id/credentials/:credentialId',
    { schema: { params: z.object({ id: C.Id, credentialId: C.Id }), response: { 200: C.Ok } } },
    async (request) => {
      await authentication.removeCredential(actor(request), request.params.id, request.params.credentialId);
      return { ok: true as const };
    },
  );
  app.put(
    '/api/principals/:id/credentials/:credentialId/wrap',
    {
      schema: {
        params: z.object({ id: C.Id, credentialId: C.Id }),
        body: z.object({ wrappedKey: C.WrappedKey }).strict(),
        response: { 200: C.Ok },
      },
    },
    async (request) => {
      await authentication.setWrap(
        actor(request),
        request.params.id,
        request.params.credentialId,
        request.body.wrappedKey,
      );
      return { ok: true as const };
    },
  );
  app.get(
    '/api/principals/:id/relations',
    { schema: { params: C.IdParams, querystring: C.PageQuery, response: { 200: C.listOf(C.Relation) } } },
    (request) =>
      principals.relations(actor(request), request.params.id, request.query.limit, request.query.after),
  );
  app.post(
    '/api/relations',
    {
      bodyLimit: 32 * 1024 * 1024,
      config: { approval: true },
      schema: { body: C.RelationInput.extend({ secrets: C.KeyUpdates.optional() }), response: { 200: C.Ok } },
    },
    async (request) => {
      await principals.relate(
        actor(request),
        request.body.subjectId,
        request.body.relation,
        request.body.principalId,
        request.body.secrets,
      );
      return { ok: true as const };
    },
  );
  app.get(
    '/api/relations/recipients',
    {
      schema: {
        querystring: z.object({ subjectId: C.Id, principalId: C.Id }),
        response: { 200: C.listOf(C.KeySharingItem) },
      },
    },
    async (request) => {
      await authorization.requirePrincipal(actor(request), request.query.principalId, 'share');
      await principals.get(request.query.subjectId);
      return principals.keySharing.plan(
        actor(request),
        request.query.principalId,
        request.query.subjectId,
        'member',
      );
    },
  );
  app.delete(
    '/api/relations',
    { config: { approval: true }, schema: { body: C.RelationInput, response: { 200: C.Ok } } },
    async (request) => {
      await principals.unrelate(
        actor(request),
        request.body.subjectId,
        request.body.relation,
        request.body.principalId,
      );
      return { ok: true as const };
    },
  );
  app.get(
    '/api/principals/:id/grants',
    { schema: { params: C.IdParams, response: { 200: C.listOf(C.Grant) } } },
    async (request) => ({ items: await principals.grants(actor(request), request.params.id), next: null }),
  );
  app.put(
    '/api/principals/:id/grants/:principalId',
    {
      config: { approval: true },
      schema: {
        params: z.object({ id: C.Id, principalId: C.Id }),
        body: z.object({ actions: z.array(C.Action).min(1) }).strict(),
        response: { 200: C.Ok },
      },
    },
    async (request) => {
      await principals.grant(
        actor(request),
        request.params.id,
        request.params.principalId,
        request.body.actions,
      );
      return { ok: true as const };
    },
  );
  app.delete(
    '/api/principals/:id/grants/:principalId',
    {
      config: { approval: true },
      schema: { params: z.object({ id: C.Id, principalId: C.Id }), response: { 200: C.Ok } },
    },
    async (request) => {
      await authorization.requirePrincipal(actor(request), request.params.id, 'share');
      await context.db.pool.query('DELETE FROM principal_grants WHERE target_id=$1 AND principal_id=$2', [
        request.params.id,
        request.params.principalId,
      ]);
      return { ok: true as const };
    },
  );
  app.post(
    '/api/principals/:id/revoke',
    {
      config: { approval: true },
      schema: { params: C.IdParams, body: z.object({ principalId: C.Id }).strict(), response: { 200: C.Ok } },
    },
    async (request) => {
      await principals.revoke(actor(request), request.params.id, request.body.principalId);
      return { ok: true as const };
    },
  );
  app.post(
    '/api/principals/:id/transfer',
    {
      bodyLimit: 32 * 1024 * 1024,
      config: { approval: true },
      schema: {
        params: C.IdParams,
        body: z.object({ to: C.Id, secrets: C.KeyUpdates.optional() }).strict(),
        response: { 200: C.Ok },
      },
    },
    async (request) => {
      await principals.transfer(actor(request), request.params.id, request.body.to, request.body.secrets);
      return { ok: true as const };
    },
  );
  app.get(
    '/api/principals/:id/transfer-recipients',
    {
      schema: {
        params: C.IdParams,
        querystring: z.object({ to: C.Id }),
        response: { 200: C.listOf(C.KeySharingItem) },
      },
    },
    async (request) => {
      await authorization.requirePrincipal(actor(request), request.params.id, 'transfer');
      await principals.get(request.query.to);
      return principals.keySharing.plan(actor(request), request.params.id, request.query.to, 'owner');
    },
  );
  app.get(
    '/api/principals/:id/audit',
    { schema: { params: C.IdParams, querystring: C.PageQuery, response: { 200: C.listOf(C.AuditEntry) } } },
    async (request) => {
      await authorization.requirePrincipal(actor(request), request.params.id, 'read');
      return context.audit.list(request.params.id, request.query.limit, request.query.after);
    },
  );
  await routesResources(app, context);
  await routesRequests(app, context, cookieOptions);
  await routesAccounts(app, context);
  await routesMcp(app);
  await web(app);
  return app;
}
export type ApiApp = Awaited<ReturnType<typeof buildApp>>;
