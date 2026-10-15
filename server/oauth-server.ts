import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { fail } from './errors.js';
import { digest, token } from './vault.js';

// Foundation as an OAuth 2.1 authorization server for MCP clients such as Claude.ai and ChatGPT.
// Clients register dynamically, the owner approves in the browser, and the issued access token
// is an ordinary API key of the approving principal, listed and revocable with the other keys.
const CODE_SECONDS = 600;
const TOKEN_DAYS = 90;
const Registration = z.object({
  redirect_uris: z.array(z.url()).min(1).max(10),
  client_name: z.string().min(1).max(100).optional(),
}).loose();
const Client = z.object({ name: z.string(), redirectUris: z.array(z.string()) });
const Authorize = z.object({
  clientId: z.string().min(1).max(4096),
  redirectUri: z.url(),
  codeChallenge: z.string().regex(/^[A-Za-z0-9_-]{43,128}$/),
  codeChallengeMethod: z.literal('S256'),
  state: z.string().max(1000).optional(),
  resource: z.url().optional(),
  principalId: z.uuid(),
}).strict();
const CodeData = z.object({
  codeHash: z.string(), clientId: z.string(), redirectUri: z.string(), codeChallenge: z.string(),
  name: z.string(), resource: z.string().nullable(),
});

function allowedRedirect(value: string) {
  const url = new URL(value);
  return url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname));
}
function oauthError(code: string, description: string) {
  return { error: code, error_description: description };
}

export async function routesOAuthServer(app: ApiApp, context: Context) {
  const { config, vault, authentication, authorization, db } = context;
  const origin = config.origin, resource = origin + '/api/mcp';
  const client = async (clientId: string) => {
    try {
      return Client.parse(await vault.decrypt(clientId, 'oauth-client'));
    } catch {
      return null;
    }
  };
  const resourceMetadata = () => ({
    resource, authorization_servers: [origin], bearer_methods_supported: ['header'], resource_name: 'Foundation',
  });
  app.get('/.well-known/oauth-protected-resource', { schema: { hide: true } }, resourceMetadata);
  app.get('/.well-known/oauth-protected-resource/api/mcp', { schema: { hide: true } }, resourceMetadata);
  app.get('/.well-known/oauth-authorization-server', { schema: { hide: true } }, () => ({
    issuer: origin,
    authorization_endpoint: origin + '/oauth/authorize',
    token_endpoint: origin + '/api/oauth/token',
    registration_endpoint: origin + '/api/oauth/register',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
  }));
  await app.register(async (scope) => {
    scope.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_request, body, done) =>
      done(null, Object.fromEntries(new URLSearchParams(String(body)))));
    scope.post('/api/oauth/register', {
      config: { rateLimit: { max: 30, timeWindow: '1 hour' } }, schema: { hide: true },
    }, async (request, reply) => {
      const parsed = Registration.safeParse(request.body);
      if (!parsed.success || !parsed.data.redirect_uris.every(allowedRedirect))
        return reply.code(400).send(oauthError('invalid_redirect_uri', 'Use https redirect URIs, or http on localhost.'));
      const name = parsed.data.client_name ?? new URL(parsed.data.redirect_uris[0]!).hostname;
      const clientId = await vault.encrypt({ name, redirectUris: parsed.data.redirect_uris }, 'oauth-client');
      return reply.code(201).send({
        client_id: clientId, client_id_issued_at: Math.floor(Date.now() / 1000), client_name: name,
        redirect_uris: parsed.data.redirect_uris, grant_types: ['authorization_code'], response_types: ['code'],
        token_endpoint_auth_method: 'none',
      });
    });
    scope.post('/api/oauth/token', {
      config: { rateLimit: { max: 60, timeWindow: '1 minute' } }, schema: { hide: true },
    }, async (request, reply) => {
      const body = (request.body ?? {}) as Record<string, string | undefined>;
      if (body.grant_type !== 'authorization_code')
        return reply.code(400).send(oauthError('unsupported_grant_type', 'Use the authorization_code grant.'));
      if (!body.code || !body.code_verifier || !body.redirect_uri || !body.client_id)
        return reply.code(400).send(oauthError('invalid_request', 'Send code, code_verifier, redirect_uri, and client_id.'));
      const row = await db.one<{ principal_id: string; data: unknown }>(
        "DELETE FROM challenges WHERE kind='oauth-code' AND data->>'codeHash'=$1 AND expires_at>now() RETURNING principal_id,data",
        [digest(body.code)]);
      const code = row ? CodeData.safeParse(row.data) : null;
      const challenge = createHash('sha256').update(body.code_verifier).digest('base64url');
      if (!row || !code?.success || code.data.clientId !== body.client_id || code.data.redirectUri !== body.redirect_uri ||
        code.data.codeChallenge !== challenge || (body.resource && code.data.resource && body.resource !== code.data.resource))
        return reply.code(400).send(oauthError('invalid_grant', 'The authorization code is invalid or expired.'));
      const expiresAt = new Date(Date.now() + TOKEN_DAYS * 86400_000).toISOString();
      const issued = await authentication.issueKey(row.principal_id, code.data.name, expiresAt);
      return reply.header('pragma', 'no-cache').send({
        access_token: issued.token, token_type: 'Bearer', expires_in: TOKEN_DAYS * 86400,
      });
    });
  });
  app.get('/api/oauth/client', {
    schema: { hide: true, querystring: z.object({ client_id: z.string().min(1).max(4096), redirect_uri: z.url() }) },
  }, async (request) => {
    actor(request);
    const registered = await client(request.query.client_id);
    if (!registered || !registered.redirectUris.includes(request.query.redirect_uri))
      fail(400, 'invalid_client', 'This application or its return address is not registered.');
    return { name: registered.name, host: new URL(request.query.redirect_uri).host };
  });
  app.post('/api/oauth/authorizations', { schema: { hide: true, body: Authorize } }, async (request) => {
    const who = actor(request), input = request.body;
    await authorization.requirePrincipal(who, input.principalId, 'manage_credentials');
    const registered = await client(input.clientId);
    if (!registered || !registered.redirectUris.includes(input.redirectUri))
      fail(400, 'invalid_client', 'This application or its return address is not registered.');
    if (input.resource && input.resource !== resource && input.resource !== origin)
      fail(400, 'invalid_target', 'Request access to Foundation.');
    const code = token();
    await db.pool.query(
      "INSERT INTO challenges(id,kind,principal_id,data,expires_at) VALUES($1,'oauth-code',$2,$3,now()+make_interval(secs => $4))",
      [randomUUID(), input.principalId, JSON.stringify(CodeData.parse({
        codeHash: digest(code), clientId: input.clientId, redirectUri: input.redirectUri,
        codeChallenge: input.codeChallenge, name: registered.name, resource: input.resource ?? null,
      })), CODE_SECONDS]);
    const target = new URL(input.redirectUri);
    target.searchParams.set('code', code);
    if (input.state !== undefined) target.searchParams.set('state', input.state);
    target.searchParams.set('iss', origin);
    return { redirectTo: target.href };
  });
}
