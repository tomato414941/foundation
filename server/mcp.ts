import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { DEFAULT_NEGOTIATED_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS } from '@modelcontextprotocol/sdk/types.js';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import { Json } from '../shared/contracts.js';
import { fail } from './errors.js';
import { registerMetadataTools } from '../runtime/mcp-metadata.js';

export async function routesMcp(app: ApiApp, origin: string) {
  // Without a token, point the client to the OAuth metadata so it can ask the owner to sign in.
  const challenge = 'Bearer resource_metadata="' + origin + '/.well-known/oauth-protected-resource/api/mcp"';
  for (const method of ['GET', 'DELETE'] as const)
    app.route({ method, url: '/api/mcp', schema: { hide: true }, handler: (_request, reply) =>
      reply.code(405).header('allow', 'POST').send({ error: { code: 'method_not_allowed', message: 'Send MCP requests with POST.' } }) });
  app.post('/api/mcp', { schema: { body: Json, hide: true } }, async (request, reply) => {
    if (!request.actor)
      return reply.code(401).header('www-authenticate', challenge)
        .send({ error: { code: 'unauthenticated', message: 'Sign in to continue.' } });
    actor(request);
    const body = request.body;
    if (!body || typeof body !== 'object' || Array.isArray(body))
      fail(400, 'invalid_rpc', 'Send one MCP JSON-RPC request.');
    const params =
      body.params && typeof body.params === 'object' && !Array.isArray(body.params) ? body.params : {};
    const version = body.method === 'initialize' ? params.protocolVersion
      : request.headers['mcp-protocol-version'] ?? DEFAULT_NEGOTIATED_PROTOCOL_VERSION;
    if (typeof version !== 'string' || !SUPPORTED_PROTOCOL_VERSIONS.includes(version))
      fail(400, 'unsupported_protocol', 'Use MCP ' + SUPPORTED_PROTOCOL_VERSIONS.join(', ') + '.');
    const server = new McpServer(
      { name: 'Foundation', version: '1.0.0' },
      {
        instructions: 'Foundation holds what this principal owns and may use. To act on a request, search for the matching API with foundation_schema, read with foundation_read, and make changes with foundation_api. Run saved functions with foundation_invoke_function after finding them with foundation_functions. When Foundation returns a URL for consent or secret input, give it to the user. Never put secret values in requests.',
      },
    );
    registerMetadataTools(server, {
      async schema() { return app.swagger(); },
      async request(method, path, body) {
        const headers: Record<string, string> = {};
        if (request.headers.authorization) headers.authorization = request.headers.authorization;
        if (request.headers.cookie) headers.cookie = request.headers.cookie;
        if (request.headers.origin) headers.origin = request.headers.origin;
        if (body !== undefined) headers['content-type'] = 'application/json';
        const result = await app.inject({
          method: method as 'GET',
          url: path,
          headers,
          ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
        });
        if (result.statusCode >= 400) throw new Error(result.headers['content-type']?.includes('application/json')
          ? result.json().error?.message ?? 'The API request failed.' : 'The API request failed.');
        return {
          status: result.statusCode,
          body: result.headers['content-type']?.includes('application/json') ? result.json() : result.body,
        };
      },
    });
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    await server.connect(transport);
    reply.hijack();
    try {
      await transport.handleRequest(request.raw, reply.raw, body);
    } finally {
      await transport.close();
      await server.close();
    }
  });
}
