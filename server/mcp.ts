import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { LATEST_PROTOCOL_VERSION } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import { Json } from '../shared/contracts.js';
import { fail } from './errors.js';

export async function routesMcp(app: ApiApp) {
  app.post('/api/mcp', { schema: { body: Json, hide: true } }, async (request, reply) => {
    actor(request);
    const body = request.body;
    if (!body || typeof body !== 'object' || Array.isArray(body))
      fail(400, 'invalid_rpc', 'Send one MCP JSON-RPC request.');
    const params =
      body.params && typeof body.params === 'object' && !Array.isArray(body.params) ? body.params : {};
    if (
      body.method === 'initialize'
        ? params.protocolVersion !== LATEST_PROTOCOL_VERSION
        : request.headers['mcp-protocol-version'] !== LATEST_PROTOCOL_VERSION
    )
      fail(400, 'unsupported_protocol', 'Use MCP ' + LATEST_PROTOCOL_VERSION + '.');
    const server = new McpServer(
      { name: 'Foundation', version: '1.0.0' },
      {
        instructions:
          'Use foundation_api to manage principals, service connections, encrypted resources, and runs. Use approval requests when a person must provide permission or enter a secret. Secret values belong in approved input forms, not in messages.',
      },
    );
    server.registerTool(
      'foundation_schema',
      { description: 'Read the Foundation API schema.', inputSchema: z.object({}) },
      async () => ({ content: [{ type: 'text', text: JSON.stringify(app.swagger()) }] }),
    );
    server.registerTool(
      'foundation_api',
      {
        description: 'Call the Foundation API with the authenticated principal’s permissions.',
        inputSchema: z.object({
          method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
          path: z.string().startsWith('/api/').max(2048),
          body: Json.optional(),
        }),
      },
      async (input) => {
        if (/^\/api\/mcp(?:[/?]|$)/u.test(input.path) || input.path.includes('\\'))
          return {
            isError: true,
            content: [{ type: 'text', text: 'Choose a Foundation resource API path.' }],
          };
        const headers: Record<string, string> = {};
        if (request.headers.authorization) headers.authorization = request.headers.authorization;
        if (request.headers.cookie) headers.cookie = request.headers.cookie;
        if (request.headers.origin) headers.origin = request.headers.origin;
        if (input.body !== undefined) headers['content-type'] = 'application/json';
        const result = await app.inject({
          method: input.method,
          url: input.path,
          headers,
          ...(input.body !== undefined ? { payload: JSON.stringify(input.body) } : {}),
        });
        return {
          isError: result.statusCode >= 400,
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                status: result.statusCode,
                body: result.headers['content-type']?.includes('application/json')
                  ? result.json()
                  : result.body,
              }),
            },
          ],
        };
      },
    );
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
