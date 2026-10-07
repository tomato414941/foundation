import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { LATEST_PROTOCOL_VERSION } from '@modelcontextprotocol/sdk/types.js';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import { Json } from '../shared/contracts.js';
import { fail } from './errors.js';
import { registerMetadataTools } from '../runtime/mcp-metadata.js';

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
          'This endpoint manages Foundation metadata and approval requests. Protected values and executions require client encryption and signatures. Use foundation mcp on a device holding an explicitly authorized identity to sign runs and decrypt results. For service consent or secret entry, create a CONNECT approval request for the browser; never submit plaintext credentials to this API.',
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
