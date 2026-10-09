import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { Json } from '../shared/contracts.js';

export const ResponseFormat = z.enum(['json', 'markdown']).default('json');
export function mcpReply(value: unknown, format: 'json' | 'markdown' = 'json'): CallToolResult {
  let data = JSON.parse(JSON.stringify(value)) as unknown;
  const serialized = JSON.stringify(data);
  if (serialized.length > 25_000) data = { truncated: true, preview: serialized.slice(0, 24_000),
    characters: serialized.length, hint: 'Use a smaller API limit or a specific schema path/component.' };
  const text = format === 'markdown' ? '```json\n' + JSON.stringify(data, null, 2) + '\n```' : JSON.stringify(data);
  return { content: [{ type: 'text', text }], structuredContent: { data } };
}
export async function mcpCall(work: () => Promise<unknown>, format: 'json' | 'markdown' = 'json'): Promise<CallToolResult> {
  try { return mcpReply(await work(), format); }
  catch (error) {
    return { isError: true, content: [{ type: 'text', text: error instanceof Error ? error.message : 'The operation could not be completed.' }] };
  }
}
export function registerMetadataTools(server: McpServer, gateway: {
  schema(): Promise<unknown>;
  request(method: string, path: string, body?: unknown): Promise<unknown>;
}) {
  server.registerTool('foundation_schema', {
    title: 'Inspect the Foundation API',
    description: 'Inspect API paths or a named schema component. With no filter, lists available paths and component names. Use foundation_api with page limits and cursors for resource metadata.',
    inputSchema: z.object({ path: z.string().startsWith('/api/').optional(), component: z.string().max(200).optional(),
      response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, input => mcpCall(async () => {
    const spec = z.object({ paths: z.record(z.string(), Json), components: z.object({ schemas: z.record(z.string(), Json).default({}) }).optional() })
      .parse(await gateway.schema());
    if (input.path) return spec.paths[input.path] ?? { error: 'Choose a path from foundation_schema.' };
    if (input.component) return spec.components?.schemas[input.component] ?? { error: 'Choose a component from foundation_schema.' };
    return { paths: Object.keys(spec.paths), components: Object.keys(spec.components?.schemas ?? {}) };
  }, input.response_format));
  server.registerTool('foundation_api', {
    title: 'Call the Foundation API',
    description: 'Call Foundation resource, process, and approval APIs as this principal. Start a command with POST /api/environments/{id}/processes. Read state, exit status, and paginated stdout/stderr through GET /api/processes/{id}/output; use its next offset to read more. Inspect or cancel a process through /api/processes/{id}. Include limit/after on list paths. Protected variables and connections require client encryption; use CONNECT approval requests for service consent.',
    inputSchema: z.object({ method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
      path: z.string().startsWith('/api/').max(2048), body: Json.optional(), response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, input => mcpCall(async () => {
    const url = new URL(input.path, 'https://foundation.invalid');
    if (url.origin !== 'https://foundation.invalid' || !url.pathname.startsWith('/api/') ||
      /^\/api\/mcp(?:\/|$)/u.test(url.pathname) || /[\\\u0000-\u001f]/u.test(input.path) || url.hash)
      throw new Error('Choose a Foundation resource API path.');
    return gateway.request(input.method, url.pathname + url.search, input.body);
  }, input.response_format));
}
