import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { Id, Json } from '../shared/contracts.js';

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
  request(method: string, path: string, body?: unknown, confirmation?: string): Promise<unknown>;
}) {
  server.registerTool('foundation_schema', {
    title: 'Inspect the Foundation API',
    description: 'Find the Foundation API for a request. Pass query with words from the request to list matching paths, methods, and summaries; pass path or component for details. With no filter, lists every path and component name.',
    inputSchema: z.object({ query: z.string().max(200).optional(), path: z.string().startsWith('/api/').optional(), component: z.string().max(200).optional(),
      response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, input => mcpCall(async () => {
    const spec = z.object({ paths: z.record(z.string(), Json), components: z.object({ schemas: z.record(z.string(), Json).default({}) }).optional() })
      .parse(await gateway.schema());
    if (input.path) return spec.paths[input.path] ?? { error: 'Choose a path from foundation_schema.' };
    if (input.query) {
      const words = input.query.toLowerCase().split(/\s+/u).filter(Boolean);
      return Object.entries(spec.paths).flatMap(([path, operations]) =>
        Object.entries(operations as Record<string, { summary?: string; description?: string }>).map(([method, operation]) =>
          ({ method: method.toUpperCase(), path, summary: operation?.summary ?? operation?.description ?? '' })))
        .filter(entry => words.every(word => (entry.path + ' ' + entry.summary).toLowerCase().includes(word)));
    }
    if (input.component) return spec.components?.schemas[input.component] ?? { error: 'Choose a component from foundation_schema.' };
    return { paths: Object.keys(spec.paths), components: Object.keys(spec.components?.schemas ?? {}) };
  }, input.response_format));
  server.registerTool('foundation_read', {
    title: 'Read from Foundation',
    description: 'Read Foundation data as this principal with a GET request. Changes nothing. Find the path with foundation_schema.',
    inputSchema: z.object({
      path: z.string().startsWith('/api/').max(2048), response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, input => mcpCall(async () => {
    const url = new URL(input.path, 'https://foundation.invalid');
    if (url.origin !== 'https://foundation.invalid' || !url.pathname.startsWith('/api/') ||
      /^\/api\/mcp(?:\/|$)/u.test(url.pathname) || /[\\\u0000-\u001f]/u.test(input.path) || url.hash)
      throw new Error('Choose a Foundation resource API path.');
    return gateway.request('GET', url.pathname + url.search);
  }, input.response_format));
  server.registerTool('foundation_api', {
    title: 'Change Foundation',
    description: 'Create, change, or delete Foundation data as this principal. Find the path and body with foundation_schema. When the response includes a URL for consent or secret input, give it to the user. ' +
      'A change to sign-in methods, keys, or who manages a principal fails with confirmation_required and names the operation and methods: ' +
      'POST /api/confirmations with that operation, prove it (for email, POST /api/confirmations/{id}/email and ask the user for the code, then POST /api/confirmations/{id}/proof with method email and the code), ' +
      'and send the same change again with confirmation set to the confirmation ID.',
    inputSchema: z.object({ method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
      path: z.string().startsWith('/api/').max(2048), body: Json.optional(), confirmation: Id.optional(),
      response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, input => mcpCall(async () => {
    const url = new URL(input.path, 'https://foundation.invalid');
    if (url.origin !== 'https://foundation.invalid' || !url.pathname.startsWith('/api/') ||
      /^\/api\/mcp(?:\/|$)/u.test(url.pathname) || /[\\\u0000-\u001f]/u.test(input.path) || url.hash)
      throw new Error('Choose a Foundation resource API path.');
    return gateway.request(input.method, url.pathname + url.search, input.body, input.confirmation);
  }, input.response_format));
}
