import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { Id, Json, JsonObject } from '../shared/contracts.js';

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
  executionResult?(id: string): Promise<unknown>;
}) {
  server.registerTool('foundation_functions', {
    title: 'Find callable functions', description: 'List functions available to this identity and their declared inputs. Execute permission exposes the calling interface; reading the program requires separate permission.',
    inputSchema: z.object({ query: z.string().max(200).optional(), limit: z.number().int().min(1).max(100).default(20),
      after: Id.optional(), response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, input => mcpCall(() => {
    const query = new URLSearchParams({ limit: String(input.limit), ...(input.query ? { query: input.query } : {}),
      ...(input.after ? { after: input.after } : {}) });
    return gateway.request('GET', '/api/functions?' + query);
  }, input.response_format));
  server.registerTool('foundation_invoke_function', {
    title: 'Invoke a saved function', description: 'Call a function using only its ID and declared arguments. Requires execute permission on the function. Connections and variables stay inside the approved executor. Returns an execution ID; use foundation_execution_result to read its state and result. Reuse the same id and arguments after a transport failure to avoid starting another invocation.',
    inputSchema: z.object({ functionId: Id, arguments: JsonObject.default({}), id: Id.optional(), response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, input => mcpCall(async () => {
    const id = input.id ?? crypto.randomUUID();
    try { return await gateway.request('POST', '/api/functions/' + input.functionId + '/executions', { id, arguments: input.arguments }); }
    catch (error) { throw new Error((error instanceof Error ? error.message : 'The invocation request failed.') +
      ' Check execution ' + id + ' or retry with the same id and arguments.'); }
  }, input.response_format));
  server.registerTool('foundation_execution_result', {
    title: 'Read an execution', description: 'Read an execution state, error, and result. Does not start or retry work. Large results are returned as JSON text with offset/limit and a next offset.',
    inputSchema: z.object({ id: Id, offset: z.number().int().min(0).default(0),
      limit: z.number().int().min(1).max(20000).default(20000), response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, input => mcpCall(async () => {
    const execution = gateway.executionResult ? await gateway.executionResult(input.id)
      : (await gateway.request('GET', '/api/executions/' + input.id) as { body: unknown }).body;
    const { results, ...metadata } = execution as Record<string, unknown>, serialized = JSON.stringify(results), text = serialized.slice(input.offset, input.offset + input.limit);
    return { ...metadata, offset: input.offset, text, next: input.offset + text.length < serialized.length ? input.offset + text.length : null };
  }, input.response_format));
  server.registerTool('foundation_cancel_execution', {
    title: 'Cancel a function invocation', description: 'Cancel a queued invocation or ask its executor to stop an active invocation. Cancellation cannot undo effects that already happened. Inspect the final invocation state before deciding to call again.',
    inputSchema: z.object({ id: Id, response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, input => mcpCall(() => gateway.request('POST', '/api/executions/' + input.id + '/cancel', {}), input.response_format));
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
    description: 'Call Foundation resource, process, and approval APIs as this principal. Start a command with POST /api/environments/{id}/processes. Read state, exit status, and paginated stdout/stderr through GET /api/processes/{id}/output; use its next offset to read more. Inspect or cancel a process through /api/processes/{id}. Include limit/after on list paths. Use POST /api/executions with operations (name, input, optional input fields) and optional responderId to prepare work. Return its url to the principal supplying consent or private input. Protected variables and connections require client encryption in that continuation screen.',
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
