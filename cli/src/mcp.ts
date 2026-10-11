import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { Command, HttpRequest, Id, JsonObject, Name } from '../../shared/contracts.js';
import { FunctionSave } from '../../shared/operations.js';
import { Task } from '../../shared/execution.js';
import type { CustodyClient } from '../../shared/client.js';
import { mcpCall, registerMetadataTools, ResponseFormat } from '../../runtime/mcp-metadata.js';
import type { Client } from './client.js';
import { privateClient } from './custody.js';
import { operationClient } from './operations.js';
import { FunctionClient } from '../../shared/function-client.js';
import packageInfo from '../package.json' with { type: 'json' };

const Operation = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('http'), request: HttpRequest,
    save: z.record(z.string().max(500), Name).default({}) }).strict(),
  Command.extend({ kind: z.literal('command') }).strict(),
]);
export function createLocalMcp(client: Client, custody: () => CustodyClient = () => privateClient(client).custody) {
  const server = new McpServer({ name: 'foundation-mcp-server', version: packageInfo.version }, {
    instructions: 'Use foundation_functions to find callable functions, foundation_invoke_function to invoke one with its declared arguments, and foundation_invocation_result to read the result. Function calls require execute permission; they do not require encryption keys or access to the program, environment, connections, or variables. Use foundation_save_function with local keys to publish a definition and approve its protected inputs. Use foundation_schema to discover the common Foundation API and foundation_api to manage resources and start commands through /api/environments/{id}/processes. Inspect or cancel a process through /api/processes/{id}. For protected caller programs, foundation_run signs and encrypts a request for an explicitly selected, previously trusted executor. Reference variable and connection IDs in protected bindings or command inputs. GET /api/operations lists user operations. Prepare operations with POST /api/operation-executions and operations containing name, input, and optional input fields, with an optional responderId. It returns an execution ID and continuation URL; protected values are entered directly in that screen. Requests deliver executions when a handoff is needed. Use foundation_execution_result to verify and decrypt protected execution results; uncertain means inspect the destination before issuing another operation. Fingerprint trust is established separately through foundation trust or the browser, not by a model tool.',
  });
  registerMetadataTools(server, {
    schema: () => client.json('/api/openapi.json'),
    async request(method, path, body) {
      const response = await client.response(path, { method, body });
      return { status: response.status, body: response.status === 204 ? null : await response.json() };
    },
  });
  server.registerTool('foundation_save_function', {
    title: 'Save a reusable function',
    description: 'Save a fixed program, its arguments and result format, and its execution environment. Command programs read arguments as JSON from stdin and write their result to stdout in temporary working storage. Approves the exact function for its protected inputs using local encryption keys. Share its execute permission to allow calls without direct input access. Reference variable or connection IDs; never supply their plaintext.',
    inputSchema: FunctionSave.extend({ response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, input => mcpCall(async () => {
    const { response_format: _format, ...destination } = input;
    const result = await new FunctionClient(client, custody()).save(destination);
    return { id: result.id, name: result.name, version: result.version };
  }, input.response_format));
  server.registerTool('foundation_run', {
    title: 'Run on an explicitly trusted executor',
    description: 'Sign and encrypt one HTTP request or command for an explicitly selected, trusted executor. Requires environment permission and caller-program input grants. Use foundation_invoke_function for saved functions. Use save to map HTTP result JSON pointers to encrypted variable names. Returns the execution ID and state. Retry transport failures with foundation_resume_execution and the returned ID.',
    inputSchema: z.object({ ownerId: Id.optional(), environmentId: Id.optional(),
      operation: Operation, response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, input => mcpCall(async () => {
    const environmentId = input.environmentId;
    if (!environmentId) throw new Error('Choose an execution environment.');
    const operation = input.operation.kind === 'http' ? { kind: 'http', request: input.operation.request } : input.operation;
    const result = await operationClient(client, custody()).execute({ name: 'run.execute', input: JsonObject.parse({
      ownerId: input.ownerId ?? client.identity.principalId, environmentId, operation,
      save: input.operation.kind === 'http' ? input.operation.save : {},
    }) });
    if (!('kind' in result) || result.kind !== 'run') return result;
    const { task } = result, operationId = task.intent.operationContext!.id;
    return { id: task.id, state: task.state, environmentId: task.environmentId, operationId,
      url: client.identity.origin + '/operations/' + operationId };
  }, input.response_format));
  server.registerTool('foundation_execution_result', {
    title: 'Verify and open an execution result',
    description: 'Read state and locally verify/decrypt the signed result for an execution started by this identity. The result is disclosed to this MCP client. For large results, use offset/limit to read a JSON text slice. Does not execute or retry the operation.',
    inputSchema: z.object({ id: Id, offset: z.number().int().min(0).default(0),
      limit: z.number().int().min(1).max(20000).default(20000), response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, input => mcpCall(async () => {
    const task = await client.json('/api/executions/' + input.id, {}, Task), result = await custody().result(task);
    const serialized = JSON.stringify(result), text = serialized.slice(input.offset, input.offset + input.limit);
    return { id: task.id, state: task.state, error: task.error, offset: input.offset, text,
      next: input.offset + text.length < serialized.length ? input.offset + text.length : null };
  }, input.response_format));
  server.registerTool('foundation_resume_execution', {
    title: 'Resubmit the same signed execution',
    description: 'Resubmit the exact locally saved request after a submission transport failure. Uses the same ID and encrypted request, so it cannot dispatch an already dispatched operation again.',
    inputSchema: z.object({ id: Id, response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, input => mcpCall(async () => {
    const task = await custody().resume(input.id);
    return { id: task.id, state: task.state, environmentId: task.environmentId };
  }, input.response_format));
  return server;
}
export async function startMcp(client: Client) {
  const server = createLocalMcp(client);
  await server.connect(new StdioServerTransport());
  return 0;
}
