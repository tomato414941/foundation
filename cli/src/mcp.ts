import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { Command, FunctionInputAccess, HttpRequest, Id, JsonObject, Name } from '../../shared/contracts.js';
import { FunctionSave, Execution } from '../../shared/executions.js';
import { Task } from '../../shared/runtime-protocol.js';
import type { CustodyClient } from '../../shared/client.js';
import { mcpCall, registerMetadataTools, ResponseFormat } from '../../runtime/mcp-metadata.js';
import type { Client } from './client.js';
import { privateClient } from './custody.js';
import { executionClient } from './executions.js';
import { FunctionClient } from '../../shared/function-client.js';
import packageInfo from '../package.json' with { type: 'json' };

const Operation = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('http'), request: HttpRequest,
    save: z.record(z.string().max(500), Name).default({}) }).strict(),
  Command.extend({ kind: z.literal('command') }).strict(),
]);
export function createLocalMcp(client: Client, custody: () => CustodyClient = () => privateClient(client).custody) {
  const server = new McpServer({ name: 'foundation-mcp-server', version: packageInfo.version }, {
    instructions: 'Use foundation_functions to find callable functions, foundation_invoke_function to invoke one with its declared arguments, and foundation_execution_result to read the result. Function calls require execute permission; they do not require encryption keys or access to the program, environment, connections, or variables. Use foundation_save_function with local keys to publish an environment-independent definition, then foundation_configure_function to select its execution environment and approve protected inputs. Use foundation_schema to discover the common Foundation API and foundation_api to manage resources and start commands through /api/environments/{id}/processes. Inspect or cancel a process through /api/processes/{id}. For protected caller programs, foundation_run signs and encrypts a request for an explicitly selected, previously trusted executor. Reference variable and connection IDs in protected bindings or command inputs. GET /api/definitions lists user operations. Prepare operations with POST /api/executions and operations containing name, input, and optional input fields, with an optional responderId. It returns an execution ID and continuation URL; protected values are entered directly in that screen. Requests deliver executions when a handoff is needed. Use foundation_execution_result to verify and decrypt protected execution results; uncertain means inspect the destination before issuing another operation. Fingerprint trust is established separately through foundation trust or the browser, not by a model tool.',
  });
  registerMetadataTools(server, {
    schema: () => client.json('/api/openapi.json'),
    async executionResult(id) {
      const execution = await client.json('/api/executions/' + id, {}, Execution);
      for (const step of execution.steps) {
        const run = step.runs.filter(run => run.kind === 'run').at(-1);
        if (!run) continue;
        const task = await client.json('/api/runtime/runs/' + run.id, {}, Task);
        if (task.receipt) execution.results[step.index] = (await custody().result(task))?.result ?? null;
      }
      return execution;
    },
    async request(method, path, body) {
      const response = await client.response(path, { method, body });
      return { status: response.status, body: response.status === 204 ? null : await response.json() };
    },
  });
  server.registerTool('foundation_save_function', {
    title: 'Save a reusable function',
    description: 'Save a reusable program, its arguments and result format independently of an execution environment. Command programs read arguments as JSON from stdin and write their result to stdout in temporary working storage. Configure its execution environment separately with foundation_configure_function before invoking it. Reference variable or connection IDs; never supply their plaintext.',
    inputSchema: FunctionSave.extend({ response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, input => mcpCall(async () => {
    const { response_format: _format, ...destination } = input;
    const result = await new FunctionClient(client, custody()).save(destination);
    return { id: result.id, name: result.name, version: result.version };
  }, input.response_format));
  server.registerTool('foundation_configure_function', {
    title: 'Configure function execution',
    description: 'Select the execution environment and approve access to the exact function inputs using local encryption keys. Requires permission to update the function and use the selected environment. Set environmentId to null to clear the settings and revoke input access. Changing execution settings preserves the function definition and its version.',
    inputSchema: z.object({ functionId: Id, environmentId: Id.nullable(),
      inputAccess: FunctionInputAccess.default({ expiresAt: null }), response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  }, input => mcpCall(() => new FunctionClient(client, custody()).configure(input.functionId,
    { environmentId: input.environmentId, inputAccess: input.inputAccess }), input.response_format));
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
    const result = await executionClient(client, custody()).execute({ name: 'run.execute', input: JsonObject.parse({
      ownerId: input.ownerId ?? client.identity.principalId, environmentId, operation,
      save: input.operation.kind === 'http' ? input.operation.save : {},
    }) });
    if (!('kind' in result) || result.kind !== 'run') return result;
    const { task } = result, operationId = task.intent.operationContext!.id;
    return { id: operationId, state: task.state === 'queued' ? 'running' : task.state, environmentId: task.environmentId,
      url: client.identity.origin + '/executions/' + operationId };
  }, input.response_format));
  server.registerTool('foundation_resume_execution', {
    title: 'Resubmit the same signed execution',
    description: 'Resubmit the exact locally saved request after a submission transport failure. Uses the same ID and encrypted request, so it cannot dispatch an already dispatched operation again.',
    inputSchema: z.object({ id: Id, response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, input => mcpCall(async () => {
    const result = await executionClient(client, custody()).continue(input.id);
    return 'kind' in result && result.kind === 'run'
      ? client.json('/api/executions/' + result.task.intent.operationContext!.id, {}, Execution) : result;
  }, input.response_format));
  return server;
}
export async function startMcp(client: Client) {
  const server = createLocalMcp(client);
  await server.connect(new StdioServerTransport());
  return 0;
}
