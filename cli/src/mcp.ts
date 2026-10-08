import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { Command, HttpRequest, Id, Name, Resource } from '../../shared/contracts.js';
import { Task } from '../../shared/execution.js';
import type { ExecutionOperation } from '../../shared/execution.js';
import type { CustodyClient } from '../../shared/client.js';
import { mcpCall, registerMetadataTools, ResponseFormat } from '../../runtime/mcp-metadata.js';
import type { Client } from './client.js';
import { privateClient } from './custody.js';
import packageInfo from '../package.json' with { type: 'json' };

const Operation = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('http'), request: HttpRequest,
    save: z.record(z.string().max(500), Name).default({}) }).strict(),
  Command.extend({ kind: z.literal('command') }).strict(),
  z.object({ kind: z.literal('function'), id: Id, arguments: z.record(z.string(), z.string()).default({}) }).strict(),
]);
export function createLocalMcp(client: Client, custody: () => CustodyClient = () => privateClient(client).custody) {
  const server = new McpServer({ name: 'foundation-mcp-server', version: packageInfo.version }, {
    instructions: 'This bridge uses its configured Foundation identity and locally held signing keys. Discover principals, resources and environments with foundation_api. Use foundation_run only with an explicitly selected, previously trusted executor. Reference variable and connection IDs in bindings or command inputs. For new variables or service consent, create a CONNECT approval request and let the person complete the browser form. Never send secret values to the metadata API. Use foundation_execution_result to verify and decrypt a result; uncertain means inspect the destination before issuing another operation. Fingerprint trust is established separately through foundation trust or the browser, not by a model tool.',
  });
  registerMetadataTools(server, {
    schema: () => client.json('/api/openapi.json'),
    async request(method, path, body) {
      const response = await client.response(path, { method, body });
      return { status: response.status, body: response.status === 204 ? null : await response.json() };
    },
  });
  server.registerTool('foundation_run', {
    title: 'Run on an explicitly trusted executor',
    description: 'Sign and encrypt one HTTP request, saved function, or command for the selected executor. Returns its ID and state. Use resource IDs for credentials, not plaintext. The executor must already be trusted and authorized for every input. Commands and arbitrary HTTP require a caller-program grant. Retry transport failures only with foundation_resume_execution and the returned ID.',
    inputSchema: z.object({ ownerId: Id.optional(), environmentId: Id,
      operation: Operation, response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, input => mcpCall(async () => {
    let operation: ExecutionOperation;
    if (input.operation.kind === 'function') {
      const resource = await client.json('/api/resources/' + input.operation.id, {}, Resource);
      if (resource.kind !== 'function') throw new Error('Choose a saved function.');
      operation = { kind: 'function', definition: resource.data, arguments: input.operation.arguments, outputs: {} };
    } else if (input.operation.kind === 'http') operation = { ...input.operation, save: {} };
    else operation = input.operation;
    const task = await custody().submit(input.ownerId ?? client.identity.principalId, input.environmentId, operation,
      input.operation.kind === 'http' ? { save: input.operation.save } : {});
    return { id: task.id, state: task.state, environmentId: task.environmentId };
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
