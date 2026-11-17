import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { Id } from '../../shared/contracts.js';
import { mcpCall, registerMetadataTools, ResponseFormat } from '../../runtime/mcp-metadata.js';
import { ApiError } from './client.js';
import type { Client } from './client.js';
import { SSHAccount } from '../../shared/ssh.js';
import { sshAccess } from './ssh-access.js';
import packageInfo from '../package.json' with { type: 'json' };

export function createLocalMcp(client: Client) {
  const server = new McpServer({ name: 'foundation-mcp-server', version: packageInfo.version }, {
    instructions: 'Foundation holds what this principal owns and may use. To act on a request, search for the matching API with foundation_schema, read with foundation_read, and make changes with foundation_api. When Foundation returns a URL for consent or secret input, give it to the user. Never put secret values in requests. This local server can also apply SSH access from this machine.',
  });
  registerMetadataTools(server, {
    schema: () => client.json('/api/openapi.json'),
    async request(method, path, body, confirmation) {
      // A change waiting for confirmation names what to confirm and how, so that it can be proved and sent again.
      const response = await client.response(path, { method, body, ...(confirmation ? { confirmation } : {}) }).catch((error: unknown) => {
        if (error instanceof ApiError && error.details !== undefined)
          throw new Error(error.message + ' ' + JSON.stringify({ code: error.code, ...(error.details as object) }));
        throw error;
      });
      return { status: response.status, body: response.status === 204 ? null : await response.json() };
    },
  });
  server.registerTool('foundation_ssh_access', {
    title: 'Apply or check SSH access on a host',
    description: 'Sign in to an SSH host over SSH from this machine, verifying the host keys registered in Foundation, and apply the authorized keys Foundation decided for each account between the lines it manages, leaving other lines as they are; or with check, only read them. Reports what each account shows afterwards. Signs in with a private key file on this machine, an SSH key whose private key is kept in Foundation, or otherwise the agent and keys OpenSSH finds for this user. Decide which keys are let in with foundation_api first.',
    inputSchema: z.object({ hostId: Id, check: z.boolean().default(false), account: SSHAccount.optional(),
      identity: z.string().min(1).optional(), sshKeyId: Id.optional(), response_format: ResponseFormat }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, input => mcpCall(() => sshAccess(client, input.hostId, { check: input.check,
    ...(input.account ? { account: input.account } : {}), ...(input.identity ? { identity: input.identity } : {}),
    ...(input.sshKeyId ? { keyId: input.sshKeyId } : {}) }), input.response_format));
  return server;
}
export async function startMcp(client: Client) {
  const server = createLocalMcp(client);
  await server.connect(new StdioServerTransport());
  return 0;
}
