#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { hostname } from 'node:os';
import { z } from 'zod';
import { Id, Name } from '../../shared/contracts.js';
import { FUNCTION_RUNTIME_VERSION, HTTP_RUNTIME_VERSION } from '../../shared/runtime-protocol.js';
import { Client } from './client.js';
import { readIdentity } from './config.js';
import { startAgent } from './agent.js';
import { currentIdentity } from './keys.js';
import { KeysReplaced } from '../../shared/key-rotations.js';

async function main() {
  const args = parseArgs({ allowPositionals: true, options: {
    version: { type: 'boolean' }, origin: { type: 'string' }, owner: { type: 'string' }, id: { type: 'string' },
    name: { type: 'string' }, isolation: { type: 'string' }, image: { type: 'string' }, once: { type: 'boolean' },
  } });
  if (args.values.version) {
    process.stdout.write(`Foundation executor: functions ${FUNCTION_RUNTIME_VERSION}, HTTP ${HTTP_RUNTIME_VERSION}\n`);
    return 0;
  }
  const mode = args.positionals[0] ?? 'start';
  if (mode !== 'start') throw new Error('Use foundation-executor start.');
  const supplied = process.env.FOUNDATION_AGENT_OPTIONS;
  delete process.env.FOUNDATION_AGENT_OPTIONS;
  const input = supplied ? JSON.parse(supplied) : { ...args.values, ownerId: args.values.owner };
  // When the principal's keys are replaced while it runs, the agent stops, moves to the new keys and starts again.
  for (;;) {
    const client = new Client(await currentIdentity(await readIdentity(input.origin))), session = await client.session();
    if (!session.principal) throw new Error('The machine identity is no longer valid.');
    try {
      return await startAgent(client, { id: input.id ? Id.parse(input.id) : undefined,
        ownerId: Id.parse(input.ownerId ?? session.principal.id), name: Name.parse(input.name ?? hostname()),
        isolation: z.enum(['process', 'container']).parse(input.isolation ?? 'process'),
        image: input.image, once: input.once });
    } catch (error) {
      if (!(error instanceof KeysReplaced)) throw error;
      input.id ??= error.environmentId;
    }
  }
}
try { process.exitCode = await main(); }
catch (error) { process.stderr.write((error instanceof Error ? error.message : 'The execution agent failed.') + '\n'); process.exitCode = 1; }
