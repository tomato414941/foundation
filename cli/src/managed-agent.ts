import { randomBytes } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import { EnvironmentBootstrap } from '../../shared/protocol.js';
import { bindKeys, newIdentityKeys, signBinding } from '../../shared/authority.js';
import { ApiError, Client } from './client.js';
import { configPath, origin, readIdentity, saveIdentity } from './config.js';
import { startAgent } from './agent.js';

export async function managedAgent() {
  const value = process.env.FOUNDATION_EXECUTOR_BOOTSTRAP;
  if (!value) throw new Error('The executor enrollment is missing.');
  const input = EnvironmentBootstrap.parse(JSON.parse(Buffer.from(value, 'base64url').toString('utf8')));
  input.origin = origin(input.origin);
  delete process.env.FOUNDATION_EXECUTOR_BOOTSTRAP;
  let exists = false;
  try { await lstat(configPath()); exists = true; }
  catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error; }
  if (!exists) {
    const keys = await newIdentityKeys(), binding = bindKeys(input.executorId, keys);
    await saveIdentity({ origin: input.origin, principalId: input.executorId,
      token: 'fk_' + randomBytes(32).toString('base64url'), keys, binding });
  }
  const identity = await readIdentity(input.origin), client = new Client(identity);
  if (identity.principalId !== input.executorId || !identity.keys || !identity.binding)
    throw new Error('The saved keys belong to another executor.');
  const current = await client.session().catch(async error => {
    if (!(error instanceof ApiError) || error.status !== 401) throw error;
    await enrollManaged(input, client);
    return client.session();
  });
  if (!current.principal) throw new Error('The executor credential is no longer active.');
  return startAgent(client, { id: input.id, ownerId: input.ownerId, name: input.name,
    isolation: 'container',
    image: input.commandImage, managed: true });
}

export async function enrollManaged(input: ReturnType<typeof EnvironmentBootstrap.parse>, client: Client) {
  const { keys, binding, token } = client.identity;
  if (!keys || !binding) throw new Error('Create executor keys before enrollment.');
  const response = await fetch(input.origin + '/api/environments/' + input.id + '/enroll', {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(30_000),
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ bootstrap: input.bootstrap, token, binding: await signBinding(binding, keys) }),
  });
  if (!response.ok) throw new Error('The executor could not enroll. Keep its saved keys and check the environment status.');
}
