import { mkdir, open, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { privateClient } from './custody.js';
import type { Client } from './client.js';
import { canonical, hash } from '../../shared/authority.js';
import { Id } from '../../shared/contracts.js';
import { signEnvironment, verifyEnvironment } from '../../shared/execution.js';
import type { RegisteredEnvironment } from '../../shared/execution.js';
import { FileJournal } from '../../runtime/journal.js';
import { Connections } from '../../runtime/connections.js';
import { Executor } from '../../runtime/executor.js';
import { CommandProcess } from '../../runtime/command.js';

export async function startAgent(client: Client, options: {
  id?: string; ownerId: string; name: string; callers: string[]; isolation: 'process' | 'container';
  image?: string; managed?: boolean; once?: boolean;
}) {
  const { custody, directory, keys, binding, broker, transport } = privateClient(client);
  const id = Id.parse(options.id ?? crypto.randomUUID()), path = join(directory, 'executors', id);
  await mkdir(path, { recursive: true, mode: 0o700 });
  const lockPath = join(path, 'process.lock');
  const lock = await open(lockPath, 'wx', 0o600).catch(() => {
    throw new Error('This executor directory is locked. Check that its previous process has stopped before removing ' + lockPath + '.');
  });
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  try {
    await lock.writeFile(JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }));
    await lock.sync();
    const journal = new FileJournal(path, client.identity.origin, binding, keys);
    let environment = await journal.read<RegisteredEnvironment>('environment_' + id);
    if (environment) {
      await verifyEnvironment(environment);
      if (environment.manifest.ownerId !== options.ownerId || canonical(environment.manifest.executor) !== canonical(binding))
        throw new Error('Use the owner and identity originally registered for this executor.');
    } else {
      const callers = [];
      for (const principal of new Set(options.callers.length ? options.callers : [binding.principalId])) {
        const caller = principal === binding.principalId ? binding : (await custody.inspectIdentity(principal)).binding;
        await custody.trusted(caller); callers.push(caller);
      }
      environment = await signEnvironment({ format: 1, id, origin: client.identity.origin, ownerId: options.ownerId,
        name: options.name, executor: binding, operatorId: binding.principalId, driver: options.managed ? 'managed' : 'attached',
        capabilities: ['http', 'command', 'function', 'connect', 'refresh', 'revoke'], callers,
        isolation: options.isolation, ...(options.image ? { commandImage: options.image } : {}), revision: 1 }, keys);
      await journal.write('environment_' + id, environment);
    }
    await client.json('/api/environments/' + id + '/registration', { method: 'PUT', body: environment });
    process.stdout.write(JSON.stringify({ environmentId: id, identityId: binding.principalId,
      fingerprint: await hash(binding), isolation: environment.manifest.isolation,
      ...(environment.manifest.isolation === 'process' ? { notice: 'Only allow trusted code on this host.' } : {}) }) + '\n');
    const connections = new Connections(binding, keys, broker.connections(), journal, transport);
    const executor = new Executor(environment, keys, broker, journal, transport,
      new CommandProcess({ isolation: environment.manifest.isolation, image: environment.manifest.commandImage }), connections);
    await connections.reconcile();
    await executor.reconcile();
    do {
      const claimed = await executor.tick(controller.signal);
      if (options.once) break;
      if (!claimed) await delay(1000, undefined, { signal: controller.signal });
    } while (!controller.signal.aborted);
  } catch (error) {
    if (!controller.signal.aborted) throw error;
  } finally {
    process.off('SIGINT', stop); process.off('SIGTERM', stop);
    await lock.close();
    await rm(lockPath, { force: true });
  }
  return 0;
}
