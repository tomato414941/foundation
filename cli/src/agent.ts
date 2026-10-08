import { mkdir } from 'node:fs/promises';
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
import { DeliveryPending, Executor } from '../../runtime/executor.js';
import { CommandProcess } from '../../runtime/command.js';
import { journalLock } from '../../runtime/lock.js';
import { detectAwsPrincipal } from '../../runtime/roles.js';
import { Operations } from '../../shared/custody.js';

export async function startAgent(client: Client, options: {
  id?: string; ownerId: string; name: string; callers: string[]; isolation: 'process' | 'container';
  image?: string; managed?: boolean; once?: boolean;
}) {
  const { custody, directory, keys, binding, broker, transport } = privateClient(client);
  const id = Id.parse(options.id ?? crypto.randomUUID()), path = join(directory, 'executors', id);
  await mkdir(path, { recursive: true, mode: 0o700 });
  const release = await journalLock(join(path, 'process.lock'));
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  try {
    const journal = new FileJournal(path, client.identity.origin, binding, keys);
    let environment = await journal.read<RegisteredEnvironment>('environment_' + id);
    const awsPrincipal = await detectAwsPrincipal();
    if (environment) {
      await verifyEnvironment(environment);
      if (environment.manifest.ownerId !== options.ownerId || canonical(environment.manifest.executor) !== canonical(binding))
        throw new Error('Use the owner and identity originally registered for this executor.');
      // The AWS identity may come and go with the machine's credentials; the registration says what it is now.
      if ((environment.manifest.awsPrincipal ?? null) !== awsPrincipal) {
        const { awsPrincipal: _previous, ...manifest } = environment.manifest;
        environment = await signEnvironment({ ...manifest, ...(awsPrincipal ? { awsPrincipal } : {}),
          revision: manifest.revision + 1 }, keys);
        await journal.write('environment_' + id, environment);
      }
    } else {
      const callers = [];
      for (const principal of new Set(options.callers.length ? options.callers : [binding.principalId])) {
        const caller = principal === binding.principalId ? binding : (await custody.inspectIdentity(principal)).binding;
        await custody.trusted(caller); callers.push(caller);
      }
      environment = await signEnvironment({ format: 2, id, origin: client.identity.origin, ownerId: options.ownerId,
        name: options.name, executor: binding, operatorId: binding.principalId, driver: options.managed ? 'managed' : 'attached',
        capabilities: Object.values(Operations), callers,
        isolation: options.isolation, ...(options.image ? { commandImage: options.image } : {}),
        ...(awsPrincipal ? { awsPrincipal } : {}), revision: 1 }, keys);
      await journal.write('environment_' + id, environment);
    }
    await client.json('/api/environments/' + id + '/registration', { method: 'PUT', body: environment });
    process.stdout.write(JSON.stringify({ environmentId: id, identityId: binding.principalId,
      fingerprint: await hash(binding), isolation: environment.manifest.isolation,
      ...(environment.manifest.awsPrincipal ? { awsPrincipal: environment.manifest.awsPrincipal } : {}),
      ...(environment.manifest.isolation === 'process' ? { notice: 'Only allow trusted code on this host.' } : {}) }) + '\n');
    const connections = new Connections(binding, keys, broker.connections(), journal, transport);
    const executor = new Executor(environment, keys, broker, journal, transport,
      new CommandProcess({ isolation: environment.manifest.isolation, image: environment.manifest.commandImage }), connections);
    do {
      const pending = [...await connections.reconcile(), ...await executor.reconcile()];
      if (pending.length) process.stderr.write(JSON.stringify({ event: 'reconciliation_pending', ids: pending }) + '\n');
      let claimed = false;
      try { claimed = await executor.tick(controller.signal); }
      catch (error) { if (!(error instanceof DeliveryPending) || options.once) throw error; }
      if (options.once) break;
      if (!claimed) await delay(1000, undefined, { signal: controller.signal });
    } while (!controller.signal.aborted);
  } catch (error) {
    if (!controller.signal.aborted) throw error;
  } finally {
    process.off('SIGINT', stop); process.off('SIGTERM', stop);
    await release();
  }
  return 0;
}
