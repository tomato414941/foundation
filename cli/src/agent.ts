import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { privateClient } from './custody.js';
import type { Client } from './client.js';
import { canonical, fingerprint } from '../../shared/authority.js';
import { Id } from '../../shared/contracts.js';
import { FUNCTION_RUNTIME_VERSION, HTTP_RUNTIME_VERSION, signEnvironment, verifyEnvironment } from '../../shared/runtime-protocol.js';
import type { RegisteredEnvironment } from '../../shared/runtime-protocol.js';
import { FileJournal } from '../../runtime/journal.js';
import { Connections } from '../../runtime/connections.js';
import { DeliveryPending, Executor } from '../../runtime/executor.js';
import { CommandProcess } from '../../runtime/command.js';
import { journalLock } from '../../runtime/lock.js';
import { detectAwsPrincipal } from '../../runtime/aws-principal.js';
import { Operations } from '../../shared/custody.js';
import { ProcessBroker, ProcessExecutor } from '../../runtime/process.js';
import { FunctionBroker, FunctionExecutor } from '../../runtime/functions.js';

export async function startAgent(client: Client, options: {
  id?: string; ownerId: string; name: string; isolation: 'process' | 'container';
  image?: string; functionImage?: string; once?: boolean;
}) {
  const { directory, keys, binding, broker, transport } = privateClient(client);
  const id = Id.parse(options.id ?? crypto.randomUUID()), path = join(directory, 'executors', id);
  await mkdir(path, { recursive: true, mode: 0o700 });
  const workspace = join(path, 'workspace');
  await mkdir(workspace, { recursive: true, mode: 0o700 });
  const release = await journalLock(join(path, 'process.lock'));
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  try {
    const journal = new FileJournal(path, client.identity.origin, binding, keys);
    let environment = await journal.read<RegisteredEnvironment>('environment_' + id);
    const awsPrincipal = await detectAwsPrincipal();
    const settings = environment ? { isolation: environment.manifest.isolation,
      image: environment.manifest.commandImage, functionImage: environment.manifest.functionImage } : options;
    const execution = { isolation: settings.isolation, ...(settings.image ? { commandImage: settings.image } : {}),
      ...(settings.functionImage ? { functionImage: settings.functionImage } : {}) };
    if (environment) {
      await verifyEnvironment(environment);
      if (environment.manifest.ownerId !== options.ownerId || canonical(environment.manifest.executor) !== canonical(binding))
        throw new Error('Use the owner and identity originally registered for this executor.');
      // Keep runtime support and the machine's current AWS identity in the signed registration.
      if (environment.manifest.functionVersion !== FUNCTION_RUNTIME_VERSION || environment.manifest.httpVersion !== HTTP_RUNTIME_VERSION ||
        environment.manifest.resultVersion !== 1 || (environment.manifest.awsPrincipal ?? null) !== awsPrincipal ||
        environment.manifest.isolation !== execution.isolation || environment.manifest.commandImage !== execution.commandImage ||
        environment.manifest.functionImage !== execution.functionImage) {
        const { awsPrincipal: _previous, commandImage: _commandImage, functionImage: _functionImage, ...manifest } = environment.manifest;
        environment = await signEnvironment({ ...manifest, functionVersion: FUNCTION_RUNTIME_VERSION, httpVersion: HTTP_RUNTIME_VERSION,
          resultVersion: 1, ...execution, ...(awsPrincipal ? { awsPrincipal } : {}),
          revision: manifest.revision + 1 }, keys);
        await journal.write('environment_' + id, environment);
      }
    } else {
      environment = await signEnvironment({ format: 3, id, origin: client.identity.origin, ownerId: options.ownerId,
        name: options.name, executor: binding, operatorId: binding.principalId, driver: 'attached',
        capabilities: Object.values(Operations), functionVersion: FUNCTION_RUNTIME_VERSION, httpVersion: HTTP_RUNTIME_VERSION, resultVersion: 1,
        ...execution,
        ...(awsPrincipal ? { awsPrincipal } : {}), revision: 1 }, keys);
      await journal.write('environment_' + id, environment);
    }
    await client.json('/api/environments/' + id + '/registration', { method: 'PUT', body: environment });
    process.stdout.write(JSON.stringify({ environmentId: id, identityId: binding.principalId,
      fingerprint: await fingerprint(binding), isolation: environment.manifest.isolation,
      ...(environment.manifest.awsPrincipal ? { awsPrincipal: environment.manifest.awsPrincipal } : {}),
      ...(environment.manifest.isolation === 'process' ? { notice: 'Only allow trusted code on this host.' } : {}) }) + '\n');
    const connections = new Connections(binding, keys, broker.connections(), journal, transport);
    const workingDirectory = environment.manifest.isolation === 'container' ? '/workspace' : process.cwd();
    const commands = new CommandProcess({ isolation: environment.manifest.isolation, image: environment.manifest.commandImage,
      workspace });
    const functionCommands = environment.manifest.functionImage
      ? new CommandProcess({ isolation: 'container', image: environment.manifest.functionImage }) : commands;
    const executor = new Executor(environment, keys, broker, journal, transport, commands, connections, functionCommands);
    const functions = new FunctionExecutor(executor, new FunctionBroker(client), journal);
    await client.json('/api/environments/' + id + '/processes/registration', { method: 'PUT', body: { workingDirectory } });
    const processes = new ProcessExecutor(id, new ProcessBroker(client), journal, commands);
    do {
      const pending = [...await connections.reconcile(), ...await executor.reconcile(), ...await functions.reconcile(), ...await processes.reconcile()];
      if (pending.length) process.stderr.write(JSON.stringify({ event: 'reconciliation_pending', ids: pending }) + '\n');
      let claimed = false;
      try { claimed = await executor.tick(controller.signal); claimed = await functions.tick(controller.signal) || claimed;
        claimed = await processes.tick(controller.signal) || claimed; }
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
