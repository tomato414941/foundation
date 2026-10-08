import { fixture } from './support.js';
import { MemoryObjects, MemoryPayments, MemoryRunner } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { Worker } from '../server/worker.js';
import { randomBytes } from 'node:crypto';
import { bindKeys, hash, newIdentityKeys, signBinding } from '../shared/authority.js';
import { EnvironmentBootstrap } from '../shared/protocol.js';
import { signEnvironment } from '../shared/execution.js';
import { Client } from '../cli/src/client.js';
import { HttpBroker } from '../runtime/broker.js';
import { Executor } from '../runtime/executor.js';
import { Connections } from '../runtime/connections.js';
import { CommandProcess } from '../runtime/command.js';
import { MemoryJournal } from './delegation-support.js';
import type { EnvironmentOptions } from '../shared/contracts.js';

const agents = new Map<string, Executor>();
const running = new Map<string, Promise<void>>();
class BrowserRunner extends MemoryRunner {
  override async start(id: string, options: EnvironmentOptions, environment: Record<string, string>,
    created: (id: string, volume: string) => Promise<void>) {
    const machine = await super.start(id, options, environment, created);
    if (agents.has(id)) return machine;
    const bootstrap = EnvironmentBootstrap.parse(JSON.parse(Buffer.from(environment.FOUNDATION_EXECUTOR_BOOTSTRAP!, 'base64url').toString()));
    const keys = await newIdentityKeys(), binding = bindKeys(bootstrap.executorId, keys);
    const token = 'fk_' + randomBytes(32).toString('base64url');
    const enrollment = await app.inject({ method: 'POST', url: '/api/environments/' + id + '/enroll',
      payload: { bootstrap: bootstrap.bootstrap, binding: await signBinding(binding, keys), token } });
    if (enrollment.statusCode !== 200) throw new Error(enrollment.body);
    const client = new Client({ origin, principalId: binding.principalId, token, keys, binding });
    const registration = await signEnvironment({ format: 1, id, origin, ownerId: bootstrap.ownerId,
      name: bootstrap.name, executor: binding, operatorId: binding.principalId, driver: 'managed',
      callers: bootstrap.callers, capabilities: ['http', 'command', 'function', 'connect', 'refresh', 'revoke'],
      isolation: 'container', commandImage: bootstrap.commandImage,
      awsPrincipal: 'arn:aws:iam::123456789012:role/foundation-test-executor', revision: 1 }, keys);
    await client.json('/api/environments/' + id + '/registration', { method: 'PUT', body: registration });
    const broker = new HttpBroker(client), journal = new MemoryJournal();
    const transport = { async send() { return { status: 200, headers: {}, body: new TextEncoder().encode('{}') }; } };
    // This UI fixture simulates provisioning; container isolation has its own integration test.
    agents.set(id, new Executor(registration, keys, broker, journal, transport,
      new CommandProcess({ isolation: 'process' }), new Connections(binding, keys, broker.connections(), journal, transport)));
    return machine;
  }
  override async stop(id: string) { agents.delete(id); await super.stop(id); }
}

const fixtureData = await fixture();
const port = Number(process.env.FOUNDATION_TEST_PORT ?? 3458);
const origin = 'http://localhost:' + port;
const context = await createContext(
  {
    ...fixtureData.config,
    origin,
    FOUNDATION_ORIGIN: origin,
    FOUNDATION_PORT: port,
    FOUNDATION_PROXY_ADDRESSES: '127.0.0.1',
  },
  {
    db: fixtureData.db,
    mailer: fixtureData.mailer,
    storage: new MemoryObjects(),
    payments: new MemoryPayments(),
    runner: new BrowserRunner(),
    transport: {
      async send(request) {
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: new TextEncoder().encode(
            JSON.stringify({ message: 'Hello from the test service', method: request.method }),
          ),
        };
      },
    },
  },
);
const app = await buildApp(context);
app.get('/__test/ready', async () => ({ pid: process.pid }));
app.get<{ Params: { id: string } }>('/__test/executor/:id/fingerprint', async request => {
  const agent = agents.get(request.params.id);
  return agent ? { id: agent.binding.principalId, fingerprint: await hash(agent.binding) } : null;
});
app.get<{ Params: { address: string } }>('/__test/mail/:address', async (request) => ({
  link: fixtureData.mailer.sent.findLast((item) => item.address === request.params.address)?.link ?? null,
}));
app.post<{ Body: { principalId: string } }>('/__test/payment', async (request) => {
  await context.db.pool.query(
    "INSERT INTO payment_accounts(principal_id,customer_id,status) VALUES($1,$2,'active') ON CONFLICT(principal_id) DO UPDATE SET status='active'",
    [request.body.principalId, 'customer-' + request.body.principalId],
  );
  return { ok: true };
});
const worker = new Worker(context, (error) => app.log.error(error));
try {
  await app.listen({ host: '127.0.0.1', port });
} catch (error) {
  await app.close();
  await fixtureData.close();
  throw error;
}
worker.start();
const executorTimer = setInterval(() => {
  for (const [id, agent] of agents) if (!running.has(id)) {
    const task = agent.tick().then(() => {}).catch(error => app.log.error(error)).finally(() => running.delete(id));
    running.set(id, task);
  }
}, 1000);
let closing = false;
async function close() {
  if (closing) return;
  closing = true;
  clearInterval(executorTimer);
  await Promise.all(running.values());
  await worker.stop();
  await app.close();
  await fixtureData.close();
}
process.once('SIGTERM', () => {
  void close();
});
process.once('SIGINT', () => {
  void close();
});
