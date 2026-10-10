import { fixture } from './support.js';
import { Operations } from '../shared/custody.js';
import { MemoryObjects, MemoryPayments, MemoryRunner } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { Worker } from '../server/worker.js';
import { randomBytes } from 'node:crypto';
import { bindKeys, fingerprint, newIdentityKeys, signBinding } from '../shared/authority.js';
import { EnvironmentBootstrap } from '../shared/protocol.js';
import { signEnvironment } from '../shared/execution.js';
import { Client } from '../cli/src/client.js';
import { HttpBroker } from '../runtime/broker.js';
import { Executor } from '../runtime/executor.js';
import { Connections } from '../runtime/connections.js';
import { CommandProcess } from '../runtime/command.js';
import { MemoryJournal } from './delegation-support.js';
import type { EnvironmentOptions } from '../shared/contracts.js';
import { DomainError } from '../server/errors.js';
import { SSHWorkerState } from '../shared/ssh.js';
import type { Transport } from '../server/transport.js';
import type { AwsConnectionRequest } from '../shared/aws.js';

const agents = new Map<string, Executor>();
const running = new Map<string, Promise<void>>();
const roleRequests = new Map<string, Array<{ arn: string; externalId: string; region: string }>>();
const awsRequests = new Map<string, AwsConnectionRequest[]>();
const oauthRequests = new Map<string, Array<{ clientId: string | null; clientSecret: string | null; scope: string | null }>>();
const sshAgents = new Map<string, { client: Client; hostKey: string; revision: number }>();
const deletions = new Map<string, { phase: 'stop' | 'volume'; gate?: Promise<void>; release?: () => void; fail?: boolean }>();
class BrowserRunner extends MemoryRunner {
  private async beforeDelete(id: string, phase: 'stop' | 'volume') {
    const key = phase === 'stop' ? id : [...deletions.keys()].find(key => 'vol_' + key.replaceAll('-', '') === id);
    const plan = key ? deletions.get(key) : null;
    if (plan?.phase !== phase) return;
    if (plan.fail) { plan.fail = false; throw new DomainError(502, 'runner_unavailable', 'Provider unavailable'); }
    if (plan.gate) await plan.gate;
  }
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
    const registration = await signEnvironment({ format: 3, id, origin, ownerId: bootstrap.ownerId,
      name: bootstrap.name, executor: binding, operatorId: binding.principalId, driver: 'managed',
      capabilities: Object.values(Operations),
      isolation: 'container', commandImage: bootstrap.commandImage,
      awsPrincipal: 'arn:aws:iam::123456789012:role/service/foundation-test-executor', revision: 1 }, keys);
    await client.json('/api/environments/' + id + '/registration', { method: 'PUT', body: registration });
    if (bootstrap.ssh) sshAgents.set(id, { client, revision: 0,
      hostKey: 'ssh-ed25519 ' + Buffer.concat([Buffer.from('0000000b7373682d6564323535313900000020', 'hex'), randomBytes(32)]).toString('base64') });
    const broker = new HttpBroker(client), journal = new MemoryJournal();
    const transport: Transport = { async send(request) {
      if (request.url === 'https://ca.ovh.com/auth/oauth2/token') {
        const form = new URLSearchParams(String(request.body ?? ''));
        const requests = oauthRequests.get(id) ?? [];
        requests.push({ clientId: form.get('client_id'), clientSecret: form.get('client_secret'), scope: form.get('scope') });
        oauthRequests.set(id, requests);
        return { status: 200, headers: { 'content-type': 'application/json' }, body: new TextEncoder().encode(JSON.stringify({
          access_token: 'browser-ovh-token-' + requests.length, token_type: 'Bearer', expires_in: 3600, scope: 'all',
        })) };
      }
      return { status: 200, headers: {}, body: new TextEncoder().encode('{}') };
    } };
    // This UI fixture simulates provisioning; container isolation has its own integration test.
    agents.set(id, new Executor(registration, keys, broker, journal, transport,
      new CommandProcess({ isolation: 'process' }), new Connections(binding, keys, broker.connections(), journal, transport, {
        async obtain(arn, externalId, region) {
          const requests = roleRequests.get(id) ?? [];
          requests.push({ arn, externalId, region });
          roleRequests.set(id, requests);
          return { AWS_ACCESS_KEY_ID: 'browser-role-key', AWS_SECRET_ACCESS_KEY: 'browser-role-secret',
            AWS_SESSION_TOKEN: 'browser-role-session', AWS_DEFAULT_REGION: region };
        },
      }, {
        async obtain(input) {
          const requests = awsRequests.get(id) ?? [];
          requests.push(input); awsRequests.set(id, requests);
          if (input.authentication.kind === 'session' && input.authentication.expiresAt <= Date.now())
            throw new DomainError(409, 'reconnect_required', 'Reconnect with current AWS credentials.');
          if (input.role) {
            const requests = roleRequests.get(id) ?? [];
            requests.push({ arn: input.role.arn, externalId: input.role.externalId ?? '', region: input.region });
            roleRequests.set(id, requests);
          }
          const authentication = input.authentication;
          const sourceIdentity = { accountId: '123456789012', principalId: 'BROWSERSOURCE',
            arn: authentication.kind === 'environment'
              ? 'arn:aws:sts::123456789012:assumed-role/foundation-test-executor/browser'
              : 'arn:aws:iam::123456789012:user/browser-operator' };
          const identity = input.role ? { accountId: input.role.arn.split(':')[4]!, principalId: 'BROWSERROLE',
            arn: 'arn:aws:sts::' + input.role.arn.split(':')[4] + ':assumed-role/' + input.role.arn.split('/').at(-1) + '/browser' }
            : sourceIdentity;
          return { state: { authentication, region: input.region, ...(input.role ? { role: input.role } : {}), sourceIdentity, identity },
            credentials: input.role || authentication.kind === 'environment'
              ? { AWS_ACCESS_KEY_ID: 'browser-role-key', AWS_SECRET_ACCESS_KEY: 'browser-role-secret',
                AWS_SESSION_TOKEN: 'browser-role-session', AWS_DEFAULT_REGION: input.region, AWS_REGION: input.region }
              : { AWS_ACCESS_KEY_ID: authentication.accessKeyId, AWS_SECRET_ACCESS_KEY: authentication.secretAccessKey,
                AWS_SESSION_TOKEN: authentication.kind === 'session' ? authentication.sessionToken : '',
                AWS_DEFAULT_REGION: input.region, AWS_REGION: input.region } };
        },
      })));
    return machine;
  }
  override async stop(id: string) { await this.beforeDelete(id, 'stop'); agents.delete(id); sshAgents.delete(id); await super.stop(id); }
  override async removeVolume(id: string) { await this.beforeDelete(id, 'volume'); await super.removeVolume(id); }
}

const fixtureData = await fixture({ FLY_SSH_HOST: 'ssh.foundation.test' });
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
app.get<{ Params: { id: string } }>('/__test/executor/:id/roles', async request => roleRequests.get(request.params.id) ?? []);
app.get<{ Params: { id: string } }>('/__test/executor/:id/aws', async request => awsRequests.get(request.params.id) ?? []);
app.get<{ Params: { id: string } }>('/__test/executor/:id/oauth', async request => oauthRequests.get(request.params.id) ?? []);
app.post<{ Params: { id: string }; Body: { phase: 'stop' | 'volume'; mode: 'hold' | 'fail' | 'release' } }>(
  '/__test/deletion/:id', async request => {
    const { id } = request.params;
    if (request.body.mode === 'release') { deletions.get(id)?.release?.(); deletions.delete(id); }
    else {
      const plan: { phase: 'stop' | 'volume'; gate?: Promise<void>; release?: () => void; fail?: boolean } = { phase: request.body.phase };
      if (request.body.mode === 'hold') plan.gate = new Promise(resolve => { plan.release = resolve; });
      else plan.fail = true;
      deletions.set(id, plan);
    }
    return { ok: true };
  });
app.get<{ Params: { id: string } }>('/__test/executor/:id/fingerprint', async request => {
  const agent = agents.get(request.params.id);
  return agent ? { id: agent.binding.principalId, fingerprint: await fingerprint(agent.binding) } : null;
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
    const task = agent.tick().then(async () => {
      const ssh = sshAgents.get(id);
      if (ssh) {
        const state = await ssh.client.json('/api/environments/' + id + '/ssh/heartbeat', { method: 'POST',
          body: { hostKey: ssh.hostKey, appliedRevision: ssh.revision, activeSessions: 0 } }, SSHWorkerState);
        if (state.configuration) ssh.revision = state.configuration.revision;
      }
    }).catch(error => app.log.error(error)).finally(() => running.delete(id));
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
