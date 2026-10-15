import { fixture } from './support.js';
import { Operations } from '../shared/custody.js';
import { MemoryFiles, MemoryPayments, MemoryRunner } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { Worker } from '../server/worker.js';
import { randomUUID } from 'node:crypto';
import { fingerprint } from '../shared/authority.js';
import { FUNCTION_RUNTIME_VERSION, HTTP_RUNTIME_VERSION, signEnvironment } from '../shared/runtime-protocol.js';
import { Client } from '../cli/src/client.js';
import { HttpBroker } from '../runtime/broker.js';
import { Executor } from '../runtime/executor.js';
import { FunctionExecutor, FunctionBroker } from '../runtime/functions.js';
import { Connections } from '../runtime/connections.js';
import { CommandProcess } from '../runtime/command.js';
import { MemoryJournal } from './delegation-support.js';
import { DomainError } from '../server/errors.js';
import type { Transport } from '../server/transport.js';
import type { AwsConnectionRequest } from '../shared/aws.js';
import { ovhSignature } from '../runtime/ovh.js';

const agents = new Map<string, Executor>();
const functionAgents = new Map<string, FunctionExecutor>();
const running = new Map<string, Promise<void>>();
const disconnected = new Set<string>();
const roleRequests = new Map<string, Array<{ arn: string; externalId: string; region: string }>>();
const awsRequests = new Map<string, AwsConnectionRequest[]>();
const oauthRequests = new Map<string, Array<{ clientId: string | null; clientSecret: string | null; scope: string | null }>>();
const ovhApprovals = new Map<string, { redirection: string; consumerKey: string; rules: Array<{ method: string; path: string }>; approved: boolean }>();
const deletions = new Map<string, { phase: 'stop' | 'volume'; gate?: Promise<void>; release?: () => void; fail?: boolean }>();
class BrowserRunner extends MemoryRunner {
  private async beforeDelete(id: string, phase: 'stop' | 'volume') {
    const key = phase === 'stop' ? id : [...deletions.keys()].find(key => 'vol_' + key.replaceAll('-', '') === id);
    const plan = key ? deletions.get(key) : null;
    if (plan?.phase !== phase) return;
    if (plan.fail) { plan.fail = false; throw new DomainError(502, 'runner_unavailable', 'Provider unavailable'); }
    if (plan.gate) await plan.gate;
  }
  async attach(ownerId: string, name: string) {
    const id = randomUUID(), principal = await fixtureData.person(name + ' principal');
    const { keys, binding, token } = principal;
    await context.relations.draw({ id: ownerId }, { subjectId: principal.actor.id, relation: 'agent', objectId: ownerId });
    const client = new Client({ origin, principalId: binding.principalId, token, keys, binding });
    const registration = await signEnvironment({ format: 3, id, origin, ownerId,
      name, executor: binding, operatorId: binding.principalId, driver: 'attached',
      capabilities: Object.values(Operations), functionVersion: FUNCTION_RUNTIME_VERSION, httpVersion: HTTP_RUNTIME_VERSION, resultVersion: 1,
      isolation: 'process', awsPrincipal: 'arn:aws:iam::123456789012:role/service/foundation-test-executor', revision: 1 }, keys);
    await client.json('/api/environments/' + id + '/registration', { method: 'PUT', body: registration });
    const broker = new HttpBroker(client), journal = new MemoryJournal();
    const transport: Transport = { async send(request) {
      if (request.url === 'https://receiver.example/private-webhook' && request.method === 'POST') {
        const accepted = request.headers?.['content-type'] === 'application/json' &&
          request.headers?.Authorization === 'Bearer browser-private-bearer' && JSON.parse(String(request.body)).message === 'Hello';
        return { status: accepted ? 200 : 400, headers: { 'content-type': 'application/json' },
          body: new TextEncoder().encode(JSON.stringify({ accepted })) };
      }
      if (request.url.startsWith('https://ca.api.ovh.com/1.0/')) {
        const response = (body: unknown, status = 200) => ({ status, headers: { 'content-type': 'application/json' },
          body: new TextEncoder().encode(JSON.stringify(body)) });
        if (request.url.endsWith('/auth/time')) return response(Math.floor(Date.now() / 1000));
        if (request.url.endsWith('/auth/credential')) {
          const body = JSON.parse(String(request.body)), token = crypto.randomUUID();
          ovhApprovals.set(token, { redirection: body.redirection, rules: body.accessRules,
            consumerKey: 'consumer-' + token, approved: false });
          return response({ state: 'pendingValidation', consumerKey: 'consumer-' + token,
            validationUrl: 'https://auth.ca.ovhcloud.com/api/auth?credentialToken=' + token });
        }
        const bearer = request.headers?.Authorization?.startsWith('Bearer ');
        const consumerKey = request.headers?.['X-Ovh-Consumer'];
        const approval = [...ovhApprovals.values()].find(value => value.consumerKey === consumerKey);
        if (!bearer) {
          if (approval && !approval.approved) return response({ message: 'Not approved' }, 403);
          const credentials = { applicationKey: request.headers?.['X-Ovh-Application'] ?? '', applicationSecret: 'browser-app-secret', consumerKey: consumerKey ?? '' };
          if (request.headers?.['X-Ovh-Signature'] !== ovhSignature(credentials, request, Number(request.headers?.['X-Ovh-Timestamp'])))
            return response({ message: 'Invalid signature' }, 403);
        }
        if (request.url.endsWith('/auth/details')) return response({ account: 'aa12345-ovh',
          identities: ['urn:v1:ca:identity:' + (bearer ? 'user:aa12345-ovh/operator' : 'account:aa12345-ovh')],
          user: bearer ? 'operator' : null, description: bearer ? 'OVH operator' : 'OVH account', roles: null });
        if (request.url.endsWith('/auth/currentCredential')) return response({ credentialId: 123,
          status: 'validated', expiration: null, allowedIPs: null,
          rules: approval?.rules ?? [{ method: 'GET', path: '/auth/details' }, { method: 'GET', path: '/auth/currentCredential' }, { method: 'GET', path: '/vps/*' }] });
      }
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
    // The fixture attaches an optional runtime for protected operation tests.
    agents.set(id, new Executor(registration, keys, broker, journal, transport,
      new CommandProcess({ isolation: 'process' }), new Connections(binding, keys, broker.connections(), journal, transport, {
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
    functionAgents.set(id, new FunctionExecutor(agents.get(id)!, new FunctionBroker(client), journal));
    return { id, principalId: binding.principalId, fingerprint: await fingerprint(binding) };
  }
  override async stop(id: string) { await this.beforeDelete(id, 'stop'); await super.stop(id); }
  override async removeVolume(id: string) { await this.beforeDelete(id, 'volume'); await super.removeVolume(id); }
}

const fixtureData = await fixture();
const browserRunner = new BrowserRunner();
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
    storage: new MemoryFiles(),
    payments: new MemoryPayments(),
    runner: browserRunner, ssh: browserRunner.ssh,
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
app.post<{ Body: { ownerId: string; name: string } }>('/__test/executor', request =>
  browserRunner.attach(request.body.ownerId, request.body.name));
app.get<{ Params: { id: string } }>('/__test/executor/:id/roles', async request => roleRequests.get(request.params.id) ?? []);
app.get<{ Params: { id: string } }>('/__test/executor/:id/aws', async request => awsRequests.get(request.params.id) ?? []);
app.get<{ Params: { id: string } }>('/__test/executor/:id/oauth', async request => oauthRequests.get(request.params.id) ?? []);
app.post<{ Body: { credentialToken: string } }>('/__test/ovh/approve', async request => {
  const approval = ovhApprovals.get(request.body.credentialToken);
  if (!approval) throw new Error('Choose an existing OVH authorization request.');
  approval.approved = true;
  return { redirection: approval.redirection };
});
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
app.post<{ Params: { id: string }; Body: { connected: boolean } }>('/__test/executor/:id/connectivity', async request => {
  const { id } = request.params, agent = agents.get(id);
  if (!agent) throw new Error('Choose an existing execution environment.');
  if (request.body.connected) {
    await context.delegation.heartbeat({ id: agent.binding.principalId }, id);
    disconnected.delete(id);
  } else {
    disconnected.add(id);
    await running.get(id);
    await context.db.pool.query("UPDATE executor_environments SET heartbeat_at=now()-interval '2 minutes' WHERE resource_id=$1", [id]);
  }
  return { ok: true };
});
// A passkey registered where the browser could not wrap the private key for it.
app.post<{ Params: { id: string } }>('/__test/credentials/:id/unwrap', async request => {
  await context.db.pool.query('UPDATE credentials SET private_wrap=NULL WHERE id=$1', [request.params.id]);
  return { ok: true };
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
  for (const [id, agent] of agents) if (!running.has(id) && !disconnected.has(id)) {
    const task = agent.tick().then(() => functionAgents.get(id)?.tick())
      .catch(error => app.log.error(error)).finally(() => running.delete(id));
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
