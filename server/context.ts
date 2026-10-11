import type { Configuration } from './config.js';
import { Database } from './database.js';
import { Vault } from './vault.js';
import { Authorization } from './authorization.js';
import { Audit } from './audit.js';
import { Principals } from './principals.js';
import { Relations } from './relations.js';
import { Authentication } from './authentication.js';
import { ResendMailer } from './mail.js';
import type { Mailer } from './mail.js';
import { Resources } from './resources.js';
import { Catalog } from './catalog.js';
import { PublicTransport } from './transport.js';
import type { Transport } from './transport.js';
import { Functions } from './functions.js';
import { KeySharing } from './key-sharing.js';
import { Billing, StripePayments } from './billing.js';
import type { PaymentProvider } from './billing.js';
import { Objects, S3Objects } from './objects.js';
import type { ObjectStore } from './objects.js';
import { EC2Runner } from './ec2-runner.js';
import type { Runner } from './runner.js';
import { Environments } from './environments.js';
import { Integrations } from './integrations.js';
import { Requests } from './requests.js';
import { Devices } from './devices.js';
import { Bindings } from './bindings.js';
import { Custody } from './custody.js';
import { Delegation } from './delegation.js';
import { ConnectionOperations } from './connection-operations.js';
import { OAuthRelays } from './oauth-relays.js';
import { Operations } from '../shared/custody.js';
import { builtinDefinitions } from './builtin-definitions.js';
import { Executions } from './executions.js';
import { migrateExecutions } from './migrate-executions.js';
import { migrateRequests } from './migrate-requests.js';
import { canonical } from '../shared/authority.js';
import { fail, DomainError } from './errors.js';
import { Processes } from './processes.js';
import { Invocations } from './invocations.js';

export interface Dependencies {
  db?: Database;
  mailer?: Mailer;
  transport?: Transport;
  payments?: PaymentProvider;
  storage?: ObjectStore;
  runner?: Runner;
}
export async function createContext(config: Configuration, deps: Dependencies = {}) {
  const db = deps.db ?? new Database(config.DATABASE_URL);
  if (!deps.runner) {
    const tables = await db.one<{ jobs: string | null; resources: string | null }>(
      "SELECT to_regclass('environment_jobs') AS jobs,to_regclass('resources') AS resources");
    if (tables?.jobs && tables.resources && await db.one(
      "SELECT 1 FROM environment_jobs j JOIN resources r ON r.id=j.resource_id WHERE r.data->>'driver'='managed' AND to_jsonb(j)->>'provider' IS DISTINCT FROM 'ec2' LIMIT 1"))
      throw new Error('Migrate existing managed environment disks and provider records before starting the EC2 deployment.');
  }
  await db.initialize();
  const vault = await Vault.initialize(db, config),
    authorization = new Authorization(db),
    audit = new Audit(db),
    principals = new Principals(db, authorization, audit),
    resources = new Resources(db, authorization, audit, principals),
    billing = new Billing(db, authorization, audit, deps.payments ?? new StripePayments(config), config),
    relations = new Relations(db, authorization, audit, principals, resources, billing);
  const mailer = deps.mailer ?? new ResendMailer(config.RESEND_API_KEY, config.FOUNDATION_MAIL_FROM),
    authentication = new Authentication(db, principals, authorization, audit, mailer, config);
  const catalog = await Catalog.load(resources, config),
    transport = deps.transport ?? new PublicTransport(config.origin),
    functions = new Functions(resources, config.origin);
  const bindings = new Bindings(db, authorization, audit),
    custody = new Custody(resources, bindings, relations, config.origin),
    delegation = new Delegation(resources, bindings, custody, config.origin),
    connectionOperations = new ConnectionOperations(custody),
    oauthRelays = new OAuthRelays(delegation);
  const processes = new Processes(resources, delegation);
  const invocations = new Invocations(functions, custody, delegation);
  principals.keySharing = new KeySharing(custody);
  const objects = new Objects(resources, billing, deps.storage ?? new S3Objects(config)),
    environments = new Environments(
      resources,
      billing,
      deps.runner ?? new EC2Runner(config),
      vault,
      config,
      delegation,
    );
  const devices = new Devices(db, authorization, audit, config.origin);
  const integrations = new Integrations(db, authorization, config.origin);
  const definitions = builtinDefinitions({ authorization, principals, relations, resources, catalog, environments,
    objects, billing, processes, integrations, custody, delegation, functions, invocations });
  await migrateExecutions(db, vault);
  await migrateRequests(db);
  const executions = new Executions(db, vault, authorization, definitions, audit, principals, config.origin);
  executions.runtime = {
    get: (actor, reference) => reference.kind === 'run' ? delegation.get(actor, reference.id) : invocations.get(actor, reference.id),
    cancel: (actor, reference) => reference.kind === 'run' ? delegation.cancel(actor, reference.id) : invocations.cancel(actor, reference.id),
  };
  await executions.importRuntimeHistory();
  const requests = new Requests(db, authorization, authentication, config.origin, executions);
  delegation.checkOperationContext = async (actor, intent) => {
    const context = intent.operationContext!, { plan } = await executions.input(actor, context.id);
    if (context.index !== plan.index || canonical(context.invocation) !== canonical(plan.invocation) ||
      canonical(intent.approval ?? null) !== canonical(plan.approval ?? null) ||
      (plan.invocation.name === 'connection.connect' && (plan.continuation?.kind !== 'connection' || plan.continuation.id !== context.continuationId)) ||
      (['run.execute', 'connection.revoke'].includes(plan.invocation.name) && (plan.continuation?.kind !== 'run' || plan.continuation.id !== intent.id)))
      fail(409, 'operation_changed', 'Use the prepared operation and its current continuation.');
  };
  delegation.completed = async task => {
    const execution = task.intent.operationContext;
    if (!execution) return;
    const proof = task.kind === 'connect'
      ? await db.one<{ id: string }>("SELECT resource_id AS id FROM resource_custody WHERE content->>'creationRunId'=$1", [task.id])
      : null;
    if (task.kind === 'connect' && !proof) return;
    try {
      await executions.complete({ id: task.actorId }, execution.id, execution.index,
        proof ? { runId: task.id, resourceId: proof.id } : { runId: task.id });
    } catch (error) {
      if (!(error instanceof DomainError) || error.status >= 500) throw error;
    }
  };
  delegation.checkApproval = async (actor, intent) => {
    const { plan } = await executions.input(actor, intent.approval!.id), input = plan.invocation.input;
    const kind = plan.invocation.name === 'connection.connect' ? 'connect' : plan.invocation.name === 'run.execute'
      ? (input.operation as { kind: keyof typeof Operations }).kind : plan.invocation.name === 'connection.revoke' ? 'revoke' : null;
    if (!intent.operationContext || intent.operationContext.id !== intent.approval!.id || plan.index !== intent.approval!.index ||
      input.ownerId !== intent.ownerId || !kind || intent.operation !== Operations[kind] ||
      (input.environmentId && input.environmentId !== intent.environmentId))
      throw new Error('Use the operation and execution environment approved by this request.');
  };
  return {
    config,
    db,
    vault,
    authorization,
    audit,
    principals,
    relations,
    mailer,
    authentication,
    resources,
    catalog,
    transport,
    functions,
    billing,
    objects,
    environments,
    integrations,
    requests,
    definitions,
    executions,
    devices,
    bindings,
    custody,
    delegation,
    connectionOperations,
    oauthRelays,
    processes,
    invocations,
  };
}
export type Context = Awaited<ReturnType<typeof createContext>>;
