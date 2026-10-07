import type { Configuration } from './config.js';
import { Database } from './database.js';
import { Vault, ServerIdentity } from './vault.js';
import { Authorization } from './authorization.js';
import { Audit } from './audit.js';
import { Principals } from './principals.js';
import { Authentication } from './authentication.js';
import { ResendMailer } from './mail.js';
import type { Mailer } from './mail.js';
import { Resources } from './resources.js';
import { Catalog } from './catalog.js';
import { PublicTransport } from './transport.js';
import type { Transport } from './transport.js';
import { OAuth } from './oauth.js';
import { Services } from './services.js';
import type { RoleProvider } from './services.js';
import { Inputs } from './inputs.js';
import { HttpExecution } from './http-execution.js';
import { Billing, StripePayments } from './billing.js';
import type { PaymentProvider } from './billing.js';
import { Objects, S3Objects } from './objects.js';
import type { ObjectStore } from './objects.js';
import { FlyRunner } from './runner.js';
import type { Runner } from './runner.js';
import { Environments } from './environments.js';
import { Runs } from './runs.js';
import { Integrations } from './integrations.js';
import { Requests } from './requests.js';
import { Bindings } from './bindings.js';
import { Custody } from './custody.js';
import { Delegation } from './delegation.js';
import { ConnectionOperations } from './connection-operations.js';
import { OAuthRelays } from './oauth-relays.js';

export interface Dependencies {
  db?: Database;
  mailer?: Mailer;
  transport?: Transport;
  payments?: PaymentProvider;
  storage?: ObjectStore;
  runner?: Runner;
  roles?: RoleProvider;
}
export async function createContext(config: Configuration, deps: Dependencies = {}) {
  const db = deps.db ?? new Database(config.DATABASE_URL);
  await db.initialize();
  const vault = await Vault.initialize(db, config),
    identity = await ServerIdentity.initialize(db, vault),
    authorization = new Authorization(db),
    audit = new Audit(db),
    principals = new Principals(db, authorization, audit, identity.id);
  const mailer = deps.mailer ?? new ResendMailer(config.RESEND_API_KEY, config.FOUNDATION_MAIL_FROM),
    authentication = new Authentication(db, principals, authorization, audit, mailer, config);
  const resources = new Resources(db, authorization, audit, principals, identity),
    catalog = await Catalog.load(resources, config),
    transport = deps.transport ?? new PublicTransport(config.origin),
    oauth = new OAuth(transport),
    services = new Services(resources, catalog, vault, oauth, config, deps.roles),
    inputs = new Inputs(resources, services),
    http = new HttpExecution(resources, inputs, transport, config.origin);
  await services.initialize();
  const billing = new Billing(db, authorization, audit, deps.payments ?? new StripePayments(config), config),
    objects = new Objects(resources, billing, deps.storage ?? new S3Objects(config)),
    environments = new Environments(
      resources,
      authentication,
      billing,
      deps.runner ?? new FlyRunner(config),
      vault,
      config,
    ),
    runs = new Runs(resources, http, environments, inputs, vault);
  const integrations = new Integrations(db, authorization, vault, transport, config.origin),
    requests = new Requests(
      db,
      authorization,
      principals,
      authentication,
      integrations,
      audit,
      vault,
      config.origin,
    );
  services.checkApproval = (actor, connection) => requests.continuation(actor, connection);
  services.completed = (actor, result) => requests.completed(actor, result);
  services.cancelled = (actor) => requests.connectionCancelled(actor);
  const bindings = new Bindings(db, authorization, audit),
    custody = new Custody(resources, bindings, config.origin),
    delegation = new Delegation(resources, bindings, custody, config.origin),
    connectionOperations = new ConnectionOperations(custody),
    oauthRelays = new OAuthRelays(delegation);
  return {
    config,
    db,
    vault,
    identity,
    authorization,
    audit,
    principals,
    mailer,
    authentication,
    resources,
    catalog,
    transport,
    oauth,
    services,
    inputs,
    http,
    billing,
    objects,
    environments,
    runs,
    integrations,
    requests,
    bindings,
    custody,
    delegation,
    connectionOperations,
    oauthRelays,
  };
}
export type Context = Awaited<ReturnType<typeof createContext>>;
