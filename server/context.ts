import type { Configuration } from './config.js';
import { Database } from './database.js';
import { Vault } from './vault.js';
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
import { Functions } from './functions.js';
import { KeySharing } from './key-sharing.js';
import { Billing, StripePayments } from './billing.js';
import type { PaymentProvider } from './billing.js';
import { Objects, S3Objects } from './objects.js';
import type { ObjectStore } from './objects.js';
import { FlyRunner } from './runner.js';
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
  await db.initialize();
  const vault = await Vault.initialize(db, config),
    authorization = new Authorization(db),
    audit = new Audit(db),
    principals = new Principals(db, authorization, audit);
  const mailer = deps.mailer ?? new ResendMailer(config.RESEND_API_KEY, config.FOUNDATION_MAIL_FROM),
    authentication = new Authentication(db, principals, authorization, audit, mailer, config);
  const resources = new Resources(db, authorization, audit, principals),
    catalog = await Catalog.load(resources, config),
    transport = deps.transport ?? new PublicTransport(config.origin),
    functions = new Functions(resources, config.origin);
  const bindings = new Bindings(db, authorization, audit),
    custody = new Custody(resources, bindings, config.origin),
    delegation = new Delegation(resources, bindings, custody, config.origin),
    connectionOperations = new ConnectionOperations(custody),
    oauthRelays = new OAuthRelays(delegation);
  principals.keySharing = new KeySharing(custody);
  const billing = new Billing(db, authorization, audit, deps.payments ?? new StripePayments(config), config),
    objects = new Objects(resources, billing, deps.storage ?? new S3Objects(config)),
    environments = new Environments(
      resources,
      billing,
      deps.runner ?? new FlyRunner(config),
      vault,
      config,
      delegation,
    );
  const devices = new Devices(db, authorization, audit, config.origin);
  const integrations = new Integrations(db, authorization, config.origin),
    requests = new Requests(
      db,
      authorization,
      principals,
      authentication,
      audit,
      vault,
      config.origin,
    );
  delegation.checkApproval = async (actor, intent) => {
    const plan = await requests.connectionPlan(actor, intent.approval!.id);
    if (plan.index !== intent.approval!.index || plan.input.ownerId !== intent.ownerId || intent.operation !== 'connect' ||
      (plan.input.environmentId && plan.input.environmentId !== intent.environmentId))
      throw new Error('Use the connection and execution environment approved by this request.');
  };
  return {
    config,
    db,
    vault,
    authorization,
    audit,
    principals,
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
    devices,
    bindings,
    custody,
    delegation,
    connectionOperations,
    oauthRelays,
  };
}
export type Context = Awaited<ReturnType<typeof createContext>>;
