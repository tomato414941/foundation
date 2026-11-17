import type { Configuration } from './config.js';
import { Database } from './database.js';
import { Vault } from './vault.js';
import { Authorization } from './authorization.js';
import { Audit } from './audit.js';
import { Principals } from './principals.js';
import { Relations } from './relations.js';
import { Authentication } from './authentication.js';
import { Confirmations } from './confirmations.js';
import { ResendMailer } from './mail.js';
import type { Mailer } from './mail.js';
import { Resources } from './resources.js';
import { Catalog } from './catalog.js';
import { PublicTransport } from './transport.js';
import type { Transport } from './transport.js';
import { KeySharing } from './key-sharing.js';
import { Billing, StripePayments } from './billing.js';
import type { PaymentProvider } from './billing.js';
import { Objects, S3Objects } from './objects.js';
import type { ObjectStore } from './objects.js';
import { SSHAccess } from './ssh-access.js';
import { Integrations } from './integrations.js';
import { Requests } from './requests.js';
import { Devices } from './devices.js';
import { Bindings } from './bindings.js';
import { KeyResets } from './key-resets.js';
import { KeyRotations } from './key-rotations.js';
import { Keyrings } from './keyrings.js';
import { Custody } from './custody.js';
import { ConnectionOperations } from './connection-operations.js';
import { OAuthRelays } from './oauth-relays.js';
import { builtinDefinitions } from './builtin-definitions.js';
import { Executions } from './executions.js';

export interface Dependencies {
  db?: Database;
  mailer?: Mailer;
  transport?: Transport;
  payments?: PaymentProvider;
  storage?: ObjectStore;
}
export async function createContext(config: Configuration, deps: Dependencies = {}, options: { migrate?: boolean } = {}) {
  const db = deps.db ?? new Database(config.DATABASE_URL);
  if (options.migrate) await db.migrate();
  else await db.assertReady();
  const vault = await Vault.initialize(db, config),
    authorization = new Authorization(db),
    audit = new Audit(db),
    principals = new Principals(db, authorization, audit),
    resources = new Resources(db, authorization, audit, principals),
    billing = new Billing(db, authorization, audit, deps.payments ?? new StripePayments(config), config),
    mailer = deps.mailer ?? new ResendMailer(config.RESEND_API_KEY, config.FOUNDATION_MAIL_FROM),
    confirmations = new Confirmations(db, mailer, config),
    relations = new Relations(db, authorization, audit, principals, resources, billing, confirmations);
  const authentication = new Authentication(db, principals, authorization, audit, mailer, config, confirmations),
    keyResets = new KeyResets(db, authorization, audit, config);
  const catalog = await Catalog.load(resources, config),
    transport = deps.transport ?? new PublicTransport(config.origin);
  const bindings = new Bindings(db, authorization, audit, confirmations),
    keyrings = new Keyrings(db, authorization, audit, resources, bindings, config.origin),
    custody = new Custody(resources, bindings, relations, config.origin),
    connectionOperations = new ConnectionOperations(custody),
    oauthRelays = new OAuthRelays(resources, bindings, config.origin, () => executions);
  const keyRotations = new KeyRotations(custody);
  principals.keySharing = new KeySharing(custody);
  const objects = new Objects(resources, billing, deps.storage ?? new S3Objects(config));
  const devices = new Devices(db, authorization, audit, config.origin);
  const integrations = new Integrations(db, authorization, config.origin);
  const sshAccess = new SSHAccess(db, resources, audit, confirmations);
  const definitions = builtinDefinitions({ authorization, principals, relations, resources, catalog,
    objects, billing, integrations, custody, sshAccess });
  const executions = new Executions(db, vault, authorization, definitions, audit, principals, config.origin, confirmations);
  const requests = new Requests(db, authorization, authentication, config.origin, executions);
  const context = {
    config,
    db,
    vault,
    authorization,
    audit,
    principals,
    relations,
    mailer,
    confirmations,
    authentication,
    keyResets,
    keyRotations,
    sshAccess,
    resources,
    catalog,
    transport,
    billing,
    objects,
    integrations,
    requests,
    definitions,
    executions,
    devices,
    bindings,
    keyrings,
    custody,
    connectionOperations,
    oauthRelays,
  };
  if (options.migrate) {
    const [{ migrateExecutions }, { migrateRequests }, { migrateFiles }, { migrateStorage }, { migrateDelegates }, { removeEnvironments }] = await Promise.all([
      import('./migrations/migrate-executions.js'), import('./migrations/migrate-requests.js'),
      import('./migrations/migrate-files.js'), import('./migrations/migrate-storage.js'), import('./migrations/migrate-delegates.js'),
      import('./migrations/remove-environments.js'),
    ]);
    await migrateExecutions(db, vault);
    await migrateRequests(db);
    await migrateFiles(db, vault);
    await migrateStorage(db, vault);
    await migrateDelegates(db, vault);
    await removeEnvironments(db, vault);
    await db.assertReady();
  }
  return context;
}
export type Context = Awaited<ReturnType<typeof createContext>>;
