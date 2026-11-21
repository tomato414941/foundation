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
import { KeySharing } from './key-sharing.js';
import { Objects, S3Objects } from './objects.js';
import type { ObjectStore } from './objects.js';
import { SSHAccess } from './ssh-access.js';
import { Integrations } from './integrations.js';
import { Requests } from './requests.js';
import { Devices } from './devices.js';
import { KeyResets } from './key-resets.js';
import { Custody } from './custody.js';
import { ConnectionOperations } from './connection-operations.js';
import { OAuthRelays } from './oauth-relays.js';
import { builtinDefinitions } from './builtin-definitions.js';
import { Operations } from './operations.js';

export interface Dependencies {
  db?: Database;
  mailer?: Mailer;
  transport?: Transport;
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
    mailer = deps.mailer ?? new ResendMailer(config.RESEND_API_KEY, config.FOUNDATION_MAIL_FROM),
    relations = new Relations(db, authorization, audit, principals, resources);
  const authentication = new Authentication(db, principals, authorization, audit, mailer, config),
    keyResets = new KeyResets(db, authorization, audit, config);
  const catalog = await Catalog.load(resources, config),
    transport = deps.transport ?? new PublicTransport(config.origin);
  const custody = new Custody(resources, relations),
    connectionOperations = new ConnectionOperations(custody),
    oauthRelays = new OAuthRelays(resources, custody, config.origin, () => operations);
  principals.keySharing = new KeySharing(custody);
  const objects = new Objects(resources, deps.storage ?? new S3Objects(config), config.FOUNDATION_INCLUDED_STORAGE_BYTES);
  const devices = new Devices(db, authorization, audit, config.origin);
  const integrations = new Integrations(db, authorization, config.origin);
  const sshAccess = new SSHAccess(db, resources, audit);
  const definitions = builtinDefinitions({ authorization, principals, relations, resources, catalog,
    objects, integrations, custody, sshAccess });
  // Each side of a change that needs another's agreement reaches the other: an operation asks through a request, and an
  // approved request makes its operations.
  let requests: Requests;
  const operations = new Operations(db, vault, authorization, definitions, principals, config.origin, () => requests);
  requests = new Requests(db, vault, authorization, definitions, principals, audit, config.origin, operations);
  const context = {
    config,
    db,
    vault,
    authorization,
    audit,
    principals,
    relations,
    mailer,
    authentication,
    keyResets,
    sshAccess,
    resources,
    catalog,
    transport,
    objects,
    integrations,
    requests,
    definitions,
    operations,
    devices,
    custody,
    connectionOperations,
    oauthRelays,
  };
  return context;
}
export type Context = Awaited<ReturnType<typeof createContext>>;
