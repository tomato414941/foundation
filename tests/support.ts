import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { configuration } from '../server/config.js';
import { Database } from '../server/database.js';
import { Vault } from '../server/vault.js';
import { Authorization } from '../server/authorization.js';
import { Audit } from '../server/audit.js';
import { Principals } from '../server/principals.js';
import { Relations } from '../server/relations.js';
import { Authentication } from '../server/authentication.js';
import { Resources } from '../server/resources.js';
import type { Mailer } from '../server/mail.js';
import { bindKeys, newIdentityKeys, publicPart, signBinding } from '../shared/authority.js';
import type { IdentityKeys } from '../shared/authority.js';
import { Confirmations } from '../server/confirmations.js';
import type { Actor } from '../server/authorization.js';
import type { ConfirmationOperation } from '../shared/confirmations.js';
import { confirmedActor } from './confirmation-support.js';
import { Bindings } from '../server/bindings.js';
import { KeyResets } from '../server/key-resets.js';
import { Custody } from '../server/custody.js';
import { KeySharing } from '../server/key-sharing.js';
import { Billing, StripePayments } from '../server/billing.js';
import type { PaymentProvider } from '../server/billing.js';

function testDatabaseUrl() {
  const value = process.env.TEST_DATABASE_URL;
  if (!value) throw new Error('Run npm test or npm run test:ui, or set TEST_DATABASE_URL.');
  return value;
}
export const databaseUrl = testDatabaseUrl();
export class TestMailer implements Mailer {
  readonly enabled = true;
  readonly sent: Array<{ address: string; link: string; locale: 'ja' | 'en' }> = [];
  readonly codes: Array<{ address: string; code: string; locale: 'ja' | 'en' }> = [];
  async send(address: string, link: string, locale: 'ja' | 'en') {
    this.sent.push({ address, link, locale });
  }
  async sendCode(address: string, code: string, locale: 'ja' | 'en') {
    this.codes.push({ address, code, locale });
  }
}
// Registers an identity with its keys, as the CLI does.
export async function enroll(authentication: Authentication, name: string, keys?: IdentityKeys) {
  const identityKeys = keys ?? await newIdentityKeys(), binding = bindKeys(randomUUID(), identityKeys);
  return { ...await authentication.enroll(name, await signBinding(binding, identityKeys)), keys: identityKeys, binding };
}
export async function fixture(overrides: Record<string, string> = {}, payments?: PaymentProvider) {
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({ connectionString: databaseUrl });
  await admin.query(`CREATE SCHEMA "${schema}"`);
  const dataDirectory = await mkdtemp(join(tmpdir(), 'foundation-test-'));
  const config = await configuration({
    DATABASE_URL: databaseUrl,
    FOUNDATION_KEY: randomBytes(32).toString('base64url'),
    FOUNDATION_DATA: dataDirectory,
    FOUNDATION_ORIGIN: 'https://foundation.test',
    FOUNDATION_LOG_LEVEL: 'silent',
    ...overrides,
  });
  const db = new Database(databaseUrl, { schema });
  await db.migrate();
  const vault = await Vault.initialize(db, config);
  const authorization = new Authorization(db),
    audit = new Audit(db),
    principals = new Principals(db, authorization, audit),
    resources = new Resources(db, authorization, audit, principals),
    billing = new Billing(db, authorization, audit, payments ?? new StripePayments(config), config),
    mailer = new TestMailer(),
    confirmations = new Confirmations(db, mailer, config),
    relations = new Relations(db, authorization, audit, principals, resources, billing, confirmations);
  const authentication = new Authentication(db, principals, authorization, audit, mailer, config, confirmations),
    keyResets = new KeyResets(db, authorization, audit, config);
  const bindings = new Bindings(db, authorization, audit, confirmations), custody = new Custody(resources, bindings, relations, config.origin);
  principals.keySharing = new KeySharing(custody);
  async function person(name = 'Owner') {
    const identityKeys = await newIdentityKeys();
    const keys = { ...identityKeys, publicKey: publicPart(identityKeys.encryption), privateKey: identityKeys.encryption };
    const { binding, ...enrollment } = await enroll(authentication, name, identityKeys);
    const actor = (await authentication.authenticate(enrollment.token))!;
    return { ...enrollment, actor, keys, binding };
  }
  // The person's actor carrying a confirmation of the change, signed with its keys, as a client confirms it.
  const confirmed = (person: { actor: Actor; keys: IdentityKeys }, operation: ConfirmationOperation) =>
    confirmedActor(confirmations, person.actor, person.keys, operation);
  async function close() {
    await db.close();
    await admin.query(`DROP SCHEMA "${schema}" CASCADE`);
    await admin.end();
    await rm(dataDirectory, { recursive: true, force: true });
  }
  return {
    config,
    db,
    vault,
    bindings,
    custody,
    authorization,
    audit,
    principals,
    relations,
    billing,
    authentication,
    confirmations,
    keyResets,
    resources,
    mailer,
    person,
    confirmed,
    close,
  };
}
