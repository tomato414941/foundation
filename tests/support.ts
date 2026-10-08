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
import { Bindings } from '../server/bindings.js';
import { Custody } from '../server/custody.js';
import { KeySharing } from '../server/key-sharing.js';

export const databaseUrl =
  process.env.TEST_DATABASE_URL ??
  'postgres://foundation:foundation-local-test-only@127.0.0.1:55473/foundation_rebuild';
export class TestMailer implements Mailer {
  readonly enabled = true;
  readonly sent: Array<{ address: string; link: string; locale: 'ja' | 'en' }> = [];
  async send(address: string, link: string, locale: 'ja' | 'en') {
    this.sent.push({ address, link, locale });
  }
}
export async function fixture(overrides: Record<string, string> = {}) {
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
    FLY_COMMAND_IMAGE: 'docker.io/library/node@sha256:' + '1'.repeat(64),
    ...overrides,
  });
  const db = new Database(databaseUrl, { schema });
  await db.initialize();
  const vault = await Vault.initialize(db, config);
  const authorization = new Authorization(db),
    audit = new Audit(db),
    principals = new Principals(db, authorization, audit),
    relations = new Relations(db, authorization, audit, principals);
  const mailer = new TestMailer(),
    authentication = new Authentication(db, principals, authorization, audit, mailer, config);
  const resources = new Resources(db, authorization, audit, principals);
  const bindings = new Bindings(db, authorization, audit), custody = new Custody(resources, bindings, config.origin);
  principals.keySharing = new KeySharing(custody);
  async function person(name = 'Owner') {
    const identityKeys = await newIdentityKeys();
    const keys = { ...identityKeys, publicKey: publicPart(identityKeys.encryption), privateKey: identityKeys.encryption };
    const enrollment = await authentication.enroll(name, keys.publicKey);
    const actor = (await authentication.authenticate(enrollment.token))!;
    const binding = bindKeys(actor.id, identityKeys);
    await bindings.publish(actor, await signBinding(binding, identityKeys));
    return { ...enrollment, actor, keys, binding };
  }
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
    authentication,
    resources,
    mailer,
    person,
    close,
  };
}
