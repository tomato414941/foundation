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
import { encode, newIdentityKeys, publicPart } from '../shared/encryption.js';
import type { IdentityKeysValue } from '../shared/encryption.js';
import { sealItem } from '../shared/custody.js';
import type { JsonValue } from '../shared/contracts.js';
import type { ProtectedKindName } from '../shared/protected.js';
import type { Actor } from '../server/authorization.js';
import { KeyResets } from '../server/key-resets.js';
import { Custody } from '../server/custody.js';
import { KeySharing } from '../server/key-sharing.js';

function testDatabaseUrl() {
  const value = process.env.TEST_DATABASE_URL;
  if (!value) throw new Error('Run npm test or npm run test:ui, or set TEST_DATABASE_URL.');
  return value;
}
export const databaseUrl = testDatabaseUrl();
export class TestMailer implements Mailer {
  readonly enabled = true;
  readonly sent: Array<{ address: string; link: string; locale: 'ja' | 'en' }> = [];
  async send(address: string, link: string, locale: 'ja' | 'en') {
    this.sent.push({ address, link, locale });
  }
}
// Registers an identity with its key, as the CLI does.
export async function enroll(authentication: Authentication, name: string, keys?: IdentityKeysValue) {
  const identityKeys = keys ?? await newIdentityKeys();
  return { ...await authentication.enroll(name, publicPart(identityKeys.encryption)), keys: identityKeys };
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
    ...overrides,
  });
  const db = new Database(databaseUrl, { schema });
  await db.migrate();
  const vault = await Vault.initialize(db, config);
  const authorization = new Authorization(db),
    audit = new Audit(db),
    principals = new Principals(db, authorization, audit),
    resources = new Resources(db, authorization, audit, principals),
    mailer = new TestMailer(),
    relations = new Relations(db, authorization, audit, principals, resources);
  const authentication = new Authentication(db, principals, authorization, audit, mailer, config),
    keyResets = new KeyResets(db, authorization, audit, config);
  const custody = new Custody(resources, relations);
  principals.keySharing = new KeySharing(custody);
  async function person(name = 'Owner') {
    const identityKeys = await newIdentityKeys();
    const keys = { ...identityKeys, publicKey: publicPart(identityKeys.encryption), privateKey: identityKeys.encryption };
    const enrollment = await enroll(authentication, name, identityKeys);
    const actor = (await authentication.authenticate(enrollment.token))!;
    return { ...enrollment, actor, keys };
  }
  // Seals a value for whoever may open a new item of the owner's, as a device does, and saves it as that item.
  async function keep(actor: Actor, ownerId: string, name: string, value: string,
    kind: ProtectedKindName = 'variable', metadata?: Record<string, JsonValue>) {
    const bytes = encode(value), id = randomUUID();
    const content = await sealItem(bytes, await custody.ownerRecipients(ownerId), 1, metadata ?? { bytes: bytes.byteLength });
    return custody.put(actor, { id, name, kind, ownerId, content });
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
    custody,
    authorization,
    audit,
    principals,
    relations,
    authentication,
    keyResets,
    resources,
    mailer,
    person,
    keep,
    close,
  };
}
