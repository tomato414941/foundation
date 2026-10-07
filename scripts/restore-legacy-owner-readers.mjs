import { createHash, timingSafeEqual } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { calculateJwkThumbprint } from 'jose';

const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
class RepairError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const requireCondition = (condition, code) => { if (!condition) throw new RepairError(code); };

// A one-off repair for the pre-custody store. It only adds the existing owner's
// public key to server-readable secrets. It does not alter any access grants.
export async function restoreLegacyOwnerReaders({ db, vault, open, seal }, {
  ownerId, expectedCount, applyPlan,
}) {
  requireCondition(uuid.test(ownerId), 'invalid_owner');
  requireCondition(Number.isSafeInteger(expectedCount) && expectedCount >= 0, 'invalid_count');
  requireCondition(applyPlan === undefined || /^[a-f0-9]{64}$/.test(applyPlan), 'invalid_plan');
  return db.transaction(async connection => {
    await connection.query("SET LOCAL lock_timeout='5s'");
    await connection.query('SELECT pg_advisory_xact_lock(736023743)');
    const owner = await db.one('SELECT id,public_key FROM principals WHERE id=$1 FOR UPDATE', [ownerId], connection);
    requireCondition(owner?.public_key, 'owner_key_required');
    const ownerKeyFingerprint = await calculateJwkThumbprint(owner.public_key, 'sha256');
    const stored = await db.one("SELECT value FROM system_settings WHERE name='server-identity'", [], connection);
    requireCondition(stored?.value?.key && uuid.test(stored.value.id) && stored.value.id !== ownerId, 'legacy_identity_required');
    const server = stored.value;
    const rows = await db.all("SELECT id,owner_id,kind,name,data,sealed,version FROM resources WHERE owner_id=$1 AND kind='secret' ORDER BY id FOR UPDATE", [ownerId], connection);
    requireCondition(rows.length === expectedCount, 'resource_count_changed');
    const migrated = await db.one("SELECT to_regclass('resource_custody') AS name", [], connection);
    if (migrated.name) {
      const current = await db.one('SELECT count(*)::int AS count FROM resource_custody WHERE resource_id=ANY($1::uuid[])', [rows.map(row => row.id)], connection);
      requireCondition(current.count === 0, 'signed_custody_requires_client');
    }
    const planHash = digest({ ownerId, ownerKeyFingerprint, server: { id: server.id, publicKey: server.publicKey }, rows });
    if (applyPlan !== undefined) requireCondition(planHash === applyPlan, 'plan_changed');
    const pending = rows.filter(row => !row.sealed?.recipients?.some(recipient => recipient.header.kid === ownerId));
    // Restrict this repair to the observed server-only case; other recipients
    // require a separate plan that proves their keys and preserves their access.
    for (const row of pending) requireCondition(row.sealed?.recipients?.length === 1 &&
      row.sealed.recipients[0].header.kid === server.id, 'different_recipients');
    const serverKey = pending.length ? await vault.decrypt(server.key, 'server-identity') : null;
    if (serverKey) requireCondition(await calculateJwkThumbprint(serverKey, 'sha256') ===
      await calculateJwkThumbprint(server.publicKey, 'sha256'), 'legacy_key_changed');
    let verified = 0;
    for (const row of pending) {
      const context = 'resource:' + row.id;
      const bytes = await open(row.sealed, serverKey, server.id, context);
      let checked;
      try {
        const next = await seal(bytes, [{ id: server.id, publicKey: server.publicKey },
          { id: owner.id, publicKey: owner.public_key }], context);
        checked = await open(next, serverKey, server.id, context);
        requireCondition(bytes.length === checked.length && timingSafeEqual(bytes, checked), 'content_changed');
        requireCondition(next.recipients.length === 2 && next.recipients.some(item => item.header.kid === ownerId) &&
          next.recipients.some(item => item.header.kid === server.id), 'recipient_verification_failed');
        if (applyPlan !== undefined) {
          const data = { ...row.data, recipients: next.recipients.map(item => item.header.kid) };
          const changed = await connection.query(
            "UPDATE resources SET sealed=$3,data=$4,version=version+1,updated_at=now() WHERE id=$1 AND version=$2 AND owner_id=$5 AND kind='secret'",
            [row.id, row.version, JSON.stringify(next), JSON.stringify(data), ownerId]);
          requireCondition(changed.rowCount === 1, 'resource_changed');
          await connection.query('INSERT INTO audit_log(owner_id,actor_id,action,target_id,details) VALUES($1,NULL,$2,$3,$4)',
            [ownerId, 'secret.restoreOwnerRecipient', row.id, JSON.stringify({ ownerKeyFingerprint, planHash,
              previousVersion: row.version, source: 'operator-maintenance' })]);
        }
        verified++;
      } finally {
        bytes.fill(0); checked?.fill(0);
      }
    }
    return { ownerId, ownerKeyFingerprint, planHash, total: rows.length, verified,
      changed: applyPlan === undefined ? 0 : verified, mode: applyPlan === undefined ? 'preview' : 'apply' };
  });
}

async function main() {
  const { values } = parseArgs({ options: { owner: { type: 'string' }, count: { type: 'string' },
    apply: { type: 'string' }, 'expect-commit': { type: 'string' } } });
  requireCondition(values['expect-commit'] && process.env.FOUNDATION_COMMIT === values['expect-commit'], 'deployment_changed');
  requireCondition(process.env.DATABASE_URL && (process.env.FOUNDATION_KMS_KEY || process.env.FOUNDATION_KEY), 'runtime_configuration_required');
  const module = path => import(pathToFileURL(resolve('dist', path)).href);
  const [{ Database }, { Vault }, encryption] = await Promise.all([
    module('server/database.js'), module('server/vault.js'), module('shared/encryption.js'),
  ]);
  const db = new Database(process.env.DATABASE_URL);
  try {
    // Never initialize a schema or create replacement server keys during repair.
    const check = await db.one("SELECT 1 FROM system_settings WHERE name='key-check'");
    const key = process.env.FOUNDATION_KEY ? new Uint8Array(Buffer.from(process.env.FOUNDATION_KEY, 'base64url')) : null;
    const kmsKey = key || await db.one("SELECT 1 FROM system_settings WHERE name='kms-key'");
    requireCondition(check && kmsKey, 'existing_vault_required');
    const vault = await Vault.initialize(db, { key, FOUNDATION_KMS_KEY: process.env.FOUNDATION_KMS_KEY,
      AWS_REGION: process.env.AWS_REGION });
    console.log(JSON.stringify(await restoreLegacyOwnerReaders({ db, vault, open: encryption.open, seal: encryption.seal }, {
      ownerId: values.owner, expectedCount: Number(values.count), applyPlan: values.apply,
    })));
  } finally { await db.close(); }
}

if (process.argv[1] === '-' || (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)) {
  await main().catch(error => {
    console.error('Owner-reader repair failed: ' + (error instanceof RepairError ? error.code : 'verification_failed'));
    process.exitCode = 1;
  });
}
