import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

const requireState = (condition, code) => { if (!condition) throw new Error(code); };

// Complete the existing server identity in its own vault. Keep the encryption
// key and legacy wrapper while connections still depend on their old format.
export async function migrateServerIdentity({ db, vault, authority }, { principalId, apply = false }) {
  const { canonical, completeKeys, fingerprint, bindKeys, signBinding, verifyBinding, hash } = authority;
  return db.transaction(async connection => {
    await connection.query("SET LOCAL lock_timeout='5s'");
    await connection.query('SELECT pg_advisory_xact_lock(736023743)');
    const stored = await db.one("SELECT value FROM system_settings WHERE name='server-identity' FOR UPDATE", [], connection);
    const state = stored?.value;
    requireState(state?.id === principalId && state.key, 'server_identity_mismatch');
    const principal = await db.one('SELECT id,name,public_key FROM principals WHERE id=$1 FOR UPDATE', [principalId], connection);
    requireState(principal?.public_key, 'principal_key_required');
    const legacy = await vault.decrypt(state.key, 'server-identity');
    const encryptionFingerprint = await fingerprint(legacy);
    requireState(encryptionFingerprint === await fingerprint(principal.public_key) &&
      encryptionFingerprint === await fingerprint(state.publicKey), 'encryption_key_mismatch');
    const current = await db.one('SELECT binding,signature FROM principal_key_bindings WHERE principal_id=$1 AND retired_at IS NULL', [principalId], connection);
    if (current || state.keys) {
      requireState(current && state.keys && state.format === 1, 'incomplete_migration');
      await verifyBinding(current);
      const { keys, completed } = await completeKeys(await vault.decrypt(state.keys, 'server-identity:keys'));
      requireState(!completed && canonical(current.binding) === canonical(state.binding) &&
        encryptionFingerprint === await fingerprint(keys.encryption) &&
        await fingerprint(keys.signing) === await fingerprint(current.binding.signing) &&
        current.binding.principalId === principalId &&
        encryptionFingerprint === await fingerprint(current.binding.encryption), 'binding_key_mismatch');
      return { principalId, encryptionFingerprint, bindingId: current.binding.id, migrated: true, changed: false };
    }
    if (!apply) return { principalId, encryptionFingerprint, migrated: false, changed: false };
    const { keys } = await completeKeys(legacy);
    const binding = bindKeys(principalId, keys), signed = await signBinding(binding, keys);
    await verifyBinding(signed);
    const wrapped = await vault.encrypt(keys, 'server-identity:keys');
    const checked = await vault.decrypt(wrapped, 'server-identity:keys');
    requireState(canonical(keys) === canonical(checked), 'wrapped_key_mismatch');
    await connection.query('INSERT INTO principal_key_bindings(id,principal_id,binding,signature) VALUES($1,$2,$3,$4)',
      [binding.id, principalId, JSON.stringify(binding), signed.signature]);
    await connection.query("UPDATE system_settings SET value=$1 WHERE name='server-identity'",
      [JSON.stringify({ ...state, format: 1, keys: wrapped, binding })]);
    await connection.query('INSERT INTO audit_log(owner_id,actor_id,action,target_id,details) VALUES($1,NULL,$2,$3,$4)',
      [principalId, 'principal.bindKeys', binding.id, JSON.stringify({ generation: 1, source: 'operator-maintenance',
        encryptionFingerprint, bindingHash: await hash(binding) })]);
    return { principalId, encryptionFingerprint, bindingId: binding.id, migrated: true, changed: true };
  });
}

async function main() {
  const { values } = parseArgs({ options: { principal: { type: 'string' }, apply: { type: 'boolean' },
    'expect-commit': { type: 'string' } } });
  requireState(values['expect-commit'] && process.env.FOUNDATION_COMMIT === values['expect-commit'], 'deployment_changed');
  requireState(/^[a-f0-9-]{36}$/.test(values.principal ?? ''), 'principal_required');
  const module = path => import(pathToFileURL(resolve('dist', path)).href);
  const [{ Database }, { Vault }, authority] = await Promise.all([
    module('server/database.js'), module('server/vault.js'), module('shared/authority.js'),
  ]);
  const db = new Database(process.env.DATABASE_URL);
  try {
    requireState(await db.one("SELECT 1 FROM system_settings WHERE name='key-check'"), 'existing_vault_required');
    const key = process.env.FOUNDATION_KEY ? new Uint8Array(Buffer.from(process.env.FOUNDATION_KEY, 'base64url')) : null;
    requireState(key || await db.one("SELECT 1 FROM system_settings WHERE name='kms-key'"), 'existing_vault_required');
    const vault = await Vault.initialize(db, { key, FOUNDATION_KMS_KEY: process.env.FOUNDATION_KMS_KEY, AWS_REGION: process.env.AWS_REGION });
    console.log(JSON.stringify(await migrateServerIdentity({ db, vault, authority }, { principalId: values.principal, apply: values.apply })));
  } finally { await db.close(); }
}

if (process.argv[1] === '-' || (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)) {
  await main().catch(() => { console.error('Server identity migration failed verification.'); process.exitCode = 1; });
}
