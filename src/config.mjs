import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { resolve } from 'node:path';

export function configuration(env = process.env) {
  const dataDir = resolve(env.FOUNDATION_DATA_DIR || '.foundation');
  const database = resolve(dataDir, 'state.sqlite');
  const port = Number(env.FOUNDATION_PORT || 3417);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid FOUNDATION_PORT');
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  chmodSync(dataDir, 0o700);
  const keyPath = resolve(dataDir, 'encryption-key');
  const kms = { keyId: env.FOUNDATION_KMS_KEY_ID || '', region: env.FOUNDATION_AWS_REGION || 'ap-northeast-1' };
  const bind = env.FOUNDATION_BIND || '127.0.0.1';
  if (!/^(127\.0\.0\.1|0\.0\.0\.0|::1|::)$/.test(bind)) throw new Error('FOUNDATION_BIND must be 127.0.0.1, 0.0.0.0, ::1 or ::');
  let encodedKey = env.FOUNDATION_ENCRYPTION_KEY;
  if (!encodedKey) {
    if (!existsSync(keyPath) && !kms.keyId) {
      if (existsSync(database)) throw new Error('Existing encrypted database requires its original encryption key');
      writeFileSync(keyPath, randomBytes(32).toString('base64') + '\n', { flag: 'wx', mode: 0o600 });
    }
    if (existsSync(keyPath)) { chmodSync(keyPath, 0o600); encodedKey = readFileSync(keyPath, 'utf8').trim(); }
  }
  // With KMS, a missing plaintext key means the wrapped key in the database (or a fresh key) is used.
  const encryptionKey = encodedKey ? Buffer.from(encodedKey, 'base64') : null;
  if (encryptionKey && (encryptionKey.length !== 32 || encryptionKey.toString('base64') !== encodedKey)) throw new Error('FOUNDATION_ENCRYPTION_KEY must be 32 bytes encoded as base64');
  if (!encryptionKey && !kms.keyId) throw new Error('No encryption key: set FOUNDATION_ENCRYPTION_KEY, keep the key file, or configure FOUNDATION_KMS_KEY_ID');
  return {
    dataDir, database, port, bind, encryptionKey, kms, trustedProxies: (env.FOUNDATION_TRUSTED_PROXIES || '').split(',').map(value => value.trim()).filter(Boolean),
    publicOrigin: env.FOUNDATION_PUBLIC_ORIGIN || undefined,
    // Sign-in links go out through Resend, from this address.
    mail: { key: env.FOUNDATION_RESEND_API_KEY || '', from: env.FOUNDATION_EMAIL_FROM || '' },
    // Charging for what is used beyond the free part, through Foundation's Stripe account and its two metered prices.
    stripe: { key: env.FOUNDATION_STRIPE_API_KEY || '', computePrice: env.FOUNDATION_STRIPE_COMPUTE_PRICE || '', storagePrice: env.FOUNDATION_STRIPE_STORAGE_PRICE || '', webhookSecret: env.FOUNDATION_STRIPE_WEBHOOK_SECRET || '' },
    // Lent machines run on Fly Machines when a runner app, its token and the machine image are all given.
    runner: { token: env.FOUNDATION_FLY_TOKEN || '', app: env.FOUNDATION_FLY_APP || '', image: env.FOUNDATION_FLY_IMAGE || '', region: env.FOUNDATION_FLY_REGION || 'nrt' },
    objects: { bucket: env.FOUNDATION_OBJECTS_BUCKET || '', region: env.FOUNDATION_OBJECTS_REGION || env.FOUNDATION_AWS_REGION || 'ap-northeast-1' },
  };
}
