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
  let encodedKey = env.FOUNDATION_ENCRYPTION_KEY;
  if (!encodedKey) {
    if (!existsSync(keyPath)) {
      if (existsSync(database)) {
        const db = new DatabaseSync(database, { readOnly: true });
        const version = db.prepare('PRAGMA user_version').get().user_version;
        db.close();
        if (version >= 2) throw new Error('Existing encrypted database requires its original encryption key');
      }
      writeFileSync(keyPath, randomBytes(32).toString('base64') + '\n', { flag: 'wx', mode: 0o600 });
    }
    chmodSync(keyPath, 0o600);
    encodedKey = readFileSync(keyPath, 'utf8').trim();
  }
  const encryptionKey = Buffer.from(encodedKey, 'base64');
  if (encryptionKey.length !== 32 || encryptionKey.toString('base64') !== encodedKey) throw new Error('FOUNDATION_ENCRYPTION_KEY must be 32 bytes encoded as base64');
  const signup = env.FOUNDATION_SIGNUP || 'allowlist';
  if (!['allowlist', 'open'].includes(signup)) throw new Error('FOUNDATION_SIGNUP must be allowlist or open');
  const allowedEmails = (env.FOUNDATION_ALLOWED_EMAILS || '').split(',').map(value => value.trim().toLowerCase()).filter(Boolean);
  if (allowedEmails.some(value => !/^[^\s@]+@[^\s@]+$/.test(value))) throw new Error('FOUNDATION_ALLOWED_EMAILS must be a comma-separated list of email addresses');
  return {
    dataDir, database, port, encryptionKey, signup: { mode: signup, emails: allowedEmails },
    publicOrigin: env.FOUNDATION_PUBLIC_ORIGIN || undefined,
    supabase: { url: env.FOUNDATION_SUPABASE_URL || '', key: env.FOUNDATION_SUPABASE_PUBLISHABLE_KEY || '', emailEnabled: env.FOUNDATION_EMAIL_LOGIN_ENABLED === 'true' },
    google: { clientId: env.FOUNDATION_GOOGLE_CLIENT_ID || '', clientSecret: env.FOUNDATION_GOOGLE_CLIENT_SECRET || '' },
    expo: { sessionLogin: env.FOUNDATION_EXPO_SESSION_LOGIN === 'true' },
  };
}
