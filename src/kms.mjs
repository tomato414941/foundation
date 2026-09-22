import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { signAws, serverCredentials } from './aws-sigv4.mjs';

// Envelope encryption: the 32-byte key that seals every stored credential is itself wrapped by a KMS key
// and kept, wrapped, in the database. On start Foundation asks KMS to unwrap it and holds it only in memory.
// Taking the database and the host therefore yields nothing without KMS, whose use is logged and revocable.
export class Kms {
  constructor({ keyId, region, fetcher = fetch, credentials = null }) {
    if (!keyId || !region) throw new Error('KMS needs FOUNDATION_KMS_KEY_ID and FOUNDATION_AWS_REGION');
    this.keyId = keyId; this.region = region; this.fetcher = fetcher; this.credentials = credentials;
  }
  async call(action, payload) {
    const credentials = this.credentials || (this.credentials = await serverCredentials({ fetcher: this.fetcher }));
    const request = signAws({ service: 'kms', region: this.region, host: 'kms.' + this.region + '.amazonaws.com', body: JSON.stringify(payload), credentials,
      headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'TrentService.' + action } });
    let response;
    try { response = await this.fetcher(request.url, { method: 'POST', headers: request.headers, body: request.body, redirect: 'error', signal: AbortSignal.timeout(12_000) }); }
    catch { throw new Error('KMS is unreachable; Foundation will not start without its key.'); }
    let data;
    try { data = await response.json(); } catch { data = null; }
    if (!response.ok) throw new Error('KMS refused ' + action + ' (' + response.status + ', ' + (data?.__type || 'unknown') + '). Check the key policy and the instance role.');
    return data;
  }
  async wrap(key) {
    const data = await this.call('Encrypt', { KeyId: this.keyId, Plaintext: key.toString('base64'), EncryptionContext: { app: 'foundation', purpose: 'data-key' } });
    if (typeof data?.CiphertextBlob !== 'string') throw new Error('KMS returned no ciphertext.');
    return data.CiphertextBlob;
  }
  async unwrap(blob) {
    const data = await this.call('Decrypt', { KeyId: this.keyId, CiphertextBlob: blob, EncryptionContext: { app: 'foundation', purpose: 'data-key' } });
    const key = Buffer.from(String(data?.Plaintext || ''), 'base64');
    if (key.length !== 32) throw new Error('KMS returned an unusable key.');
    return key;
  }
}

// Resolves the data key for this deployment. Without KMS the given key (file or environment) is used as before.
// With KMS: an already wrapped key is unwrapped; otherwise the current key is wrapped once and stored,
// so an existing database migrates without re-encrypting rows; a fresh database gets a new random key.
export async function resolveEncryptionKey({ database, encryptionKey, kms, log = console.log }) {
  if (!kms) return encryptionKey;
  const db = new DatabaseSync(database);
  try {
    db.exec('CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL)');
    const wrapped = db.prepare("SELECT value FROM metadata WHERE name='wrapped_key'").get();
    if (wrapped) return await kms.unwrap(wrapped.value);
    const key = encryptionKey || randomBytes(32);
    const blob = await kms.wrap(key);
    db.prepare('INSERT INTO metadata VALUES (?, ?)').run('wrapped_key', blob);
    log(encryptionKey ? 'Encryption key wrapped by KMS and stored; the plaintext key file or variable is no longer needed.' : 'New encryption key generated and wrapped by KMS.');
    return key;
  } finally { db.close(); }
}
