import { randomBytes, createHash } from 'node:crypto';
import { CompactEncrypt, compactDecrypt } from 'jose';
import { KMSClient, GenerateDataKeyCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { encode, decode } from '../shared/encryption.js';
import type { Database } from './database.js';
import type { Configuration } from './config.js';

export const digest = (value: string) => createHash('sha256').update(value).digest('hex');
export const token = () => randomBytes(32).toString('base64url');
export class Vault {
  constructor(private readonly key: Uint8Array) {}
  async encrypt(value: unknown, context: string): Promise<string> {
    return new CompactEncrypt(encode(JSON.stringify(value)))
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', ctx: context })
      .encrypt(this.key);
  }
  async decrypt<T>(value: string, context: string): Promise<T> {
    const result = await compactDecrypt(value, this.key, {
      keyManagementAlgorithms: ['dir'],
      contentEncryptionAlgorithms: ['A256GCM'],
    });
    if (result.protectedHeader.ctx !== context) throw new Error('Encrypted record context does not match.');
    return JSON.parse(decode(result.plaintext)) as T;
  }
  static async initialize(db: Database, config: Configuration): Promise<Vault> {
    return db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023741)');
      return Vault.create(db, config);
    });
  }
  private static async create(db: Database, config: Configuration): Promise<Vault> {
    let key = config.key;
    if (!key) {
      const kms = new KMSClient({ region: config.AWS_REGION });
      const saved = await db.one<{ value: { ciphertext: string } }>(
        "SELECT value FROM system_settings WHERE name='kms-key'",
      );
      if (saved) {
        const result = await kms.send(
          new DecryptCommand({
            KeyId: config.FOUNDATION_KMS_KEY,
            CiphertextBlob: Buffer.from(saved.value.ciphertext, 'base64'),
            EncryptionContext: { application: 'Foundation' },
          }),
        );
        key = result.Plaintext ? new Uint8Array(result.Plaintext) : null;
      } else {
        const result = await kms.send(
          new GenerateDataKeyCommand({
            KeyId: config.FOUNDATION_KMS_KEY,
            KeySpec: 'AES_256',
            EncryptionContext: { application: 'Foundation' },
          }),
        );
        if (!result.Plaintext || !result.CiphertextBlob) throw new Error('KMS did not return a data key.');
        await db.pool.query("INSERT INTO system_settings(name,value) VALUES ('kms-key',$1)", [
          JSON.stringify({ ciphertext: Buffer.from(result.CiphertextBlob).toString('base64') }),
        ]);
        key = new Uint8Array(result.Plaintext);
      }
      kms.destroy();
    }
    if (!key || key.length !== 32) throw new Error('A 256-bit master key is required.');
    const vault = new Vault(key);
    const check = await db.one<{ value: string }>("SELECT value FROM system_settings WHERE name='key-check'");
    if (check) await vault.decrypt(check.value, 'key-check');
    else
      await db.pool.query("INSERT INTO system_settings(name,value) VALUES ('key-check',$1)", [
        JSON.stringify(await vault.encrypt('Foundation', 'key-check')),
      ]);
    return vault;
  }
}
