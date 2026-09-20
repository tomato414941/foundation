import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export class Vault {
  constructor(key) {
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('A 32-byte encryption key is required');
    this.key = key;
  }
  seal(value, context) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(context));
    const content = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), content]).toString('base64');
  }
  open(value, context) {
    const packed = Buffer.from(value, 'base64');
    const decipher = createDecipheriv('aes-256-gcm', this.key, packed.subarray(0, 12));
    decipher.setAAD(Buffer.from(context));
    decipher.setAuthTag(packed.subarray(12, 28));
    return JSON.parse(Buffer.concat([decipher.update(packed.subarray(28)), decipher.final()]).toString('utf8'));
  }
}
