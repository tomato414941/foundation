import { lstat, mkdir, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { CompactEncrypt, compactDecrypt, importJWK } from 'jose';
import { canonical } from '../shared/digest.js';
import { decode, encode, thumbprint } from '../shared/encryption.js';
import type { DeviceKeys } from '../shared/client.js';
import { secureWrite } from '../cli/src/config.js';

export interface Journal {
  read<T>(id: string): Promise<T | null>;
  write(id: string, value: unknown): Promise<void>;
  keys(prefix: string): Promise<string[]>;
  pending(prefix: string): Promise<string[]>;
}

const JournalId = z.string().regex(/^(refresh|checkpoint)_[A-Za-z0-9_-]{1,100}$/);
// Records of kinds this machine no longer keeps are left out, and go with their directory when it is moved.
const kept = (name: string) => JournalId.safeParse(name).success;
// What this machine keeps of the work it does with the identity's key, sealed for that key, in private files.
export class FileJournal implements Journal {
  private indexing?: Promise<void>;
  constructor(readonly directory: string, readonly origin: string, readonly device: DeviceKeys) {}

  private context(id: string) {
    return canonical({ purpose: 'executor-journal', origin: this.origin, id: JournalId.parse(id) });
  }
  private keyId() { return thumbprint(this.device.publicKey); }
  async read<T>(id: string): Promise<T | null> {
    const context = this.context(id), path = join(this.directory, id + '.json');
    try {
      const stat = await lstat(path);
      if (!stat.isFile() || stat.isSymbolicLink() || (process.platform !== 'win32' && (stat.mode & 0o077)))
        throw new Error('The journal must use private regular files.');
      const envelope = z.string().max(32_000_000).parse(JSON.parse(await readFile(path, 'utf8')));
      const privateKey = this.device.privateKey instanceof CryptoKey ? this.device.privateKey
        : await importJWK(this.device.privateKey, 'ECDH-ES+A256KW');
      const decrypted = await compactDecrypt(envelope, privateKey, {
        keyManagementAlgorithms: ['ECDH-ES+A256KW'], contentEncryptionAlgorithms: ['A256GCM'],
      });
      if (decrypted.protectedHeader.kid !== await this.keyId() || decrypted.protectedHeader.ctx !== context)
        throw new Error('The journal entry belongs to another operation.');
      const record = JSON.parse(decode(decrypted.plaintext)) as { context: string; value: T };
      if (record.context !== context) throw new Error('The journal entry belongs to another operation.');
      return record.value;
    } catch (error) {
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return null;
      throw error;
    }
  }
  private async writeEntry(id: string, value: unknown) {
    const context = this.context(id), bytes = encode(canonical({ context, value }));
    if (bytes.byteLength > 20_000_000) throw new Error('The journal entry is too large.');
    const envelope = await new CompactEncrypt(bytes).setProtectedHeader({
      alg: 'ECDH-ES+A256KW', enc: 'A256GCM', kid: await this.keyId(), ctx: context,
    }).encrypt(await importJWK(this.device.publicKey, 'ECDH-ES+A256KW'));
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await secureWrite(join(this.directory, id + '.json'), canonical(envelope), true);
  }
  private delivery(id: string) { return id.startsWith('refresh_'); }
  private delivered(value: unknown) {
    return !!value && typeof value === 'object' && 'delivered' in value && value.delivered === true;
  }
  private async markPending(id: string) {
    await mkdir(join(this.directory, 'pending'), { recursive: true, mode: 0o700 });
    await secureWrite(join(this.directory, 'pending', JournalId.parse(id)), '', true);
  }
  private index() {
    return this.indexing ??= (async () => {
      const checkpoint = 'checkpoint_pending_index';
      if (await this.read(checkpoint)) return;
      // Index existing durable records once; the records remain the source of truth for replay protection.
      for (const id of await this.keys('')) {
        if (!this.delivery(id)) continue;
        const record = await this.read(id);
        if (record && !this.delivered(record)) await this.markPending(id);
      }
      await this.writeEntry(checkpoint, { version: 1 });
    })();
  }
  async write(id: string, value: unknown) {
    await this.index();
    const delivered = this.delivered(value);
    if (this.delivery(id) && !delivered) await this.markPending(id);
    await this.writeEntry(id, value);
    if (this.delivery(id) && delivered) await rm(join(this.directory, 'pending', id), { force: true });
  }
  async pending(prefix: string) {
    await this.index();
    let entries;
    try { entries = await readdir(join(this.directory, 'pending'), { withFileTypes: true }); }
    catch (error) {
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return [];
      throw error;
    }
    return entries.filter(entry => entry.isFile() && entry.name.startsWith(prefix) && kept(entry.name)).map(entry => entry.name);
  }
  async keys(prefix: string) {
    let files;
    try { files = await readdir(this.directory, { withFileTypes: true }); }
    catch (error) {
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return [];
      throw error;
    }
    return files.filter(file => file.isFile() && file.name.startsWith(prefix) && file.name.endsWith('.json') && kept(file.name.slice(0, -5)))
      .map(file => file.name.slice(0, -5));
  }
}
