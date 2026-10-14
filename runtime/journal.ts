import { lstat, mkdir, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { CompactEncrypt, compactDecrypt, importJWK } from 'jose';
import { canonical, sign, verify } from '../shared/authority.js';
import type { BoundKeys, IdentityKeys } from '../shared/authority.js';
import { decode, encode } from '../shared/encryption.js';
import { secureWrite } from '../cli/src/config.js';

export interface Journal {
  read<T>(id: string): Promise<T | null>;
  write(id: string, value: unknown): Promise<void>;
  keys(prefix: string): Promise<string[]>;
  pending(prefix: string): Promise<string[]>;
}

const JournalId = z.string().regex(/^(run|process|invocation|function|connect|refresh|checkpoint|identity|environment|flow)_[A-Za-z0-9_-]{1,100}$/);
export class FileJournal implements Journal {
  private indexing?: Promise<void>;
  constructor(readonly directory: string, readonly origin: string,
    readonly binding: BoundKeys, readonly privateKeys: IdentityKeys) {}

  private context(id: string) {
    return canonical({ purpose: 'executor-journal', origin: this.origin, bindingId: this.binding.id,
      id: JournalId.parse(id) });
  }
  async read<T>(id: string): Promise<T | null> {
    const context = this.context(id), path = join(this.directory, id + '.json');
    try {
      const stat = await lstat(path);
      if (!stat.isFile() || stat.isSymbolicLink() || (process.platform !== 'win32' && (stat.mode & 0o077)))
        throw new Error('The execution journal must use private regular files.');
      const envelope = z.string().max(32_000_000).parse(JSON.parse(await readFile(path, 'utf8')));
      const decrypted = await compactDecrypt(envelope, await importJWK(this.privateKeys.encryption, 'ECDH-ES+A256KW'), {
        keyManagementAlgorithms: ['ECDH-ES+A256KW'], contentEncryptionAlgorithms: ['A256GCM'],
      });
      if (decrypted.protectedHeader.kid !== this.binding.id || decrypted.protectedHeader.ctx !== context)
        throw new Error('The journal entry belongs to another operation.');
      const signed = JSON.parse(decode(decrypted.plaintext)) as {
        context: string; value: T; signature: string;
      };
      if (signed.context !== context) throw new Error('The journal entry belongs to another operation.');
      await verify({ context, value: signed.value }, signed.signature, this.binding.signing, 'journal');
      return signed.value;
    } catch (error) {
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return null;
      throw error;
    }
  }
  private async writeEntry(id: string, value: unknown) {
    const context = this.context(id), record = { context, value };
    const signature = await sign(record, this.privateKeys.signing, 'journal');
    const bytes = encode(canonical({ ...record, signature }));
    if (bytes.byteLength > 20_000_000) throw new Error('The execution record is too large.');
    const envelope = await new CompactEncrypt(bytes).setProtectedHeader({
      alg: 'ECDH-ES+A256KW', enc: 'A256GCM', kid: this.binding.id, ctx: context,
    }).encrypt(await importJWK(this.binding.encryption, 'ECDH-ES+A256KW'));
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await secureWrite(join(this.directory, id + '.json'), canonical(envelope), true);
  }
  private delivery(id: string) { return /^(run|process|invocation|refresh)_/.test(id); }
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
    return entries.filter(entry => entry.isFile() && entry.name.startsWith(prefix)).map(entry => JournalId.parse(entry.name));
  }
  async keys(prefix: string) {
    let files;
    try { files = await readdir(this.directory, { withFileTypes: true }); }
    catch (error) {
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return [];
      throw error;
    }
    return files.filter(file => file.isFile() && file.name.startsWith(prefix) && file.name.endsWith('.json'))
      .map(file => JournalId.parse(file.name.slice(0, -5)));
  }
}
