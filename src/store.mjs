import { DatabaseSync } from 'node:sqlite';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { Vault } from './crypto.mjs';
import { SCHEMA_VERSION, STEPS, SCHEMA } from './migrations.mjs';

export class Store {
  constructor(path, key) {
    this.transactionDepth = 0;
    this.vault = new Vault(key);
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    if (path !== ':memory:') chmodSync(path, 0o600);
    this.db.exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=3000; PRAGMA secure_delete=ON;');
    // Known earlier schemas are migrated transactionally; unrecognized files are left intact.
    const version = this.db.prepare('PRAGMA user_version').get().user_version;
    const empty = !this.db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'metadata'").get();
    // Migrations and the encryption-key check share a transaction.
    const behind = !empty && version >= 1 && version < SCHEMA_VERSION && [...Array(SCHEMA_VERSION - version)].every((_, step) => STEPS[version + step + 1]);
    const mine = version === SCHEMA_VERSION && !empty, fresh = version === 0 && empty;
    if (!mine && !fresh && !behind) { this.db.close(); throw new Error('This database was not created by this version of Foundation. Start from a new database file.'); }
    try {
      this.transaction(() => {
        if (fresh) this.db.exec(SCHEMA);
        if (behind) {
          for (let next = version + 1; next <= SCHEMA_VERSION; next++) {
            const step = STEPS[next];
            if (typeof step === 'function') step(this); else this.db.exec(step);
          }
          this.db.exec('PRAGMA user_version = ' + SCHEMA_VERSION);
        }
        const check = this.db.prepare("SELECT value FROM metadata WHERE name='key_check'").get();
        if (check) this.vault.open(check.value, 'key_check');
        else this.db.prepare('INSERT INTO metadata VALUES (?, ?)').run('key_check', this.vault.seal(true, 'key_check'));
      });
      this.sweep();
    } catch (error) { this.db.close(); throw error; }
  }
  transaction(fn) {
    const nested = this.transactionDepth > 0, savepoint = 'foundation_' + this.transactionDepth;
    this.db.exec(nested ? 'SAVEPOINT ' + savepoint : 'BEGIN IMMEDIATE');
    this.transactionDepth++;
    try { const result = fn(); this.db.exec(nested ? 'RELEASE ' + savepoint : 'COMMIT'); return result; }
    catch (error) { this.db.exec(nested ? 'ROLLBACK TO ' + savepoint + '; RELEASE ' + savepoint : 'ROLLBACK'); throw error; }
    finally { this.transactionDepth--; }
  }
  sweep() {
    this.db.prepare('DELETE FROM oauth_flows WHERE expires_at<=?').run(Date.now());
    this.db.prepare('DELETE FROM credentials WHERE expires_at IS NOT NULL AND expires_at<=?').run(Date.now());
    this.db.prepare('DELETE FROM sessions WHERE expires_at<=?').run(Date.now());
    this.db.prepare('DELETE FROM requests WHERE expires_at<=?').run(Date.now());
  }
  close() { this.db.close(); }
}
