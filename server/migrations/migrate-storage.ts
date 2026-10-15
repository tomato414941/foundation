import { readFile } from 'node:fs/promises';
import type { Database } from '../database.js';
import type { Vault } from '../vault.js';
import type { JsonValue, RequestedOperation } from '../../shared/contracts.js';

const operationNames: Record<string, string> = {
  'file.create': 'object.create',
  'file.update': 'object.update',
  'file.link': 'object.link',
};
interface Snapshot {
  operations: RequestedOperation[];
  results: Array<JsonValue | null>;
}

export async function migrateStorage(db: Database, vault: Vault) {
  await db.transaction(async connection => {
    await connection.query('SELECT pg_advisory_xact_lock(736023749)');
    if (await db.one("SELECT 1 FROM schema_migrations WHERE name='004-storage'", [], connection)) return;
    await connection.query(await readFile(new URL('./004-storage.sql', import.meta.url), 'utf8'));
    let after: string | null = null;
    for (;;) {
      const rows: Array<{ id: string; snapshot: string }> = await db.all(
        'SELECT id,snapshot FROM executions WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT 100 FOR UPDATE', [after], connection);
      for (const row of rows) {
        const snapshot = await vault.decrypt<Snapshot>(row.snapshot, 'operation-execution:' + row.id);
        let changed = false;
        for (const [index, operation] of snapshot.operations.entries()) {
          const name = Object.hasOwn(operationNames, operation.name) ? operationNames[operation.name] : undefined;
          if (name) { operation.name = name; changed = true; }
          const result = snapshot.results[index];
          if (['object.create', 'object.update', 'resource.create', 'resource.update'].includes(operation.name) &&
            result && typeof result === 'object' && !Array.isArray(result) && result.kind === 'file') {
            result.kind = 'object'; changed = true;
          }
          if (['principal.create', 'principal.rename'].includes(operation.name) &&
            result && typeof result === 'object' && !Array.isArray(result) && Array.isArray(result.createKinds) &&
            result.createKinds.includes('file')) {
            result.createKinds = result.createKinds.map(kind => kind === 'file' ? 'object' : kind); changed = true;
          }
        }
        if (changed) await connection.query('UPDATE executions SET snapshot=$2,revision=revision+1 WHERE id=$1',
          [row.id, await vault.encrypt(snapshot, 'operation-execution:' + row.id)]);
      }
      if (rows.length < 100) break;
      after = rows.at(-1)!.id;
    }
    await connection.query("INSERT INTO schema_migrations(name) VALUES('004-storage')");
  });
}
