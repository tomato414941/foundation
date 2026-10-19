import { readFile } from 'node:fs/promises';
import type { Database } from '../database.js';
import type { Vault } from '../vault.js';
import type { RequestedOperation } from '../../shared/contracts.js';

interface Snapshot {
  operations: RequestedOperation[];
}

export async function migrateDelegates(db: Database, vault: Vault) {
  await db.transaction(async connection => {
    await connection.query('SELECT pg_advisory_xact_lock(736023750)');
    if (await db.one("SELECT 1 FROM schema_migrations WHERE name='006-delegates'", [], connection)) return;
    await connection.query(await readFile(new URL('./006-delegates.sql', import.meta.url), 'utf8'));
    let after: string | null = null;
    for (;;) {
      const rows: Array<{ id: string; snapshot: string }> = await db.all(
        'SELECT id,snapshot FROM executions WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT 100 FOR UPDATE', [after], connection);
      for (const row of rows) {
        const snapshot = await vault.decrypt<Snapshot>(row.snapshot, 'operation-execution:' + row.id);
        let changed = false;
        for (const operation of snapshot.operations) {
          if (['relation.draw', 'relation.erase'].includes(operation.name) && operation.input.relation === 'agent') {
            operation.input.relation = 'delegate'; changed = true;
          }
        }
        if (changed) await connection.query('UPDATE executions SET snapshot=$2,revision=revision+1 WHERE id=$1',
          [row.id, await vault.encrypt(snapshot, 'operation-execution:' + row.id)]);
      }
      if (rows.length < 100) break;
      after = rows.at(-1)!.id;
    }
    await connection.query("INSERT INTO schema_migrations(name) VALUES('006-delegates')");
  });
}
