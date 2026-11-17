import { readFile } from 'node:fs/promises';
import type { Database } from '../database.js';
import type { Vault } from '../vault.js';
import type { RequestedOperation } from '../../shared/contracts.js';

// Operations that ran work on execution environments, which Foundation no longer has. Their records go with them.
const removed = new Set(['run.execute', 'run.cancel', 'connection.revoke', 'function.save', 'function.configure', 'function.delete',
  'function.invoke', 'function.cancel', 'environment.start', 'environment.stop', 'environment.ssh', 'process.start', 'process.cancel']);
// Saving a value or an application named the environments allowed to use it; the operations no longer take that list.
const saves = new Set(['variable.save', 'app.save']);

export async function removeEnvironments(db: Database, vault: Vault) {
  await db.transaction(async connection => {
    await connection.query('SELECT pg_advisory_xact_lock(736023751)');
    if (await db.one("SELECT 1 FROM schema_migrations WHERE name='012-remove-environments'", [], connection)) return;
    await connection.query(await readFile(new URL('./012-remove-environments.sql', import.meta.url), 'utf8'));
    let after: string | null = null;
    for (;;) {
      const rows: Array<{ id: string; snapshot: string }> = await db.all(
        'SELECT id,snapshot FROM executions WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT 100 FOR UPDATE', [after], connection);
      for (const row of rows) {
        const snapshot = await vault.decrypt<{ operations: RequestedOperation[] }>(row.snapshot, 'operation-execution:' + row.id);
        if (snapshot.operations.some(operation => removed.has(operation.name))) {
          await connection.query('DELETE FROM executions WHERE id=$1', [row.id]);
          continue;
        }
        const listed = snapshot.operations.filter(operation => saves.has(operation.name) && 'environmentIds' in operation.input);
        if (!listed.length) continue;
        for (const operation of listed) delete operation.input.environmentIds;
        await connection.query('UPDATE executions SET snapshot=$2 WHERE id=$1',
          [row.id, await vault.encrypt(snapshot, 'operation-execution:' + row.id)]);
      }
      if (rows.length < 100) break;
      after = rows.at(-1)!.id;
    }
    await connection.query("INSERT INTO schema_migrations(name) VALUES('012-remove-environments')");
  });
}
