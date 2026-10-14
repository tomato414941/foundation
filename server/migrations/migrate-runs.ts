import type { Database } from '../database.js';
import type { Vault } from '../vault.js';
import type { JsonValue } from '../../shared/contracts.js';
import { Operation } from '../../shared/contracts.js';

interface HistoricalRun {
  id: string; owner_id: string; actor_id: string; resource_id: string | null;
  kind: 'http' | 'command' | 'function';
  state: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
  private_input: string; result: JsonValue | null; error: string | null;
  created_at: Date; started_at: Date | null; finished_at: Date | null;
}

export async function migrateRuns(db: Database, vault: Vault) {
  await db.transaction(async connection => {
    await connection.query('SELECT pg_advisory_xact_lock(736023747)');
    if (await db.one("SELECT 1 FROM schema_migrations WHERE name='historical-server-runs'", [], connection)) return;
    const installed = await db.one<{ runs: string | null }>("SELECT to_regclass('runs') AS runs", [], connection);
    if (installed?.runs) {
      await connection.query('LOCK TABLE runs IN ACCESS EXCLUSIVE MODE');
      const rows = await db.all<HistoricalRun>('SELECT * FROM runs ORDER BY created_at,id', [], connection);
      if (rows.some(row => row.state === 'queued' || row.state === 'running'))
        throw new Error('Finish historical server runs before migrating their results.');
      // Keep the previous server's maintenance cycle from expiring imported history during the rollout.
      const expiresAt = new Date(Date.now() + 86_400_000);
      for (const row of rows) {
        const actor = { id: row.actor_id }, input = { ownerId: row.owner_id,
          ...(row.kind === 'function' ? row.resource_id ? { functionId: row.resource_id } : {}
            : { operation: { kind: row.kind }, ...(row.resource_id ? { environmentId: row.resource_id } : {}) }) };
        const result = row.error ? { error: { code: 'run_failed', message: row.error }, result: row.result } : row.result;
        const snapshot = { actor, creatorActor: actor, agreementIndex: null, responders: [], submissionDigest: null,
          operations: [Operation.parse({ name: row.kind === 'function' ? 'function.invoke' : 'run.execute', input })],
          index: row.state === 'succeeded' ? 1 : 0, results: [result], proofs: [null], inFlight: null, continuation: null,
          archive: { format: 'server-run', record: row } };
        await connection.query(`INSERT INTO executions(id,actor_id,creator_id,owner_id,state,wait,snapshot,expires_at,created_at)
          VALUES($1,$2,$2,$3,$4,NULL,$5,$6,$7)`, [row.id, row.actor_id, row.owner_id, row.state,
          await vault.encrypt(snapshot, 'operation-execution:' + row.id), expiresAt, row.created_at]);
      }
      await connection.query('DROP TABLE runs');
    }
    await connection.query("INSERT INTO schema_migrations(name) VALUES('historical-server-runs')");
  });
}
