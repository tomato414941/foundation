import type { Context } from '../context.js';
import type { DefinitionCall } from '../../shared/executions.js';
import type { JsonValue } from '../../shared/contracts.js';
import { Id } from '../../shared/contracts.js';

export async function migrateHistory(context: Context) {
    if (await context.db.one("SELECT 1 FROM schema_migrations WHERE name='unified-execution-history'")) return;
    const jobs = await context.db.all<{ id: string; actor_id: string }>(`SELECT id,actor_id FROM execution_tasks
      WHERE request->'intent'->'operationContext' IS NULL AND NOT EXISTS(SELECT 1 FROM executions e WHERE e.id=execution_tasks.id)`);
    for (const job of jobs) await context.executions.recordRuntime('run', await context.executions.runtime.get({ id: job.actor_id }, { kind: 'run', id: job.id }));
    const functions = await context.db.all<{ id: string; actor_id: string }>(`SELECT id,actor_id FROM function_invocations f
      WHERE NOT EXISTS(SELECT 1 FROM executions e WHERE e.id=f.id)`);
    const roots = await context.db.all<{ id: string; snapshot: string }>('SELECT id,snapshot FROM executions');
    const included = new Set<string>();
    for (const row of roots) {
      const snapshot = await context.vault.decrypt<{ operations: DefinitionCall[]; results: Array<JsonValue | null> }>(row.snapshot, 'operation-execution:' + row.id);
      for (const operation of snapshot.operations)
        if (operation.name === 'function.invoke' && typeof operation.input.id === 'string') included.add(operation.input.id);
      for (const result of snapshot.results)
        if (result && typeof result === 'object' && !Array.isArray(result) && typeof result.id === 'string') included.add(result.id);
      const owner = snapshot.operations.map(operation => operation.input.ownerId).find(value => Id.safeParse(value).success);
      if (owner) await context.db.pool.query('UPDATE executions SET owner_id=$2 WHERE id=$1 AND owner_id IS NULL AND EXISTS(SELECT 1 FROM principals WHERE id=$2)', [row.id, owner]);
    }
    for (const job of functions) {
      if (!included.has(job.id)) await context.executions.recordRuntime('function', await context.executions.runtime.get({ id: job.actor_id }, { kind: 'function', id: job.id }));
    }
    await context.db.pool.query('UPDATE executions SET owner_id=creator_id WHERE owner_id IS NULL');
    await context.db.pool.query("INSERT INTO schema_migrations(name) VALUES('unified-execution-history') ON CONFLICT DO NOTHING");
}
