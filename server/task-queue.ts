import type { QueryResultRow } from 'pg';
import type { Database, Queryable } from './database.js';

type Table = 'execution_tasks' | 'environment_processes' | 'function_invocations';
interface TaskError { code: string; message: string; }

// Domain services authorize work and validate results. This queue owns leases and state transitions.
export class TaskQueue {
  constructor(readonly db: Database, readonly table: Table,
    readonly options: { errorFormat?: 'text' | 'json'; cancelledError?: TaskError } = {}) {}
  private error(error: TaskError | null) {
    return error === null ? null : this.options.errorFormat === 'json' ? JSON.stringify(error) : error.code;
  }
  private get errorType() { return this.options.errorFormat === 'json' ? 'jsonb' : 'text'; }
  claim<T extends QueryResultRow>(environmentId: string, lease: string, connection: Queryable) {
    return this.db.one<T>(`UPDATE ${this.table} SET state='running',phase='claimed',lease_token=$2,
      lease_until=now()+interval '60 seconds' WHERE id=(SELECT id FROM ${this.table}
      WHERE environment_id=$1 AND state='queued' ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *`,
      [environmentId, lease], connection);
  }
  async dispatch(id: string, lease: string) {
    return Boolean(await this.db.one(`UPDATE ${this.table} SET phase='dispatched',started_at=now()
      WHERE id=$1 AND lease_token=$2 AND state='running' AND phase='claimed'
      AND cancel_requested=false AND lease_until>now() RETURNING id`, [id, lease]));
  }
  async renew(id: string, lease: string) {
    return Boolean(await this.db.one(`UPDATE ${this.table} SET lease_until=now()+interval '60 seconds'
      WHERE id=$1 AND lease_token=$2 AND state='running' AND cancel_requested=false AND lease_until>now() RETURNING id`, [id, lease]));
  }
  cancel(id: string, error: TaskError = { code: 'cancellation_pending', message: 'Cancellation is waiting for the executor to confirm.' },
    connection: Queryable = this.db.pool, field: 'id' | 'environment_id' = 'id', cancelledError = this.options.cancelledError ?? null) {
    return connection.query(`UPDATE ${this.table} SET cancel_requested=true,
      state=CASE WHEN phase='dispatched' THEN 'uncertain' ELSE 'cancelled' END,
      phase=CASE WHEN phase='dispatched' THEN phase ELSE 'settled' END,
      error=CASE WHEN phase='dispatched' THEN $2::${this.errorType} ELSE $3::${this.errorType} END,
      finished_at=CASE WHEN phase='dispatched' THEN NULL ELSE now() END,
      lease_until=CASE WHEN phase='dispatched' THEN now()+interval '60 seconds' ELSE NULL END
      WHERE ${field}=$1 AND state IN ('queued','running')`, [id, this.error(error),
        this.error(cancelledError)]);
  }
  async active(environmentId: string) {
    const row = await this.db.one<{ count: string }>(`SELECT count(*) FROM ${this.table} WHERE environment_id=$1 AND
      (state='running' OR state='uncertain' AND phase='dispatched' AND finished_at IS NULL)`, [environmentId]);
    return Number(row?.count ?? 0);
  }
  recover() {
    return this.db.pool.query(`UPDATE ${this.table} SET state=CASE WHEN phase='dispatched' THEN 'uncertain' ELSE 'queued' END,
      error=CASE WHEN phase='dispatched' THEN $1::${this.errorType} ELSE NULL END,
      phase=CASE WHEN phase='dispatched' THEN phase ELSE 'queued' END,
      finished_at=CASE WHEN phase='dispatched' THEN now() ELSE NULL END,lease_until=NULL
      WHERE lease_until<now() AND (state='running' OR
        (state='uncertain' AND cancel_requested=true AND phase='dispatched' AND finished_at IS NULL))`,
      [this.error({ code: 'execution_interrupted', message: 'Check the result before starting this work again.' })]);
  }
}
