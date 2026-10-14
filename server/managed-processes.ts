import { randomUUID } from 'node:crypto';
import type { Processes, ProcessRow } from './processes.js';
import type { Environments } from './environments.js';
import { SSHProcess } from './ssh-process.js';
import { failure } from './errors.js';

export class ManagedProcesses {
  readonly runtime: SSHProcess;
  constructor(readonly processes: Processes, readonly environments: Environments) {
    this.runtime = new SSHProcess(environments.client);
  }
  async tick() {
    const db = this.processes.resources.db, lease = randomUUID();
    const row = await db.one<ProcessRow>(
      `UPDATE environment_processes p SET lease_token=$1,lease_until=now()+interval '60 seconds',
       state=CASE WHEN p.state='queued' THEN 'running' ELSE p.state END,
       phase=CASE WHEN p.phase='queued' THEN 'claimed' ELSE p.phase END
       WHERE id=(SELECT p.id FROM environment_processes p JOIN resources r ON r.id=p.environment_id
         WHERE p.executor_id IS NULL AND r.data->>'driver'='managed' AND p.phase<>'settled'
           AND p.state IN ('queued','running','uncertain') AND (p.lease_until IS NULL OR p.lease_until<now())
         ORDER BY p.lease_until NULLS FIRST,p.created_at FOR UPDATE OF p SKIP LOCKED LIMIT 1) RETURNING p.*`, [lease]);
    if (!row) return false;
    const renewal = setInterval(() => {
      void db.pool.query("UPDATE environment_processes SET lease_until=now()+interval '60 seconds' WHERE id=$1 AND lease_token=$2",
        [row.id, lease]).catch(() => {});
    }, 20_000);
    renewal.unref();
    let dispatched = row.phase === 'dispatched';
    try {
      let revoked = false;
      try { await this.processes.validate(row.actor, row.environment_id); }
      catch (error) {
        if (failure(error).status >= 500) throw error;
        revoked = true;
      }
      if (revoked && !dispatched) {
        await db.pool.query(`UPDATE environment_processes SET state='failed',phase='settled',
          error='authorization_changed',finished_at=now() WHERE id=$1 AND lease_token=$2`, [row.id, lease]);
        return true;
      }
      const destination = await this.environments.connection(row.environment_id);
      if (!dispatched) {
        const started = await db.one(`UPDATE environment_processes SET phase='dispatched',started_at=now()
          WHERE id=$1 AND lease_token=$2 AND state='running' AND phase='claimed'
            AND cancel_requested=false AND lease_until>now() RETURNING id`, [row.id, lease]);
        if (!started) return true;
        dispatched = true;
        await this.runtime.start(destination, this.processes.view(row));
      }
      const current = await db.one<{ cancel_requested: boolean }>('SELECT cancel_requested FROM environment_processes WHERE id=$1', [row.id]);
      const cancelled = revoked || current?.cancel_requested;
      let remote = await this.runtime.inspect(destination, row.id);
      if (cancelled && remote.state === 'running') {
        await this.runtime.cancel(destination, row.id);
        remote = await this.runtime.inspect(destination, row.id);
        // A successful OS stop confirms cancellation even if systemd unloads the transient unit.
        if (remote.state === 'uncertain') remote = { ...remote, state: 'failed' };
      }
      const done = remote.state !== 'running';
      const state = done && cancelled && remote.state !== 'uncertain' ? 'cancelled' : remote.state;
      const error = revoked ? 'authorization_changed' : remote.state === 'uncertain' ? 'execution_interrupted' : null;
      await db.pool.query(
        `UPDATE environment_processes SET state=$3,result=$4,error=$5,
         phase=CASE WHEN $6 THEN 'settled' ELSE phase END,finished_at=CASE WHEN $6 THEN now() ELSE NULL END
         WHERE id=$1 AND lease_token=$2 AND phase<>'settled'`,
        [row.id, lease, state, JSON.stringify(remote.result), error, done]);
      await db.pool.query("UPDATE resources SET data=jsonb_set(data,'{lastActiveAt}',to_jsonb($2::text)) WHERE id=$1",
        [row.environment_id, new Date().toISOString()]);
    } catch (error) {
      if (dispatched) await db.pool.query(
        `UPDATE environment_processes SET state='uncertain',error='ssh_unavailable'
         WHERE id=$1 AND lease_token=$2 AND phase='dispatched'`, [row.id, lease]);
      else if (failure(error).status < 500) await db.pool.query(
        `UPDATE environment_processes SET state='failed',phase='settled',error=$3,finished_at=now()
         WHERE id=$1 AND lease_token=$2`, [row.id, lease, failure(error).code]);
    } finally {
      clearInterval(renewal);
      await db.pool.query(
        `UPDATE environment_processes SET lease_token=NULL,
         lease_until=CASE WHEN phase='settled' THEN NULL ELSE now()+interval '2 seconds' END
         WHERE id=$1 AND lease_token=$2`, [row.id, lease]);
    }
    return true;
  }
}
