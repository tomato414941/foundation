import { randomUUID } from 'node:crypto';
import type { Actor } from './authorization.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Authentication } from './authentication.js';
import type { Billing } from './billing.js';
import type { Runner, RunnerJob } from './runner.js';
import type { Vault } from './vault.js';
import type { Configuration } from './config.js';
import { EnvironmentInput, EnvironmentResource } from '../shared/contracts.js';
import type { EnvironmentOptions } from '../shared/contracts.js';
import { fail, failure, required } from './errors.js';
import { newEncryptionKey } from '../shared/encryption.js';
import { redact } from '../shared/values.js';

export class Environments {
  constructor(
    readonly resources: Resources,
    readonly authentication: Authentication,
    readonly billing: Billing,
    readonly runner: Runner,
    readonly vault: Vault,
    readonly config: Configuration,
  ) {}
  async create(actor: Actor, ownerId: string, options: EnvironmentOptions, name?: string) {
    if (!this.runner.enabled) fail(503, 'environments_unavailable', 'Environments are not configured.');
    if (!(await this.resources.authorization.canCreate(actor, ownerId, 'environment')))
      fail(403, 'forbidden', 'You cannot open environments for this principal.');
    if (options.lifetime.idleSeconds > options.lifetime.maxSeconds)
      fail(400, 'invalid_lifetime', 'The idle timeout cannot exceed the maximum lifetime.');
    if (options.identityId)
      await this.resources.authorization.requirePrincipal(actor, options.identityId, 'credentials');
    return this.resources.db.transaction(async (connection) => {
      await this.billing.reserve(
        ownerId,
        'compute',
        options.lifetime.maxSeconds * { small: 1, medium: 2, large: 4 }[options.size],
        connection,
      );
      const id = randomUUID(),
        environment: Record<string, string> = {};
      if (options.identityId) {
        const pair = await newEncryptionKey();
        const key = await this.authentication.issueKey(
          options.identityId,
          'Environment ' + id.slice(0, 8),
          new Date(Date.now() + (options.lifetime.maxSeconds + 180) * 1000).toISOString(),
          id,
          connection,
          pair.publicKey,
        );
        environment.FOUNDATION_ORIGIN = this.config.origin;
        environment.FOUNDATION_TOKEN = key.token;
        environment.FOUNDATION_PRINCIPAL_ID = options.identityId;
        environment.FOUNDATION_PRIVATE_KEY = Buffer.from(JSON.stringify(pair.privateKey)).toString(
          'base64url',
        );
      }
      const now = new Date().toISOString();
      const row = await this.resources.insert(
        ownerId,
        'environment',
        name ?? 'Environment ' + id.slice(0, 8),
        { ...options, state: 'starting', startedAt: null, stoppedAt: null, lastActiveAt: now, error: null },
        { id, privateData: await this.vault.encrypt({ environment }, 'resource:' + id) },
        connection,
      );
      await connection.query('INSERT INTO environment_jobs(resource_id) VALUES($1)', [id]);
      await this.resources.audit.record(ownerId, actor.id, 'environment.create', id, {}, connection);
      return row;
    });
  }
  async stop(actor: Actor, row: ResourceRow) {
    if (row.kind !== 'environment') fail(400, 'wrong_kind', 'This item is not an environment.');
    await this.resources.authorization.requireResource(actor, row, 'delete');
    await this.requestStop(row.id);
    return this.resources.get(row.id);
  }
  async requestStop(id: string, error: string | null = null) {
    await this.resources.db.transaction(async (connection) => {
      await connection.query(
        `UPDATE resources SET data=data||jsonb_build_object('state','stopping','error',$2::text),version=version+1,updated_at=now() WHERE id=$1 AND data->>'state' IN ('starting','running','stopping')`,
        [id, error],
      );
      await connection.query('DELETE FROM credentials WHERE environment_id=$1', [id]);
    });
  }
  async execute(actor: Actor, id: string, job: RunnerJob, signal: AbortSignal) {
    const row = await this.resources.get(id);
    await this.resources.authorization.requireResource(actor, row, 'execute');
    if (row.kind !== 'environment' || row.data.state !== 'running')
      fail(409, 'environment_unavailable', 'Wait for the environment to start.');
    const data = EnvironmentResource.shape.data.parse(row.data),
      remaining = Math.floor(
        (new Date(data.startedAt!).getTime() + data.lifetime.maxSeconds * 1000 - Date.now()) / 1000,
      );
    if (remaining <= 0) fail(409, 'environment_expired', 'The environment reached its lifetime limit.');
    await this.billing.requirePayment(row.owner_id);
    const state = required(
      await this.resources.db.one<{ machine_id: string | null }>(
        'SELECT machine_id FROM environment_jobs WHERE resource_id=$1',
        [id],
      ),
    );
    if (!state.machine_id) fail(409, 'environment_unavailable', 'Wait for the environment to start.');
    const heartbeat = setInterval(() => {
      void this.resources.db.pool
        .query(
          "UPDATE resources SET data=jsonb_set(data,'{lastActiveAt}',to_jsonb($2::text)) WHERE id=$1 AND data->>'state'='running'",
          [id, new Date().toISOString()],
        )
        .catch(() => {});
    }, 10_000);
    heartbeat.unref();
    try {
      const result = await this.runner.execute(
        state.machine_id,
        { ...job, timeoutSeconds: Math.min(job.timeoutSeconds, remaining) },
        signal,
      );
      const privateData = await this.vault.decrypt<{ environment: Record<string, string> }>(
        required(row.private_data),
        'resource:' + id,
      );
      const token = privateData.environment.FOUNDATION_TOKEN,
        key = privateData.environment.FOUNDATION_PRIVATE_KEY;
      const sensitive = [token, key].filter((value): value is string => Boolean(value));
      if (key) {
        const decoded = Buffer.from(key, 'base64url').toString('utf8');
        sensitive.push(decoded, String((JSON.parse(decoded) as { d: string }).d));
      }
      return {
        ...result,
        stdout: redact(result.stdout, sensitive),
        stderr: redact(result.stderr, sensitive),
      };
    } catch (error) {
      if (signal.aborted) await this.requestStop(id);
      throw error;
    } finally {
      clearInterval(heartbeat);
      await this.resources.db.pool.query(
        "UPDATE resources SET data=jsonb_set(data,'{lastActiveAt}',to_jsonb($2::text)) WHERE id=$1",
        [id, new Date().toISOString()],
      );
    }
  }
  async tick() {
    const expired = await this.resources.db.all<{ id: string }>(
      `SELECT id FROM resources WHERE kind='environment' AND data->>'state'='running' AND ((data->>'startedAt')::timestamptz+(data->'lifetime'->>'maxSeconds')::int*interval '1 second'<=now() OR (data->>'lastActiveAt')::timestamptz+(data->'lifetime'->>'idleSeconds')::int*interval '1 second'<=now())`,
    );
    for (const row of expired) await this.requestStop(row.id);
    const lease = randomUUID();
    const job = await this.resources.db.one<{
      resource_id: string;
      machine_id: string | null;
      attempts: number;
    }>(
      `UPDATE environment_jobs j SET lease_until=now()+interval '2 minutes',lease_token=$1,attempts=attempts+1 WHERE resource_id=(
      SELECT j.resource_id FROM environment_jobs j JOIN resources r ON r.id=j.resource_id WHERE (j.lease_until IS NULL OR j.lease_until<now()) AND j.retry_at<=now() AND r.data->>'state' IN ('starting','stopping') ORDER BY r.created_at FOR UPDATE OF j SKIP LOCKED LIMIT 1
    ) RETURNING j.*`,
      [lease],
    );
    if (!job) return false;
    let row = await this.resources.get(job.resource_id);
    try {
      if (row.data.state === 'starting') {
        await this.billing.requirePayment(row.owner_id);
        const privateData = await this.vault.decrypt<{ environment: Record<string, string> }>(
          required(row.private_data),
          'resource:' + row.id,
        );
        await this.runner.start(
          row.id,
          EnvironmentInput.parse({
            image: row.data.image,
            size: row.data.size,
            lifetime: row.data.lifetime,
            identityId: row.data.identityId,
          }),
          privateData.environment,
          async (machineId) => {
            await this.resources.db.pool.query(
              'UPDATE environment_jobs SET machine_id=$3 WHERE resource_id=$1 AND lease_token=$2',
              [row.id, lease, machineId],
            );
            await this.resources.db.pool.query(
              "UPDATE resources SET data=jsonb_set(data,'{startedAt}',to_jsonb($2::text)) WHERE id=$1 AND data->>'startedAt' IS NULL",
              [row.id, new Date().toISOString()],
            );
          },
        );
        const now = new Date().toISOString();
        await this.resources.db.pool.query(
          `UPDATE resources SET data=data||jsonb_build_object('state','running','lastActiveAt',$2::text),version=version+1 WHERE id=$1 AND data->>'state'='starting'`,
          [row.id, now],
        );
      } else if (row.data.state === 'stopping') {
        const machine = job.machine_id ?? (await this.runner.find(row.id));
        if (machine) await this.runner.stop(machine);
        await this.resources.db.transaction(async (connection) => {
          row = required(
            await this.resources.db.one<ResourceRow>(
              'SELECT * FROM resources WHERE id=$1 FOR UPDATE',
              [row.id],
              connection,
            ),
          );
          const seconds = row.data.startedAt
            ? Math.max(0, Math.ceil((Date.now() - new Date(String(row.data.startedAt)).getTime()) / 1000))
            : 0;
          await this.billing.record(
            row.owner_id,
            'compute',
            seconds *
              { small: 1, medium: 2, large: 4 }[String(row.data.size) as 'small' | 'medium' | 'large'],
            'environment:' + row.id,
            connection,
          );
          await this.resources.update(
            row,
            {
              data: {
                ...row.data,
                state: row.data.error ? 'failed' : 'stopped',
                stoppedAt: new Date().toISOString(),
              },
            },
            connection,
          );
          await connection.query('DELETE FROM credentials WHERE environment_id=$1', [row.id]);
          await this.resources.audit.record(
            row.owner_id,
            null,
            'environment.stop',
            row.id,
            { seconds },
            connection,
          );
        });
      }
      await this.resources.db.pool.query(
        'UPDATE environment_jobs SET lease_until=NULL,lease_token=NULL WHERE resource_id=$1 AND lease_token=$2',
        [row.id, lease],
      );
    } catch (error) {
      if (row.data.state === 'starting') await this.requestStop(row.id, failure(error).message);
      await this.resources.db.pool.query(
        "UPDATE environment_jobs SET lease_until=NULL,lease_token=NULL,retry_at=now()+$3::int*interval '1 second' WHERE resource_id=$1 AND lease_token=$2",
        [row.id, lease, Math.min(300, 2 ** Math.min(job.attempts, 8))],
      );
    }
    return true;
  }
  async remove(actor: Actor, row: ResourceRow) {
    await this.resources.authorization.requireResource(actor, row, 'delete');
    if (!['stopped', 'failed'].includes(String(row.data.state)))
      fail(409, 'environment_active', 'Stop the environment before removing it.');
    await this.resources.delete(actor, row);
  }
  async enforcePayment() {
    const rows = await this.resources.db.all<{ id: string; owner_id: string }>(
      "SELECT id,owner_id FROM resources WHERE kind='environment' AND data->>'state'='running'",
    );
    for (const row of rows) {
      try {
        await this.billing.requirePayment(row.owner_id);
      } catch (error) {
        if (failure(error).code === 'payment_required')
          await this.requestStop(row.id, 'The payment method is no longer active.');
        else throw error;
      }
    }
  }
}
