import { randomUUID } from 'node:crypto';
import type { z } from 'zod';
import type { Actor } from './authorization.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Billing } from './billing.js';
import type { Runner } from './runner.js';
import { digest, token } from './vault.js';
import type { Vault } from './vault.js';
import type { Configuration } from './config.js';
import type { Delegation } from './delegation.js';
import { EnvironmentInput } from '../shared/contracts.js';
import type { EnvironmentOptions } from '../shared/contracts.js';
import { EnvironmentBootstrap, EnvironmentEnrollment } from '../shared/protocol.js';
import { canonical, hash, verifyBinding } from '../shared/authority.js';
import { fail, failure, required } from './errors.js';

interface Job {
  resource_id: string; machine_id: string | null; volume_id: string | null;
  bootstrap_ciphertext: string | null; bootstrap_digest: string | null;
  bootstrap_expires_at: Date | null; enrollment_digest: string | null; attempts: number;
}
export class Environments {
  constructor(readonly resources: Resources, readonly billing: Billing, readonly runner: Runner,
    readonly vault: Vault, readonly config: Configuration, readonly delegation: Delegation) {}

  async create(actor: Actor, ownerId: string, options: EnvironmentOptions, name?: string) {
    if (!this.runner.enabled) fail(503, 'environments_unavailable', 'Environments are not configured.');
    if (!(await this.resources.authorization.canCreate(actor, ownerId, 'environment')))
      fail(403, 'forbidden', 'You cannot open environments for this principal.');
    if (options.lifetime.idleSeconds > options.lifetime.maxSeconds)
      fail(400, 'invalid_lifetime', 'The idle timeout cannot exceed the maximum lifetime.');
    const image = options.image ?? this.config.FLY_COMMAND_IMAGE;
    if (!/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(image))
      fail(400, 'image_required', 'Choose a command image pinned to its SHA-256 digest.');
    const callers = await Promise.all([...new Set(options.callerIds ?? [actor.id])].map(async id => {
      await this.resources.principals.get(id);
      return (await this.delegation.bindings.current(id)).binding;
    }));
    return this.resources.db.transaction(async connection => {
      await this.billing.reserve(ownerId, 'compute',
        options.lifetime.maxSeconds * { small: 1, medium: 2, large: 4 }[options.size], connection);
      const id = randomUUID(), label = name ?? 'Foundation Agent ' + id.slice(0, 8);
      const executor = await this.resources.principals.create(label, null, undefined, connection);
      const bootstrap = EnvironmentBootstrap.parse({ id, executorId: executor.id, ownerId, name: label,
        origin: this.config.origin, bootstrap: token(), commandImage: image, callers });
      const row = await this.resources.insert(ownerId, 'environment', label, {
        ...options, image, driver: 'managed', executorId: executor.id, operatorId: executor.id,
        capabilities: ['http', 'command', 'function', 'connect', 'refresh', 'revoke'], isolation: 'container',
        state: 'starting', startedAt: null, stoppedAt: null, lastActiveAt: new Date().toISOString(), error: null,
      }, { id }, connection);
      await connection.query(
        `INSERT INTO environment_jobs(resource_id,bootstrap_digest,bootstrap_ciphertext,bootstrap_expires_at)
         VALUES($1,$2,$3,now()+interval '15 minutes')`,
        [id, digest(bootstrap.bootstrap), await this.vault.encrypt(bootstrap, 'executor-bootstrap:' + id)]);
      await this.resources.audit.record(ownerId, actor.id, 'environment.create', id, { executorId: executor.id }, connection);
      return row;
    });
  }

  async enroll(id: string, input: z.infer<typeof EnvironmentEnrollment>) {
    const value = EnvironmentEnrollment.parse(input), binding = await verifyBinding(value.binding);
    if (binding.generation !== 1 || binding.previous !== null)
      fail(400, 'invalid_key_binding', 'Start the executor with its first key binding.');
    await this.resources.db.transaction(async connection => {
      const row = await this.resources.get(id, connection);
      const job = required(await this.resources.db.one<Job>(
        'SELECT * FROM environment_jobs WHERE resource_id=$1 FOR UPDATE', [id], connection));
      if (job.bootstrap_digest !== digest(value.bootstrap) || !job.bootstrap_expires_at ||
        job.bootstrap_expires_at.getTime() <= Date.now() || !['starting', 'running'].includes(String(row.data.state)) ||
        binding.principalId !== row.data.executorId)
        fail(403, 'bootstrap_expired', 'This executor enrollment has expired.');
      const enrollmentDigest = await hash({ binding, token: value.token });
      if (job.enrollment_digest) {
        if (job.enrollment_digest === enrollmentDigest) return;
        fail(409, 'executor_enrolled', 'Use the keys already registered for this executor.');
      }
      await connection.query('UPDATE principals SET public_key=$2 WHERE id=$1',
        [binding.principalId, JSON.stringify(binding.encryption)]);
      await connection.query(
        'INSERT INTO principal_key_bindings(id,principal_id,binding,signature) VALUES($1,$2,$3,$4)',
        [binding.id, binding.principalId, JSON.stringify(binding), value.binding.signature]);
      await connection.query(
        `INSERT INTO credentials(id,principal_id,kind,name,identifier,environment_id)
         VALUES($1,$2,'key',$3,$4,$5)`,
        [randomUUID(), binding.principalId, row.name, digest(value.token), id]);
      await connection.query('UPDATE environment_jobs SET enrollment_digest=$2 WHERE resource_id=$1', [id, enrollmentDigest]);
      await this.resources.audit.record(row.owner_id, binding.principalId, 'environment.enroll', id,
        { fingerprint: await hash(binding) }, connection);
    });
  }

  async stop(actor: Actor, row: ResourceRow) {
    if (row.kind !== 'environment') fail(400, 'wrong_kind', 'This item is not an environment.');
    await this.resources.authorization.requireResource(actor, row, 'delete');
    await this.requestStop(row.id);
    return this.resources.get(row.id);
  }
  async requestStop(id: string, error: string | null = null) {
    const row = await this.resources.get(id);
    if (['stopped', 'failed'].includes(String(row.data.state))) return;
    await this.delegation.stop({ id: row.owner_id }, id);
    const managed = await this.resources.db.one('SELECT 1 FROM environment_jobs WHERE resource_id=$1', [id]);
    if (managed) await this.resources.db.pool.query(
      "UPDATE resources SET data=data||jsonb_build_object('state','stopping','error',$2::text),version=version+1 WHERE id=$1",
      [id, error]);
  }
  async tick() {
    const expired = await this.resources.db.all<{ id: string }>(
      `SELECT r.id FROM resources r JOIN environment_jobs j ON j.resource_id=r.id
       WHERE r.data->>'state' IN ('starting','running') AND (
         (r.data->>'startedAt')::timestamptz+(r.data->'lifetime'->>'maxSeconds')::int*interval '1 second'<=now()
         OR (r.data->>'lastActiveAt')::timestamptz+(r.data->'lifetime'->>'idleSeconds')::int*interval '1 second'<=now()
           AND NOT EXISTS(SELECT 1 FROM execution_tasks t WHERE t.environment_id=r.id AND t.state IN ('queued','running'))
         OR r.data->>'state'='starting' AND j.bootstrap_expires_at<now())`);
    for (const row of expired) await this.requestStop(row.id, 'The environment reached its lifetime limit.');
    const lease = randomUUID();
    const job = await this.resources.db.one<Job>(
      `UPDATE environment_jobs j SET lease_until=now()+interval '2 minutes',lease_token=$1,attempts=attempts+1
       WHERE resource_id=(SELECT j.resource_id FROM environment_jobs j JOIN resources r ON r.id=j.resource_id
         WHERE (j.lease_until IS NULL OR j.lease_until<now()) AND j.retry_at<=now()
           AND r.data->>'state' IN ('starting','stopping')
         ORDER BY r.created_at FOR UPDATE OF j SKIP LOCKED LIMIT 1) RETURNING j.*`, [lease]);
    if (!job) return false;
    let row = await this.resources.get(job.resource_id);
    try {
      if (row.data.state === 'starting') {
        await this.billing.requirePayment(row.owner_id);
        const bootstrap = EnvironmentBootstrap.parse(await this.vault.decrypt(
          required(job.bootstrap_ciphertext), 'executor-bootstrap:' + row.id));
        await this.runner.start(row.id, EnvironmentInput.parse({
          image: row.data.image, size: row.data.size, lifetime: row.data.lifetime, callerIds: row.data.callerIds,
        }), { FOUNDATION_EXECUTOR_BOOTSTRAP: Buffer.from(canonical(bootstrap)).toString('base64url') },
        async (machineId, volumeId) => {
          await this.resources.db.pool.query(
            'UPDATE environment_jobs SET machine_id=$3,volume_id=$4 WHERE resource_id=$1 AND lease_token=$2',
            [row.id, lease, machineId, volumeId]);
          await this.resources.db.pool.query(
            "UPDATE resources SET data=jsonb_set(data,'{startedAt}',to_jsonb($2::text)) WHERE id=$1 AND data->>'startedAt' IS NULL",
            [row.id, new Date().toISOString()]);
        });
      } else if (row.data.state === 'stopping') {
        const machine = job.machine_id ?? await this.runner.find(row.id);
        if (machine) await this.runner.stop(machine);
        await this.resources.db.transaction(async connection => {
          row = required(await this.resources.db.one<ResourceRow>(
            'SELECT * FROM resources WHERE id=$1 FOR UPDATE', [row.id], connection));
          const seconds = row.data.startedAt
            ? Math.max(0, Math.ceil((Date.now() - Date.parse(String(row.data.startedAt))) / 1000)) : 0;
          await this.billing.record(row.owner_id, 'compute',
            seconds * { small: 1, medium: 2, large: 4 }[String(row.data.size) as EnvironmentOptions['size']],
            'environment:' + row.id, connection);
          await this.resources.update(row, { data: { ...row.data,
            state: row.data.error ? 'failed' : 'stopped', stoppedAt: new Date().toISOString() } }, connection);
          await connection.query('DELETE FROM credentials WHERE environment_id=$1', [row.id]);
          await connection.query('UPDATE environment_jobs SET bootstrap_ciphertext=NULL,bootstrap_digest=NULL WHERE resource_id=$1', [row.id]);
          await this.resources.audit.record(row.owner_id, null, 'environment.stop', row.id, { seconds }, connection);
        });
      }
      await this.resources.db.pool.query(
        "UPDATE environment_jobs SET lease_until=NULL,lease_token=NULL,retry_at=now()+interval '5 seconds' WHERE resource_id=$1 AND lease_token=$2",
        [row.id, lease]);
    } catch (error) {
      if (row.data.state === 'starting') await this.requestStop(row.id, failure(error).message);
      await this.resources.db.pool.query(
        "UPDATE environment_jobs SET lease_until=NULL,lease_token=NULL,retry_at=now()+$3::int*interval '1 second' WHERE resource_id=$1 AND lease_token=$2",
        [row.id, lease, Math.min(300, 2 ** Math.min(job.attempts, 8))]);
    }
    return true;
  }
  async remove(actor: Actor, row: ResourceRow) {
    await this.resources.authorization.requireResource(actor, row, 'delete');
    if (!['stopped', 'failed'].includes(String(row.data.state)))
      fail(409, 'environment_active', 'Stop the environment before removing it.');
    const job = await this.resources.db.one<Job>('SELECT * FROM environment_jobs WHERE resource_id=$1', [row.id]);
    if (job?.volume_id) await this.runner.removeVolume(job.volume_id);
    await this.resources.delete(actor, row);
  }
  async enforcePayment() {
    const rows = await this.resources.db.all<{ id: string; owner_id: string }>(
      "SELECT r.id,r.owner_id FROM resources r JOIN environment_jobs j ON j.resource_id=r.id WHERE r.data->>'state' IN ('starting','running')");
    for (const row of rows) {
      try { await this.billing.requirePayment(row.owner_id); }
      catch (error) {
        if (failure(error).code === 'payment_required') await this.requestStop(row.id, 'The payment method is no longer active.');
        else throw error;
      }
    }
  }
}
