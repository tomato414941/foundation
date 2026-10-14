import { createHash, randomUUID } from 'node:crypto';
import type { z } from 'zod';
import type { Actor } from './authorization.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Billing } from './billing.js';
import type { Runner } from './runner.js';
import { digest, token } from './vault.js';
import type { Vault } from './vault.js';
import type { Configuration } from './config.js';
import type { Delegation } from './delegation.js';
import { EnvironmentInput, EnvironmentDeletion } from '../shared/contracts.js';
import type { EnvironmentOptions, EnvironmentStopReason } from '../shared/contracts.js';
import { EnvironmentBootstrap, EnvironmentEnrollment } from '../shared/protocol.js';
import { SSHConnection, SSHView, sshKeyBytes } from '../shared/ssh.js';
import type { SSHHeartbeat, SSHUpdate } from '../shared/ssh.js';
import { canonical, fingerprint, hash, verifyBinding } from '../shared/authority.js';
import { fail, failure, required } from './errors.js';

interface Job {
  resource_id: string; machine_id: string | null; volume_id: string | null;
  bootstrap_ciphertext: string | null; bootstrap_digest: string | null;
  network_slot: number | null; bootstrap_expires_at: Date | null; enrollment_digest: string | null; attempts: number;
}
interface Deletion {
  resource_id: string; owner_id: string; actor_id: string | null;
  state: 'pending' | 'failed' | 'complete'; error: string | null;
}
export class Environments {
  constructor(readonly resources: Resources, readonly billing: Billing, readonly runner: Runner,
    readonly vault: Vault, readonly config: Configuration, readonly delegation: Delegation) {}

  get sshEnabled() { return this.runner.enabled; }

  async create(actor: Actor, ownerId: string, options: EnvironmentOptions, name?: string) {
    if (!this.runner.enabled) fail(503, 'environments_unavailable', 'Environments are not configured.');
    if (!(await this.resources.authorization.canCreate(actor, ownerId, 'environment')))
      fail(403, 'forbidden', 'You cannot open environments for this principal.');
    const image = options.image ?? this.config.ENVIRONMENT_COMMAND_IMAGE;
    if (!/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(image))
      fail(400, 'image_required', 'Choose a command image pinned to its SHA-256 digest.');
    if (options.ssh?.authorizedKeys.length && !this.sshEnabled)
      fail(503, 'ssh_unavailable', 'SSH is not configured for managed environments.');
    return this.resources.db.transaction(async connection => {
      await this.billing.reserve(ownerId, 'compute', { small: 1, medium: 2, large: 4 }[options.size], connection);
      const id = randomUUID(), label = name ?? '実行環境 ' + id.slice(0, 8);
      await connection.query("SELECT pg_advisory_xact_lock(hashtext(current_schema() || ':environment_networks'))");
      const network = await this.resources.db.one<{ slot: number }>(
        `SELECT slot FROM generate_series(0,4091) AS slot
         WHERE NOT EXISTS(SELECT 1 FROM environment_jobs WHERE network_slot=slot) ORDER BY slot LIMIT 1`, [], connection);
      if (!network) fail(503, 'environment_capacity', 'All environment networks are in use. Try again later.');
      const { ssh: requestedSSH, ...settings } = options;
      let ssh: z.infer<typeof SSHConnection> | undefined;
      if (this.sshEnabled) {
        ssh = SSHConnection.parse({ authorizedKeys: requestedSSH?.authorizedKeys ?? [],
          host: null, port: 22, username: 'root', workingDirectory: '/workspace',
          hostKey: null, fingerprint: null, revision: 1, appliedRevision: 0, activeSessions: 0 });
      }
      const executor = await this.resources.principals.create(label, null, undefined, connection);
      const bootstrap = EnvironmentBootstrap.parse({ id, executorId: executor.id, ownerId, name: label,
        origin: this.config.origin, bootstrap: token(), commandImage: image, ...(ssh ? { ssh: { port: ssh.port } } : {}) });
      const row = await this.resources.insert(ownerId, 'environment', label, {
        ...settings, ...(ssh ? { ssh } : {}), image, driver: 'managed', executorId: executor.id, operatorId: executor.id,
        capabilities: ['http', 'command', 'function', 'connect', 'refresh', 'revoke'], isolation: 'container',
        state: 'starting', startedAt: null, stoppedAt: null, stopReason: null, lastActiveAt: new Date().toISOString(), error: null,
      }, { id }, connection);
      await connection.query(
        `INSERT INTO environment_jobs(resource_id,bootstrap_digest,bootstrap_ciphertext,bootstrap_expires_at,provider,network_slot)
         VALUES($1,$2,$3,now()+interval '15 minutes','ec2',$4)`,
        [id, digest(bootstrap.bootstrap), await this.vault.encrypt(bootstrap, 'executor-bootstrap:' + id), network.slot]);
      await this.resources.audit.record(ownerId, actor.id, 'environment.create', id, { executorId: executor.id }, connection);
      return row;
    });
  }

  private sshView(row: ResourceRow) {
    if (row.kind !== 'environment') fail(400, 'wrong_kind', 'Choose an environment.');
    if (!row.data.ssh) return null;
    const ssh = SSHConnection.parse(row.data.ssh);
    const state = !['starting', 'running'].includes(String(row.data.state)) || row.data.deletion ? 'stopped'
      : row.data.state === 'starting' ? 'starting'
      : !ssh.host || ssh.appliedRevision !== ssh.revision || !ssh.hostKey ? 'configuring'
      : ssh.authorizedKeys.length ? 'ready' : 'disabled';
    return SSHView.parse({ ...ssh, state });
  }
  async ssh(actor: Actor, id: string) {
    const row = await this.resources.get(id);
    await this.resources.authorization.requireResource(actor, row, 'read');
    return this.sshView(row);
  }
  async updateSSH(actor: Actor, id: string, input: z.infer<typeof SSHUpdate>) {
    return this.resources.db.transaction(async connection => {
      const row = required(await this.resources.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1 FOR UPDATE', [id], connection));
      await this.resources.authorization.requireResource(actor, row, 'update', connection);
      const ssh = this.sshView(row);
      if (!ssh) fail(409, 'ssh_unavailable', 'SSH is not available in this environment.');
      if (row.data.deletion) fail(409, 'environment_unavailable', 'This environment is being deleted.');
      if (input.revision !== undefined && input.revision !== ssh.revision)
        fail(409, 'changed', 'The SSH keys have changed. Read them again before saving.');
      const previous = SSHConnection.parse(row.data.ssh);
      const updated = await this.resources.update(row, { data: { ...row.data,
        ssh: { ...previous, authorizedKeys: [...new Set(input.authorizedKeys)], revision: previous.revision + 1 } } }, connection);
      await this.resources.audit.record(row.owner_id, actor.id, 'environment.ssh_keys_updated', id,
        { keys: input.authorizedKeys.length }, connection);
      return this.sshView(updated)!;
    });
  }
  async sshHeartbeat(actor: Actor, id: string, input: z.infer<typeof SSHHeartbeat>) {
    return this.resources.db.transaction(async connection => {
      await this.delegation.requireExecutor(actor, id);
      const row = required(await this.resources.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1 FOR UPDATE', [id], connection));
      const ssh = this.sshView(row);
      if (!ssh || ssh.state === 'stopped') fail(409, 'ssh_unavailable', 'SSH is not available in this environment.');
      if (input.appliedRevision > ssh.revision) fail(409, 'changed', 'Use the current SSH settings.');
      const fingerprint = 'SHA256:' + createHash('sha256').update(required(sshKeyBytes(input.hostKey))).digest('base64').replace(/=+$/, '');
      if (ssh.fingerprint && ssh.fingerprint !== fingerprint)
        fail(409, 'ssh_host_key_changed', 'Restore this environment’s saved SSH host key.');
      if (!ssh.hostKey || ssh.appliedRevision !== input.appliedRevision || ssh.activeSessions !== input.activeSessions) {
        const settings = SSHConnection.parse(row.data.ssh);
        await this.resources.update(row, { data: { ...row.data,
          ssh: { ...settings, hostKey: input.hostKey, fingerprint, appliedRevision: input.appliedRevision,
            activeSessions: input.activeSessions } } }, connection);
      }
      if (input.activeSessions > 0) await connection.query(
        "UPDATE resources SET data=jsonb_set(data,'{lastActiveAt}',to_jsonb($2::text)) WHERE id=$1",
        [id, new Date().toISOString()]);
      return { configuration: { authorizedKeys: ssh.authorizedKeys, port: ssh.port, revision: ssh.revision } };
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
      if (job.bootstrap_digest && job.bootstrap_digest !== digest(value.bootstrap) || !job.bootstrap_expires_at ||
        job.bootstrap_expires_at.getTime() <= Date.now() || !['starting', 'running'].includes(String(row.data.state)) ||
        binding.principalId !== row.data.executorId)
        fail(403, 'bootstrap_expired', 'This executor enrollment has expired.');
      const enrollmentDigest = await hash({ binding, token: value.token });
      if (job.enrollment_digest) {
        if (job.enrollment_digest !== enrollmentDigest)
          fail(409, 'executor_enrolled', 'Use the keys already registered for this executor.');
        if (await this.resources.db.one('SELECT 1 FROM credentials WHERE environment_id=$1 AND identifier=$2',
          [id, digest(value.token)], connection)) return;
        if (row.data.state !== 'starting') fail(403, 'bootstrap_expired', 'Start the environment before enrolling its saved identity.');
        await this.delegation.bindings.requireCurrent(binding);
        await connection.query(
          `INSERT INTO credentials(id,principal_id,kind,name,identifier,environment_id)
           VALUES($1,$2,'key',$3,$4,$5)`,
          [randomUUID(), binding.principalId, row.name, digest(value.token), id]);
        return;
      }
      if (job.bootstrap_digest !== digest(value.bootstrap)) fail(403, 'bootstrap_expired', 'This executor enrollment has expired.');
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
        { fingerprint: await fingerprint(binding) }, connection);
    });
  }

  async start(actor: Actor, row: ResourceRow) {
    if (row.kind !== 'environment') fail(400, 'wrong_kind', 'Choose an environment.');
    if (!this.runner.enabled) fail(503, 'environments_unavailable', 'Environments are not configured.');
    return this.resources.db.transaction(async connection => {
      await this.billing.lockCompute(connection);
      row = await this.resources.get(row.id, connection);
      await this.resources.authorization.requireResource(actor, row, 'update', connection);
      if (row.data.driver !== 'managed') fail(409, 'environment_unavailable', 'Start this environment on its host.');
      if (row.data.deletion) fail(409, 'environment_unavailable', 'This environment is being deleted.');
      if (['starting', 'running'].includes(String(row.data.state))) return row;
      if (row.data.state === 'stopping') fail(409, 'environment_stopping', 'Wait for the environment to stop.');
      await this.billing.reserve(row.owner_id, 'compute',
        { small: 1, medium: 2, large: 4 }[String(row.data.size) as EnvironmentOptions['size']], connection);
      await connection.query('SELECT resource_id FROM executor_environments WHERE resource_id=$1 FOR UPDATE', [row.id]);
      row = required(await this.resources.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1 FOR UPDATE', [row.id], connection));
      if (row.data.deletion || !['stopped', 'failed'].includes(String(row.data.state)))
        fail(409, 'environment_unavailable', 'Read the current environment state before starting it.');
      const job = required(await this.resources.db.one<Job>('SELECT * FROM environment_jobs WHERE resource_id=$1 FOR UPDATE', [row.id], connection));
      if (!job.machine_id && !job.bootstrap_ciphertext)
        fail(409, 'environment_unavailable', 'The environment instance is no longer available.');
      await connection.query(
        `UPDATE environment_jobs SET retry_at=now(),attempts=0,lease_until=NULL,lease_token=NULL,
          metered_at=NULL,bootstrap_expires_at=now()+interval '15 minutes' WHERE resource_id=$1`, [row.id]);
      await connection.query('UPDATE executor_environments SET heartbeat_at=NULL WHERE resource_id=$1', [row.id]);
      row = await this.resources.update(row, { data: { ...row.data, state: 'starting', startedAt: null,
        stoppedAt: null, stopReason: null, error: null, lastActiveAt: new Date().toISOString(),
        ...(row.data.ssh ? { ssh: { ...SSHConnection.parse(row.data.ssh), host: null, activeSessions: 0 } } : {}) } }, connection);
      await this.resources.audit.record(row.owner_id, actor.id, 'environment.start', row.id, {}, connection);
      return row;
    });
  }
  async stop(actor: Actor, row: ResourceRow) {
    if (row.kind !== 'environment') fail(400, 'wrong_kind', 'This item is not an environment.');
    await this.resources.authorization.requireResource(actor, row, 'delete');
    await this.requestStop(row.id, null, 'manual');
    return this.resources.get(row.id);
  }
  async requestStop(id: string, error: string | null = null, reason: z.infer<typeof EnvironmentStopReason> | null = null) {
    await this.resources.db.transaction(async connection => {
      await this.billing.lockCompute(connection);
      let row = await this.resources.get(id, connection);
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [row.owner_id]);
      await connection.query('SELECT resource_id FROM executor_environments WHERE resource_id=$1 FOR UPDATE', [id]);
      row = required(await this.resources.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1 FOR UPDATE', [id], connection));
      if (['stopping', 'stopped', 'failed'].includes(String(row.data.state))) return;
      await this.delegation.stop({ id: row.owner_id }, id, connection);
      const managed = await this.resources.db.one('SELECT 1 FROM environment_jobs WHERE resource_id=$1', [id], connection);
      if (managed) {
        await connection.query(
          "UPDATE resources SET data=data||jsonb_build_object('state','stopping','stoppedAt',NULL,'error',$2::text,'stopReason',$3::text),version=version+1 WHERE id=$1",
          [id, error, reason]);
        await connection.query('UPDATE environment_jobs SET retry_at=now() WHERE resource_id=$1', [id]);
      }
    });
  }
  async tick(stoppingOnly = false) {
    await this.enforceUsage();
    const expired = await this.resources.db.all<{ id: string; reason: 'timeout' | 'idle' | 'bootstrap' }>(
      `SELECT id,reason FROM (SELECT r.id,CASE
         WHEN r.data->>'state'='starting' AND j.bootstrap_expires_at<now() THEN 'bootstrap'
         WHEN (r.data->>'startedAt')::timestamptz+(r.data->'lifetime'->>'maxSeconds')::int*interval '1 second'<=now() THEN 'timeout'
         WHEN r.data->>'state'='running' AND (r.data->>'lastActiveAt')::timestamptz+(r.data->'lifetime'->>'idleSeconds')::int*interval '1 second'<=now()
           AND coalesce((r.data->'ssh'->>'activeSessions')::int,0)=0
           AND NOT EXISTS(SELECT 1 FROM execution_tasks t WHERE t.environment_id=r.id AND t.state IN ('queued','running'))
           AND NOT EXISTS(SELECT 1 FROM environment_processes p WHERE p.environment_id=r.id AND p.state IN ('queued','running'))
           AND NOT EXISTS(SELECT 1 FROM function_invocations i WHERE i.environment_id=r.id AND
             (i.state IN ('queued','running') OR (i.state='uncertain' AND i.phase='dispatched' AND i.finished_at IS NULL))) THEN 'idle'
         END AS reason FROM resources r JOIN environment_jobs j ON j.resource_id=r.id
         WHERE r.data->>'state' IN ('starting','running')) limits WHERE reason IS NOT NULL`);
    for (const row of expired) await this.requestStop(row.id,
      row.reason === 'bootstrap' ? 'The environment did not finish starting.' : null,
      row.reason === 'bootstrap' ? null : row.reason);
    const lease = randomUUID();
    const job = await this.resources.db.one<Job>(
      `UPDATE environment_jobs j SET lease_until=now()+interval '2 minutes',lease_token=$1,attempts=attempts+1
       WHERE resource_id=(SELECT j.resource_id FROM environment_jobs j JOIN resources r ON r.id=j.resource_id
         WHERE (j.lease_until IS NULL OR j.lease_until<now()) AND j.retry_at<=now()
           AND (r.data->>'state'='starting' AND r.data->>'startedAt' IS NULL
             OR r.data->>'state'='stopping' OR r.data->'deletion'->>'state'='pending')
           AND coalesce(r.data->'deletion'->>'state','')<>'failed'
           AND (NOT $2::boolean OR r.data->>'state'='stopping' OR r.data->'deletion'->>'state'='pending')
         ORDER BY r.created_at FOR UPDATE OF j SKIP LOCKED LIMIT 1) RETURNING j.*`, [lease, stoppingOnly]);
    if (!job) return false;
    let row = await this.resources.get(job.resource_id);
    const renewal = setInterval(() => {
      void this.resources.db.pool.query(
        "UPDATE environment_jobs SET lease_until=now()+interval '2 minutes' WHERE resource_id=$1 AND lease_token=$2",
        [row.id, lease]).catch(() => {});
    }, 30_000);
    renewal.unref();
    let deletionStep: 'stop' | 'disk' | 'network' | 'resource' = 'stop';
    try {
      if (row.data.state === 'starting') {
        await this.billing.requirePayment(row.owner_id);
        const created = async (machineId: string, volumeId: string, host: string) => {
          await this.resources.db.transaction(async connection => {
            await this.billing.lockCompute(connection);
            await connection.query(
              'UPDATE environment_jobs SET machine_id=$3,volume_id=$4 WHERE resource_id=$1 AND lease_token=$2',
              [row.id, lease, machineId, volumeId]);
            await connection.query(
              "UPDATE resources SET data=jsonb_set(jsonb_set(data,'{startedAt}',to_jsonb(coalesce(data->>'startedAt',$2::text))),'{ssh,host}',to_jsonb($3::text)),version=version+1,updated_at=now() WHERE id=$1",
              [row.id, new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(), host]);
          });
        };
        if (job.machine_id) {
          const { volumeId, host } = await this.runner.resume(job.machine_id);
          await created(job.machine_id, volumeId, host);
        } else {
          const bootstrap = EnvironmentBootstrap.parse(await this.vault.decrypt(
            required(job.bootstrap_ciphertext), 'executor-bootstrap:' + row.id));
          await this.runner.start(row.id, EnvironmentInput.parse({ image: row.data.image, size: row.data.size, lifetime: row.data.lifetime }),
            { FOUNDATION_EXECUTOR_BOOTSTRAP: Buffer.from(canonical(bootstrap)).toString('base64url') }, created, required(job.network_slot));
        }
      } else if (row.data.state === 'stopping') {
        const machine = row.data.driver === 'attached' ? null : job.machine_id ?? await this.runner.find(row.id);
        if (machine) {
          await this.resources.db.pool.query(
            'UPDATE environment_jobs SET machine_id=$3 WHERE resource_id=$1 AND lease_token=$2', [row.id, lease, machine]);
          await this.runner.stop(machine);
        }
        await this.resources.db.transaction(async connection => {
          await this.billing.measureCompute(connection, row.id);
          row = required(await this.resources.db.one<ResourceRow>(
            'SELECT * FROM resources WHERE id=$1 FOR UPDATE', [row.id], connection));
          const seconds = row.data.startedAt
            ? Math.max(0, Math.ceil((Date.now() - Date.parse(String(row.data.startedAt))) / 1000)) : 0;
          row = await this.resources.update(row, { data: { ...row.data,
            state: row.data.error ? 'failed' : 'stopped', stoppedAt: new Date().toISOString() } }, connection);
          await this.resources.audit.record(row.owner_id, null, 'environment.stop', row.id, { seconds }, connection);
        });
      }
      const deletion = await this.resources.db.one<Deletion>(
        "SELECT * FROM environment_deletions WHERE resource_id=$1 AND state='pending'", [row.id]);
      if (deletion && ['stopped', 'failed'].includes(String(row.data.state))) {
        const machine = row.data.driver === 'attached' ? null : job.machine_id ?? await this.runner.find(row.id);
        if (machine) await this.runner.terminate(machine);
        deletionStep = 'disk';
        const volume = row.data.driver === 'attached' ? null : job.volume_id ?? await this.runner.findVolume(row.id);
        if (volume) await this.runner.removeVolume(volume);
        deletionStep = 'network';
        if (row.data.driver !== 'attached') await this.runner.removeNetwork(row.id);
        deletionStep = 'resource';
        await this.resources.db.transaction(async connection => {
          await connection.query('DELETE FROM credentials WHERE environment_id=$1', [row.id]);
          await this.resources.delete({ id: deletion.actor_id ?? row.owner_id }, row, connection);
          await connection.query(
            "UPDATE environment_deletions SET state='complete',error=NULL,completed_at=now() WHERE resource_id=$1", [row.id]);
        });
      }
      await this.resources.db.pool.query(
        "UPDATE environment_jobs SET lease_until=NULL,lease_token=NULL,retry_at=now()+interval '5 seconds' WHERE resource_id=$1 AND lease_token=$2",
        [row.id, lease]);
    } catch (error) {
      const deleting = await this.resources.db.one<Deletion>(
        "SELECT * FROM environment_deletions WHERE resource_id=$1 AND state='pending'", [row.id]);
      if (row.data.state === 'starting') await this.requestStop(row.id, deleting ? null : failure(error).message);
      else if (deleting) await this.resources.db.transaction(async connection => {
        const cause = failure(error).code;
        const code = ['runner_unavailable', 'runner_response'].includes(cause)
          ? deletionStep === 'disk' ? 'environment_disk_delete_failed'
            : deletionStep === 'network' ? 'environment_network_delete_failed' : 'environment_stop_failed' : cause;
        await connection.query(
          "UPDATE environment_deletions SET state='failed',error=$2 WHERE resource_id=$1", [row.id, code]);
        await connection.query(
          "UPDATE resources SET data=data||jsonb_build_object('deletion',jsonb_build_object('state','failed','error',$2::text)),version=version+1,updated_at=now() WHERE id=$1",
          [row.id, code]);
      });
      await this.resources.db.pool.query(
        "UPDATE environment_jobs SET lease_until=NULL,lease_token=NULL,retry_at=now()+$3::int*interval '1 second' WHERE resource_id=$1 AND lease_token=$2",
        [row.id, lease, deleting ? 0 : Math.min(300, 2 ** Math.min(job.attempts, 8))]);
    } finally { clearInterval(renewal); }
    return true;
  }
  async remove(actor: Actor, row: ResourceRow) {
    if (row.kind !== 'environment') fail(400, 'wrong_kind', 'Choose an environment.');
    await this.resources.db.transaction(async connection => {
      await this.billing.lockCompute(connection);
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [row.owner_id]);
      await connection.query('SELECT resource_id FROM executor_environments WHERE resource_id=$1 FOR UPDATE', [row.id]);
      row = required(await this.resources.db.one<ResourceRow>(
        'SELECT * FROM resources WHERE id=$1 FOR UPDATE', [row.id], connection));
      await this.resources.authorization.requireResource(actor, row, 'delete', connection);
      const existing = await this.resources.db.one<Deletion>(
        'SELECT * FROM environment_deletions WHERE resource_id=$1', [row.id], connection);
      if (existing?.state === 'pending') return;
      if (!['stopped', 'failed'].includes(String(row.data.state))) {
        await this.delegation.stop({ id: row.owner_id }, row.id, connection);
        row = await this.resources.get(row.id, connection);
        if (row.data.driver !== 'attached') row.data.state = 'stopping';
      }
      await connection.query(
        `INSERT INTO environment_deletions(resource_id,owner_id,actor_id,state) VALUES($1,$2,$3,'pending')
         ON CONFLICT(resource_id) DO UPDATE SET state='pending',error=NULL,actor_id=EXCLUDED.actor_id`,
        [row.id, row.owner_id, actor.id]);
      await this.resources.update(row, { data: { ...row.data, deletion: { state: 'pending', error: null } } }, connection);
      await connection.query(
        `INSERT INTO environment_jobs(resource_id) VALUES($1)
         ON CONFLICT(resource_id) DO UPDATE SET retry_at=now(),attempts=0`, [row.id]);
      await this.resources.audit.record(row.owner_id, actor.id, 'environment.delete_requested', row.id, {}, connection);
    });
    return EnvironmentDeletion.parse({ state: 'pending', error: null });
  }
  async deletion(actor: Actor, id: string) {
    const deletion = required(await this.resources.db.one<Deletion>(
      'SELECT * FROM environment_deletions WHERE resource_id=$1', [id]));
    const row = await this.resources.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1', [id]);
    if (row) await this.resources.authorization.requireResource(actor, row, 'read');
    else if (!actor.requestId && deletion.actor_id === actor.id) await this.resources.authorization.active(actor);
    else await this.resources.authorization.requirePrincipal(actor, deletion.owner_id, 'read');
    return EnvironmentDeletion.parse(deletion);
  }
  async enforcePayment() {
    const rows = await this.resources.db.all<{ id: string; owner_id: string }>(
      "SELECT r.id,r.owner_id FROM resources r JOIN environment_jobs j ON j.resource_id=r.id WHERE r.data->>'state' IN ('starting','running')");
    for (const row of rows) {
      try { await this.billing.requirePayment(row.owner_id); }
      catch (error) {
        if (failure(error).code === 'payment_required') await this.requestStop(row.id, null, 'payment');
        else throw error;
      }
    }
  }
  async enforceUsage() {
    await this.billing.measureCompute();
    const capacity = this.config.FOUNDATION_BILLING_MODE === 'included' &&
      await this.billing.computeUsage(null) >= this.config.FOUNDATION_INCLUDED_COMPUTE_SECONDS;
    const rows = await this.resources.db.all<{ id: string; owner_id: string }>(
      "SELECT r.id,r.owner_id FROM resources r JOIN environment_jobs j ON j.resource_id=r.id WHERE r.data->>'driver'='managed' AND r.data->>'state' IN ('starting','running')");
    const exhausted = new Map<string, boolean>();
    for (const row of rows) {
      if (!exhausted.has(row.owner_id)) {
        const usage = await this.billing.usage(row.owner_id);
        exhausted.set(row.owner_id, usage.computeSeconds >= usage.computeLimit);
      }
      if (exhausted.get(row.owner_id)) await this.requestStop(row.id, null, 'quota');
      else if (capacity) await this.requestStop(row.id, null, 'capacity');
    }
  }
}
