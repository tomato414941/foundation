import { createHash, randomUUID } from 'node:crypto';
import type { z } from 'zod';
import type { Actor } from './authorization.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Billing } from './billing.js';
import type { Runner } from './runner.js';
import type { Vault } from './vault.js';
import type { Configuration } from './config.js';
import type { Delegation } from './delegation.js';
import { EnvironmentInput, EnvironmentDeletion } from '../shared/contracts.js';
import type { EnvironmentOptions, EnvironmentStopReason } from '../shared/contracts.js';
import { SSHConnection, SSHView, sshKeyBytes } from '../shared/ssh.js';
import type { SSHUpdate } from '../shared/ssh.js';
import { SSHKeys, shellQuote } from './ssh-client.js';
import type { SSHClient, SSHDestination } from './ssh-client.js';
import { fail, failure, required } from './errors.js';

interface Job {
  resource_id: string; machine_id: string | null; volume_id: string | null;
  ssh_ciphertext: string | null; network_slot: number | null;
  provision_expires_at: Date | null; attempts: number;
}
interface Deletion {
  resource_id: string; owner_id: string; actor_id: string | null;
  state: 'pending' | 'failed' | 'complete'; error: string | null;
}
export class Environments {
  constructor(readonly resources: Resources, readonly billing: Billing, readonly runner: Runner,
    readonly vault: Vault, readonly config: Configuration, readonly delegation: Delegation, readonly client: SSHClient) {}

  get sshEnabled() { return this.runner.enabled; }

  async create(actor: Actor, ownerId: string, options: EnvironmentOptions, name?: string) {
    if (!this.runner.enabled) fail(503, 'environments_unavailable', 'Environments are not configured.');
    if (!(await this.resources.authorization.canCreate(actor, ownerId, 'environment')))
      fail(403, 'forbidden', 'You cannot open environments for this principal.');
    if (options.ssh?.authorizedKeys.length && !this.sshEnabled)
      fail(503, 'ssh_unavailable', 'SSH is not configured for managed environments.');
    const keys = await this.client.keys();
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
          host: null, port: 22, username: 'ubuntu', workingDirectory: '/home/ubuntu',
          hostKey: keys.hostPublicKey, fingerprint: 'SHA256:' + createHash('sha256')
            .update(required(sshKeyBytes(keys.hostPublicKey))).digest('base64').replace(/=+$/, ''), revision: 1, appliedRevision: 0, activeSessions: 0 });
      }
      const row = await this.resources.insert(ownerId, 'environment', label, {
        ...settings, ...(ssh ? { ssh } : {}), driver: 'managed',
        capabilities: ['command'], processes: { workingDirectory: '/home/ubuntu' },
        state: 'starting', startedAt: null, stoppedAt: null, stopReason: null, lastActiveAt: new Date().toISOString(), error: null,
      }, { id }, connection);
      await connection.query(
        `INSERT INTO environment_jobs(resource_id,ssh_ciphertext,provision_expires_at,provider,network_slot)
         VALUES($1,$2,now()+interval '15 minutes','ec2',$3)`,
        [id, await this.vault.encrypt(keys, 'environment-ssh:' + id), network.slot]);
      await this.resources.audit.record(ownerId, actor.id, 'environment.create', id, {}, connection);
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
      await connection.query('UPDATE environment_jobs SET ssh_sync_at=NULL WHERE resource_id=$1', [id]);
      await this.resources.audit.record(row.owner_id, actor.id, 'environment.ssh_keys_updated', id,
        { keys: input.authorizedKeys.length }, connection);
      return this.sshView(updated)!;
    });
  }

  async connection(id: string): Promise<SSHDestination> {
    const row = await this.resources.get(id), ssh = SSHConnection.parse(row.data.ssh);
    const job = required(await this.resources.db.one<Job>('SELECT * FROM environment_jobs WHERE resource_id=$1', [id]));
    if (!ssh.host || !ssh.hostKey || !job.ssh_ciphertext)
      fail(503, 'ssh_unavailable', 'The execution environment is not ready for SSH.');
    const keys = SSHKeys.parse(await this.vault.decrypt(job.ssh_ciphertext, 'environment-ssh:' + id));
    return { id, host: ssh.host, port: ssh.port, username: ssh.username, privateKey: keys.privateKey, hostKey: ssh.hostKey };
  }

  async syncSSH(id: string) {
    return this.resources.db.transaction(async connection => {
      const lock = await this.resources.db.one<{ locked: boolean }>(
        "SELECT pg_try_advisory_xact_lock(hashtextextended($1,736023745)) AS locked", [id], connection);
      if (!lock?.locked) return null;
      const row = await this.resources.get(id), ssh = SSHConnection.parse(row.data.ssh);
      const job = required(await this.resources.db.one<Job>('SELECT * FROM environment_jobs WHERE resource_id=$1', [id]));
      const keys = SSHKeys.parse(await this.vault.decrypt(required(job.ssh_ciphertext), 'environment-ssh:' + id));
      const content = [keys.publicKey, ...ssh.authorizedKeys].join('\n') + '\n';
      const script = [
        'set -eu', 'umask 077', 'command -v ss >/dev/null',
        "key_file=$(mktemp /etc/ssh/.foundation-keys.XXXXXX)",
        "trap 'rm -f -- \"$key_file\"' EXIT",
        'printf %s ' + shellQuote(Buffer.from(content).toString('base64')) + ' | base64 --decode > "$key_file"',
        'chmod 644 "$key_file"', 'mv -f -- "$key_file" /etc/ssh/foundation_authorized_keys',
        'ss -Hnt state established ' + shellQuote('( sport = :' + ssh.port + ' )') + ' | wc -l',
      ].join('\n');
      const result = await this.client.run(await this.connection(id), 'sudo -n /bin/sh -s', script);
      if (result.code || !/^\d+$/.test(result.stdout.trim()))
        fail(502, 'ssh_unavailable', 'The SSH settings could not be applied.');
      const activeSessions = Math.min(1024, Math.max(0, Number(result.stdout.trim()) - 1));
      const current = required(await this.resources.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1 FOR UPDATE', [id], connection));
      if (!['starting', 'running'].includes(String(current.data.state)) || current.data.deletion) return null;
      await this.resources.update(current, { data: { ...current.data, state: 'running',
        ...(activeSessions ? { lastActiveAt: new Date().toISOString() } : {}),
        ssh: { ...SSHConnection.parse(current.data.ssh), appliedRevision: ssh.revision, activeSessions } } }, connection);
      await connection.query('UPDATE environment_jobs SET ssh_checked_at=now() WHERE resource_id=$1', [id]);
      return activeSessions;
    });
  }

  async refreshSSH() {
    const job = await this.resources.db.one<{ resource_id: string }>(
      `UPDATE environment_jobs SET ssh_sync_at=now()+interval '30 seconds' WHERE resource_id=(
         SELECT j.resource_id FROM environment_jobs j JOIN resources r ON r.id=j.resource_id
         WHERE r.data->>'state'='running' AND NOT (r.data ? 'deletion')
           AND (j.ssh_sync_at IS NULL OR j.ssh_sync_at<=now())
         ORDER BY j.ssh_sync_at NULLS FIRST FOR UPDATE OF j SKIP LOCKED LIMIT 1) RETURNING resource_id`);
    if (job) await this.syncSSH(job.resource_id);
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
      if (!job.machine_id && !job.ssh_ciphertext)
        fail(409, 'environment_unavailable', 'The environment instance is no longer available.');
      await connection.query(
        `UPDATE environment_jobs SET retry_at=now(),attempts=0,lease_until=NULL,lease_token=NULL,
          metered_at=NULL,ssh_checked_at=NULL,ssh_sync_at=NULL,provision_expires_at=now()+interval '15 minutes' WHERE resource_id=$1`, [row.id]);
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
         WHEN r.data->>'state'='starting' AND j.provision_expires_at<now() THEN 'bootstrap'
         WHEN (r.data->>'startedAt')::timestamptz+(r.data->'lifetime'->>'maxSeconds')::int*interval '1 second'<=now() THEN 'timeout'
         WHEN r.data->>'state'='running' AND (r.data->>'lastActiveAt')::timestamptz+(r.data->'lifetime'->>'idleSeconds')::int*interval '1 second'<=now()
           AND NOT EXISTS(SELECT 1 FROM execution_tasks t WHERE t.environment_id=r.id AND t.state IN ('queued','running'))
           AND NOT EXISTS(SELECT 1 FROM environment_processes p WHERE p.environment_id=r.id AND p.phase<>'settled')
           AND NOT EXISTS(SELECT 1 FROM function_invocations i WHERE i.environment_id=r.id AND
             (i.state IN ('queued','running') OR (i.state='uncertain' AND i.phase='dispatched' AND i.finished_at IS NULL))) THEN 'idle'
         END AS reason FROM resources r JOIN environment_jobs j ON j.resource_id=r.id
         WHERE r.data->>'state' IN ('starting','running')) limits WHERE reason IS NOT NULL`);
    for (const row of expired) {
      if (row.reason === 'idle') {
        try { if (await this.syncSSH(row.id) !== 0) continue; }
        catch { continue; }
      }
      await this.requestStop(row.id,
        row.reason === 'bootstrap' ? 'The environment did not finish starting.' : null,
        row.reason === 'bootstrap' ? null : row.reason);
    }
    const lease = randomUUID();
    const job = await this.resources.db.one<Job>(
      `UPDATE environment_jobs j SET lease_until=now()+interval '2 minutes',lease_token=$1,attempts=attempts+1
       WHERE resource_id=(SELECT j.resource_id FROM environment_jobs j JOIN resources r ON r.id=j.resource_id
         WHERE (j.lease_until IS NULL OR j.lease_until<now()) AND j.retry_at<=now()
           AND (r.data->>'state'='starting'
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
        if (job.machine_id && !row.data.startedAt) {
          const { volumeId, host } = await this.runner.resume(job.machine_id);
          await created(job.machine_id, volumeId, host);
        } else if (!job.machine_id) {
          const keys = SSHKeys.parse(await this.vault.decrypt(required(job.ssh_ciphertext), 'environment-ssh:' + row.id));
          await this.runner.start(row.id, EnvironmentInput.parse({ size: row.data.size, lifetime: row.data.lifetime }),
            { keys, authorizedKeys: SSHConnection.parse(row.data.ssh).authorizedKeys }, created, required(job.network_slot));
        }
        try { await this.syncSSH(row.id); }
        catch { return true; }
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
          await connection.query(`UPDATE environment_processes SET state='uncertain',phase='settled',
            error='environment_stopped',finished_at=now(),lease_token=NULL,lease_until=NULL
            WHERE environment_id=$1 AND executor_id IS NULL AND phase<>'settled'`, [row.id]);
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
    } finally {
      clearInterval(renewal);
      await this.resources.db.pool.query(
        "UPDATE environment_jobs SET lease_until=NULL,lease_token=NULL,retry_at=greatest(retry_at,now()+interval '5 seconds') WHERE resource_id=$1 AND lease_token=$2",
        [row.id, lease]);
    }
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
